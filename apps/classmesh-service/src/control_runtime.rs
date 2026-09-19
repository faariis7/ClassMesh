use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use classmesh_control::diagnostics::handshake_diagnostic_code;
use classmesh_control::handshake::{server_hello_enrolled, ServerHelloConfig};
use classmesh_control::quic::{
    enrolled_server_config_with_resolver, ControlChannel, DEFAULT_IO_TIMEOUT,
};
use classmesh_identity_win::{
    cng_server_cert_resolver, CngMachineKey, MachineIdentityBundle,
};
use classmesh_protocol::{Capability, PROTOCOL_VERSION};
use classmesh_security::AuthorizationStore;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::sync::oneshot;

const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct ControlRuntimeState {
    pub(crate) identity: MachineIdentityBundle,
    pub(crate) authorization: AuthorizationStore,
    pub(crate) key: CngMachineKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlRuntimeConfig {
    pub(crate) bind_address: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct PersistedControlRuntimeConfig {
    version: u32,
    bind_address: String,
}

impl ControlRuntimeConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("control runtime config metadata failed: {error}"))?;
        let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if declared > MAX_CONFIG_BYTES {
            return Err(format!(
                "control runtime config is {declared} bytes; maximum is {MAX_CONFIG_BYTES}"
            ));
        }

        let file = File::open(path)
            .map_err(|error| format!("control runtime config open failed: {error}"))?;
        let mut bytes = Vec::with_capacity(declared.min(MAX_CONFIG_BYTES));
        file.take(u64::try_from(MAX_CONFIG_BYTES + 1).expect("config bound fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("control runtime config read failed: {error}"))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "control runtime config is {} bytes; maximum is {MAX_CONFIG_BYTES}",
                bytes.len()
            ));
        }

        let persisted: PersistedControlRuntimeConfig = serde_json::from_slice(&bytes)
            .map_err(|error| format!("control runtime config JSON failed: {error}"))?;
        if persisted.version != CONFIG_VERSION {
            return Err(format!(
                "unsupported control runtime config version {}",
                persisted.version
            ));
        }

        let bind_address = persisted
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|_| "control runtime bind_address must be a socket address".to_owned())?;
        if bind_address.port() == 0 {
            return Err("control runtime bind port must be non-zero".to_owned());
        }

        Ok(Self { bind_address })
    }
}

#[derive(Debug)]
pub(crate) struct ControlRuntime {
    stop_tx: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    local_address: SocketAddr,
}

impl ControlRuntime {
    pub(crate) fn start(
        state: ControlRuntimeState,
        config: ControlRuntimeConfig,
    ) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (stop_tx, stop_rx) = oneshot::channel();

        let thread = thread::Builder::new()
            .name("classmesh-control".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "control Tokio runtime creation failed: {error}"
                        )));
                        return;
                    }
                };

                runtime.block_on(run_listener(state, config, ready_tx, stop_rx));
            })
            .map_err(|error| format!("control runtime thread creation failed: {error}"))?;

        let local_address = match ready_rx.recv_timeout(READY_TIMEOUT) {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => {
                let _ = thread.join();
                return Err(error);
            }
            Err(error) => {
                let _ = stop_tx.send(());
                let _ = thread.join();
                return Err(format!("control runtime readiness failed: {error}"));
            }
        };

        Ok(Self {
            stop_tx: Some(stop_tx),
            thread: Some(thread),
            local_address,
        })
    }

    #[must_use]
    pub(crate) const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    #[must_use]
    pub(crate) fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    pub(crate) fn stop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            eprintln!("ClassMesh control runtime thread panicked during shutdown");
        }
    }
}

impl Drop for ControlRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn run_listener(
    state: ControlRuntimeState,
    config: ControlRuntimeConfig,
    ready_tx: mpsc::SyncSender<Result<SocketAddr, String>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let endpoint = match build_endpoint(&state, config) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = ready_tx.send(Err(error));
            return;
        }
    };
    let local_address = match endpoint.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let _ = ready_tx.send(Err(format!(
                "control listener local address failed: {error}"
            )));
            return;
        }
    };
    if ready_tx.send(Ok(local_address)).is_err() {
        endpoint.close(0_u32.into(), b"service startup abandoned");
        return;
    }

    let authorization = Arc::new(state.authorization);
    let session_ids = Arc::new(AtomicU64::new(1));

    loop {
        tokio::select! {
            _ = &mut stop_rx => {
                endpoint.close(0_u32.into(), b"service stopping");
                endpoint.wait_idle().await;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let authorization = Arc::clone(&authorization);
                let session_ids = Arc::clone(&session_ids);
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    let mut channel = match ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT).await {
                        Ok(channel) => channel,
                        Err(_) => {
                            connection.close(0_u32.into(), b"control stream rejected");
                            return;
                        }
                    };

                    let session_id = next_session_id(&session_ids);
                    let hello_config = ServerHelloConfig {
                        local_version: PROTOCOL_VERSION,
                        local_capabilities: BTreeSet::from([Capability::ServiceSessionWorker]),
                        control_session_id: session_id,
                    };
                    let now_unix_ms = match unix_time_ms() {
                        Ok(value) => value,
                        Err(_) => {
                            connection.close(0_u32.into(), b"invalid service clock");
                            return;
                        }
                    };

                    match server_hello_enrolled(
                        &connection,
                        &mut channel,
                        &hello_config,
                        authorization.as_ref(),
                        now_unix_ms,
                    )
                    .await
                    {
                        Ok((_session, peer)) => {
                            eprintln!(
                                "ClassMesh enrolled control session {} established",
                                peer.control_session_id
                            );
                            let _ = connection.closed().await;
                        }
                        Err(error) => {
                            eprintln!(
                                "ClassMesh control handshake rejected: {}",
                                handshake_diagnostic_code(&error)
                            );
                            connection.close(0_u32.into(), b"control handshake rejected");
                        }
                    }
                });
            }
        }
    }
}

fn build_endpoint(
    state: &ControlRuntimeState,
    config: ControlRuntimeConfig,
) -> Result<Endpoint, String> {
    if state.identity.trust_roots_der.is_empty() {
        return Err("machine identity has no client trust roots".to_owned());
    }

    let mut roots = RootCertStore::empty();
    for root in &state.identity.trust_roots_der {
        roots
            .add(CertificateDer::from(root.clone()))
            .map_err(|_| "machine identity contains an invalid client trust root".to_owned())?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|error| format!("client certificate verifier creation failed: {error}"))?;

    let certificate_chain = state
        .identity
        .certificate_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let resolver = cng_server_cert_resolver(certificate_chain, state.key.clone())
        .map_err(|error| format!("protected server credential rejected: {error}"))?;
    let server_config = enrolled_server_config_with_resolver(resolver, verifier)
        .map_err(|error| format!("enrolled QUIC server configuration failed: {error}"))?;

    Endpoint::server(server_config, config.bind_address)
        .map_err(|error| format!("control listener bind failed: {error}"))
}

fn unix_time_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "system clock cannot be represented in milliseconds".to_owned())
}

fn next_session_id(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn test_path() -> std::path::PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "classmesh-control-runtime-config-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test directory");
        directory.join("control-runtime.json")
    }

    #[test]
    fn config_requires_supported_version_and_nonzero_port() {
        let path = test_path();
        fs::write(
            &path,
            r#"{"version":1,"bind_address":"127.0.0.1:44991"}"#,
        )
        .expect("write config");
        assert_eq!(
            ControlRuntimeConfig::load(&path).expect("valid config"),
            ControlRuntimeConfig {
                bind_address: "127.0.0.1:44991".parse().expect("socket"),
            }
        );

        fs::write(&path, r#"{"version":1,"bind_address":"127.0.0.1:0"}"#)
            .expect("write invalid port");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        fs::write(
            &path,
            r#"{"version":2,"bind_address":"127.0.0.1:44991"}"#,
        )
        .expect("write invalid version");
        assert!(ControlRuntimeConfig::load(&path).is_err());

        let _ = fs::remove_dir_all(path.parent().expect("test parent"));
    }

    #[test]
    fn session_ids_are_nonzero_and_monotonic() {
        let counter = AtomicU64::new(1);
        assert_eq!(next_session_id(&counter), 1);
        assert_eq!(next_session_id(&counter), 2);
        assert_eq!(next_session_id(&counter), 3);
    }
}
