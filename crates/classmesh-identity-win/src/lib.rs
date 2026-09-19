#![cfg_attr(not(windows), forbid(unsafe_code))]

mod machine_identity;

pub use machine_identity::{
    DurableMachineIdentity, MachineIdentityBundle, MachineIdentityStateError,
};

#[cfg(windows)]
mod cng;
#[cfg(windows)]
mod tls;

#[cfg(windows)]
pub use cng::{CngKeyError, CngMachineKey, CngRcgenSigningKey};
#[cfg(windows)]
pub use tls::{
    CngRustlsSigningKey, CngTlsError, cng_client_cert_resolver, cng_server_cert_resolver,
};
