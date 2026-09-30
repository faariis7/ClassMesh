use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_network::AssembledFrame;
use classmesh_network::multicast_receiver::ReceivedGroupMediaCiphertext;
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaError, GroupMediaFrameBinding, GroupMediaKeyMaterial,
    GroupMediaReceiver, GroupMediaReplayError,
};
use classmesh_windows_runtime::ipc::ServicePresentationKeyClear;
use classmesh_windows_runtime::ipc_sensitive::{
    PresentationKeyInstallBinding, SensitivePresentationKeyInstall,
};

#[derive(Debug)]
pub enum WorkerGroupMediaKeyError {
    BindingChangeRequiresClear,
    StaleEpoch { current: u32, received: u32 },
    NoInstalledKey,
    StreamMismatch { expected: u32, received: u32 },
    Security(GroupMediaError),
}

impl WorkerGroupMediaKeyError {
    #[must_use]
    pub const fn disrupts_decode_continuity(&self) -> bool {
        !matches!(
            self,
            Self::Security(GroupMediaError::Replay(
                GroupMediaReplayError::Duplicate | GroupMediaReplayError::TooOld
            ))
        )
    }
}

impl Display for WorkerGroupMediaKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingChangeRequiresClear => formatter.write_str(
                "group-media key binding changed without clearing the current Worker presentation",
            ),
            Self::StaleEpoch { current, received } => write!(
                formatter,
                "group-media epoch must increase: current={current}, received={received}"
            ),
            Self::NoInstalledKey => formatter.write_str("no group-media key is installed"),
            Self::StreamMismatch { expected, received } => write!(
                formatter,
                "group-media ciphertext stream mismatch: expected={expected}, received={received}"
            ),
            Self::Security(error) => write!(formatter, "group-media security: {error}"),
        }
    }
}

impl Error for WorkerGroupMediaKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::BindingChangeRequiresClear
            | Self::StaleEpoch { .. }
            | Self::NoInstalledKey
            | Self::StreamMismatch { .. } => None,
        }
    }
}

impl From<GroupMediaError> for WorkerGroupMediaKeyError {
    fn from(value: GroupMediaError) -> Self {
        Self::Security(value)
    }
}

struct InstalledWorkerGroupMediaKey {
    binding: PresentationKeyInstallBinding,
    receiver: GroupMediaReceiver,
}

impl std::fmt::Debug for InstalledWorkerGroupMediaKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledWorkerGroupMediaKey")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct WorkerGroupMediaKeyState {
    installed: Option<InstalledWorkerGroupMediaKey>,
}

impl WorkerGroupMediaKeyState {
    #[must_use]
    pub fn binding(&self) -> Option<PresentationKeyInstallBinding> {
        self.installed.as_ref().map(|installed| installed.binding)
    }

    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.installed.is_some()
    }

    pub fn install(
        &mut self,
        install: SensitivePresentationKeyInstall,
    ) -> Result<PresentationKeyInstallBinding, WorkerGroupMediaKeyError> {
        let binding = install.binding();
        if let Some(current) = self.binding() {
            let same_presentation = binding.control_session_id == current.control_session_id
                && binding.presentation_id == current.presentation_id
                && binding.stream_id == current.stream_id;
            if !same_presentation {
                return Err(WorkerGroupMediaKeyError::BindingChangeRequiresClear);
            }
            if binding.epoch <= current.epoch {
                return Err(WorkerGroupMediaKeyError::StaleEpoch {
                    current: current.epoch,
                    received: binding.epoch,
                });
            }
        }

        let (binding, mut key_bytes) = install.into_parts();
        let epoch = GroupMediaEpoch::new(binding.epoch)?;
        let key_material = GroupMediaKeyMaterial::import_received_wire(&mut key_bytes[..])?;
        let receiver = GroupMediaReceiver::with_default_replay_tolerance(epoch, &key_material)?;

        self.installed = Some(InstalledWorkerGroupMediaKey { binding, receiver });
        Ok(binding)
    }

    pub fn open_frame(
        &mut self,
        frame: &ReceivedGroupMediaCiphertext,
    ) -> Result<Vec<u8>, WorkerGroupMediaKeyError> {
        let installed = self
            .installed
            .as_mut()
            .ok_or(WorkerGroupMediaKeyError::NoInstalledKey)?;
        if frame.stream_id() != installed.binding.stream_id {
            return Err(WorkerGroupMediaKeyError::StreamMismatch {
                expected: installed.binding.stream_id,
                received: frame.stream_id(),
            });
        }

        let epoch = GroupMediaEpoch::new(installed.binding.epoch)?;
        let binding = GroupMediaFrameBinding::new(
            installed.binding.presentation_id,
            installed.binding.stream_id,
            epoch,
            frame.frame_id(),
            frame.timestamp_us(),
            frame.keyframe(),
        )?;
        installed
            .receiver
            .open_bound_frame(frame.ciphertext(), binding)
            .map_err(Into::into)
    }

    pub fn open_access_unit(
        &mut self,
        frame: ReceivedGroupMediaCiphertext,
    ) -> Result<AssembledFrame, WorkerGroupMediaKeyError> {
        let stream_id = frame.stream_id();
        let frame_id = frame.frame_id();
        let timestamp_us = frame.timestamp_us();
        let keyframe = frame.keyframe();
        let data = self.open_frame(&frame)?;

        Ok(AssembledFrame {
            stream_id,
            frame_id,
            timestamp_us,
            keyframe,
            data,
        })
    }

    pub fn clear_if_matches(&mut self, clear: ServicePresentationKeyClear) -> bool {
        let Some(current) = self.binding() else {
            return false;
        };
        if current.control_session_id != clear.control_session_id
            || current.request_id != clear.request_id
            || current.presentation_id != clear.presentation_id
            || current.stream_id != clear.stream_id
            || current.epoch != clear.epoch
        {
            return false;
        }
        self.installed.take().is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_network::multicast::{MulticastMembership, MulticastProbeOutcome};
    use classmesh_network::multicast_receiver::{
        ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveState,
        ProtectedMulticastReceiverConfig,
    };
    use classmesh_network::{PacketizeMeta, packetize_frame};
    use classmesh_protocol::PROTOCOL_VERSION;
    use classmesh_protocol::control_wire::PresentationKeyGrant;
    use classmesh_security::group_media::{GROUP_MEDIA_KEY_BYTES, GroupMediaSender};

    use super::*;

    const PRESENTATION_ID: u64 = 55;
    const STREAM_ID: u32 = 7;

    fn sensitive(
        control_session_id: u64,
        request_id: u64,
        presentation_id: u64,
        stream_id: u32,
        epoch: u32,
        key: u8,
    ) -> SensitivePresentationKeyInstall {
        let mut grant = PresentationKeyGrant {
            presentation_id,
            stream_id: u64::from(stream_id),
            epoch,
            key_material: vec![key; GROUP_MEDIA_KEY_BYTES],
        };
        SensitivePresentationKeyInstall::take_from_control_grant(
            control_session_id,
            request_id,
            &mut grant,
        )
        .expect("valid sensitive install")
    }

    fn sealed(
        epoch_value: u32,
        key: u8,
        frame_id: u64,
        timestamp_us: u64,
        keyframe: bool,
        plaintext: &[u8],
    ) -> classmesh_security::group_media::SealedGroupMediaFrame {
        let mut bytes = vec![key; GROUP_MEDIA_KEY_BYTES];
        let material = GroupMediaKeyMaterial::import_received_wire(&mut bytes).expect("sender key");
        let epoch = GroupMediaEpoch::new(epoch_value).expect("epoch");
        let mut sender = GroupMediaSender::new(epoch, &material).expect("sender");
        let binding = GroupMediaFrameBinding::new(
            PRESENTATION_ID,
            STREAM_ID,
            epoch,
            frame_id,
            timestamp_us,
            keyframe,
        )
        .expect("binding");
        sender
            .seal_bound_frame(plaintext, binding)
            .expect("sealed frame")
    }

    fn received_with_transport_stream(
        sealed: &classmesh_security::group_media::SealedGroupMediaFrame,
        transport_stream_id: u32,
    ) -> ReceivedGroupMediaCiphertext {
        let membership = MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, 30),
            Ipv4Addr::new(192, 168, 50, 10),
        )
        .expect("membership");
        let teacher = Ipv4Addr::new(192, 168, 50, 20);
        let config = ProtectedMulticastReceiverConfig::new(
            membership,
            50_000,
            teacher,
            transport_stream_id,
            MulticastProbeOutcome::Available,
        )
        .expect("receiver config");
        let mut receiver = ProtectedMulticastReceiveState::new(config).expect("receiver state");
        let binding = sealed.binding();
        let packets = packetize_frame(
            sealed.as_bytes(),
            PacketizeMeta {
                protocol_major: u8::try_from(PROTOCOL_VERSION.major).expect("protocol major"),
                protocol_minor: u8::try_from(PROTOCOL_VERSION.minor).expect("protocol minor"),
                stream_id: transport_stream_id,
                frame_id: binding.frame_id(),
                first_sequence: 1,
                timestamp_us: binding.timestamp_us(),
                keyframe: binding.keyframe(),
            },
        )
        .expect("packetize ciphertext");
        let source = SocketAddr::new(IpAddr::V4(teacher), 49_999);
        let mut ready = None;
        for packet in &packets {
            if let ProtectedMulticastReceiveOutcome::Events(batch) =
                receiver.push_packet(1_000, packet, source)
                && let Some(frame) = batch.frames.into_iter().next()
            {
                ready = Some(frame);
            }
        }
        ready.expect("reassembled ciphertext")
    }

    fn received(
        sealed: &classmesh_security::group_media::SealedGroupMediaFrame,
    ) -> ReceivedGroupMediaCiphertext {
        received_with_transport_stream(sealed, sealed.binding().stream_id())
    }

    #[test]
    fn first_install_retains_only_derived_receiver_state() {
        let mut state = WorkerGroupMediaKeyState::default();
        let binding = state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x33))
            .expect("first install");

        assert_eq!(binding.control_session_id, 77);
        assert_eq!(binding.request_id, 44);
        assert_eq!(binding.presentation_id, PRESENTATION_ID);
        assert_eq!(binding.stream_id, STREAM_ID);
        assert_eq!(binding.epoch, 3);
        assert!(state.is_installed());
        let debug = format!("{state:?}");
        assert!(debug.contains("presentation_id"));
        assert!(!debug.contains("51, 51"));
    }

    #[test]
    fn exact_bound_ciphertext_opens_after_install() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x34))
            .expect("install");
        let sealed = sealed(3, 0x34, 91, 123_456, true, b"worker-presentation-frame");
        let frame = received(&sealed);

        assert_eq!(
            state.open_frame(&frame).expect("authenticated frame"),
            b"worker-presentation-frame"
        );
    }

    #[test]
    fn authenticated_access_unit_preserves_verified_frame_metadata() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x46))
            .expect("install");
        let sealed = sealed(
            3,
            0x46,
            95,
            123_460,
            true,
            b"authenticated-h264-access-unit",
        );
        let access_unit = state
            .open_access_unit(received(&sealed))
            .expect("authenticated access unit");

        assert_eq!(access_unit.stream_id, STREAM_ID);
        assert_eq!(access_unit.frame_id, 95);
        assert_eq!(access_unit.timestamp_us, 123_460);
        assert!(access_unit.keyframe);
        assert_eq!(access_unit.data, b"authenticated-h264-access-unit");
    }

    #[test]
    fn replay_only_open_failures_do_not_disrupt_decode_continuity() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x47))
            .expect("install");
        let sealed = sealed(3, 0x47, 96, 123_461, false, b"frame");

        state
            .open_access_unit(received(&sealed))
            .expect("first frame opens");
        let duplicate = state
            .open_access_unit(received(&sealed))
            .expect_err("duplicate must be rejected");
        assert!(!duplicate.disrupts_decode_continuity());

        let wrong_stream = state
            .open_access_unit(received_with_transport_stream(&sealed, STREAM_ID + 1))
            .expect_err("wrong transport stream must be rejected");
        assert!(wrong_stream.disrupts_decode_continuity());
    }

    #[test]
    fn stale_epoch_is_rejected_without_replacing_current_receiver() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x35))
            .expect("install");
        assert!(matches!(
            state.install(sensitive(77, 45, PRESENTATION_ID, STREAM_ID, 3, 0x36)),
            Err(WorkerGroupMediaKeyError::StaleEpoch {
                current: 3,
                received: 3,
            })
        ));

        let sealed = sealed(3, 0x35, 92, 123_457, false, b"still-current");
        assert_eq!(
            state
                .open_frame(&received(&sealed))
                .expect("old receiver retained"),
            b"still-current"
        );
    }

    #[test]
    fn higher_epoch_replaces_receiver_for_exact_live_binding() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x37))
            .expect("install");
        let rotated = state
            .install(sensitive(77, 45, PRESENTATION_ID, STREAM_ID, 4, 0x38))
            .expect("rotation");
        assert_eq!(rotated.epoch, 4);
        assert_eq!(rotated.request_id, 45);

        let sealed = sealed(4, 0x38, 93, 123_458, true, b"rotated");
        assert_eq!(
            state.open_frame(&received(&sealed)).expect("rotated key"),
            b"rotated"
        );
    }

    #[test]
    fn binding_change_requires_explicit_clear() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x39))
            .expect("install");

        for install in [
            sensitive(78, 45, PRESENTATION_ID, STREAM_ID, 4, 0x40),
            sensitive(77, 45, PRESENTATION_ID + 1, STREAM_ID, 4, 0x41),
            sensitive(77, 45, PRESENTATION_ID, STREAM_ID + 1, 4, 0x42),
        ] {
            assert!(matches!(
                state.install(install),
                Err(WorkerGroupMediaKeyError::BindingChangeRequiresClear)
            ));
        }

        let current = state.binding().expect("current binding");
        assert!(state.clear_if_matches(ServicePresentationKeyClear {
            control_session_id: current.control_session_id,
            request_id: current.request_id,
            presentation_id: current.presentation_id,
            stream_id: current.stream_id,
            epoch: current.epoch,
        }));
        assert!(!state.is_installed());
        assert!(
            state
                .install(sensitive(
                    78,
                    50,
                    PRESENTATION_ID + 1,
                    STREAM_ID + 1,
                    1,
                    0x43,
                ))
                .is_ok()
        );
    }

    #[test]
    fn presentation_key_clear_requires_exact_installed_binding() {
        let mut state = WorkerGroupMediaKeyState::default();
        let installed = state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x45))
            .expect("install");

        let exact = ServicePresentationKeyClear {
            control_session_id: installed.control_session_id,
            request_id: installed.request_id,
            presentation_id: installed.presentation_id,
            stream_id: installed.stream_id,
            epoch: installed.epoch,
        };
        let mut stale = exact;
        stale.request_id = stale.request_id.saturating_add(1);

        assert!(!state.clear_if_matches(stale));
        assert!(state.is_installed());
        assert!(state.clear_if_matches(exact));
        assert!(!state.is_installed());
        assert!(!state.clear_if_matches(exact));
    }

    #[test]
    fn wrong_stream_is_rejected_before_sframe_replay_state() {
        let mut state = WorkerGroupMediaKeyState::default();
        state
            .install(sensitive(77, 44, PRESENTATION_ID, STREAM_ID, 3, 0x44))
            .expect("install");
        let sealed = sealed(3, 0x44, 94, 123_459, false, b"frame");
        let wrong = received_with_transport_stream(&sealed, STREAM_ID + 1);

        assert!(matches!(
            state.open_frame(&wrong),
            Err(WorkerGroupMediaKeyError::StreamMismatch {
                expected: STREAM_ID,
                received,
            }) if received == STREAM_ID + 1
        ));
        assert_eq!(
            state
                .open_frame(&received(&sealed))
                .expect("stream mismatch must not consume replay state"),
            b"frame"
        );
    }
}
