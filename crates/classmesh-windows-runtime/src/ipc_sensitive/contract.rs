use std::fmt;

use classmesh_protocol::control_wire::{PresentationKeyAck, PresentationKeyGrant};
use classmesh_protocol::group_media_control::{
    PRESENTATION_GROUP_KEY_BYTES, validate_key_ack, validate_key_grant,
};
use zeroize::{Zeroize, Zeroizing};

use crate::ipc::{
    IPC_HEADER_LEN, IPC_VERSION_MAJOR, IPC_VERSION_MINOR, IpcFrameError, IpcHeader,
    MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
};

pub const PRESENTATION_KEY_INSTALL_PAYLOAD_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationKeyInstallBinding {
    pub control_session_id: u64,
    pub request_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}

pub struct SensitivePresentationKeyInstall {
    binding: PresentationKeyInstallBinding,
    key_material: Zeroizing<[u8; PRESENTATION_GROUP_KEY_BYTES]>,
}

impl fmt::Debug for SensitivePresentationKeyInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitivePresentationKeyInstall")
            .field("binding", &self.binding)
            .field("key_material_len", &PRESENTATION_GROUP_KEY_BYTES)
            .finish_non_exhaustive()
    }
}

impl SensitivePresentationKeyInstall {
    pub fn take_from_control_grant(
        control_session_id: u64,
        request_id: u64,
        grant: &mut PresentationKeyGrant,
    ) -> Result<Self, crate::ipc::IpcMessageError> {
        let result = (|| {
            if control_session_id == 0 || request_id == 0 {
                return Err(crate::ipc::IpcMessageError::InvalidPayload);
            }
            validate_key_grant(grant)
                .map_err(|_| crate::ipc::IpcMessageError::InvalidPayload)?;

            let stream_id = u32::try_from(grant.stream_id)
                .map_err(|_| crate::ipc::IpcMessageError::InvalidPayload)?;
            let mut key_material = Zeroizing::new([0_u8; PRESENTATION_GROUP_KEY_BYTES]);
            key_material.copy_from_slice(&grant.key_material);

            Ok(Self {
                binding: PresentationKeyInstallBinding {
                    control_session_id,
                    request_id,
                    presentation_id: grant.presentation_id,
                    stream_id,
                    epoch: grant.epoch,
                },
                key_material,
            })
        })();

        grant.key_material.zeroize();
        result
    }

    #[must_use]
    pub const fn binding(&self) -> PresentationKeyInstallBinding {
        self.binding
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PresentationKeyInstallBinding,
        Zeroizing<[u8; PRESENTATION_GROUP_KEY_BYTES]>,
    ) {
        (self.binding, self.key_material)
    }

    pub fn encode(self) -> Result<Zeroizing<Vec<u8>>, IpcFrameError> {
        let header = IpcHeader {
            version_major: IPC_VERSION_MAJOR,
            version_minor: IPC_VERSION_MINOR,
            message_type: MESSAGE_SERVICE_PRESENTATION_KEY_INSTALL,
            payload_len: u32::try_from(PRESENTATION_KEY_INSTALL_PAYLOAD_LEN)
                .map_err(|_| IpcFrameError::PayloadTooLarge)?,
        }
        .encode()?;

        let mut output =
            Zeroizing::new(Vec::with_capacity(IPC_HEADER_LEN + PRESENTATION_KEY_INSTALL_PAYLOAD_LEN));
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.binding.control_session_id.to_be_bytes());
        output.extend_from_slice(&self.binding.request_id.to_be_bytes());
        output.extend_from_slice(&self.binding.presentation_id.to_be_bytes());
        output.extend_from_slice(&self.binding.stream_id.to_be_bytes());
        output.extend_from_slice(&self.binding.epoch.to_be_bytes());
        output.extend_from_slice(&self.key_material[..]);
        debug_assert_eq!(
            output.len(),
            IPC_HEADER_LEN + PRESENTATION_KEY_INSTALL_PAYLOAD_LEN
        );
        Ok(output)
    }

    pub(super) fn decode_payload(
        payload: Zeroizing<Vec<u8>>,
    ) -> Result<Self, IpcFrameError> {
        if payload.len() != PRESENTATION_KEY_INSTALL_PAYLOAD_LEN {
            return Err(IpcFrameError::InvalidSensitivePayload);
        }

        let control_session_id =
            u64::from_be_bytes(payload[0..8].try_into().expect("eight bytes"));
        let request_id = u64::from_be_bytes(payload[8..16].try_into().expect("eight bytes"));
        let presentation_id =
            u64::from_be_bytes(payload[16..24].try_into().expect("eight bytes"));
        let stream_id = u32::from_be_bytes(payload[24..28].try_into().expect("four bytes"));
        let epoch = u32::from_be_bytes(payload[28..32].try_into().expect("four bytes"));

        if control_session_id == 0 || request_id == 0 {
            return Err(IpcFrameError::InvalidSensitivePayload);
        }
        validate_key_ack(&PresentationKeyAck {
            presentation_id,
            stream_id: u64::from(stream_id),
            epoch,
        })
        .map_err(|_| IpcFrameError::InvalidSensitivePayload)?;

        let mut key_material = Zeroizing::new([0_u8; PRESENTATION_GROUP_KEY_BYTES]);
        key_material.copy_from_slice(&payload[32..]);

        Ok(Self {
            binding: PresentationKeyInstallBinding {
                control_session_id,
                request_id,
                presentation_id,
                stream_id,
                epoch,
            },
            key_material,
        })
    }
}
