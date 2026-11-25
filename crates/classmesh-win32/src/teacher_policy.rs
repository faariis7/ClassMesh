//! Protected, read-only Teacher policy for the installed executable.
use crate::registry_epoch::{self, TEACHER_SCOPE};
use std::io;

const DISABLED: &[u8] = br#"{"version":1,"disabled":true}"#;

pub const MAX_POLICY_BYTES: usize = registry_epoch::TEACHER_DATA_MAX;

pub struct InstalledTeacherPolicy {
    checkpoint: [u8; 48],
    bytes: Vec<u8>,
}

impl InstalledTeacherPolicy {
    pub fn open() -> io::Result<Self> {
        let (checkpoint, bytes) = registry_epoch::read_teacher(TEACHER_SCOPE)?;
        if bytes == DISABLED {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Teacher policy disabled",
            ));
        }
        Ok(Self { checkpoint, bytes })
    }

    pub fn epoch(&self) -> u64 {
        u64::from_le_bytes(
            self.checkpoint[8..16]
                .try_into()
                .expect("checkpoint epoch width"),
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn still_current(&self) -> io::Result<bool> {
        Ok(registry_epoch::teacher_checkpoint(TEACHER_SCOPE)? == self.checkpoint)
    }
}

/// Explicit administrator operation. Callers must first validate the exact
/// configuration and obtain separate authorization to provision the machine.
pub fn publish_teacher_policy(epoch: u64, bytes: &[u8], create: bool) -> io::Result<()> {
    registry_epoch::publish_teacher(TEACHER_SCOPE, epoch, bytes, create)
}

/// Commit an explicit deny snapshot at a higher epoch. Keeping the anchor
/// prevents accidental recovery from an older, otherwise valid signed roster.
pub fn revoke_teacher_policy(epoch: u64) -> io::Result<()> {
    registry_epoch::publish_teacher(TEACHER_SCOPE, epoch, DISABLED, false)
}
