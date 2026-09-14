#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::IpAddr;

pub const DISCOVERY_MAGIC: u32 = 0x434D_4431; // "CMD1"
pub const DISCOVERY_PACKET_LEN: usize = 84;
pub const MAX_HOSTNAME_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryFlags(u16);

impl DiscoveryFlags {
    pub const NONE: Self = Self(0);
    pub const SERVICE_READY: Self = Self(1 << 0);
    pub const WORKER_READY: Self = Self(1 << 1);
    pub const WIRED: Self = Self(1 << 2);
    pub const WIRELESS: Self = Self(1 << 3);

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

impl core::ops::BitOr for DiscoveryFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAnnouncement {
    pub version_major: u8,
    pub version_minor: u8,
    pub flags: DiscoveryFlags,
    pub device_id: DeviceId,
    pub control_port: u16,
    pub boot_id: u64,
    pub capability_bits: u64,
    pub hostname: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    Truncated,
    BadMagic,
    InvalidHostname,
    InvalidPort,
}

impl DiscoveryAnnouncement {
    pub fn encode(&self) -> Result<[u8; DISCOVERY_PACKET_LEN], DiscoveryError> {
        if self.control_port == 0 {
            return Err(DiscoveryError::InvalidPort);
        }
        let hostname = self.hostname.as_bytes();
        if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_BYTES || !self.hostname.is_ascii() {
            return Err(DiscoveryError::InvalidHostname);
        }

        let mut out = [0_u8; DISCOVERY_PACKET_LEN];
        out[0..4].copy_from_slice(&DISCOVERY_MAGIC.to_be_bytes());
        out[4] = self.version_major;
        out[5] = self.version_minor;
        out[6..8].copy_from_slice(&self.flags.bits().to_be_bytes());
        out[8..24].copy_from_slice(&self.device_id.0);
        out[24..26].copy_from_slice(&self.control_port.to_be_bytes());
        out[26] = u8::try_from(hostname.len()).expect("hostname max is 32 bytes");
        out[28..36].copy_from_slice(&self.boot_id.to_be_bytes());
        out[36..44].copy_from_slice(&self.capability_bits.to_be_bytes());
        out[44..44 + hostname.len()].copy_from_slice(hostname);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DiscoveryError> {
        if data.len() < DISCOVERY_PACKET_LEN {
            return Err(DiscoveryError::Truncated);
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != DISCOVERY_MAGIC {
            return Err(DiscoveryError::BadMagic);
        }
        let control_port = u16::from_be_bytes([data[24], data[25]]);
        if control_port == 0 {
            return Err(DiscoveryError::InvalidPort);
        }
        let hostname_len = usize::from(data[26]);
        if hostname_len == 0 || hostname_len > MAX_HOSTNAME_BYTES {
            return Err(DiscoveryError::InvalidHostname);
        }
        let hostname_bytes = &data[44..44 + hostname_len];
        if !hostname_bytes.is_ascii() {
            return Err(DiscoveryError::InvalidHostname);
        }
        let hostname = core::str::from_utf8(hostname_bytes)
            .map_err(|_| DiscoveryError::InvalidHostname)?
            .to_owned();
        let mut device_id = [0_u8; 16];
        device_id.copy_from_slice(&data[8..24]);
        Ok(Self {
            version_major: data[4],
            version_minor: data[5],
            flags: DiscoveryFlags::from_bits(u16::from_be_bytes([data[6], data[7]])),
            device_id: DeviceId(device_id),
            control_port,
            boot_id: u64::from_be_bytes(data[28..36].try_into().expect("fixed slice")),
            capability_bits: u64::from_be_bytes(data[36..44].try_into().expect("fixed slice")),
            hostname,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub announcement: DiscoveryAnnouncement,
    pub source_ip: IpAddr,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryEvent {
    Added(DeviceId),
    Updated(DeviceId),
    Rebooted(DeviceId),
    Expired(DeviceId),
}

/// Tracks unauthenticated discovery presence only. Discovery is never authorization.
#[derive(Debug)]
pub struct DiscoveryRegistry {
    devices: BTreeMap<DeviceId, DiscoveredDevice>,
    expiry_us: u64,
}

impl DiscoveryRegistry {
    /// # Panics
    /// Panics when `expiry_us` is zero.
    #[must_use]
    pub fn new(expiry_us: u64) -> Self {
        assert!(expiry_us > 0, "discovery expiry must be non-zero");
        Self {
            devices: BTreeMap::new(),
            expiry_us,
        }
    }

    pub fn observe(
        &mut self,
        now_us: u64,
        source_ip: IpAddr,
        announcement: DiscoveryAnnouncement,
    ) -> DiscoveryEvent {
        let id = announcement.device_id;
        if let Some(existing) = self.devices.get_mut(&id) {
            let rebooted = existing.announcement.boot_id != announcement.boot_id;
            existing.announcement = announcement;
            existing.source_ip = source_ip;
            existing.last_seen_us = now_us;
            if rebooted {
                existing.first_seen_us = now_us;
                DiscoveryEvent::Rebooted(id)
            } else {
                DiscoveryEvent::Updated(id)
            }
        } else {
            self.devices.insert(
                id,
                DiscoveredDevice {
                    announcement,
                    source_ip,
                    first_seen_us: now_us,
                    last_seen_us: now_us,
                },
            );
            DiscoveryEvent::Added(id)
        }
    }

    pub fn expire(&mut self, now_us: u64) -> Vec<DiscoveryEvent> {
        let expired: Vec<DeviceId> = self
            .devices
            .iter()
            .filter_map(|(id, device)| {
                (now_us.saturating_sub(device.last_seen_us) > self.expiry_us).then_some(*id)
            })
            .collect();
        for id in &expired {
            self.devices.remove(id);
        }
        expired.into_iter().map(DiscoveryEvent::Expired).collect()
    }

    #[must_use]
    pub fn get(&self, id: DeviceId) -> Option<&DiscoveredDevice> {
        self.devices.get(&id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// Rate-limits local announcements so discovery never turns into a broadcast storm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnouncementPacer {
    interval_us: u64,
    next_due_us: Option<u64>,
}

impl AnnouncementPacer {
    /// # Panics
    /// Panics when `interval_us` is zero.
    #[must_use]
    pub fn new(interval_us: u64) -> Self {
        assert!(interval_us > 0, "discovery interval must be non-zero");
        Self {
            interval_us,
            next_due_us: None,
        }
    }

    pub fn should_announce(&mut self, now_us: u64) -> bool {
        let Some(due) = self.next_due_us else {
            self.next_due_us = Some(now_us.saturating_add(self.interval_us));
            return true;
        };
        if now_us < due {
            return false;
        }
        self.next_due_us = Some(now_us.saturating_add(self.interval_us));
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn announcement(boot_id: u64) -> DiscoveryAnnouncement {
        DiscoveryAnnouncement {
            version_major: 0,
            version_minor: 1,
            flags: DiscoveryFlags::SERVICE_READY | DiscoveryFlags::WIRED,
            device_id: DeviceId([7; 16]),
            control_port: 44_443,
            boot_id,
            capability_bits: 5,
            hostname: "PC-07".into(),
        }
    }

    #[test]
    fn announcement_round_trips_without_secrets() {
        let original = announcement(1);
        let encoded = original.encode().expect("announcement valid");
        let decoded = DiscoveryAnnouncement::decode(&encoded).expect("packet valid");
        assert_eq!(decoded, original);
    }

    #[test]
    fn registry_detects_reboot_and_expiry() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));
        let mut registry = DiscoveryRegistry::new(5_000_000);
        assert_eq!(registry.observe(0, ip, announcement(1)), DiscoveryEvent::Added(DeviceId([7; 16])));
        assert_eq!(registry.observe(1_000, ip, announcement(2)), DiscoveryEvent::Rebooted(DeviceId([7; 16])));
        assert!(registry.expire(5_000_000).is_empty());
        assert_eq!(registry.expire(5_002_000), vec![DiscoveryEvent::Expired(DeviceId([7; 16]))]);
    }

    #[test]
    fn announcement_pacer_prevents_bursts() {
        let mut pacer = AnnouncementPacer::new(1_000_000);
        assert!(pacer.should_announce(0));
        assert!(!pacer.should_announce(10));
        assert!(pacer.should_announce(1_000_000));
    }
}
