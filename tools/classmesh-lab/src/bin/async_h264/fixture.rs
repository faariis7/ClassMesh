use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::Failure;

const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

pub(super) struct Fixture {
    bytes: Vec<u8>,
    frames: usize,
    idrs: usize,
}

impl Fixture {
    pub(super) fn describe(&self) -> Value {
        json!({
            "bytes": self.bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(&self.bytes)),
            "access_units": self.frames,
            "idrs": self.idrs,
        })
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(super) fn units(&self) -> Vec<AccessUnit<'_>> {
        access_units(&self.bytes).expect("fixture was validated on load")
    }
}

pub(super) fn load(path: &Path, stage: &'static str) -> Result<Fixture, Failure> {
    let metadata = path
        .metadata()
        .map_err(|error| Failure::new(stage, error))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(Failure::new(
            stage,
            "expected a regular fixture file of at most 32 MiB",
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| Failure::new(stage, error))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Failure::new(stage, "fixture exceeded 32 MiB during read"));
    }
    let units = access_units(&bytes).map_err(|error| Failure::new(stage, error))?;
    if units.iter().any(|unit| unit.bytes.len() > 4 * 1024 * 1024) {
        return Err(Failure::new(stage, "an access unit exceeded 4 MiB"));
    }
    let frames = units.len();
    let idrs = units.iter().filter(|unit| unit.idr).count();
    Ok(Fixture {
        bytes,
        frames,
        idrs,
    })
}

// The lab fixture contract is Annex B with AUDs, progressive IDR/P access units,
// and SPS/PPS repeated ahead of every IDR. Media Foundation parses the payloads.
const MAX_UNITS: usize = 240;

#[derive(Debug)]
pub(super) struct AccessUnit<'a> {
    pub bytes: &'a [u8],
    pub idr: bool,
}

pub(super) fn access_units(bytes: &[u8]) -> Result<Vec<AccessUnit<'_>>, &'static str> {
    let mut nals = bytes
        .windows(3)
        .enumerate()
        .filter(|(_, window)| *window == [0, 0, 1])
        .map(|(start, _)| {
            let prefix = start - usize::from(start > 0 && bytes[start - 1] == 0);
            (prefix, start + 3)
        })
        .peekable();

    let mut units = Vec::new();
    let mut start = None;
    let mut picture = Picture::default();
    while let Some((prefix, header)) = nals.next() {
        let end = nals.peek().map_or(bytes.len(), |&(next, _)| next);
        if end.saturating_sub(header) < 2 || bytes[header] & 0x80 != 0 {
            return Err("truncated or invalid Annex B NAL");
        }
        let kind = bytes[header] & 31;
        if kind == 9 {
            if let Some(start) = start.replace(prefix) {
                push(&mut units, &bytes[start..prefix], picture)?;
                picture = Picture::default();
            } else if prefix != 0 {
                return Err("first AUD must start the fixture");
            }
        } else if start.is_some() {
            picture.observe(kind)?;
        } else {
            return Err("fixture must start with an Annex B AUD");
        }
    }

    let start = start.ok_or("fixture contains no AUD")?;
    push(&mut units, &bytes[start..], picture)?;
    if units.len() < 3 || !units[0].idr || !units.iter().any(|unit| !unit.idr) {
        return Err(
            "fixture needs at least three pictures starting with an IDR and including a non-IDR",
        );
    }
    Ok(units)
}

#[derive(Default)]
struct Picture {
    sps: bool,
    pps: bool,
    vcl: Option<u8>,
}

impl Picture {
    fn observe(&mut self, kind: u8) -> Result<(), &'static str> {
        match kind {
            7 if self.vcl.is_none() => self.sps = true,
            8 if self.vcl.is_none() => self.pps = true,
            5 if !(self.sps && self.pps) => return Err("IDR is missing preceding SPS/PPS"),
            1 | 5 if self.vcl.is_none_or(|vcl| vcl == kind) => self.vcl = Some(kind),
            6 | 10..=12 => {}
            _ => return Err("unexpected NAL type or mixed slices in the access unit"),
        }
        Ok(())
    }
}

fn push<'a>(
    units: &mut Vec<AccessUnit<'a>>,
    bytes: &'a [u8],
    picture: Picture,
) -> Result<(), &'static str> {
    let kind = picture.vcl.ok_or("AUD has no coded picture")?;
    if units.len() == MAX_UNITS {
        return Err("fixture has too many access units");
    }
    units.push(AccessUnit {
        bytes,
        idr: kind == 5,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDING: &[u8] = &[
        0, 0, 0, 1, 9, 0xf0, 0, 0, 1, 0x67, 42, 0, 0, 1, 0x68, 7, 0, 0, 1, 0x65, 9, 0, 0, 1, 9,
        0xf0, 0, 0, 1, 0x41, 8, 0, 0, 0, 1, 9, 0xf0, 0, 0, 1, 0x41, 3,
    ];

    #[test]
    fn preserves_access_units_and_identifies_idr_with_mixed_start_codes() {
        let units = access_units(RECORDING).unwrap();
        assert_eq!(units.len(), 3);
        assert_eq!(units[0].bytes, &RECORDING[..21]);
        assert!(units[0].idr);
        assert!(!units[1].idr);
        assert_eq!(units[2].bytes, &RECORDING[31..]);
    }

    #[test]
    fn rejects_missing_aud_empty_units_and_parameter_sets_after_first_slice() {
        assert!(access_units(&RECORDING[6..]).is_err());
        assert!(access_units(&RECORDING[..25]).is_err());
        let mut malformed = RECORDING.to_vec();
        malformed[9] = 0x65;
        malformed[19] = 0x67;
        assert!(access_units(&malformed).is_err());
    }

    #[test]
    fn bounds_access_unit_count() {
        let mut too_many = RECORDING.to_vec();
        for _ in 0..MAX_UNITS {
            too_many.extend_from_slice(&RECORDING[21..31]);
        }
        assert!(access_units(&too_many).is_err());
    }
}
