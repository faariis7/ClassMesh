use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use classmesh_video::{Codec, EncoderClass, EncoderProbeResult};
use serde::{Deserialize, Serialize};

use crate::{EncoderBenchmarkResult, EncoderCapabilityCacheKey};

const CACHE_VERSION: u32 = 1;
const MAX_CACHE_BYTES: usize = 64 * 1024;
const MAX_ADAPTER_IDENTITY_LEN: usize = 128;
const MAX_DRIVER_VERSION_LEN: usize = 128;
const MAX_ENCODER_CLSID_LEN: usize = 128;
const MAX_BACKEND_NAME_LEN: usize = 256;
const MAX_FRAME_COUNT: u64 = 1_000_000;

#[derive(Debug)]
pub enum EncoderCapabilityCacheError {
    Io(std::io::Error),
    Json(serde_json::Error),
    CacheTooLarge { bytes: usize, maximum: usize },
    UnsupportedVersion(u32),
    InvalidString(&'static str),
    InvalidProfile,
    InvalidProbe,
    InvalidCodec(u8),
    InvalidClass(u8),
    InvalidFrameCount,
}

impl fmt::Display for EncoderCapabilityCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "encoder capability cache I/O failed: {error}"),
            Self::Json(error) => write!(f, "encoder capability cache JSON failed: {error}"),
            Self::CacheTooLarge { bytes, maximum } => {
                write!(
                    f,
                    "encoder capability cache is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported encoder capability cache version {version}")
            }
            Self::InvalidString(field) => {
                write!(f, "encoder capability cache contains invalid {field}")
            }
            Self::InvalidProfile => write!(f, "encoder capability cache contains invalid profile"),
            Self::InvalidProbe => write!(f, "encoder capability cache contains invalid probe data"),
            Self::InvalidCodec(value) => {
                write!(f, "encoder capability cache contains codec {value}")
            }
            Self::InvalidClass(value) => {
                write!(f, "encoder capability cache contains class {value}")
            }
            Self::InvalidFrameCount => {
                write!(f, "encoder capability cache contains invalid frame counts")
            }
        }
    }
}

impl std::error::Error for EncoderCapabilityCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EncoderCapabilityCacheError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for EncoderCapabilityCacheError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone)]
pub struct DurableEncoderCapabilityCache {
    path: PathBuf,
}

impl DurableEncoderCapabilityCache {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_exact(
        &self,
        expected: &EncoderCapabilityCacheKey,
    ) -> Result<Option<EncoderBenchmarkResult>, EncoderCapabilityCacheError> {
        let backup = sibling_with_suffix(&self.path, ".bak");
        let source = if self.path.exists() {
            self.path.as_path()
        } else if backup.exists() {
            backup.as_path()
        } else {
            return Ok(None);
        };

        let metadata = fs::metadata(source)?;
        let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if declared > MAX_CACHE_BYTES {
            return Err(EncoderCapabilityCacheError::CacheTooLarge {
                bytes: declared,
                maximum: MAX_CACHE_BYTES,
            });
        }

        let file = File::open(source)?;
        let mut bytes = Vec::with_capacity(declared.min(MAX_CACHE_BYTES));
        file.take(u64::try_from(MAX_CACHE_BYTES + 1).expect("cache bound fits u64"))
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CACHE_BYTES {
            return Err(EncoderCapabilityCacheError::CacheTooLarge {
                bytes: bytes.len(),
                maximum: MAX_CACHE_BYTES,
            });
        }

        let persisted: PersistedCache = serde_json::from_slice(&bytes)?;
        let (key, result) = persisted.into_key_and_result()?;
        if &key != expected {
            return Ok(None);
        }
        Ok(Some(result.into_result(&key)?))
    }

    pub fn save(
        &self,
        key: &EncoderCapabilityCacheKey,
        result: &EncoderBenchmarkResult,
    ) -> Result<(), EncoderCapabilityCacheError> {
        validate_key(key)?;
        validate_result_for_key(key, result)?;

        let persisted = PersistedCache::from_parts(key, result);
        let bytes = serde_json::to_vec_pretty(&persisted)?;
        if bytes.len() > MAX_CACHE_BYTES {
            return Err(EncoderCapabilityCacheError::CacheTooLarge {
                bytes: bytes.len(),
                maximum: MAX_CACHE_BYTES,
            });
        }

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let temporary = sibling_with_suffix(&self.path, ".tmp");
        let backup = sibling_with_suffix(&self.path, ".bak");
        let _ = fs::remove_file(&temporary);

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);

        let _ = fs::remove_file(&backup);
        if self.path.exists() {
            fs::rename(&self.path, &backup)?;
        }

        if let Err(error) = fs::rename(&temporary, &self.path) {
            if backup.exists() && !self.path.exists() {
                let _ = fs::rename(&backup, &self.path);
            }
            return Err(EncoderCapabilityCacheError::Io(error));
        }

        let _ = fs::remove_file(&backup);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedCache {
    version: u32,
    key: PersistedKey,
    result: PersistedResult,
}

impl PersistedCache {
    fn from_parts(key: &EncoderCapabilityCacheKey, result: &EncoderBenchmarkResult) -> Self {
        Self {
            version: CACHE_VERSION,
            key: PersistedKey::from_key(key),
            result: PersistedResult::from_result(result),
        }
    }

    fn into_key_and_result(
        self,
    ) -> Result<(EncoderCapabilityCacheKey, PersistedResult), EncoderCapabilityCacheError> {
        if self.version != CACHE_VERSION {
            return Err(EncoderCapabilityCacheError::UnsupportedVersion(
                self.version,
            ));
        }
        let key = self.key.into_key()?;
        Ok((key, self.result))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKey {
    adapter_identity: String,
    driver_version: String,
    encoder_clsid: String,
    width: u16,
    height: u16,
    target_fps: u16,
    bitrate_bps: u32,
}

impl PersistedKey {
    fn from_key(key: &EncoderCapabilityCacheKey) -> Self {
        Self {
            adapter_identity: key.adapter_identity.clone(),
            driver_version: key.driver_version.clone(),
            encoder_clsid: key.encoder_clsid.clone(),
            width: key.width,
            height: key.height,
            target_fps: key.target_fps,
            bitrate_bps: key.bitrate_bps,
        }
    }

    fn into_key(self) -> Result<EncoderCapabilityCacheKey, EncoderCapabilityCacheError> {
        let key = EncoderCapabilityCacheKey {
            adapter_identity: self.adapter_identity,
            driver_version: self.driver_version,
            encoder_clsid: self.encoder_clsid,
            width: self.width,
            height: self.height,
            target_fps: self.target_fps,
            bitrate_bps: self.bitrate_bps,
        };
        validate_key(&key)?;
        Ok(key)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedResult {
    backend: String,
    codec: u8,
    advertised_hardware: bool,
    gpu_native_input: bool,
    low_latency_accepted: bool,
    sustained_fps: f32,
    p50_encode_ms: f32,
    p95_encode_ms: f32,
    reset_ok: bool,
    dynamic_bitrate_ok: bool,
    keyframe_request_ok: bool,
    class: u8,
    output_frames: u64,
    dropped_or_missing: u64,
}

impl PersistedResult {
    fn from_result(result: &EncoderBenchmarkResult) -> Self {
        Self {
            backend: result.probe.backend.clone(),
            codec: codec_to_wire(result.probe.codec),
            advertised_hardware: result.probe.advertised_hardware,
            gpu_native_input: result.probe.gpu_native_input,
            low_latency_accepted: result.probe.low_latency_accepted,
            sustained_fps: result.probe.sustained_fps,
            p50_encode_ms: result.probe.p50_encode_ms,
            p95_encode_ms: result.probe.p95_encode_ms,
            reset_ok: result.probe.reset_ok,
            dynamic_bitrate_ok: result.probe.dynamic_bitrate_ok,
            keyframe_request_ok: result.probe.keyframe_request_ok,
            class: class_to_wire(result.class),
            output_frames: u64::try_from(result.output_frames).unwrap_or(u64::MAX),
            dropped_or_missing: u64::try_from(result.dropped_or_missing).unwrap_or(u64::MAX),
        }
    }

    fn into_result(
        self,
        key: &EncoderCapabilityCacheKey,
    ) -> Result<EncoderBenchmarkResult, EncoderCapabilityCacheError> {
        let result = EncoderBenchmarkResult {
            probe: EncoderProbeResult {
                backend: self.backend,
                codec: codec_from_wire(self.codec)?,
                advertised_hardware: self.advertised_hardware,
                gpu_native_input: self.gpu_native_input,
                low_latency_accepted: self.low_latency_accepted,
                sustained_fps: self.sustained_fps,
                p50_encode_ms: self.p50_encode_ms,
                p95_encode_ms: self.p95_encode_ms,
                reset_ok: self.reset_ok,
                dynamic_bitrate_ok: self.dynamic_bitrate_ok,
                keyframe_request_ok: self.keyframe_request_ok,
            },
            class: class_from_wire(self.class)?,
            output_frames: usize::try_from(self.output_frames)
                .map_err(|_| EncoderCapabilityCacheError::InvalidFrameCount)?,
            dropped_or_missing: usize::try_from(self.dropped_or_missing)
                .map_err(|_| EncoderCapabilityCacheError::InvalidFrameCount)?,
        };
        validate_result_for_key(key, &result)?;
        Ok(result)
    }
}

fn validate_key(key: &EncoderCapabilityCacheKey) -> Result<(), EncoderCapabilityCacheError> {
    validate_string(
        "adapter identity",
        &key.adapter_identity,
        MAX_ADAPTER_IDENTITY_LEN,
    )?;
    validate_string(
        "driver version",
        &key.driver_version,
        MAX_DRIVER_VERSION_LEN,
    )?;
    validate_string("encoder CLSID", &key.encoder_clsid, MAX_ENCODER_CLSID_LEN)?;
    if key.width == 0 || key.height == 0 || key.target_fps == 0 || key.bitrate_bps == 0 {
        return Err(EncoderCapabilityCacheError::InvalidProfile);
    }
    Ok(())
}

fn validate_result_for_key(
    key: &EncoderCapabilityCacheKey,
    result: &EncoderBenchmarkResult,
) -> Result<(), EncoderCapabilityCacheError> {
    validate_string("backend", &result.probe.backend, MAX_BACKEND_NAME_LEN)?;
    let finite_non_negative = |value: f32| value.is_finite() && value >= 0.0;
    if !finite_non_negative(result.probe.sustained_fps)
        || !result.probe.p50_encode_ms.is_finite()
        || result.probe.p50_encode_ms <= 0.0
        || !result.probe.p95_encode_ms.is_finite()
        || result.probe.p95_encode_ms <= 0.0
        || result.probe.p50_encode_ms > result.probe.p95_encode_ms
    {
        return Err(EncoderCapabilityCacheError::InvalidProbe);
    }

    let output_frames = u64::try_from(result.output_frames)
        .map_err(|_| EncoderCapabilityCacheError::InvalidFrameCount)?;
    let missing = u64::try_from(result.dropped_or_missing)
        .map_err(|_| EncoderCapabilityCacheError::InvalidFrameCount)?;
    if output_frames > MAX_FRAME_COUNT
        || missing > MAX_FRAME_COUNT
        || output_frames.saturating_add(missing) > MAX_FRAME_COUNT
    {
        return Err(EncoderCapabilityCacheError::InvalidFrameCount);
    }

    let measured_class = result.probe.classify();
    let workload_class = class_for_key(measured_class, key);
    if result.class > workload_class
        || (result.class != EncoderClass::Unsupported
            && (result.probe.codec != Codec::H264 || !result.probe.advertised_hardware))
    {
        return Err(EncoderCapabilityCacheError::InvalidProbe);
    }
    Ok(())
}

fn class_for_key(
    class: EncoderClass,
    key: &EncoderCapabilityCacheKey,
) -> EncoderClass {
    if key.width < 1920 || key.height < 1080 || key.target_fps < 30 {
        return class.min(EncoderClass::Compatibility);
    }
    if key.target_fps < 60 {
        return class.min(EncoderClass::Presentation1080p30);
    }
    class
}

fn validate_string(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), EncoderCapabilityCacheError> {
    if value.is_empty() || value.len() > maximum {
        return Err(EncoderCapabilityCacheError::InvalidString(field));
    }
    Ok(())
}

const fn codec_to_wire(codec: Codec) -> u8 {
    match codec {
        Codec::H264 => 1,
        Codec::Hevc => 2,
        Codec::Av1 => 3,
    }
}

fn codec_from_wire(value: u8) -> Result<Codec, EncoderCapabilityCacheError> {
    match value {
        1 => Ok(Codec::H264),
        2 => Ok(Codec::Hevc),
        3 => Ok(Codec::Av1),
        other => Err(EncoderCapabilityCacheError::InvalidCodec(other)),
    }
}

const fn class_to_wire(class: EncoderClass) -> u8 {
    match class {
        EncoderClass::Unsupported => 0,
        EncoderClass::Compatibility => 1,
        EncoderClass::Presentation1080p30 => 2,
        EncoderClass::Presentation1080p60 => 3,
    }
}

fn class_from_wire(value: u8) -> Result<EncoderClass, EncoderCapabilityCacheError> {
    match value {
        0 => Ok(EncoderClass::Unsupported),
        1 => Ok(EncoderClass::Compatibility),
        2 => Ok(EncoderClass::Presentation1080p30),
        3 => Ok(EncoderClass::Presentation1080p60),
        other => Err(EncoderCapabilityCacheError::InvalidClass(other)),
    }
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn test_path(name: &str) -> PathBuf {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "classmesh-encoder-cache-{}-{name}-{id}.json",
            std::process::id()
        ))
    }

    fn key(driver: &str) -> EncoderCapabilityCacheKey {
        EncoderCapabilityCacheKey {
            adapter_identity: "00000001:00000002".into(),
            driver_version: driver.into(),
            encoder_clsid: "{encoder-clsid}".into(),
            width: 1280,
            height: 720,
            target_fps: 30,
            bitrate_bps: 2_500_000,
        }
    }

    fn result() -> EncoderBenchmarkResult {
        EncoderBenchmarkResult {
            probe: EncoderProbeResult {
                backend: "test encoder".into(),
                codec: Codec::H264,
                advertised_hardware: true,
                gpu_native_input: true,
                low_latency_accepted: true,
                sustained_fps: 30.0,
                p50_encode_ms: 4.0,
                p95_encode_ms: 8.0,
                reset_ok: true,
                dynamic_bitrate_ok: false,
                keyframe_request_ok: true,
            },
            class: EncoderClass::Compatibility,
            output_frames: 120,
            dropped_or_missing: 0,
        }
    }

    #[test]
    fn exact_key_round_trips() {
        let path = test_path("roundtrip");
        let cache = DurableEncoderCapabilityCache::new(&path);
        cache.save(&key("31.0.15.5123"), &result()).expect("save");
        assert_eq!(
            cache.load_exact(&key("31.0.15.5123")).expect("load"),
            Some(result())
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stale_driver_is_cache_miss() {
        let path = test_path("stale");
        let cache = DurableEncoderCapabilityCache::new(&path);
        cache.save(&key("31.0.15.5123"), &result()).expect("save");
        assert_eq!(cache.load_exact(&key("31.0.15.6000")).expect("load"), None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bitrate_change_is_cache_miss() {
        let path = test_path("bitrate-stale");
        let cache = DurableEncoderCapabilityCache::new(&path);
        let stored = key("31.0.15.5123");
        cache.save(&stored, &result()).expect("save");
        let mut expected = stored;
        expected.bitrate_bps = 1_500_000;
        assert_eq!(cache.load_exact(&expected).expect("load"), None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn malformed_json_fails_closed() {
        let path = test_path("malformed");
        fs::write(&path, b"{not-json").expect("write");
        let cache = DurableEncoderCapabilityCache::new(&path);
        assert!(matches!(
            cache.load_exact(&key("31.0.15.5123")),
            Err(EncoderCapabilityCacheError::Json(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsupported_version_fails_closed() {
        let path = test_path("version");
        let mut persisted = PersistedCache::from_parts(&key("31.0.15.5123"), &result());
        persisted.version = 99;
        fs::write(&path, serde_json::to_vec(&persisted).expect("serialize")).expect("write");
        let cache = DurableEncoderCapabilityCache::new(&path);
        assert!(matches!(
            cache.load_exact(&key("31.0.15.5123")),
            Err(EncoderCapabilityCacheError::UnsupportedVersion(99))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_class_cannot_exceed_measured_probe() {
        let path = test_path("class-escalation");
        let cache = DurableEncoderCapabilityCache::new(&path);
        let mut invalid = result();
        invalid.probe.sustained_fps = 10.0;
        assert!(matches!(
            cache.save(&key("31.0.15.5123"), &invalid),
            Err(EncoderCapabilityCacheError::InvalidProbe)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cached_class_is_capped_by_exact_profile_geometry() {
        let path = test_path("geometry-class");
        let cache = DurableEncoderCapabilityCache::new(&path);
        let mut invalid = result();
        invalid.class = EncoderClass::Presentation1080p30;
        assert!(matches!(
            cache.save(&key("31.0.15.5123"), &invalid),
            Err(EncoderCapabilityCacheError::InvalidProbe)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cached_class_is_capped_by_exact_profile_fps() {
        let path = test_path("fps-class");
        let cache = DurableEncoderCapabilityCache::new(&path);
        let mut expected = key("31.0.15.5123");
        expected.width = 1920;
        expected.height = 1080;
        expected.target_fps = 30;
        expected.bitrate_bps = 5_000_000;
        let mut invalid = result();
        invalid.probe.sustained_fps = 60.0;
        invalid.probe.p50_encode_ms = 4.0;
        invalid.probe.p95_encode_ms = 8.0;
        invalid.class = EncoderClass::Presentation1080p60;
        assert!(matches!(
            cache.save(&expected, &invalid),
            Err(EncoderCapabilityCacheError::InvalidProbe)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn positive_cached_capability_requires_advertised_hardware() {
        let path = test_path("software-positive");
        let cache = DurableEncoderCapabilityCache::new(&path);
        let mut invalid = result();
        invalid.probe.advertised_hardware = false;
        assert!(matches!(
            cache.save(&key("31.0.15.5123"), &invalid),
            Err(EncoderCapabilityCacheError::InvalidProbe)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn oversized_cache_is_rejected_before_parse() {
        let path = test_path("oversized");
        fs::write(&path, vec![b'x'; MAX_CACHE_BYTES + 1]).expect("write");
        let cache = DurableEncoderCapabilityCache::new(&path);
        assert!(matches!(
            cache.load_exact(&key("31.0.15.5123")),
            Err(EncoderCapabilityCacheError::CacheTooLarge { .. })
        ));
        let _ = fs::remove_file(path);
    }
}
