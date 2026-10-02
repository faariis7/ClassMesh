#[cfg(windows)]
mod control_runtime;
#[cfg(windows)]
mod monitoring;

#[cfg(windows)]
mod windows_service_app {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use classmesh_codec_win::capability_cache::DurableEncoderCapabilityCache;
    use classmesh_codec_win::{EncoderBenchmarkResult, EncoderCapabilityCacheKey};
    use classmesh_identity_win::{CngMachineKey, DurableMachineIdentity};
    use classmesh_protocol::control_wire::{InputEvent, StreamReconfigure};
    use classmesh_protocol::feedback::FeedbackMessage;
    use classmesh_security::persistence::DurableAuthorizationState;
    use classmesh_security::{CredentialFingerprint, PrincipalId};
    use classmesh_video::{Codec, EncoderClass, EncoderProbeResult};