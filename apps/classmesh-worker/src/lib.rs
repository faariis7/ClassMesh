#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod clipboard_native;
pub mod clipboard_read_fallback;
pub mod clipboard_read_guarded;
#[cfg(windows)]
pub mod encoder_benchmark;
pub mod group_media_receive;
#[cfg(windows)]
pub mod monitoring;
#[cfg(windows)]
pub mod presentation;
pub mod presentation_decode_render;
pub mod presentation_delivery_telemetry;
#[cfg(windows)]
pub mod presentation_fanout;
pub mod presentation_multicast_receive;
#[cfg(windows)]
pub mod presentation_multicast_send;
pub mod presentation_unicast_receive;
#[cfg(windows)]
pub mod receiver_render;
#[cfg(windows)]
pub mod udp_stream;
