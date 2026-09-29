#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
pub mod encoder_benchmark;
pub mod group_media_receive;
pub mod presentation_multicast_receive;
#[cfg(windows)]
pub mod presentation;
#[cfg(windows)]
pub mod receiver_render;
#[cfg(windows)]
pub mod udp_stream;
