#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
pub mod encoder_benchmark;
pub mod group_media_receive;
#[cfg(windows)]
pub mod monitoring;
#[cfg(windows)]
pub mod presentation;
pub mod presentation_decode_render;
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
