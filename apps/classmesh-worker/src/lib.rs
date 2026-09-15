#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
pub mod presentation;
#[cfg(windows)]
pub mod receiver_render;
