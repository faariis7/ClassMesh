#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod d3d11;

#[cfg(windows)]
pub use d3d11::{FlipPresenter, PresentMetrics};
