#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod d3d11;

#[cfg(windows)]
pub use d3d11::{
    DxgiFailureClass, FlipPresenter, PresentMetrics, PresentOutcome, ResizeOutcome,
    classify_dxgi_error,
};
