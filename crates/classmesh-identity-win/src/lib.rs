#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod cng;

#[cfg(windows)]
pub use cng::{CngKeyError, CngMachineKey, CngRcgenSigningKey};
