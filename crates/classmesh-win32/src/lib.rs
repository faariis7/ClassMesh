#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod session;
#[cfg(windows)]
mod session_process;

#[cfg(windows)]
pub use session::current_session_id;
#[cfg(windows)]
pub use session_process::{LaunchError, SessionProcess, launch_worker_in_session};
