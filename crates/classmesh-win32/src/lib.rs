#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod input;
#[cfg(windows)]
mod named_pipe;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod session_process;

#[cfg(windows)]
pub use input::{
    ABSOLUTE_COORDINATE_MAX, InputAction, InputError, InputInjector, InputKey, MouseButton,
};
#[cfg(windows)]
pub use named_pipe::{NamedPipeClient, NamedPipeServer, PipeError, PipePeer, worker_pipe_name};
#[cfg(windows)]
pub use session::current_session_id;
#[cfg(windows)]
pub use session_process::{
    LaunchError, SessionProcess, launch_worker_in_session, session_user_sid,
};
