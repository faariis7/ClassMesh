#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod input;
#[cfg(windows)]
mod named_pipe;
#[cfg(windows)]
mod power;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod session_process;
#[cfg(windows)]
mod teacher_interaction;
#[cfg(windows)]
mod workstation;

#[cfg(windows)]
pub use input::{
    ABSOLUTE_COORDINATE_MAX, InputAction, InputDesktopUnavailable, InputError, InputInjector,
    InputKey, MouseButton,
};
#[cfg(windows)]
pub use named_pipe::{NamedPipeClient, NamedPipeServer, PipeError, PipePeer, worker_pipe_name};
#[cfg(windows)]
pub use power::{
    SystemPowerAction, SystemPowerController, SystemPowerError, SystemPowerRequestOutcome,
    Win32SystemPowerController,
};
#[cfg(windows)]
pub use session::current_session_id;
#[cfg(windows)]
pub use session_process::{
    LaunchError, SessionProcess, launch_worker_in_session, session_user_sid,
};

#[cfg(windows)]
pub use teacher_interaction::{
    OpenTargetLauncher, TeacherInteractionAcceptance, TeacherInteractionExecutionError,
    TeacherMessagePresenter, Win32OpenTargetLauncher, Win32TeacherMessagePresenter,
    WindowsAppIdentity,
};
#[cfg(windows)]
pub use workstation::{Win32WorkstationLocker, WorkstationLockError, WorkstationLocker};
