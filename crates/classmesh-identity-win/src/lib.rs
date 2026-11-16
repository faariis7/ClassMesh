#![cfg_attr(not(windows), forbid(unsafe_code))]

mod machine_identity;
mod teacher_roster;

pub use teacher_roster::{
    RosterEvidence, RosterRejection, TeacherRosterRequest, qualify_teacher_device_roster,
    qualify_teacher_roster,
};

pub use machine_identity::{
    DurableMachineIdentity, MachineIdentityBundle, MachineIdentityStateError,
};

#[cfg(windows)]
mod cng;
#[cfg(windows)]
mod teacher_binding;
#[cfg(windows)]
pub use teacher_binding::{BindingQualificationError, qualify_existing_key_binding};
#[cfg(windows)]
mod tls;

#[cfg(windows)]
pub use cng::{CngKeyError, CngMachineKey, CngRcgenSigningKey};
#[cfg(windows)]
pub use tls::{
    CngRustlsSigningKey, CngTlsError, cng_client_cert_resolver, cng_server_cert_resolver,
};
