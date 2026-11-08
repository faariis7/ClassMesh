//! Reviewer evidence, never an authenticated principal or session.
#[cfg(windows)]
pub mod native;

/// Measurement context facts. Fabricated values are useful only in unit tests;
/// native measurement always collects its own facts from Windows, never input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(windows, derive(serde::Serialize))]
pub struct CallerContext {
    pub elevated: bool,
    pub elevation_type: u32,
    pub admin_sid_present: bool,
    pub effective_admin: bool,
    pub service_account: bool,
    pub debug_present: bool,
    pub unexpected_privileges: bool,
    pub restricted: bool,
    pub app_container: bool,
    pub impersonating: bool,
    pub integrity: u32,
    pub session: u32,
    pub ui_access: bool,
}

impl CallerContext {
    /// Strict experiment eligibility, NOT principal authentication. Filtered
    /// administrators and artificial restricted tokens do not qualify.
    pub fn refusal(&self) -> Option<&'static str> {
        if self.elevated
            || self.elevation_type != 1
            || self.admin_sid_present
            || self.effective_admin
        {
            Some("elevated_or_administrator_account")
        } else if self.service_account || self.session == 0 {
            Some("not_ordinary_interactive_account")
        } else if self.debug_present || self.unexpected_privileges {
            Some("nonstandard_privilege_assignment")
        } else if self.restricted
            || self.app_container
            || self.impersonating
            || self.ui_access
            || self.integrity != 0x2000
        {
            Some("modified_or_nonordinary_execution_context")
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(windows, derive(serde::Serialize))]
pub struct ProcessObject {
    pub pid: u32,
    pub created: u64,
}

impl ProcessObject {
    /// Consistency only. PID/creation time does not establish account or signer.
    pub fn require_same_live(self, observed: Self, alive: bool) -> Result<(), &'static str> {
        if self.pid == 0 || self.created == 0 || self != observed || !alive {
            Err("process_object_changed_or_exited")
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ordinary() -> CallerContext {
        CallerContext {
            elevated: false,
            elevation_type: 1,
            admin_sid_present: false,
            effective_admin: false,
            service_account: false,
            debug_present: false,
            unexpected_privileges: false,
            restricted: false,
            app_container: false,
            impersonating: false,
            integrity: 0x2000,
            session: 1,
            ui_access: false,
        }
    }

    #[test]
    fn synthetic_ordinary_context_only_qualifies_measurement_not_authentication() {
        assert!(ordinary().refusal().is_none());
    }

    #[test]
    fn reject_each_nonordinary_context_before_any_target_access() {
        let changes: &[fn(&mut CallerContext)] = &[
            |c| c.elevated = true,
            |c| c.elevation_type = 2,
            |c| c.elevation_type = 3,
            |c| c.admin_sid_present = true,
            |c| c.effective_admin = true,
            |c| c.service_account = true,
            |c| c.debug_present = true,
            |c| c.unexpected_privileges = true,
            |c| c.restricted = true,
            |c| c.app_container = true,
            |c| c.impersonating = true,
            |c| c.integrity = 0x3000,
            |c| c.integrity = 0x1000,
            |c| c.session = 0,
            |c| c.ui_access = true,
        ];
        for change in changes {
            let mut c = ordinary();
            change(&mut c);
            assert!(c.refusal().is_some());
        }
    }

    #[test]
    fn pid_equality_does_not_accept_a_restarted_or_missing_process_object() {
        let original = ProcessObject {
            pid: 60,
            created: 100,
        };
        assert!(original.require_same_live(original, true).is_ok());
        assert!(
            original
                .require_same_live(
                    ProcessObject {
                        pid: 60,
                        created: 200
                    },
                    true
                )
                .is_err()
        );
        assert!(
            original
                .require_same_live(
                    ProcessObject {
                        pid: 70,
                        created: 100
                    },
                    true
                )
                .is_err()
        );
        assert!(original.require_same_live(original, false).is_err());
        assert!(
            ProcessObject { pid: 0, created: 0 }
                .require_same_live(ProcessObject { pid: 0, created: 0 }, true)
                .is_err()
        );
    }
}
