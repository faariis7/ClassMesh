//! Reviewer evidence, never an authenticated principal or session.
#[cfg(windows)]
pub mod native;

#[cfg(test)]
mod tests {
    use super::*;
    fn ordinary() -> CallerContext {
        CallerContext { elevated: false, elevation_type: 1, admin_sid_present: false,
            effective_admin: false, service_account: false, debug_present: false,
            unexpected_privileges: false, restricted: false, app_container: false,
            impersonating: false, integrity: 0x2000, session: 1, ui_access: false }
    }

    #[test]
    fn synthetic_ordinary_context_only_qualifies_measurement_not_authentication() {
        assert!(ordinary().refusal().is_none());
    }

    #[test]
    fn reject_each_nonordinary_context_before_any_target_access() {
        let changes: &[fn(&mut CallerContext)] = &[
            |c| c.elevated = true, |c| c.elevation_type = 2, |c| c.elevation_type = 3,
            |c| c.admin_sid_present = true, |c| c.effective_admin = true,
            |c| c.service_account = true, |c| c.debug_present = true,
            |c| c.unexpected_privileges = true, |c| c.restricted = true,
            |c| c.app_container = true, |c| c.impersonating = true,
            |c| c.integrity = 0x3000, |c| c.integrity = 0x1000,
            |c| c.session = 0, |c| c.ui_access = true,
        ];
        for change in changes { let mut c = ordinary(); change(&mut c); assert!(c.refusal().is_some()); }
    }

    #[test]
    fn pid_equality_does_not_accept_a_restarted_or_missing_process_object() {
        let original = ProcessObject { pid: 60, created: 100 };
        assert!(original.require_same_live(original, true).is_ok());
        assert!(original.require_same_live(ProcessObject { pid: 60, created: 200 }, true).is_err());
        assert!(original.require_same_live(ProcessObject { pid: 70, created: 100 }, true).is_err());
        assert!(original.require_same_live(original, false).is_err());
        assert!(ProcessObject { pid: 0, created: 0 }.require_same_live(ProcessObject { pid: 0, created: 0 }, true).is_err());
    }
}
