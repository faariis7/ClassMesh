//! Opt-in trusted-Windows policy store. Not enabled by default.
use std::io;
use classmesh_security::AuthorizationStore;

pub struct TrustedPolicySession {
    authorization: AuthorizationStore,
    epoch: u64,
}
impl TrustedPolicySession {
    pub fn authorization(&self) -> &AuthorizationStore { &self.authorization }
    pub fn epoch(&self) -> u64 { self.epoch }
}
fn provision_at(_: &str, _: u64, _: &[u8]) -> io::Result<()> { Err(io::Error::other("RED: native install missing")) }
fn install_at(_: &str, _: u64, _: &[u8]) -> io::Result<()> { Err(io::Error::other("RED: native install missing")) }
fn open_at(_: &str) -> io::Result<TrustedPolicySession> { Err(io::Error::other("RED: session lease missing")) }

#[cfg(test)]
mod tests {
    use super::*;
    const VALID: &[u8] = br#"{"version":1,"principals":[]}"#;

    #[test]
    fn native_install_orders_blob_before_anchor_and_excludes_active_runtime() {
        let scope = format!("ClassMesh-anchor-probe-install-{}", std::process::id());
        provision_at(&scope, 1, VALID).expect("native protected provision");
        let root = crate::program_data_known_folder::resolve_os_program_data_path().unwrap().join(&scope);
        let state = root.join("state");
        assert!(provision_at(&scope, 1, VALID).is_err());
        let session = open_at(&scope).expect("trusted startup");
        assert_eq!(session.epoch(), 1);
        assert!(open_at(&scope).is_err(), "one Service/install owner across processes");
        assert!(install_at(&scope, 2, VALID).is_err());
        assert!(!state.join("policy-0000000000000002.json").exists());
        drop(session);
        assert!(install_at(&scope, 2, b"not JSON").is_err());
        assert!(!state.join("policy-0000000000000002.json").exists());
        install_at(&scope, 2, VALID).unwrap();
        assert!(install_at(&scope, 1, VALID).is_err());
        assert!(install_at(&scope, 2, VALID).is_err());
        assert_eq!(open_at(&scope).unwrap().epoch(), 2);
        // A partial orphan from an interrupted stage cannot be adopted or overwritten.
        let orphan = state.join("policy-0000000000000003.json");
        std::fs::write(&orphan, b"torn").unwrap();
        assert!(install_at(&scope, 3, VALID).is_err());
        assert_eq!(std::fs::read(&orphan).unwrap(), b"torn");
        assert_eq!(open_at(&scope).unwrap().epoch(), 2);
        install_at(&scope, 4, VALID).unwrap();
        assert_eq!(open_at(&scope).unwrap().epoch(), 4);
        let current = state.join("policy-0000000000000004.json");
        std::fs::write(&current, [VALID, b" "].concat()).unwrap();
        assert!(open_at(&scope).is_err(), "same-epoch byte substitution fails");
        std::fs::remove_file(&current).unwrap();
        assert!(open_at(&scope).is_err(), "never recover an older blob");
        crate::registry_epoch::remove_fixture(&scope);
        std::fs::remove_dir_all(root).unwrap();
    }
}
