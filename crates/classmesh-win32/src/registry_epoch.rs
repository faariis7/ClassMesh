//! Inert Registry anchor qualification under trusted Windows; no production wiring.
use std::io;

struct RegistryAnchor;
impl RegistryAnchor {
    fn create(_scope: &str, _record: &[u8; 48]) -> io::Result<Self> {
        Err(io::Error::other("Registry anchor not implemented"))
    }
}

#[test]
fn registry_anchor_creates_without_adopting_existing_state() {
    let scope = format!("ClassMesh-anchor-probe-{}", std::process::id());
    let record = classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let _anchor = RegistryAnchor::create(&scope, &record).expect("create independent protected anchor");
}
