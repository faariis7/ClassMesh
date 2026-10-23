//! Phase12F: strict, bounded review/audit *intent* encoding, not a durable commit.
use classmesh_security::{
    AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
    PrincipalId, PrincipalKind,
    classroom_audit_intent_encoding::{
        AuditIntentEncodingError, ClassroomAuditIntentRecord, MAX_AUDIT_INTENT_BYTES,
    },
    classroom_policy_change_stage::stage_classroom_permission_change,
    classroom_policy_preview::{ClassroomPermission, ClassroomPermissionChange},
};
use std::collections::{BTreeMap, BTreeSet};

fn id(n: u8) -> PrincipalId {
    PrincipalId([n; 32])
}
fn fingerprint(n: u8) -> CredentialFingerprint {
    CredentialFingerprint([n; 32])
}
fn principal(n: u8, kind: PrincipalKind, permissions: &[Permission]) -> Principal {
    Principal {
        id: id(n),
        kind,
        enabled: true,
        permissions: BTreeSet::from_iter(permissions.iter().copied()),
        credentials: BTreeMap::from([(
            fingerprint(n),
            CredentialRecord::active(fingerprint(n), 100),
        )]),
    }
}
fn record() -> ClassroomAuditIntentRecord {
    let mut store = AuthorizationStore::default();
    store
        .upsert(principal(
            1,
            PrincipalKind::Administrator,
            &[Permission::ManagePolicy],
        ))
        .unwrap();
    store
        .upsert(principal(
            2,
            PrincipalKind::Teacher,
            &[Permission::StartPresentation],
        ))
        .unwrap();
    let draft = stage_classroom_permission_change(
        &store,
        fingerprint(1),
        ClassroomPermissionChange {
            target: id(2),
            permission: ClassroomPermission::ViewMonitoring,
            grant: true,
            request_id: 79,
            expected_policy_generation: 4,
        },
        150,
    )
    .unwrap();
    ClassroomAuditIntentRecord::from_intent(draft.audit_intent()).unwrap()
}

#[test]
fn deterministic_strict_bounded_round_trip_is_non_authorizing() {
    let rec = record();
    let encoded = rec.encode().unwrap();
    assert!(encoded.len() <= MAX_AUDIT_INTENT_BYTES);
    let text = std::str::from_utf8(&encoded).unwrap();
    assert!(text.contains("\"version\":1"));
    assert!(text.contains("\"permission\":\"view_monitoring\""));
    assert!(text.contains("\"actor\":\"0101"));
    assert!(text.contains("\"target\":\"0202"));
    assert!(!text.contains("fingerprint"));
    assert!(!text.contains("secret"));
    let decoded = ClassroomAuditIntentRecord::decode(&encoded).unwrap();
    assert_eq!(decoded, rec);
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(rec.request_id(), 79);
    assert_eq!(rec.expected_policy_generation(), 4);
    assert_eq!(rec.actor(), id(1));
    assert_eq!(rec.target(), id(2));
    assert_eq!(rec.permission(), ClassroomPermission::ViewMonitoring);
    assert!(!rec.previous_grant());
    assert!(rec.new_grant());
    assert_eq!(rec.checked_at_unix_ms(), 150);
}

#[test]
fn malformed_unknown_version_or_unknown_permission_fails_closed() {
    let bytes = record().encode().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (key, new_value) in [
        ("version", serde_json::json!(2)),
        ("permission", serde_json::json!("manage_policy")),
        ("actor", serde_json::json!("AB")),
        ("request_id", serde_json::json!(0)),
        ("expected_policy_generation", serde_json::json!(0)),
    ] {
        let old = value[key].clone();
        value[key] = new_value;
        assert!(
            ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{key}"
        );
        value[key] = old;
    }
    value["unknown_field"] = serde_json::json!("untrusted");
    assert!(ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(ClassroomAuditIntentRecord::decode(b"{}").is_err());
    assert!(ClassroomAuditIntentRecord::decode(b"not JSON").is_err());
}

#[test]
fn changing_boolean_pair_to_no_op_or_replacing_identity_rejects() {
    let bytes = record().encode().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["new_grant"] = serde_json::json!(false);
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).err(),
        Some(AuditIntentEncodingError::InvalidIntent),
    );
    value["new_grant"] = serde_json::json!(true);
    value["target"] = value["actor"].clone();
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).err(),
        Some(AuditIntentEncodingError::InvalidIntent),
    );
}

#[test]
fn noncanonical_whitespace_key_reordering_and_uppercase_identity_are_rejected() {
    let bytes = record().encode().unwrap();
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&whitespace).err(),
        Some(AuditIntentEncodingError::NonCanonical),
    );
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["actor"] = serde_json::json!("A".repeat(64));
    assert!(ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let reordered = serde_json::to_vec(&original).unwrap();
    assert_ne!(reordered, bytes, "wire key ordering is intentionally fixed");
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&reordered).err(),
        Some(AuditIntentEncodingError::NonCanonical),
    );
}

#[test]
fn oversized_and_missing_data_cannot_be_accepted() {
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&vec![b'x'; MAX_AUDIT_INTENT_BYTES + 1]).err(),
        Some(AuditIntentEncodingError::Oversize),
    );
    assert!(ClassroomAuditIntentRecord::decode(b"").is_err());
    let bytes = record().encode().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("checked_at_unix_ms");
    assert!(ClassroomAuditIntentRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn record_is_intent_only_and_requires_external_authenticated_commit() {
    // No method in this module publishes a Service store, writes files, or
    // proves that the expected policy generation is current or trustworthy.
    let record = record();
    assert_eq!(record.expected_policy_generation(), 4);
    assert_eq!(record.request_id(), 79);
    assert_eq!(
        ClassroomAuditIntentRecord::decode(&record.encode().unwrap()).unwrap(),
        record
    );
}
