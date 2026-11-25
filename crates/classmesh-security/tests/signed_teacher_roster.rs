use classmesh_security::PrincipalId;
use classmesh_security::teacher_roster::*;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};

#[test]
fn enrolled_roster_checks_signature_canonical_data_and_policy() {
    let rng = SystemRandom::new();
    let secret = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, secret.as_ref(), &rng).unwrap();
    let payload = RosterClaims {
        issuer: "issuer-lab".into(),
        key_id: "key-one".into(),
        organization: "organization-lab".into(),
        teacher: PrincipalId([7; 32]),
        issued_at_ms: 100_000,
        not_before_ms: 100_000,
        expires_at_ms: 160_000,
        epoch: 42,
        devices: vec![RosterDevice {
            principal: PrincipalId([8; 32]),
            source: 4,
        }],
    };
    let unsigned = UnsignedRoster::new(&payload).unwrap();
    let signature = key.sign(&rng, &unsigned.signing_data()).unwrap();
    let envelope = unsigned.attach_signature(signature.as_ref()).unwrap();
    let keys = [RosterKey {
        id: "key-one".into(),
        sec1: key.public_key().as_ref().to_vec(),
        revoked: false,
    }];
    let mut policy = RosterPolicy {
        issuer: "issuer-lab",
        organization: "organization-lab",
        keys: &keys,
        epoch: 42,
        payload_sha256: unsigned.payload_sha256(),
        refreshed_at_ms: 105_000,
        max_age_ms: 20_000,
        max_lifetime_ms: 90_000,
        revoked: &[],
    };
    let verify = |bytes: &[u8], policy: &RosterPolicy<'_>, now| {
        verify_teacher_roster(bytes, policy, PrincipalId([7; 32]), now)
    };
    let proof = verify(&envelope, &policy, 110_000).unwrap();
    assert_eq!(proof.devices(), &payload.devices);
    assert_eq!(proof.valid_until_ms(), 125_000);
    assert!(proof.device(PrincipalId([9; 32])).is_none());
    assert!(verify(&envelope, &policy, 110_000).is_ok());
    assert_eq!(
        verify(&envelope, &policy, 125_000).unwrap_err(),
        RosterError::Freshness
    );
    assert_eq!(
        verify(&envelope, &policy, 104_000).unwrap_err(),
        RosterError::Freshness
    );
    let mut forged = envelope.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify(&forged, &policy, 110_000).unwrap_err(),
        RosterError::Signature
    );
    let mut noncanonical = envelope.clone();
    noncanonical.splice(0..1, [0xd8, 18]);
    assert_eq!(
        verify(&noncanonical, &policy, 110_000).unwrap_err(),
        RosterError::Encoding
    );
    let mut wrong_algorithm = envelope.clone();
    // Published v1 header starts with map(2), alg label(1), ES256(-7).
    assert_eq!(&envelope[3..6], &[0xa2, 0x01, 0x26]);
    wrong_algorithm[5] = 0x27;
    assert_eq!(
        verify(&wrong_algorithm, &policy, 110_000).unwrap_err(),
        RosterError::Algorithm
    );
    let mut truncated = envelope.clone();
    truncated.truncate(truncated.len() - 64);
    assert!(verify(&truncated, &policy, 110_000).is_err());
    assert!(inspect_roster(&vec![0; MAX_ENVELOPE_BYTES + 1]).is_err());
    assert_eq!(
        verify_teacher_roster(&envelope, &policy, PrincipalId([3; 32]), 110_000).unwrap_err(),
        RosterError::Teacher
    );
    policy.organization = "another-organization";
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Organization
    );
    policy.organization = "organization-lab";
    policy.issuer = "another-issuer";
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Issuer
    );
    policy.issuer = "issuer-lab";
    let mut revoked_key = keys[0].clone();
    revoked_key.revoked = true;
    let revoked_key = [revoked_key];
    policy.keys = &revoked_key;
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Revoked
    );
    policy.keys = &[];
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Key
    );
    policy.keys = &keys;
    assert_eq!(
        verify(&envelope, &policy, 160_000).unwrap_err(),
        RosterError::Validity
    );
    assert_eq!(
        verify(&envelope, &policy, 99_999).unwrap_err(),
        RosterError::Validity
    );
    policy.payload_sha256[0] ^= 1;
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Conflict
    );
    policy.payload_sha256 = unsigned.payload_sha256();
    policy.epoch += 1;
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Epoch
    );
    policy.epoch -= 1;
    policy.revoked = &[PrincipalId([8; 32])];
    assert_eq!(
        verify(&envelope, &policy, 110_000).unwrap_err(),
        RosterError::Revoked
    );
}

#[test]
fn producer_rejects_duplicate_and_conflicting_student_assignments() {
    let mut claims = RosterClaims {
        issuer: "issuer".into(),
        key_id: "key".into(),
        organization: "org".into(),
        teacher: PrincipalId([1; 32]),
        issued_at_ms: 1,
        not_before_ms: 1,
        expires_at_ms: 100,
        epoch: 1,
        devices: vec![
            RosterDevice {
                principal: PrincipalId([2; 32]),
                source: 1,
            },
            RosterDevice {
                principal: PrincipalId([3; 32]),
                source: 1,
            },
        ],
    };
    assert!(matches!(
        UnsignedRoster::new(&claims),
        Err(RosterError::Claims)
    ));
    claims.devices[1].source = 2;
    assert!(UnsignedRoster::new(&claims).is_ok());
    claims.devices[1].principal = claims.devices[0].principal;
    assert!(matches!(
        UnsignedRoster::new(&claims),
        Err(RosterError::Claims)
    ));
    claims.devices[0].principal = claims.teacher;
    assert!(matches!(
        UnsignedRoster::new(&claims),
        Err(RosterError::Claims)
    ));
}
