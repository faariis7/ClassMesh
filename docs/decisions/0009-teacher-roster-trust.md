# ADR-0009 · Trusted Teacher roster evidence

Status: architectural direction approved for ClassMesh Core implementation and isolated lab validation. The profile below defines version 1. Production issuer, enrollment trust, freshness policy, managed CNG access and signed deployment still require independent approval.

## Signed profile

Use a tagged COSE_Sign1 (CBOR tag 18). The four fields are a protected header byte string, an empty unprotected map, an attached payload byte string and a 64-byte P-256 ECDSA signature in fixed-width big-endian r || s form. The exact protected map contains label 1 with ES256 (-7) and label 4 with the ASCII key identifier encoded as a byte string. Both headers and payload use RFC 8949 deterministic encoding. The signature covers the original protected and payload byte strings using RFC 9052 Sig_structure with external AAD `ClassMesh/TeacherRoster/v1` (ASCII, no trailing NUL). Verification uses ring's fixed P-256 SHA-256 implementation. The envelope cannot select another algorithm or carry a trust key.

Payload is the 11-element CBOR array shown below. PrincipalId and device IDs are the existing 32 bytes. Time values are unsigned Unix milliseconds. The Teacher role is integer 1. Epoch and source IDs are nonzero unsigned 64-bit integers. All array lengths are definite. There are no extensions in version 1.

```text
[1, issuer, key_id, organization, teacher_principal_id, 1,
 issued_at_ms, not_before_ms, expires_at_ms, policy_epoch,
 [[student_device_principal_id, monitoring_source_id], ...]]
```

The three identifiers are 1–48 ASCII bytes from letters, digits, hyphen, underscore and dot. There are 1–256 StudentDevice entries sorted lexicographically by PrincipalId. No duplicate identity or source is allowed, and the Teacher identity cannot also be a Student. The payload limit is 12 KiB and the complete envelope limit is 12 KiB + 256 bytes. The schema has fixed depth of three arrays in the payload and rejects nested values in scalar positions. Header duplicates, additional fields, trailing values, nonminimal encoding and indefinite collections are rejected. The profile uses minicbor's bounded, nonrecursive field reads and coset's standard Sig_structure. [COSE structures](https://www.rfc-editor.org/rfc/rfc9052.html) · [COSE algorithms](https://www.rfc-editor.org/rfc/rfc9053.html) · [Deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2)

## Protected authority

The installed Teacher reads only `HKLM\SOFTWARE\ClassMesh-Teacher-Policy-v1` in the 64-bit view. Its ACL and owner are attested through retained registry handles. LocalSystem and Administrators own and manage the state. Builtin Users may read the Teacher namespace. Ordinary startup has no publishing operation or fallback. The existing `CMPBND02` checkpoint binds the exact JSON policy bytes and the current monotonic epoch. The existing transaction fences concurrent writers and commits the new bytes and checkpoint together. An interrupted or contradictory state denies startup. Same-epoch publication and downgrade are rejected. A higher-epoch explicit deny snapshot disables all startup and retires existing sessions. The policy additionally pins the exact signed roster payload digest. Repeating the same authorized snapshot grants the same scope.

Policy config supplies the single organization and issuer, up to eight pinned ES256 verification keys, their revocation state, revoked PrincipalIds, maximum lifetime (up to 24 hours), protected refresh time and permitted age (up to one hour). The selected roster key must match the protected key ID and its verification key. Rotate by publishing a higher-epoch signed snapshot with a newly approved key, with explicit overlap and retirement of the old key where approved. Rotate Student leaf credentials with the matching independent protected policy and exact fingerprint. The Windows process closes the current session when the protected checkpoint changes, disappears or becomes unreadable, or when its time budget expires. The time budget uses a monotonic floor while running and also observes system clock advancement. The earlier of freshness, roster expiry and the bound leaf certificates' expiry limits the session.

A protected snapshot authenticates what the operator published. Offline it cannot prove the authority has issued no later revocation. Establish an independently managed refresh process within the configured interval. Expired freshness denies live operation. An administrator who can rewrite the registry, local clock, binaries or the underlying disk is outside the local threat model. Whole-machine snapshot restoration across reboots requires separate external anti-rollback controls. The existing control stream sequence independently rejects frame replay.

## Enrollment and runtime

The protected policy pins an independently approved enrollment CA, Teacher role identity, Teacher leaf fingerprint and selected roster-member StudentDevice leaf fingerprint. Teacher opens the existing role-specific, non-exportable machine CNG key and verifies the signed Teacher leaf chain, expiry, stable principal and leaf-to-key match. The runtime connects through the existing enrolled mutual TLS and authenticated QUIC Hello, rechecks the exact enrolled StudentDevice and supplies the existing Windows native control bridge. Protected policy config selects one initial Student endpoint for this version. Multiple authorized members remain supported in the signed roster. The connected UI path currently qualifies Teacher Message; media qualification remains separate.

The test-only issuer creates ephemeral ES256 keys and exports public vectors. It has no machine trust configuration output that is automatically installed. Developer keys and roots never enter the distributed Teacher binary. A native provisioning tool checks candidate CNG and roster bindings without modifying the machine in plan mode. The signed authority profile is shareable with independently approved organization issuers without embedding a signer in Teacher. [Lab tools and platform procedure](../../tools/classmesh-lab/WINDOWS_TEACHER_LIVE.md)
