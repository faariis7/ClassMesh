# ADR-0009 · Trusted Teacher roster evidence

Status: Proposed. Requires approval from the security and enrollment owners before a production verifier or launch configuration is activated.

## Decision needed

Issue #688 lacks an approved, versioned signature contract for the Teacher-side authorization roster. The existing Rust metadata type carries display-form IDs, time fields, device membership and unverified signature bytes. It has no canonical signed payload, issuer/key selection, organization binding or protected anti-rollback source. A Teacher credential and a matching Student certificate alone do not establish that a particular organization delegated this Teacher authority over that Student.

## Existing constraints

- Reuse the enrolled stable PrincipalId, non-exportable Windows CNG key and existing TLS client certificate resolver. A certificate fingerprint is a credential index, and network discovery is untrusted.
- QUIC uses enrolled mTLS and the existing Hello, role, sequence and capability checks. Service retains per-command authorization and Worker identity. Roster evidence selects the Teacher-side target and never grants Server or Worker permissions.
- Missing, stale, malformed, revoked, mismatched and unsigned inputs deny live startup. The distributed unsigned diagnostic package continues to require explicit offline mode. Protected installation and signer approval are a separate decision.

## Recommended profile

- Use one versioned COSE_Sign1 profile over exact deterministic CBOR payload bytes with fixed domain separation for ClassMesh Teacher rosters. Select the authorized algorithm and key from a protected local issuer record. An envelope-supplied issuer or key identifier can only select an already approved record.
- Sign the issuer and organization identifiers, stable Teacher PrincipalId, explicit Teacher role, issued/not-before/expiry times, monotonic policy epoch, and the bounded set of authorized StudentDevice PrincipalIds and their monitoring-source assignments. Derive the new control-session ID from verified Hello for each connection. Keep network addresses and names as routing hints subject to mTLS and exact enrolled-device verification.
- Open the identity from reviewed local provisioning inputs. Verify the enrolled leaf against the existing non-exportable CNG key and confirm the expected Teacher PrincipalId and role. Verify the Student certificate's chain and map it to the exact StudentDevice and source in the verified roster.
- Set byte, item-count, nesting and time bounds before allocating or admitting data. Require an independently protected revocation and minimum-epoch source with an approved freshness limit. Deny stale epochs, conflicting payloads at the same epoch, expired/revoked issuers or principals, and missing freshness evidence. A repeated copy of the active signed snapshot grants no additional authority. Control-frame replay remains subject to the distinct session sequence guard. Rotate keys with explicit, bounded acceptance by key ID.
- Keep fixture issuers and credentials local to tests, configure every test root explicitly, and exercise both genuine success and denial without enrolling fixtures into a system trust store.

[COSE signing profile](https://www.rfc-editor.org/rfc/rfc9052.html) · [Deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)

## Alternatives

- An enrollment authority may issue a dedicated roster-signing certificate and use detached CMS. Windows already validates CMS for release provenance, but the roster requires a separate signer profile, canonical payload, key-rotation policy and alternate-platform tooling.
- An online policy provider can deliver short-lived signed decisions with current revocation status. This shifts some freshness state to the authority and adds availability, deployment and explicit offline-failure requirements.
- Certificate-only and unsigned roster admission cannot establish scoped organization and device authorization. Neither meets the trust boundary.

## Approval and next input

Approve the profile and nominate the roster issuer and organization namespace. Supply the approved public roster signer or issuer pin and key ID, the enrollment CA public chain, the protected policy/epoch origin, the maximum roster lifetime and freshness delay, and one signed lab roster plus a revoked or stale counterpart. Approve how the ordinary Teacher user obtains access to its existing CNG key and the protected identity/configuration reader. The reviewed startup producer will then feed the authenticated native control entry point.

For an end-to-end lab run, separately supply the approved Authenticode thumbprint and exact signed Service, Worker and trusted provisioner images. Approve a named disposable VM1 window for protected configuration and temporary SCM registration, and designate the interactive user who will approve the visible Teacher Message. These inputs are public evidence or operator approvals. Private keys remain with their owners.
