# ADR-0008: RFC 9605 SFrame for Presentation Group-Media Protection

Status: Accepted for Phase 7E baseline

## Context

Wired classroom Teacher Presentation needs one encoded rendition to reach many receivers without trusting the LAN. Plain multicast is unacceptable because any station on the broadcast domain may be able to observe or inject packets.

The existing authenticated QUIC/TLS control plane can authorize presentation lifecycle and eventually deliver per-receiver key material, but multicast media itself still needs confidentiality, integrity and replay protection that are independent from transport.

ClassMesh must not invent a custom media cipher, nonce construction or unaudited replay scheme.

## Decision

ClassMesh uses **SFrame (RFC 9605)** as the group-media cryptographic construction for Teacher Presentation.

The initial implementation uses the maintained Rust `sframe` crate pinned to **2.0.0**, whose published baseline matches the ClassMesh Rust 1.85 MSRV and provides a `ring` crypto backend. The dependency remains isolated behind `classmesh-security::group_media` so network/video code does not depend directly on third-party crypto APIs.

### Cipher suite

The Phase 7 baseline is:

- SFrame cipher suite `AES_GCM_256_SHA512`;
- full 128-bit AES-GCM authentication tag as defined by the SFrame suite;
- SFrame/HKDF nonce and key derivation exactly as implemented by the RFC 9605 library;
- no ClassMesh-defined cipher, nonce derivation or MAC construction.

### Epoch and key rules

Each active presentation security epoch has:

- a non-zero monotonically assigned ClassMesh epoch number;
- a fresh cryptographically random 32-byte base key;
- the SFrame Key ID equal to the ClassMesh epoch number;
- a sender counter that starts once for that fresh epoch/key pair and never wraps/restarts for the same pair.

Recreating a sender with the same epoch **and** the same base key after its counter state is lost is forbidden because reusing the same key/KID/counter combination would violate AEAD nonce uniqueness. Runtime integration must rotate to a fresh epoch/key before rebuilding sender counter state.

A new presentation always starts with a fresh epoch/key. During an active epoch, any receiver membership change requires rotation before more media may be sealed. This is intentionally conservative: adding a receiver cannot expose earlier frames from the current epoch, and removing/revoking a receiver cannot leave the old key usable for future frames.

The receiver set is bounded to 64 principals. A principal may enter the receiver set and receive a transient key grant only while the live authorization store grants `ReceivePresentation`. Key-install acknowledgement is exact-principal + exact-epoch state; a slow or non-acknowledging receiver never creates a classroom-wide barrier for healthy receivers.

### Associated data

SFrame associated data remains outside the ciphertext and is authenticated.

ClassMesh runtime integration must provide a canonical bounded binding that identifies the authenticated presentation/media context, such as the presentation/session/stream/epoch metadata required by the final wire contract. A receiver must reconstruct the exact same associated data before accepting a frame.

The first crypto-core slice accepts bounded caller-provided associated-data bytes and does not yet define the control-wire serialization.

### Replay protection

Receivers use the SFrame replay validator:

- screening happens before decryption;
- replay state is recorded only after AEAD authentication succeeds;
- duplicate and too-old counters are rejected;
- a Key ID from another epoch is rejected;
- the ClassMesh default reorder/replay tolerance is 64 frames;
- the ClassMesh hard maximum is 512 frames.

The replay window is deliberately bounded. A forged frame that fails authentication must not consume replay state.

### Key handling

- Group-media base keys are exposed for delivery only through a bounded coordinator after a live `ReceivePresentation` authorization check; control-wire delivery is a later 7E slice.
- Keys are never sent in multicast discovery/media packets.
- Raw group-media key material is not logged.
- The ClassMesh key-material wrapper zeroizes its owned 32-byte input when dropped.
- Derived SFrame key state is owned by the SFrame implementation, which uses zeroizing secret storage.
- Key epochs/receivers remain bounded; there is no unbounded historical key store.

### Framing limits

The initial crypto wrapper enforces:

- associated data <= 256 bytes;
- plaintext encoded frame <= 8 MiB;
- sealed SFrame frame <= plaintext limit + 64 bytes;
- replay tolerance <= 512 frames.

These are safety bounds, not codec target sizes. Media policy may impose tighter bounds later.

## Dependency review

The selected `sframe` 2.0.0 release:

- implements RFC 9605;
- is MIT/Apache-2.0 licensed;
- declares Rust 1.85;
- supports AES-GCM through its default `ring` backend;
- exposes authenticated external metadata and replay validation;
- records replay state only after successful frame authentication.

The dependency is pinned exactly for the Phase 7E baseline. Upgrades require review because cryptographic/replay behavior is security-sensitive.

## Consequences

- ClassMesh does not own a custom multicast cipher or nonce format.
- Media protection remains independent of UDP/multicast socket behavior.
- Authentication failure and replay rejection can be diagnosed separately without logging secret material.
- Production multicast remains disabled until authenticated key distribution/rotation is connected and tested.
- Phase 7D pairwise multicast viability and Phase 7H classroom-scale viability remain separate physical gates.
- The one-to-one UDP vs QUIC Datagram decision under Issue #3 is unaffected.
