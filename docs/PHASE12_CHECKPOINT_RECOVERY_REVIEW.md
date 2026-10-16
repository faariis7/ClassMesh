# Phase 12: checkpoint-selected immutable policy recovery (isolated)

**Plan first — 2026-10-16.** The preceding merged PR #512 created immutable-name candidate blobs but does not provide a recovery reader. This batch adds a **read-only, unconnected** recovery seam in `classmesh-security` that selects **exactly one** candidate epoch from an independently authenticated V2 checkpoint, opens it through a caller-supplied already-qualified HANDLE opener, and verifies the checkpoint digest against the same retained file stream. It never searches for backups or picks an older epoch.

## Acceptance criteria

- Reject truncated, trailing, invalid-magic, zero-epoch V2 checkpoint and zero size bound before invoking any opener.
- Invoke the caller's qualified opener once, with the epoch encoded in the authenticated checkpoint. Do not construct or open a path inside the recovery helper.
- Reject missing, modified, wrong-epoch, oversized and unreadable selected policy bytes without retry, fallback or publication.
- Simulate crash after staging but before anchor update (old policy selected) and after anchor update but before publication (new policy selected); reject missing committed blob without falling back to old.
- Tests run on Linux workspace, hosted Windows, and if available actual Windows VM; CI on exact head before Squash merge.

## Security boundaries and non-goals

The checkpoint bytes and File returned by the opener **must** already have independently verified origin, ACL/owner, pinned ancestor chain, no reparse/hardlink abuse, and independent durable anti-rollback protection. A digest is unkeyed, and a callback that opens an untrusted path is **not qualified**. This change is **not** a trusted Windows loader, installer/bootstrap, atomic anchor writer, power-loss guarantee, hot reload, revocation or production Service integration. The current Service loader is unchanged. Physical two-PC validation and the outstanding Phase 12 gates remain open.
