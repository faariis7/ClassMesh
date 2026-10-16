# Phase 12 epoch transition protocol — security review

**Scope:** Isolated portable decision/format helper and disposable Windows integration test only. No production Service loader, writer, reload, authorization or protocol behavior changes.

## Proven contract

- Startup admits only a nonzero candidate epoch exactly equal to a separately trusted anchor. Neither a lower nor a higher candidate is silently accepted.
- Update rejects zero/stale/equal candidates, exhausted anchor, and never invokes the supplied durable commit callback for an invalid transition. A commit receipt is issued only if that callback returns success.
- A crash after anchor advancement but before policy publication rejects the older policy on next startup. This intentionally fails closed **at the expense of availability**; there is no transactional recovery protocol yet.
- Fixed-width `CMPECH01` + little-endian u64 (16 bytes) checkpoint codec rejects zero, truncated, malformed, overlong and unreadable records; supports partial reads. It provides **format validation, not authenticity or cryptographic integrity**.
- Disposable Windows Service-package test confirms a strictly protected single-link leaf is opened by retained HANDLE, denies replacement while held, and passes the bounded checkpoint parser; an added Users ACE is rejected. The test is elevated and does not qualify production ProgramData ancestors or real SCM startup.

## Unresolved critical gates

1. **No independent trusted anchor exists yet.** A caller-provided commit callback may be a no-op or an unsafe writer; its `Ok` is not an OS durability guarantee. The receipt is not a security capability or proof of provenance. The API MUST NOT be connected to live Service until a separately reviewed protected anchor with ACL/owner/HANDLE/atomic write + flush and rollback-resistant storage is built.
2. The current authorization persistence format has no production-coupled epoch field or authenticated binding between the policy bytes and the trusted checkpoint. The helper cannot by itself detect policy replacement with another document at the same epoch.
3. No atomic two-object transaction, crash-safe recovery, independent anti-rollback storage trust, prior-open HANDLE revocation, root-of-volume trust, or full native relative-open ancestor proof. Strict fail-closed startup can become unavailable after a crash between anchor commit and policy publish.
4. No authenticated policy reloader or cancellation of already-active Teacher/Worker work. Physical two-PC qualification, #477/#479 and v11 ClipboardRead failure-only remain unchanged.

**Required next work:** define an authenticated policy/epoch binding, durable protected Windows anchor and crash-consistent install protocol before any production activation; then native SCM LocalSystem qualification on both VMs and physical security gates. Never interpret successful portable/Windows tests as production acceptance.
