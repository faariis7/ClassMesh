# Independent Service identity evidence batch

Base: integration c141df23. No merges/import of #713/#716/#710; #717 files untouched.
Authority: #716 review comment 6721249865 and user engineering task.

1. Add test-first, off-default current-caller qualification and immutable process
   identity validation. Reject admin/filtered/restricted/AppContainer/impersonating/
   debug/unknown caller contexts, changed identity, absent actual-account witness.
2. Implement native self-audit and fixed existing DcomLaunch read-only capability
   probe. No token creation/switch/adjustment, impersonation, privilege enablement,
   larger-right retry, service operations or caller-selected arbitrary PID.
   JSON is evidence for a reviewer, never authentication authority.
3. Native refusal tests exercise the actual caller context; a nonqualifying CI
   token must be labelled NOT_MEASURED_CALLER_CONTEXT. A real ordinary-account
   run remains pending if that context is unavailable. Do not fake it.
4. Prepare a minimal #716 liveness-race repair as a review patch, not an import.
   Apply only to a detached exact d546360 checkout during isolated tests. RED
   must show actual owned child death during slow observation accepted before
   repair; GREEN adds final retained-object liveness and preserves errors.
5. Produce practical qualified-review packet: independent claim/source/identity/
   ordering/evidence/refusal matrix; signed-image and protected path obligations;
   reviewer/installer/lab responsibilities; exact first authorized runtime step.
6. Focused RED/GREEN; local workspace/fmt/Clippy; exact-head hosted Windows,
   Portable Rust, CodeQL/Gitleaks; independent code review. Draft PR to integration.
   CI success never qualifies the protected ClassMesh runtime.
