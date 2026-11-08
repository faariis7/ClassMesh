# SCM-bound process lease prototype execution

Authorized scope and comparisons: `docs/adr/2026-11-08-scm-bound-process-lease.md`.
This is the explicitly requested candidate/prototype, not a production rollout.

1. Commit ADR before code. Independently review the noncircular identity premise.
2. Add portable synthetic rejection tests before implementation in a feature-only
   `service_peer_probe` module. Run focused RED; implement terminal model; GREEN.
3. Add Windows-native tests before collection/mechanism code. Native tests must
   use real OS process/pipe objects and own/clean children. They cannot admit an
   SCM-authenticated session. Record missing-API RED before implementation and
   actual Windows results after the coherent candidate is pushed.
4. Implement read-only local SCM query and pipe PID/session/process observation;
   retain exact process object; expose no authentication or integer-handle API.
   Tests privately duplicate a current-process object into an owned same-user
   child with only QUERY_LIMITED_INFORMATION|SYNCHRONIZE and no inheritance.
5. Add opt-in feature checks after CI's default executable freeze, retain all
   default gates. Run local workspace tests/Clippy/fmt, opt-in tests/Clippy.
6. Obtain independent source review, resolve defects, open independent Draft PR
   to current integration, record exact CI/security results and remaining gates.
   Do not change #713's code, production auth, Teacher, QUIC, VMs or SCM state.
