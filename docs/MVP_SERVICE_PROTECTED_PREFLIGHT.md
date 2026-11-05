# Windows MVP — protected Service candidate preflight

The existing opt-in `classmesh-trusted-provision --fresh` creates protected
ProgramData and Registry state. It must **never** be used to find out whether
an unreviewed enrollment candidate is valid: a partial failed install is an
inert orphan that cannot be adopted or silently repaired.

The new **read-only** operator mode checks an enrollment candidate using the
same bounded parser, policy/identity principal and certificate fingerprint
binding, live non-exportable Windows CNG key and certificate/public-key match,
expiration, and control-config validation as the production `--fresh` path:

```powershell
# Explicit experimental-trusted-policy build on a test Windows machine.
cargo build -p classmesh-win32 --features experimental-trusted-policy --bin classmesh-trusted-provision

# Input paths must come from an independently verified StudentDevice enrollment.
# This command does NOT create Registry, ProgramData or SCM Service state.
.\\target\\debug\\classmesh-trusted-provision.exe --preflight 1 `
  C:\\Lab\\authorization.json `
  C:\\Lab\\machine-identity.json `
  C:\\Lab\\control-runtime.json
```

Success means **candidate consistency only**. The command does **not**
verify CA issuer provenance or establish trusted roots, and does not check
whether the destination ProgramData/Registry namespaces are available. The
operator must first validate the signed enrollment request/result against an
explicit approved CA using the `classmesh-lab` tools, and independently review
owner/DACL, policy scope and lifecycle before any `--fresh` action.

The new API `trusted_policy::check_fresh_install_candidate` shares the actual
preflight validation function used by `--fresh`, rather than a second
approximation. It does not install/update/repair or auto-retry anything.

Do not copy TEMP staging state manually into ProgramData, install unsigned
identities, bypass ACL/CNG authorization, or enable FileTransfer/Clipboard.
The positive LocalSystem SCM and Worker IPC acceptance remains **unproven**.
