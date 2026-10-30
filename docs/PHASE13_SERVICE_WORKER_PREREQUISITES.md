# Phase 13 Service and Worker runtime prerequisite bundle

The Windows CI artifact `classmesh-phase13-service-worker-windows-x64` contains x64 release candidates for `classmesh-service.exe` and `classmesh-worker.exe`, a schema-1 SHA-256/size index, and the scripts needed to validate it. This artifact is a deployment input, **not** an installer or production activation instruction.

On the target Windows x64 or ARM64 machine, run from the extracted artifact directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase13-service-worker-bundle.ps1 -Mode ValidateBundle -BundleDir .
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase13-service-worker-bundle.ps1 -Mode PreflightRuntime -BundleDir .
```

Validation checks every required file's size and SHA-256, and checks both executables have an x64 PE machine header. The preflight reads the installed x64 Visual C++ Redistributable version in both Windows Registry views and requires it to be at least the CI build toolset version. Missing, malformed, conflicting, or older runtime state fails with Microsoft's installer link. The script neither downloads nor installs anything, creates no Service, and changes no firewall rule. Bundle hashes are delivery integrity evidence, not a signature or a security trust anchor.

This is a point-in-time check. A future installer must verify a signed release manifest and revalidate the exact files it installs before SCM registration; a prior preflight result cannot authorize later bytes.

VM1 release builds of Service and Worker both imported `VCRUNTIME140.dll`; this is local build evidence. The CI artifact and a fresh Windows machine still require separate runtime tests. Signed installer deployment, SCM lifecycle, Worker launch, policy trust activation, update metadata, rollback, and physical qualification remain open.
