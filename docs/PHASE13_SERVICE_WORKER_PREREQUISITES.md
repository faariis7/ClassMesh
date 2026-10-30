# Phase 13 Service and Worker runtime prerequisite bundle

The Windows CI artifact `classmesh-phase13-service-worker-windows-x64` contains x64 release candidates for `classmesh-service.exe` and `classmesh-worker.exe`, a schema-2 SHA-256/size index with a separately named runtime minimum for each executable, and the scripts needed to validate it. This artifact is a deployment input, **not** an installer or production activation instruction.

On the target Windows x64 or ARM64 machine, run from the extracted artifact directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase13-service-worker-bundle.ps1 -Mode ValidateBundle -BundleDir .
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase13-service-worker-bundle.ps1 -Mode PreflightRuntime -BundleDir .
```

Validation checks every required file's size and SHA-256, and checks both executables have an x64 PE machine header. The preflight reads the installed x64 Visual C++ Redistributable version in both Windows Registry views and compares it against each executable's indexed minimum. The current CI build records the same toolset version for both independently named binaries. Missing, malformed value kinds, conflicting, or older runtime state fails with Microsoft's installer link. The script neither downloads nor installs anything, creates no Service, and changes no firewall rule. Bundle hashes are delivery integrity evidence, not a signature or a security trust anchor.

This is a point-in-time check. A future installer must verify a signed release manifest and revalidate the exact files it installs before SCM registration; a prior preflight result cannot authorize later bytes.

VM1 release builds of Service and Worker both imported `VCRUNTIME140.dll`; this is local build evidence. The CI artifact and a fresh Windows machine still require separate runtime tests. Signed installer deployment, SCM lifecycle, Worker launch, policy trust activation, update metadata, rollback, and physical qualification remain open.

## Detached signed release manifest foundation

The release operator can produce the detached pair with `scripts/phase13-sign-release.ps1 -BundleDir <trusted staging directory> -ReleaseSequence <positive version> -SignerThumbprint <CurrentUser code-signing certificate thumbprint>`. The signer requires a current RSA-2048+ code-signing certificate with an accessible private key, validates the Service/Worker bundle first, uses SHA-256 CMS, and creates signature then manifest without replacing either existing file. An interruption can leave an orphaned signature; verification rejects incomplete output. Run signing only in a trusted, access-restricted release environment. The test certificate is disposable and is never a production key.

`scripts/phase13-release-manifest.ps1` verifies a separate `release-manifest.json` and detached CMS `release-manifest.p7s` against the SHA-256 fingerprint of a signer's DER certificate supplied from an independently trusted source. It requires one detached signer and a SHA-2 digest, then checks a fixed list of six Service/Worker bundle files by length and SHA-256. The verifier uses exclusive, bounded reads; JSON cannot select additional paths. Run the verifier from a trusted checkout or installed verifier. The signer fingerprint must be provisioned outside the bundle by a trusted administrator or protected installer state.

The current CI bundle has no release signature or production signer pin and cannot pass this gate. The native test creates a disposable self-signed certificate only to exercise positive and negative verification, then removes it. Certificate pinning authenticates that exact certificate; this verifier does not check CA chains, certificate revocation, executable Authenticode, install files, commit a monotonic release sequence, or hold handles through an installer copy. A production installer must independently protect and rotate its signer pin, enforce release anti-rollback, stage into protected storage and revalidate the exact bytes at the install boundary.

Exact CI run `41138625385` at PR #644 head `dfb7a7bf` passed both hosted jobs. Its Service/Worker artifact `13018638145` was transferred unchanged to VM1: index SHA-256 `d5c44b85ea07f57788ebf6f88b19418405578ecd476bbe7532c32040cc2b5a87`, Service `5670383cd49468a5c3b487c276eb1bcff47229348abb51d062a868a7ef99a55a`, Worker `4485db4299a55bb0a0c78561e75429f1bdaf3cae86cc89fa3c0d220f0de9075f`. Bundle validation and preflight passed with required VC runtime `14.51.36231.0` and installed `14.51.36247.0`; both binaries reported `NotSigned`. PR #644 merged as `ce6fe692992b788be6cc2fd10399fe1c48aa26ce`.

The same run's Teacher schema-3 artifact `13018093504` passed unchanged validation, preflight and a seven-second responsive-window Session 1 smoke on VM1. Teacher index SHA-256 `a92f874483a818f13574ef4da0ab4ad772927608062b4995b68fd0e6306adc63`, EXE SHA-256 `5214d3cfeec6c7e3d9bce3eacf2683140f31c3aa4e460f15c5a6a9d45c901339`; its Authenticode status was also `NotSigned`. This is VM launch evidence, not fresh-clean Windows, accessibility or physical classroom qualification.
