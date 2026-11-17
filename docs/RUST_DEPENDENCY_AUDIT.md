# Rust dependency audit

The [Rust dependency audit workflow](../.github/workflows/rust-dependency-audit.yml)
runs cargo-audit 0.23.0 on pull requests, pushes to main, and daily. It can
also be run manually from Actions after it reaches the default branch. It
checks the main workspace on stable and the separate fuzz workspace on
nightly, matching their build workflows. Cargo resolves dependencies for
all declared target platforms and workspace features into each lockfile.

Each job fetches the live RustSec database and posts the audit to the Actions
run summary. Findings show the crate and resolved version, advisory ID, CVSS
score when RustSec supplies one, and the fixed version range if available.
Missing CVSS means unscored. Known vulnerabilities, unsound or yanked crate
findings, and scan failures fail the job. Maintenance warnings remain visible.
The `rustsec-workspace-*` and `rustsec-fuzz-*` artifacts retain the text report,
database revision and the exact lockfile scanned for 30 days, including when
the audit finds vulnerabilities.

## Lockfile policy

At baseline revision `19a472e5714c0945ab6585093584ba3848e53e09`, Git tracked
neither lockfile. CI resolved packages from manifests at build time, with a
separate Rust 1.85 Teacher UI check. The audit preserves that workflow by
generating a lockfile in the runner when absent. If a lockfile is added in the
future, the audit validates it with `cargo fetch --locked` and scans it without
updating it. The audit captures a point-in-time resolution that may differ
from other builds. Reproducible releases would require adopting a reviewed
lockfile and making build and release jobs consume it with `--locked`. See the
[Cargo lockfile guidance](https://doc.rust-lang.org/cargo/faq.html#why-have-cargolock-in-version-control).

## Initial findings

Baseline scanned on 2026-11-17 with RustSec database
[`02e2517f`](https://github.com/RustSec/advisory-db/commit/02e2517f457a359fc6d3440ea4560c8ea188fee8).
The root workspace resolved three vulnerability advisories and four maintenance
warnings. The separate fuzz graph had zero findings.

| Crate | Advisory | CVSS | Upstream fix |
| --- | --- | --- | --- |
| `quick-xml 0.38.4` | [RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194) | 7.5 high | `>=0.41.0` |
| `quick-xml 0.38.4` | [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195) | 7.5 high | `>=0.41.0` |
| `time 0.3.45` | [RUSTSEC-2026-0009 / CVE-2026-25727](https://rustsec.org/advisories/RUSTSEC-2026-0009) | 6.8 medium | `>=0.3.47` |

- `quick-xml 0.38.4` comes from `zbus_xml 5.1.0` through the pinned
  Teacher `eframe` accessibility dependency graph. `zbus_xml 5.1.0` requires
  `quick-xml ^0.38`. `zbus_xml 5.2.0` removes the dependency and raises its
  minimum Rust version to 1.87. The affected version appears in the all-target
  lockfile and was absent from the x64 and ARM64 Windows target trees.
- `time 0.3.45` comes through `rcgen` and its certificate dependencies,
  including the Windows build graph. `time 0.3.47` requires Rust 1.88.
  The advisory concerns RFC 2822 parsing, and the dependency scan establishes
  package presence. Runtime reachability remains unverified.
- RustSec lists `ttf-parser 0.25.1`
  ([RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192)),
  `zbus_names 4.3.1`
  ([RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371)),
  `zvariant 5.9.2`
  ([RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370)), and
  `zvariant_derive 5.9.2`
  ([RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372))
  as unmaintained, with no fixed version listed in those notices.

At this baseline the workspace audit failed for real vulnerabilities, independently
of the Windows artifact-discovery error described below.

## Remediation and MSRV decision (PR #774, 2026-11-18)

This candidate deliberately raises the workspace MSRV from **Rust 1.85 to 1.88**.
The stable toolchain, pinned Teacher `eframe 0.32.3`, security gates, accessibility
feature, and lockfile policy are retained. No advisory ignore, patched-version
relabeling, lint allowance, or audit-policy relaxation is introduced.

The new resolution was scanned using cargo-audit 0.23.0 and live advisory database
[`233155b4`](https://github.com/RustSec/advisory-db/commit/233155b4025b854c68a4b199c0e32d7fd53291a2).
It returned exit 0: **zero vulnerability findings**, with the same four visible
maintenance notices. Hosted reports and their exact lockfiles are retained by
the audit workflow; the latest exact-head CI outcome is recorded on the PR.

| Component | Rust 1.85 resolution | Rust 1.88 resolution | Compatibility constraint |
| --- | --- | --- | --- |
| `time` | 0.3.45 | 0.3.55 | First fixed release 0.3.47 requires 1.88 |
| `time-core` / `time-macros` | 0.1.7 / 0.2.25 | 0.1.9 / 0.2.32 | 0.3.47 itself requires 0.1.8 / 0.2.27; changing only `time` metadata is insufficient |
| `rcgen` / `yasna` | 0.14.7 / 0.5.2 | 0.14.10 / 0.6.0 | `rcgen >=0.14.8` requires 1.88; `asn1-rs` and `x509-parser` also consume `time` |
| `zbus_xml` | 5.1.0, requires `quick-xml ^0.38` | 5.2.1, no `quick-xml` dependency | 5.1.1 and 5.2.x require 1.87; adding a second, fixed `quick-xml` does not replace the vulnerable 0.38 copy |
| `quick-xml` | 0.38.4 plus 0.41.0 | only 0.41.0, via `wayland-scanner` | 0.41.0 is fixed for both advisories and needs only 1.79; the incompatible constraint was its parent |
| `p256` / `crypto-bigint` | 0.14.0 / 0.7.11 | 0.14.0 / 0.7.11 | Non-yanked 0.7 releases now require 1.87; retain the fixed crypto dependency |

All resolved packages declaring an MSRV fit within 1.88. `cargo tree --target all`
confirmed the complete reverse paths. The old XML dependency came through
`classmesh-teacher -> eframe -> egui-winit -> accesskit_winit -> accesskit_unix
-> atspi -> zbus-lockstep -> zbus_xml`. It was absent from the Windows target
tree, but present in the all-target lockfile and therefore still required repair.
The `time` path includes `classmesh-control`, `classmesh-identity-win`,
`classmesh-lab`, `rcgen`, `yasna`, `x509-parser`, and `asn1-rs`, including Windows.
This is graph evidence, not a claim that every vulnerable parser was reachable
from a ClassMesh network request.

### Tested alternatives

| Approach | Measured result | Tradeoff / decision |
| --- | --- | --- |
| Published fixes while keeping 1.85 | Isolated `cargo +1.85.0 check` rejects `time =0.3.47` / `time-core 0.1.8` for 1.88; rejects `zbus_xml =5.2.0` and its `zbus_names`, `zvariant`, `zvariant_derive`, `zvariant_utils`, `zcheapstr` graph for 1.87 | No compatible published route for the existing parent graph |
| Backport XML parent constraint | In a disposable copy of published `zbus_xml 5.1.0`, changed only `quick-xml` from `0.38` to `=0.41.0`; both upstream tests (`serde`, `invalid_arg_type`) passed on 1.85, with resolver fallback enabled | Feasible local parent fork using the actual fixed parser, but ClassMesh would own vendoring, provenance, and future updates; no upstream 1.85 release established |
| Backport `time` security patch | [Upstream commit `1c63dc79`](https://github.com/time-rs/time/commit/1c63dc7985b8fa26bd8c689423cc56b7a03841ee) applies cleanly to published 0.3.45; regression and upstream tests passed on 1.85 with `parsing formatting macros` | Trusted patch provenance and demonstrated compiler compatibility; still requires a maintained downstream release, full integration review and honest advisory/version reporting |
| Downgrade `p256` to 0.13.2 | A raw-signature/DER roundtrip probe passes on 1.85, but the resulting `crypto-bigint 0.5.5` is affected by [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) | Rejected; would introduce a fourth vulnerability rather than repair the graph |
| Published dependency resolution on 1.88 (selected) | Workspace tests pass on 1.88 locally; zero blocking audit findings; Windows CI now runs the full native workspace tests plus the Teacher UI check on **1.88.0 itself**, in addition to all existing stable checks | Raises the supported compiler minimum; avoids owning parser forks and retains fixed `crypto-bigint` |

The `time` backport regression first failed on unmodified 0.3.45 because it
accepted 32 nested RFC 2822 comments. After the exact upstream patch it rejects
depths 32, 128 and 10,000 while accepting a normal comment. The command was
`cargo +1.85.0 test --features 'parsing formatting macros'` in the disposable
crate copy, with an explicitly declared regression test target. Existing upstream
ignored tests were left unchanged. The patch bounds recursion at 32; no custom
parser or cryptographic implementation was written. Neither experimental fork
is installed in the ClassMesh workspace.

The declared 1.85 baseline was already inconsistent with the source: a real
`cargo +1.85.0 check --workspace` fails at `machine_identity.rs:171`, and after
an isolated equivalent syntax rewrite reveals 17 additional unstable-let-chain
diagnostics in the Service binary. These require Rust 1.88. The `p256 0.14.0`
standalone probe also rejects its newly resolved 1.87 dependencies on 1.85.
Consequently a 1.85 backport strategy would need both dependency maintenance
and source compatibility repair. The selected change records the actual minimum
and qualifies it with tests. Raising MSRV activates additional Clippy suggestions;
the accompanying source edits apply those syntax/API suggestions, with warnings
still denied. Protocols, authorization decisions and feature gates are unchanged.

### Windows artifact-discovery repair

In baseline [Windows job 133951565003](https://github.com/faariis7/ClassMesh/actions/runs/44057811599/job/133951565003),
all workspace tests passed, including 114 `classmesh-win32` tests. Freeze then
failed looking for `target/debug/deps`; Cargo 1.100 had reported the executable
under `target/debug/build/classmesh-win32/<hash>/out/` instead.

`scripts/freeze-native-tests.ps1` now requests the default-feature library test
image with `cargo test -p classmesh-win32 --lib --no-run --message-format=json`
and reads its `compiler-artifact.executable`, as specified by
[Cargo's JSON interface](https://doc.rust-lang.org/cargo/reference/external-tools.html#artifact-messages).
It requires Cargo success, a successful `build-finished`, exactly one matching
library test image, no opt-in feature, and an existing file. It runs immediately
after the real workspace tests and before opt-in builds. Existing hosted native
smoke execution, bundle indexing/validation, and upload steps remain required.

`scripts/tests/freeze_native_tests.ps1` tests legacy and relocated/custom target
paths, exact copied bytes, Cargo failure, missing/duplicate artifacts, wrong
target/kind/profile/features, absent executable, unsuccessful/missing build
completion, and malformed JSON. A real macOS Cargo invocation with a custom
`CARGO_TARGET_DIR` also exercised artifact discovery; it is not Windows runtime
proof. Full hosted Windows results are reported separately on the PR. No
physical classroom, GPU, installer, or production qualification is implied.
