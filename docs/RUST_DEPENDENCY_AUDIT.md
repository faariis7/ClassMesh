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

The fixes need an MSRV-compatible upstream release or backport, or a separately
reviewed MSRV and dependency change. The audit fails for the current workspace
until its resolution has no blocking findings.
