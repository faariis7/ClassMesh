# ClassMesh fuzzing

This directory is an independent Cargo workspace so fuzz-only nightly/libFuzzer dependencies do not affect the ClassMesh stable toolchain or Rust 1.85 production MSRV.

## Requirements

- Unix-like x86-64 or AArch64 host
- Rust nightly
- a C++11-capable compiler
- `cargo-fuzz`

Install and run:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run control_frame --manifest-path fuzz/Cargo.toml
```

For a bounded smoke run:

```bash
cargo +nightly fuzz run control_frame --manifest-path fuzz/Cargo.toml -- -runs=10000
```

The initial target feeds arbitrary bytes directly into the bounded ClassMesh control-frame decoder. The invariant is simple: malformed or oversized input may return a structured error but must never panic, allocate from an unchecked declared length, or invoke undefined behavior.

Crash artifacts belong under `fuzz/artifacts/` and must not be committed. Minimized regression inputs that represent fixed bugs should be converted into deterministic unit tests in the affected production crate.
