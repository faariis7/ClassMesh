# Phase 4 network impairment acceptance gates

The deterministic impairment tooling is accepted for merge when CI proves the portable engine and proxy compile/tests pass on Linux and Windows, and the Windows artifact is produced.

Physical LAN qualification remains separate because hosted CI cannot validate real D3D11 capture/encode/decode timing or two-machine network behavior.

## Merge gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo run -p classmesh-lab`
- Windows release build of `classmesh-network-impairment-proxy`
- artifact upload succeeds

## Physical test gates

Before closing the one-to-one Phase-4 transport issue:

1. baseline two-PC render is stable;
2. deterministic 1%, 3%, and 5% loss scenarios are recorded;
3. NACK and keyframe feedback recover without an unbounded queue;
4. 30-minute 3% loss/jitter/reorder soak shows no steadily growing latency;
5. capture/control identity stays alive through media degradation;
6. UDP results are compared with a QUIC Datagram prototype before the final unicast default is chosen.
