# ADR-0001: Windows-first with a Rust systems core

- Status: Accepted for prototype
- Date: 2026-09-15

## Context

ClassMesh is being built from scratch. Its hardest problems are real-time networking, bounded concurrent pipelines, native Windows graphics/media interop, service/session lifecycle and long-running reliability. UI iteration speed matters, but UI is not the current technical risk.

Alternative proposals included all-C#/.NET, C++/Qt, and Rust plus a separate native Windows UI.

## Decision

Use **Rust** for the engine, protocol, networking, capture/codec wrappers, service and agent core.

Remain **Windows-first** through the 1.0 architecture. Cross-platform receivers are deferred.

Do not commit the final teacher UI framework yet. The engine exposes a stable boundary so a native Windows UI can later be implemented in C#/.NET or another suitable native framework without embedding media logic into the UI.

## Why not all C# now?

C# is capable of building the product, and the existing ClassPilot prototype demonstrated that. The new project intentionally optimizes for a systems core with explicit ownership, predictable low-level resource lifetimes and strong concurrency/memory safety while interoperating with D3D11/Media Foundation.

## Why not C++/Qt?

C++/Qt is proven by Veyon and other native applications, but ClassMesh would assume more manual memory/lifetime risk across networking, codecs and asynchronous pipelines. Rust provides comparable systems-level access with stronger memory-safety guarantees.

## Consequences

Positive:

- one language for core media/network/service logic;
- strong compile-time ownership model for concurrent resource lifetimes;
- suitable for native Windows FFI and high-performance networking;
- reusable core if future clients expand beyond Windows.

Costs:

- Windows COM/Media Foundation bindings require careful unsafe boundaries;
- a future C# UI requires IPC or FFI boundary work;
- fewer turnkey examples than C++ for some Media Foundation/D3D11 combinations.

## Rule

Unsafe/native interop should be isolated in narrow Windows-specific crates. Higher-level session/network logic remains safe Rust where practical.
