# Native package engine: upstream design review and Deku decisions

**Status:** design review for the implementation in this branch. This is not a production-readiness claim.

## Executive decision

Deku will implement its package format, resolver, store, and transaction model natively in Rust. We reuse proven ideas and independently specified contracts, not copied XBPS/RPM/DNF/Nix implementation code, because the objective is an independently maintained engine. Third-party code may still be adopted later behind an explicit license and maintenance decision; every imported component must retain notices and satisfy its own license.

The first implementation slice is the native deterministic archive format in crates/deku-pkg-core/src/package_archive.rs. It can encode test fixtures and stream-verify a package payload against a bounded manifest. It does not yet install a package or authenticate the repository publisher.

## What we take from each project

| Project | Proven idea worth adopting | Deku design decision |
| --- | --- | --- |
| XBPS | A direct binary-package workflow; signed remote repository metadata; package/file integrity checks; replacement, hold, downgrade and configuration-file handling. | Keep installable artifacts and repository indexes simple to cache and inspect. Add per-file manifests and integrity checking. Remote trust stays mandatory and is handled by the TUF trust layer, not a bare artifact checksum. |
| RPM | Explicit package identity (epoch/version/release/architecture), file ownership/metadata, package verification, and a mature set of lifecycle semantics. | Define one canonical Deku identity and ownership model. Support only explicitly specified file kinds and operations; do not run foreign RPM scriptlets. RPM support begins as read-only inspection, not an alternative install engine. |
| DNF5/libdnf | Repository-aware dependency solving, transaction previews, history/replay, offline transaction handling, advisories and machine-readable output. | Make planning pure and deterministic; show proposed actions before mutation; persist a durable transaction journal and expose structured output. Add version constraints, provides/conflicts and transaction history in milestones rather than pretending a name-only dependency graph is enough. |
| Nix | Immutable/content-addressed store objects, derivation inputs, dependency closures, and profile generations that enable rollback. | Store verified payloads by digest and build profiles from explicit closures. Design generations/rollback into the transaction API early. Do not assume that a content-addressed store automatically makes ordinary Linux software relocatable or that a successful rebuild is reproducible without comparing output bytes. |
| TUF (the tough Rust client already present) | Root/targets/snapshot/timestamp trust roles, expiry and rollback-aware metadata handling. | Use the existing maintained trust adapter instead of inventing a signature protocol. The current adapter is limited to its documented role capabilities and still needs operational rotation/recovery and end-to-end tests. |

Primary upstream references:
- XBPS implementation and feature set: https://github.com/void-linux/xbps and https://docs.voidlinux.org/xbps/repositories/index.html
- RPM packaging project: https://github.com/rpm-software-management/rpm
- DNF5/libdnf and solver architecture: https://github.com/rpm-software-management/dnf5
- Nix store and derivations: https://github.com/NixOS/nix/blob/master/doc/manual/source/store/derivation/index.md
- TUF specification and Rust implementation: https://theupdateframework.io/ and https://github.com/awslabs/tough

## Native archive v1 contract

The current implementation uses this binary framing:

1. Eight-byte magic DEKUPK01.
2. Big-endian 32-bit manifest length.
3. Big-endian 64-bit payload length.
4. A JSON manifest with a strict schema.
5. Regular-file payload bytes in strictly sorted UTF-8 path order. Directories occupy no payload bytes.

The manifest records package name, version, architecture, Deku ABI identifier, license expression, runtime dependency names, and a sorted list of relative paths, object kind, Unix permission bits, size and SHA-256. The verifier streams file data through a fixed-size buffer and rejects altered payloads, undeclared trailing bytes, size mismatches, unsupported schema versions, unknown JSON fields, traversal paths, duplicate paths, file-as-parent conflicts and privileged mode bits.

Version 1 intentionally supports regular files and directories only. It rejects symlinks, hard links, device nodes, FIFOs, extended attributes, capabilities and package-supplied install scripts instead of silently assigning unsafe or ambiguous semantics. Those features can only be added with explicit policies and adversarial tests.

The digest inside an archive proves only that its bytes match its manifest. It does not identify the publisher. A client must fetch the artifact using authenticated, fresh repository metadata from the existing trust layer and verify the downloaded artifact before asking the archive verifier to inspect it.

## Trust and licensing boundaries

- Do not enable Void repositories, keys, or binary packages as Deku defaults.
- Do not bulk copy void-packages templates or their patches. Translate recipes selectively only after checking per-package licensing, patch provenance, build dependencies and Deku ABI compatibility.
- A repository's top-level license does not automatically license each upstream package, embedded patch, logo, font or binary artifact.
- RPM, DNF5/libdnf and Nix have distinct source trees and subcomponent licenses. Any future source-code import must include a file-level/component license review and preserve notices.
- This branch adds original Deku code and does not copy source files from those projects.

## Implementation sequence

1. Archive model and verifier (this branch): deterministic encoding, bounded parsing, path/mode validation, streaming digest verification, adversarial tests.
2. Canonical repository snapshot: connect catalog package identities to artifact digests, versioned metadata, authenticated freshness and signed release provenance.
3. Dependency model and solver: epoch/version/release semantics, bounded constraints, provides, conflicts, architecture/ABI filtering, backtracking or a rigorously specified resolver, and reproducible transaction plans.
4. Content-addressed store: verify-then-persist, immutable objects, index integrity, lock/concurrency handling and safe garbage collection.
5. Staged installer and journal executor: temporary root first; collision/ownership handling; crash injection; recovery that reconciles journal state with the filesystem; never claim atomicity without tests.
6. Repository client and CLI: bounded downloads, redirect/IP safeguards, resumption, offline cache, structured output and clear plan/execute separation.
7. Build/release integration: reviewed source pins in deku-recipes, isolated workers in deku-build, artifact manifests and independent rebuild comparisons, signatures issued in a separate trust domain.
8. System integration: only after package tests pass, connect to deku-system and VM-test clean install, upgrade, remove, interruption recovery, rollback and boot recovery.

## Explicit non-goals for this milestone

This code is not a general RPM/DEB converter, not a replacement for Flatpak, not a live-system installer, not a security boundary by itself, and not production-ready. RPM/DEB import remains read-only until differences in scriptlets, triggers, configuration files, alternatives and dependency expressions have safe, testable mappings. Flatpak should remain under upstream Flatpak tooling.
