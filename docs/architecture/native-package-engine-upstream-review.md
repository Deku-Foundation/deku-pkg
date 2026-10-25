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


## Native version ordering contract

The new Rust core version module defines Deku's own ordering contract rather than claiming compatibility with a foreign package manager:

- Syntax is [epoch:]upstream[-release]; epoch defaults to zero and release defaults to zero.
- Numeric runs are compared numerically without converting long digit runs to machine integers.
- Alphabetic runs compare lexically; punctuation separates runs.
- A tilde (~) sorts before the matching base version, allowing prereleases such as 2.0~rc1 to sort before 2.0.
- Explicit epochs reject leading zeroes and overflow; empty components, whitespace, and non-ASCII tokens are rejected.
- Equality is defined by the comparator so versions that compare equal also compare equal as values.

This is an RPM-inspired subset for a native contract, not RPM's full algorithm, Debian's dpkg algorithm, XBPS version semantics, or SemVer. Before recipe migration at scale, this contract must be stabilized with a cross-project corpus and property tests. Compatibility adapters must translate upstream version strings only when conversion is lossless; ambiguous versions must be rejected rather than silently reordered.

The core now also includes a pure backtracking resolver for named packages and version constraints. It selects the highest compatible version, prefers the target architecture over noarch for equal versions, applies a fail-first deterministic search strategy, and rejects cycles before producing a dependency-first plan. Search limits are explicit. It does not yet support provides/conflicts, weak dependencies, repository lookup, installed-state reconciliation, or transaction execution.


## Versioned catalog and planning CLI

The first versioned solver catalog is now defined separately from the older single-version `Catalog` model. This is intentional: changing the legacy schema silently would make existing plans ambiguous. `SolverCatalog` accepts multiple candidates with canonical versions, architecture, safe artifact filenames, SHA-256 digests and dependency constraints. JSON bytes are bounded before parsing, unknown fields are rejected, and duplicate identities/dependencies and self-dependencies fail validation.

The read-only CLI command `deku-pkg plan CATALOG ARCH REQUIREMENT...` loads this catalog, resolves the requested closure, and prints dependency-first package identities with the exact artifact filenames and digests from the validated catalog. Root requirements can use forms such as `desktop-shell>=1.0-1,<2.0-0`. This is not a download or install command. It does not establish that the catalog was published by a trusted repository; the caller must verify signed, fresh repository metadata first. The selected artifact digest must still be checked against downloaded bytes before archive inspection or any future installation.



## Content-addressed object-store prototype

The core now has a separate object-store adapter that only accepts a stream when its complete SHA-256 matches the expected digest and its byte size stays under a caller-supplied bound. It writes through a temporary file, syncs the bytes, changes the object to read-only, and uses a same-directory hard link to publish without replacing an existing content identifier. If another writer already published that digest, the existing object is re-hashed before deduplication is accepted. The store refuses symlink object paths and directories writable by group or others.

This adapter stores opaque blobs only. It does not establish publisher identity, decide whether an artifact belongs to an authorized repository snapshot, extract archive members, maintain package ownership, or roll a system profile forward/back. Consumers must first verify trusted repository metadata, then ingest using the authorized artifact digest and size bound, and then run the native archive verifier. Crash/recovery and concurrency tests beyond the initial same-process deduplication fixture remain required before a production claim.


## TUF-authenticated catalog planning path

The CLI now has a separate `trusted-plan` path that composes the pure resolver with the existing `deku-pkg-trust` crate. The command accepts an out-of-band trusted root, HTTPS metadata and target base URLs, the persistent TUF datastore, a pre-provisioned staging directory, the catalog target name, architecture and root requirements. It loads the TUF repository (including signature/expiry/rollback checks), asks the trust crate to download the catalog target into staging, parses that target with the bounded strict `SolverCatalog` parser, and only then computes the plan.

This prevents the trusted path from treating an arbitrary local JSON catalog as an official repository catalog. The earlier `plan` command remains intentionally usable for local development fixtures and prints no claim of publisher authentication. The TUF path now checks a signed target's declared length before download, caps the catalog target at 16 MiB, and verifies for each selected package that an authorized TUF target exists, its signed SHA-256 equals the digest in the TUF-authenticated catalog, and its signed length is within the native archive size limit. The package artifact bytes are still not downloaded by the planning command; no artifact is extracted or installed. The next integration gate must download each planned artifact through TUF, compare the received bytes with the catalog digest, ingest those bytes into the content store, and run the native archive verifier before staged installation can be considered.


## Verified artifact fetch and blob-store integration

The CLI now includes a read-only `trusted-fetch-plan` command. It loads repository metadata through the TUF trust adapter, downloads the catalog target only after signed metadata validation, resolves package requirements, then for each planned artifact:

1. Reads its signed target length and SHA-256 before download; rejects sizes above the native archive limit and rejects any digest disagreement between the TUF target metadata and the TUF-authenticated catalog.
2. Downloads the artifact through `TrustedRepository::download_verified_target`, which checks bytes against the signed TUF target metadata before the file is returned.
3. Re-checks that the target is a regular file with the signed length, then streams the native archive verifier over it to validate internal file paths, modes, sizes and SHA-256 values.
4. Checks that the embedded package name, canonical version and architecture exactly match the resolved catalog candidate.
5. Ingests the raw archive bytes into the content-addressed store using the catalog digest and size limit, then re-hashes the stored object and prints its path.

No package is extracted or installed. This command establishes a complete **metadata-trusted, bytes-verified, archive-inspected, content-addressed fetch path**, not a transaction executor. The next gates are build provenance/catalog release integration, file ownership/collision policy, staged extraction into an isolated root, durable install journal and crash-recovery testing before any live-root write is designed.


## DESTDIR package builder

The CLI now exposes `deku-pkg pack DESTDIR OUTPUT NAME VERSION ARCH ABI LICENSE [DEPENDENCY...]`. The builder performs a sorted filesystem walk without following symlinks, permits only regular files and directories, rejects device nodes/FIFOs and setuid/setgid/sticky modes, captures relative path/mode/size/SHA-256 metadata, and streams payload bytes in archive order. It reads every regular file once to calculate its digest and again while writing, checking size and digest in the second pass to detect changes. The CLI writes to a private same-directory temporary file, syncs it, sets the published artifact permissions, and hard-links to the destination without overwriting an existing path.

This makes native artifact creation possible from an already-populated DESTDIR. It does not execute package build scripts or assemble DESTDIR itself; that stays with the isolated worker in `deku-build`. It also does not sign artifacts or establish repository trust. The destination should be written by a controlled build worker with an isolated source/output directory, and build provenance/source pinning remain release gates.

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
