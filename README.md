# Deku Package System

Deku's package system is being developed as a native, Rust-based package manager with explicit package metadata, repository trust, dependency planning and recoverable transactions. The project separates recipe review, build execution, repository publication and client-side installation so that each trust boundary can be tested independently.

## Status

**Experimental prototype — not a production package manager.** The Rust workspace now contains a native archive format and streaming verifier, deterministic DESTDIR packer, ABI-aware version resolver, bounded catalog validation, TUF-backed repository trust adapter, content-addressed artifact store, verified artifact-fetch path, extraction into an empty protected staging directory, and an installed-package database with pure file-ownership preflight. Durable stores now persist both the transaction journal and installed-package database with protected ownership/mode checks, atomic replacement, inter-process save locks and stale-state rejection. These stores and the ownership index are still metadata primitives; no transaction executor or live-system installer exists. There is no production repository or supported system package catalog.

## Current prototype layout

- `deku_pkg/` — original Python plan/catalog prototype and command-line entry point.
- crates/deku-pkg-core/ — native archive, builder, staged extractor, version comparator, ABI-aware dependency solver, installed database/file-ownership preflight, immutable content store, durable installed-database store and transaction-journal store.
- crates/deku-pkg-trust/ — TUF-backed metadata and target verification using the existing Rust TUF implementation.
- crates/deku-pkg-cli/ — archive inspection, packaging, local/trusted planning and trusted fetch-to-store commands.
- `docs/prototype-v0.md` — initial prototype scope and acceptance gates.
- `docs/native-store-and-transactions.md` — proposed immutable store, repository trust, transaction states and compatibility policy.
- `examples/catalog.json` — illustrative Python prototype catalog.

The core does not need root privileges and does not mutate a live system. The TUF adapter verifies repository metadata and target bytes against an out-of-band trusted root, with expiry and rollback-aware metadata state. Key rotation and recovery operations, delegated-target support, production repository operation and end-to-end release provenance remain separate operational gates. A digest alone is still not publisher authentication.


## Native archive v1

The current development branch introduces an original Deku archive format with deterministic manifest ordering and a bounded streaming verifier. The manifest records package identity, ABI, license expression, runtime dependency names, file kinds, permission bits, byte sizes and SHA-256 digests. Version 1 permits regular files and directories only; it rejects traversal paths, duplicate entries, file/parent collisions, privileged mode bits, writable package directories and tampered payloads. The CLI can extract a verified archive to an existing empty protected staging directory. This is not a live-system installer; repository publisher authentication remains the responsibility of the separate TUF-backed trust layer.

Implementation and design review: docs/architecture/native-package-engine-upstream-review.md.

The workspace also includes a read-only CLI for verified archive inspection:

```sh
cargo run -p deku-pkg -- inspect ./example.dpak
cargo run -p deku-pkg -- verify ./example.dpak
cargo run -p deku-pkg -- pack ./build/destdir ./out/sample-1.0-1-x86_64.dpak sample 1.0-1 x86_64 deku1-linux-gnu MIT libc zlib
cargo run -p deku-pkg -- inspect ./out/sample-1.0-1-x86_64.dpak
mkdir -m 700 ./var/sample-stage
cargo run -p deku-pkg -- extract ./out/sample-1.0-1-x86_64.dpak ./var/sample-stage
cargo run -p deku-pkg -- files ./example.dpak
cargo run -p deku-pkg -- plan examples/solver-catalog-v1.json x86_64 deku1-linux-gnu 'desktop-shell>=1.0-1,<2.0-0'

# Trusted planning from a TUF-authenticated repository (all paths must be provisioned)
cargo run -p deku-pkg -- trusted-plan ./trusted/root.json https://packages.example.invalid/metadata/ https://packages.example.invalid/targets/ ./var/tuf-state ./var/staging catalogs/native-v1.json x86_64 deku1-linux-gnu 'desktop-shell>=1.0-1,<2.0-0'
cargo run -p deku-pkg -- trusted-fetch-plan ./trusted/root.json https://packages.example.invalid/metadata/ https://packages.example.invalid/targets/ ./var/tuf-state ./var/staging ./var/package-store catalogs/native-v1.json x86_64 deku1-linux-gnu 'desktop-shell>=1.0-1,<2.0-0'
```

Archive inspection and verification check payload digests before presenting metadata. The packer creates deterministic artifacts from an already-built DESTDIR; extract verifies the archive before copying files and rechecks payload digests while writing. Extraction requires an existing empty staging root controlled by the current user and applies restrictive checks to paths and directory modes. It is not suitable as a live-root installer. The local planner validates a bounded versioned catalog and prints a dependency-first plan pinned to exact artifact filenames and SHA-256 digests. Local planning does not authenticate publishers.
`trusted-plan` verifies the out-of-band root and current TUF metadata using `deku-pkg-trust` before downloading the catalog target into the staging directory. It requires HTTPS base URLs, a persistent protected datastore, and an existing protected staging directory. The command produces a plan only. Before downloading the catalog it enforces a 16 MiB signed-target size ceiling; for every selected package it checks that a matching signed TUF target exists, that its signed SHA-256 matches the catalog digest, and that its signed size is within the native archive limit. It does not download package artifact bytes into the content store or install software. The `.invalid` hostname above is a documentation placeholder, not a working repository.

`trusted-fetch-plan` continues beyond planning: it verifies every selected artifact against signed TUF target metadata and the catalog digest, downloads via the trust crate, checks that the archive manifest identity matches the selected name/version/architecture, then verifies the embedded package name, canonical version, architecture and ABI before writing the bytes into the content-addressed object store and re-verifying the stored object. This is still **not an installer**: it does not extract the fetched packages or write the live system. The package store path must already exist, be a real non-symlink directory, and not be group/world writable.

The catalog under `examples/` is a test fixture: its SHA-256 values are placeholders, not real artifacts. Replace them with measured hashes and authenticate the catalog through the repository-trust layer before using any catalog as authoritative metadata.


The `pack` command builds a native archive from an existing DESTDIR. It reads regular files and directories only, rejects symlinks and special filesystem objects, sorts package entries deterministically, hashes files before writing, and streams/re-hashes them while producing the archive. Output publication uses a private temporary file and refuses to overwrite an existing output; the command prints the full archive SHA-256 for catalog generation. Source and output directories must not be group/world writable. The command does not run build scripts; it packages an already-populated DESTDIR and does not install the result.

## Native version semantics

The Rust core now includes a first Deku-native version comparator. It parses an optional numeric epoch, upstream version, and optional release; compares long numeric runs without integer overflow; and sorts tilde prereleases before the matching base version. This is an intentionally documented RPM-inspired subset, not a claim of RPM, DNF, Debian, XBPS, or SemVer compatibility. It is a foundation for version constraints in the solver, not yet a complete dependency resolver.

## Native dependency resolver

The Rust core now includes an initial pure, version-aware resolver. It supports equality and ordered version constraints, chooses the highest compatible package, filters candidates by target architecture and ABI, backtracks when constraints conflict, reports unsatisfiable requirements, and rejects dependency cycles before returning a dependency-first plan. Search-state, candidate, depth, and constraint limits are enforced. This is an initial named-dependency resolver; virtual provides, explicit package conflicts, weak dependencies, installed-state reconciliation, and transaction execution are not implemented yet. Repository trust is supplied as a separate adapter rather than being embedded in the pure solver.

## Content-addressed object store

The Rust core includes an isolated blob store keyed by lowercase SHA-256. It enforces an explicit maximum size, hashes input while streaming into a temporary file, publishes only after digest validation, uses no-overwrite hard-link publication, and re-verifies an existing object before deduplication. This module stores opaque blobs; it does not extract or install packages. It expects a pre-provisioned protected directory and is not a substitute for authenticated repository metadata.

## Staged extraction and transaction journal

The Rust core exposes an extraction primitive for archive v1. It requires an existing, empty staging directory with protected permissions, validates the entire archive before writing, re-checks the manifest and file digests during extraction, and attempts to remove paths it created if an error occurs. It rejects symlinks and special files because archive v1 does not represent them. A pure installed-database and file-ownership preflight now detects duplicate file owners, file/parent conflicts, type collisions, and mismatched modes for shared directories. This is metadata-only: it does not reconcile recorded owners with the actual filesystem, remove package files, activate a live root, or roll a system back.

The transaction-journal store validates the current transaction-state schema, serializes saves with an advisory inter-process lock, rejects stale or divergent history updates, and uses synced temporary files plus atomic rename. The installed-database store uses a separate lock and monotonic generation check to reject stale or divergent database snapshots. Journal paths must be owned by the effective user and must not be group/world writable; journal opens avoid following symlinks. The journal remains evidence for recovery, not proof that filesystem state matches it. A transaction executor still needs a lock spanning the entire transaction, integration of the ownership preflight with staged-tree and real-filesystem checks, crash-injection tests, reconciliation with actual filesystem state, and explicit commit/rollback semantics.

## Run checks

Rust core tests and lint checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

The Python prototype may be validated with:

```sh
PYTHONPATH=. python -m deku_pkg.cli --catalog examples/catalog.json --install hello-deku
```

The Python command prints a plan only; it does not install software. Run the tests from a clean checkout. GitHub Actions runs the Rust formatting, Clippy and unit-test gates on pull requests.

## Security invariants

- Parse bounded metadata and reject unknown fields, duplicate JSON keys, malformed identifiers and invalid dependency graphs.
- Pin source revisions and artifact digests; a digest is an integrity check, not publisher authentication.
- Prefer streaming verification with a caller-supplied maximum artifact size instead of buffering unbounded downloads.
- Never execute arbitrary package-provided scripts as root during inspection or native installation.
- Keep ordinary queries and planning unprivileged; privileged operations need a separately reviewed and narrow helper.
- Stage into a temporary root and run the ownership preflight before live-system changes; implement activation and rollback only after interruption and recovery tests exist.
- Keep RPM/DEB inspection and import as advanced, disabled-by-default compatibility paths. Flatpak should use upstream tooling rather than a second implementation.

## Required milestones before system use

Signed/versioned repository metadata, trust roles, expiry and rollback protection, dependency/version constraints, file ownership and path safety, store immutability, transaction journaling, interruption recovery, license/provenance records, compatibility test fixtures and disposable-VM system tests must pass before this project is integrated into an installation image.

The current validator is one component of that path, not evidence that a production package repository or installable Deku system exists.

## Repository trust prototype (Rust)

The new `crates/deku-pkg-trust` crate uses the maintained `tough` Rust client for TUF 1.0 metadata verification rather than implementing a custom signature/rollback protocol. Its current boundary requires a trusted root supplied out-of-band, HTTPS-only metadata/target base URLs, an existing persistent non-symlink datastore, safe metadata expiry, bounded metadata sizes, and target download into a caller-owned staging directory. TUF verifies the downloaded target against its authenticated metadata before `save_target` persists it.

This is an integration prototype, not yet the default package-manager path:
- It does not install packages, write the live root, or perform transactions.
- The `tough 0.24.0` documentation states that delegated roles and TAP 4 multi-repository consensus are not implemented; Deku must therefore start with one top-level targets role and must not claim delegated-repository support. The Rust trust boundary opens the out-of-band root with Unix `O_NOFOLLOW`, enforces a bounded read, checks effective-UID ownership and rejects group/world-writable trust-anchor, datastore and staging paths. Ancestor-directory protection remains a deployment responsibility.
- Unit tests cover strict URL/target-name policy plus a signed local TUF fixture: verified target download, target-digest tampering, symlink rejection for trusted-root/datastore/staging paths, and shared-writable-directory rejection. Explicit key-rotation, persisted rollback/freeze, expired-metadata, and concurrent-client tests remain required before release.
- The first trusted root must come from a reviewed out-of-band channel. Downloading the initial root from the same unauthenticated repository would defeat bootstrapping trust.
