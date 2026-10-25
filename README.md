# Deku Package System

Deku's package system is being developed as a native, Rust-based package manager with explicit package metadata, repository trust, dependency planning and recoverable transactions. The project separates recipe review, build execution, repository publication and client-side installation so that each trust boundary can be tested independently.

## Status

**Experimental prototype — not a production package manager.** The repository has a metadata-only Python plan/catalog prototype and a Rust core that validates a bounded catalog, plans dependency order deterministically and checks artifact bytes against recorded SHA-256 digests. The Rust core does not fetch artifacts, authenticate repository publishers, unpack packages, execute scripts, install software, mutate the host or implement transaction recovery. No production repository or supported system package catalog is available.

## Current prototype layout

- `deku_pkg/` — original Python plan/catalog prototype and command-line entry point.
- crates/deku-pkg-core/ — Rust metadata model, bounded JSON parser, semantic validator, deterministic dependency planner, artifact-digest verifier and native archive v1 module (package_archive).
- `docs/prototype-v0.md` — initial prototype scope and acceptance gates.
- `docs/native-store-and-transactions.md` — proposed immutable store, repository trust, transaction states and compatibility policy.
- `examples/catalog.json` — illustrative Python prototype catalog.

The Rust core has no root privileges or host mutation APIs. Its streaming artifact verifier checks data integrity against the digest recorded in metadata; SHA-256 alone does not authenticate the repository publisher. A signed repository format, authenticated metadata freshness, key rotation/revocation, and the network client are not implemented yet.


## Native archive v1

The current development branch introduces an original Deku archive format with deterministic manifest ordering and a bounded streaming verifier. The manifest records package identity, ABI, license expression, runtime dependency names, file kinds, permission bits, byte sizes and SHA-256 digests. Version 1 permits regular files and directories only; it rejects traversal paths, duplicate entries, file/parent collisions, privileged mode bits and tampered payloads. It does not yet extract files, install packages, authenticate publishers by itself, or mutate the host. Repository publisher authentication remains the responsibility of the separate TUF-backed trust layer.

Implementation and design review: docs/architecture/native-package-engine-upstream-review.md.

The workspace also includes a read-only CLI for verified archive inspection:

```sh
cargo run -p deku-pkg -- inspect ./example.dpak
cargo run -p deku-pkg -- verify ./example.dpak
cargo run -p deku-pkg -- files ./example.dpak
```

Each command fully checks payload digests before displaying metadata or paths. The CLI does not install, extract, fetch, or change system state.

## Native version semantics

The Rust core now includes a first Deku-native version comparator. It parses an optional numeric epoch, upstream version, and optional release; compares long numeric runs without integer overflow; and sorts tilde prereleases before the matching base version. This is an intentionally documented RPM-inspired subset, not a claim of RPM, DNF, Debian, XBPS, or SemVer compatibility. It is a foundation for version constraints in the solver, not yet a complete dependency resolver.

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
- Stage into a temporary root before live-system changes; implement journaling and rollback only after interruption and recovery tests exist.
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
