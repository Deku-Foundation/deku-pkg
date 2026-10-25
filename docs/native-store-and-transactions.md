# Deku Package Manager: Native Store and Transaction Design

**Status:** Design contract and implementation plan (reviewed 2026-10-25). Some primitives described here now exist in the Rust prototype, but this document does not describe a production-ready package manager.

## Implemented prototype primitives (2026-10-25)

The branch contains an original DPAK v1 archive with streaming verification, deterministic DESTDIR packaging, verified extraction to an existing empty staging directory, an ABI-aware named-dependency resolver, a TUF-backed target verification/fetch adapter, a SHA-256 content-addressed blob store, a durable transaction-journal store, and a strict installed-database model with a pure file-ownership index.

The ownership preflight can detect duplicate regular-file owners, file/directory type conflicts, file-as-parent conflicts, and mismatched modes for shared directories. It records implicit parent directories with mode 0755 so that directories created by extraction participate in ownership checks. It can assess an upgrade while excluding the prior version of the same package. It does not inspect or modify actual live filesystem ownership, remove files, activate a system generation, or perform rollback.

The installed database now has a durable store at a pre-provisioned protected directory. It uses a bounded strict JSON schema, effective-user ownership checks, no-follow reads, inter-process locking for saves, monotonic generation checks, synced temporary files, atomic rename and directory sync. It rejects stale or divergent snapshots; identical same-generation saves are idempotent. This database is still only the recorded ownership snapshot: a future executor must reconcile it with the actual filesystem before trusting recovery or removal decisions. The installed database currently has strict in-memory/JSON validation; durable database publishing and reconciliation against the filesystem are not yet implemented.

The journal store serializes journal saves using an advisory lock and refuses stale/divergent history updates. The installed database has its own save lock and generation guard. These locks protect individual metadata updates only; they are not yet a transaction-wide lock around acquisition, staging, activation and recovery. The TUF client uses top-level targets only: the selected `tough` version documents that delegated target roles and TAP 4 are not supported. Do not publish split/delegated official catalogs until that support is implemented and tested.

## Goals

- Rust-native implementation with deterministic dependency solving.
- Official Deku repositories are the default trust source.
- Safe verification, explicit transaction plans, recoverable updates, and auditable package ownership.
- Optional RPM/DEB compatibility without treating foreign package scripts as trusted.
- Flatpak integration through upstream tooling, not a reimplementation of Flatpak.

## Package model

A native package descriptor should identify:
- schema version, package name, epoch/version/release, architecture, and ABI/platform target;
- immutable artifact digest and size;
- source recipe identity and immutable source revision;
- dependency constraints, conflicts, provides, and optional/recommended dependencies;
- file manifest including type, normalized relative path, mode, ownership policy, and digest for regular files;
- license expression, copyright/provenance records, maintainer identity, build environment, test results, and build attestation;
- integration declarations for desktop files, icons, shared-library cache, service units, udev rules, kernel modules, and configuration defaults.

Unknown fields in security-sensitive schemas must be rejected until explicitly supported. Names and version constraints must have one canonical representation. File paths must reject absolute paths, parent traversal, duplicate normalized paths, and unsafe archive entries. Symlink targets must be validated according to an explicit policy.

## Repository trust

A repository snapshot contains versioned metadata, package descriptors, artifact digests, key identifiers, and freshness/expiry information. Repository metadata and artifact provenance must be signed with distinct roles. A checksum proves downloaded bytes match metadata; it does not prove who published that metadata.

The design should evaluate TUF-style root/targets/snapshot/timestamp roles, key rotation and threshold policy, expiration, rollback protection, and recovery from compromised keys before inventing a custom trust protocol. Third-party repositories are not enabled or trusted implicitly.

## Dependency solver

The solver is a pure Rust library without root privileges, network access, or filesystem writes. Its inputs are a verified catalog, installed-state snapshot, requested operations, architecture, and explicit policy. It produces a deterministic plan containing:
1. packages to install, upgrade, downgrade, or remove;
2. exact artifact identities and dependency edges;
3. conflicts and file ownership changes;
4. required download and disk-space estimates;
5. trust/signature status and policy warnings;
6. any configuration or service actions that require separate approval.

The initial solver should implement exact version pins, bounded version constraints, provides/conflicts, architecture filtering, and cycle/conflict reporting. Do not attempt a SAT solver or complex weak-dependency semantics until real recipes require them. Every solver result should be reproducible from the same catalog and request.

## Store and filesystem integration

Proposed payload store: /deku/store/<content-id>/, immutable after verification. Proposed system profiles: /deku/profiles/system/<generation>/, each describing a complete coherent package set. Mutable state, cache, and transaction journals live under /deku/var/. User configuration stays in standard XDG locations and administrator configuration remains under /etc.

This layout is not sufficient by itself to make all Linux software work. Absolute paths, ELF interpreters, RPATH/RUNPATH, plugins, icons, desktop files, D-Bus activation, service units, udev rules, kernel modules, and shared-library cache integration need explicit supported mechanisms. Do not claim general compatibility until each integration type has tests. During the prototype, install only into a temporary root; do not switch the host system.

## Transaction state machine

Suggested states:
- Created
- Planned
- Verified
- Staged
- Validated
- Activated
- Committed
- RolledBack
- FailedNeedsRecovery

All transitions are journaled and validated. Before staging, verify repository signatures, metadata freshness, artifact digest, package manifest, architecture, dependency closure, conflicts, path safety, and free space. Stage files away from the live system, validate ownership and integration declarations, and activate only after all checks pass. Interrupted activation must recover to either the previous committed generation or the new fully validated generation. Do not call the implementation atomic until crash and power-loss tests prove it.

Removal only deletes files owned by the package being removed and never deletes administrator or user data. Configuration migrations must be versioned, bounded, logged, and recoverable. Service actions must be allowlisted and separately defined; arbitrary package install scripts are not part of the native package contract.

## RPM and DEB compatibility

Advanced import mode is off by default. The first milestone is read-only inspection of package metadata and file manifests. The importer must never execute RPM scriptlets or DEB maintainer scripts while inspecting. Conversion must not pretend RPM and DEB semantics are interchangeable: dependency expressions, triggers, alternatives, ownership, conffiles, and maintainer scripts differ.

Later modes may:
- rebuild upstream source using a reviewed Deku recipe, preferred;
- import a payload only if its files, dependencies, ABI, license, and integration requirements fit a declared compatibility profile;
- run unsupported software in a separate container/VM or upstream-supported sandbox where appropriate.

Reject packages that require unsupported privileged scripts, overwrite protected system files, contain unsafe paths, or cannot express their dependencies faithfully. Do not promise that every RPM or DEB package can be converted into a working native package.

## Flatpak

Call the upstream Flatpak CLI/API and let Flatpak manage runtimes, remotes, app IDs, permissions, updates, and rollback semantics. Deku's UI may present native packages and Flatpak applications together, but must clearly identify source, permissions, and update owner. Flatpak does not replace host packages such as kernel modules, boot-critical services, drivers, or system libraries.

## Rust workspace boundaries

Proposed crates, split as implementation grows:
- deku-pkg-model: canonical package, version, file-manifest, and repository metadata types.
- deku-pkg-verify: signatures, digests, metadata freshness, and trust policy.
- deku-pkg-solver: pure deterministic dependency resolution and conflict reporting.
- deku-pkg-store: immutable payload store and garbage collection.
- deku-pkg-transaction: planning, journal state machine, staging, activation, rollback.
- deku-pkg-repo: repository client, snapshots, cache, and mirror selection.
- deku-pkg-cli: command-line UX and human-readable plans.
- deku-pkg-compat: read-only RPM/DEB inspectors behind the disabled-by-default advanced feature.
- deku-pkg-flatpak: optional integration layer that calls upstream Flatpak tools.

Use safe Rust by default. Any required unsafe code must be isolated, justified, and reviewed. Avoid a monolith; keep the solver pure and independently testable.

## Milestones and acceptance criteria

1. **Model:** schema validation, canonical serialization, malformed-input tests, path and symlink tests.
2. **Catalog:** signed test metadata, expiry, key rotation, tamper detection, stale/rollback rejection.
3. **Solver:** deterministic plans, cycles, conflicts, version constraints, architecture filtering, property/fuzz tests.
4. **Store:** content-addressed files, corruption detection, no mutation after verification, safe garbage collection.
5. **Transaction:** temporary-root install, collision handling, crash injection, rollback and recovery.
6. **Build integration:** verified source pins, isolated builds, provenance and artifact signatures.
7. **Compatibility:** read-only RPM/DEB inspection, then tightly scoped import tests; advanced mode remains off by default.
8. **Desktop:** Flatpak integration and KDE Discover experience only after CLI/store/transaction invariants are tested.

No ISO should depend on this manager until clean install, upgrade, interrupted transaction, rollback, package removal, kernel recovery, and VM boot tests pass.

## TUF integration prototype

The workspace now contains `crates/deku-pkg-trust`, which wraps the maintained `tough 0.24.0` TUF client. The wrapper keeps the package model/dependency solver separate from network and trust operations. It requires:
- an out-of-band trusted root metadata file;
- HTTPS-only metadata and target endpoints without credentials, query strings or fragments;
- an existing persistent non-symlink datastore so TUF can remember previously trusted timestamp/snapshot/targets metadata versions;
- TUF safe expiration enforcement (never silently bypassed in production);
- bounded root, timestamp, snapshot and targets metadata;
- verified target saving into an existing staging directory, separate from installation.

This does **not** make the package manager production-ready. The chosen `tough` version documents that delegated roles and TAP 4 multi-repository consensus are not yet supported. The wrapper currently operates on top-level targets only. Before this becomes a supported package repository client, add checked-in/local signed repository fixtures, end-to-end tests for signatures/expiry/rollback/rotation/tampering, explicit repository bootstrap/key-recovery procedures, and a reviewed Cargo dependency lockfile. No live-system install or update is implemented.
