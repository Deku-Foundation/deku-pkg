# Deku Package Manager: Native Store and Transaction Design

**Status:** Proposed design for review. This document does not describe a production-ready package manager.

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
