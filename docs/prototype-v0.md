# Deku Package System — Prototype v0

**Status:** experimental design and plan-only code. This is not a production package manager.

## Scope

The prototype validates a local JSON catalog and computes a deterministic dependency installation order. It does not download artifacts, verify repository signatures, install files, modify the host, execute package hooks, or claim production security.

## Package record

Each record contains:
- unique package name and version string;
- explicit license expression;
- supported architecture list;
- dependency names;
- artifact filename, expected SHA-256 digest, and declared size.

The SHA-256 field is a content-integrity value only. Authenticity requires a trusted signed repository index and key policy, which are not implemented in this prototype.

## Planning behavior

- One candidate version per package name in the v0 fixture catalog.
- Requested package names are resolved through a deterministic depth-first traversal.
- Dependencies are emitted before dependants.
- Missing dependencies, duplicate package names, unsupported architecture, malformed digests, and dependency cycles fail closed.
- The plan includes package name, version, artifact digest, and size. No artifact is fetched.

## Deliberate non-goals

No SAT solver, semantic-version constraint language, repository signing, network client, privileged operations, file database, transaction engine, hooks, rollback, or real package catalog is included. Those require separate design decisions and tests.

## Next gates

1. Review the manifest contract and test malformed metadata.
2. Define repository metadata signatures, key rotation/revocation, and trust roots.
3. Evaluate version constraint and conflict semantics with real dependency fixtures.
4. Design file ownership, staged transactions, durable journals, and recovery.
5. Build a harmless package in a disposable VM before any host installation code exists.
