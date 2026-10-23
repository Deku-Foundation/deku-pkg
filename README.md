# Deku Package System

Deku's package system is a project to develop native package metadata, repository integrity, dependency planning, and safe transactions designed around Deku's requirements.

## Status

**Experimental plan-only prototype.** The current branch validates a local fixture catalog and computes a deterministic dependency order. It does not download, authenticate, build, install, update, or remove software. No production package catalog is available.

## Current prototype

- `deku_pkg/catalog.py` — strict local catalog validation.
- `deku_pkg/planner.py` — deterministic dependency-first planning with missing-dependency and cycle detection.
- `deku_pkg/cli.py` — plan-only command-line interface.
- `examples/catalog.json` — illustrative fixture catalog.
- `docs/prototype-v0.md` — scope, trust boundaries, and next gates.

Example:

```sh
PYTHONPATH=. python -m deku_pkg.cli --catalog examples/catalog.json --install hello-deku
```

The command only prints a plan. It does not perform installation.

## Design requirements

Signed/versioned repository metadata, source provenance, digest verification, dependency constraints, file ownership, transaction journaling, interruption recovery, privilege separation, license review, and rollback semantics must be designed and tested before any production use. SHA-256 alone does not authenticate a repository publisher.

The existing review-policy and upstream-register documents remain relevant to the longer-term project. This prototype is not a replacement for those review requirements.
