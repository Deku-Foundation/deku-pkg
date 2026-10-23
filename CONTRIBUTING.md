# Contributing packages to Deku Linux

This repository is not yet a production package repository. Contributions should improve traceability and testability before package volume grows.

## Before adding a package

- Identify the canonical upstream project and exact release or immutable commit.
- Read the upstream license and preserve all required notices. Check vendored files and bundled subcomponents individually.
- Confirm the source URL uses HTTPS where available and record a verified SHA-256 digest. A digest checks bytes; it does not establish who published them.
- Document build-time and runtime dependencies separately.
- Describe patches and why each is needed. Prefer upstreamable patches and avoid carrying cosmetic diffs.
- Identify whether the package runs code during build or installation, and what privileges it needs.
- Include basic test and verification steps.

## Branch workflow

- Use `dev` for integration and validation; use `main` as the reviewed baseline.
- Run the Rust formatting, Clippy, tests, and package-planner validation on `dev`.
- Open a pull request from `dev` to `main` only after checks pass.
- Keep long-lived branches to `main` and `dev`; use a fork for independent contributor work when needed.

The foundation-wide policy is documented in [CONTRIBUTING.md](https://github.com/Deku-Foundation/Deku-Foundation.github.io/blob/main/CONTRIBUTING.md) and [ENGINEERING_WORKFLOW.md](https://github.com/Deku-Foundation/Deku-Foundation.github.io/blob/main/ENGINEERING_WORKFLOW.md).

## Review requirements

A package change should include enough metadata for another maintainer to reproduce the review. Do not accept a package merely because it builds on one developer's machine.

Reviewers should check licensing, source integrity, patch scope, dependency closure, build isolation, update ownership, and security support status.

## Release boundary

No package is release-ready until the project has a documented build environment, repository metadata/signing design, update policy, and recovery procedure. Do not publish artifacts from an unreviewed pull request.
