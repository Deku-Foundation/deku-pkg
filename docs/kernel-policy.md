# Kernel tracking policy

- **Status:** research baseline; not a shipping kernel or accepted platform decision.
- **Target architecture:** x86_64 for the first prototype.
- **Preferred update stream for evaluation:** upstream stable releases.
- **Candidate recorded on 2026-10-23:** Linux 7.2.12 stable.
- **Alternative to evaluate:** Linux 6.18.58 longterm (LTS).
- **Mainline reference only:** Linux 7.3. Do not promote mainline automatically to a release candidate.

## Upstream sources

- Official release index: https://www.kernel.org/
- Mainline source repository: https://github.com/torvalds/linux
- Stable release archive: https://cdn.kernel.org/pub/linux/kernel/v7.x/
- Longterm releases and lifecycle information: https://kernel.org/releases.html

Version numbers in `kernel/versions.json` are a dated research snapshot, not a promise that they remain current. Maintainers must refresh the snapshot from the official release index before creating a kernel package or release.

## Promotion gates

A version must not be advertised as supported until all applicable gates have evidence attached to a reviewed change:

1. Verify the release signature using the upstream signing-key process; a checksum alone is not authenticity.
2. Record the exact source URL, SHA-256 digest, signing-key fingerprint, source version, and retrieval date.
3. Build in an isolated, unprivileged worker with a recorded compiler, binutils, configuration, and build logs.
4. Run configuration checks and build tests for the target architecture.
5. Boot-test in a virtual machine, then test representative physical hardware before claiming hardware support.
6. Test initramfs generation, module installation, package upgrade, rollback/recovery, and security update handling.
7. Publish only after review; signing keys and publication credentials must never be available to untrusted pull-request jobs.

## Version selection

The newest mainline version is not automatically the best release kernel. Stable releases receive targeted fixes; longterm branches are maintained over a longer lifecycle. Choose between them using the project's support capacity, hardware test coverage, and update policy. Do not promise an end-of-life date without rechecking the upstream lifecycle page.

## Current limitations

This repository does not yet contain a tested kernel package recipe, a validated kernel configuration, a bootable image, or evidence of a successful kernel build. This policy and version snapshot are groundwork only.
