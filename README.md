# Deku Linux packages

This repository will hold Deku-owned package templates, patches, and metadata after the package/build format is agreed.

## Current status

Planning and bootstrap stage. No package set is currently supported and no package should be considered trusted or release-ready.

## Principles

- Track each upstream source URL, immutable version or commit, license, and local patch.
- Keep package builds isolated and avoid running untrusted build scripts with elevated privileges.
- Verify source integrity and separate integrity hashes from authenticity/signature verification.
- Add tests and review before packages enter any release channel.
- Preserve upstream copyright and license notices.
- Do not commit credentials, signing keys, generated binaries, or unreviewed source archives.

The package manifest prototype currently lives in [Deku-Foundation/project](https://github.com/Deku-Foundation/project/tree/main/prototype/package-manifest) while its contract is being reviewed.
