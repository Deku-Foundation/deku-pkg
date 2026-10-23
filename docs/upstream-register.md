# Upstream source register

This register records projects whose packaging or build practices Deku is evaluating. It does not imply that their code has been copied, forked, or adopted.

| Project | Canonical repository | Current purpose | Import status | Next action |
|---|---|---|---|---|
| Void packages | https://github.com/void-linux/void-packages | Study package templates, dependency declarations, update workflow, and maintainer review | Evaluation only | Inspect license and a small representative template before designing a Deku-owned format |
| XBPS | https://github.com/void-linux/xbps | Evaluate binary package manager, repository metadata, and package operations | Evaluation only | Compare requirements and maintenance cost before selecting a package backend |
| Nix | https://github.com/NixOS/nix | Study isolated/reproducible build concepts and content-addressed store design | Evaluation only | Prototype only the build properties Deku needs; do not assume Nix is the package manager choice |
| Nixpkgs | https://github.com/NixOS/nixpkgs | Study large-scale package maintenance, CI and contribution workflows | Evaluation only | Review selected workflows and licensing before any reuse |

## Import record required before any copy/fork

For each imported component, add its exact upstream URL, immutable commit/tag, applicable license and notices, import date, local patch list, upstream update owner, known security advisories, and planned update cadence. Keep this record next to the imported component or in a dedicated vendor manifest.
