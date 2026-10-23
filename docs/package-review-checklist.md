# Package review checklist

Use this checklist for each new package or significant update. Record exceptions in the pull request rather than silently skipping checks.

- [ ] Canonical upstream URL and exact version/commit recorded.
- [ ] License and required notices checked for source and bundled components.
- [ ] Source archive or checkout verified; SHA-256 digest independently checked.
- [ ] Build-time and runtime dependencies documented.
- [ ] Patch set reviewed; rationale and upstreaming status recorded.
- [ ] Build tested in an isolated, unprivileged environment where feasible.
- [ ] Build/install scripts inspected for network access, privilege escalation, and destructive operations.
- [ ] Tests and smoke checks recorded.
- [ ] Security support status and update owner identified.
- [ ] No credentials, private keys, generated binaries, or unreviewed archives committed.
- [ ] Rebuild and rollback implications considered.

Passing this checklist is evidence of review, not a guarantee that a package is safe.
