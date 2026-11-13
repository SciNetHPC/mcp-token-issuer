# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the release tag.

## [0.1.14] - 2026-11-13

First public release. The code is the service that runs in SciNet production,
with small changes for external deployments. The production image at the time
of publication is `0.1.13` and predates this release; build `0.1.14` from this
tree before deploying the changes below.

### Added

- `BALAM_GROUP_CN` configuration variable, so the POSIX group used for the
  Balam access rule is not hard-coded. The default remains `lcl_balam`.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE` (MIT), and this
  changelog.
- CI workflows for type-checking, tests, the bundle build, and secret
  scanning.

### Changed

- The process now refuses to start when the configured service list contains
  a cluster-gated entry and `LDAP_URL` is unset. Previously the gated services
  were silently hidden, which is indistinguishable from a permissions bug.
  Deployments without cluster gating are unaffected.
- The UI title and introduction are no longer branded with a site name or
  hostname, so another deployment does not inherit them. Both languages were
  updated.

### Fixed

- The admin-list test sets the required secrets itself, so the suite runs
  without a local `.env`.

### Removed

- Deployment manifests and the site-specific operations runbook. Those are
  maintained privately by SciNet; this repository contains service code only.

[0.1.14]: https://github.com/SciNetHPC/mcp-token-issuer/releases/tag/v0.1.14
