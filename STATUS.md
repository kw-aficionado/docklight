# Status

This checkout began empty on 2026-10-31. The product identity is now **Docklight**, with an international container-port logo and neutral template terminology. The Go binary, CLI, service, module, and default paths retain `yggdrasil`; `/api/gameskills` and `gameskill_id` remain for data and API compatibility. Docker-backed acceptance criteria have not been exercised on a Debian or Ubuntu host.

## Phase 1 implementation

| Area | Implemented | Verification in this checkout |
| --- | --- | --- |
| CLI and configuration | `serve`, `version`, `gen-config`, `reset-password`, `reset-2fa`; generated session key and one-time admin password; config is not overwritten | Unit and local process smoke checks |
| SQLite | SQLite schema with numbered migrations; WAL mode; foreign keys; audit, users, grants, template definitions, servers, ports, and API tokens | Migration tests and panel API tests |
| Authentication | Argon2id passwords, expiring HS256 sessions, rate limits, TOTP with replay rejection, password changes, hashed scoped API tokens | Security and panel tests |
| Users and access | Admin/user roles; global, template, and server grants; API enforcement on listing, control, files, backups, console, and template creation | RBAC tests, including inaccessible-server checks |
| Templates | Bounded YAML subset parser and validator; five embedded templates; protected mount, capability, reserved variable, and setting validation | Parser and built-in template tests |
| Container lifecycle | Direct Docker Engine API client; install container, logs, start/readiness polling, stop, restart, deletion, port mappings, CPU/RAM limits, ownership repair | Compiles and has API/security tests; no Docker Engine was available for live lifecycle tests |
| Operations UI | Login, server list/detail, install status, console, file manager, encrypted backups, settings, templates, users, permissions, audit history, TOTP, password changes, and API token management | Browser smoke covered the Docklight login, server list, server detail, Backups tab, backup creation, and verification; browser console had no errors |
| File manager and protocols | Traversal/symlink protection; uploads and downloads; Minecraft Java/Bedrock status, A2S, and Source-compatible RCON | Unit tests; local TCP/UDP fixtures are opt-in because this sandbox denies local socket binds |
| Install and automation | `install.sh`, systemd unit, amd64/arm64 build CI, annotated-tag release workflow with SHA-256 sums | Shell syntax checked; installer was not run on a fresh Debian/Ubuntu VM; GitHub workflows have not run here |

## Phase 2 local backup slice

Implemented local encrypted backups with a server **Backups** tab and scoped `server.backup` permission. The stream is compressed and encrypted with authenticated AES-GCM chunks; files are checksummed and verified before registration. Restore verifies before staging, rejects symlinks and unsafe archive paths, then swaps the full data directory. The default retention is 10 per server, configurable from 1 to 100. Backups require a stopped server and use `auth.secret_key`; keep that key with the database and backup files. Server deletion removes its local backups.

The API test covers permission boundaries, cross-server denial, encryption at rest, creation, verification, restore, automatic/manual retention, corruption detection, and deletion. A loopback browser smoke created a temporary server, created and verified an encrypted backup, and found no console errors. A planted-fault check disabled the backup permission guard and the API test failed as expected, then passed after the guard was restored. The feature uses host-local storage only. SFTP, SMB, S3-compatible targets, scheduled backups, and backup notifications remain unimplemented.

The UI assets are embedded and have no CDN or frontend package dependency. It is a compact HTML/CSS/JavaScript app rather than the specified Svelte/Tailwind build. It has light and dark themes, but no offline service worker or complete installable PWA.

The template and config readers intentionally accept a bounded subset of YAML rather than general YAML 1.2. Unknown template fields are ignored, so stack/backup fields from other implementations do not create working behavior here. JWT signing and WebSocket framing are implemented locally because the corresponding requested dependencies were unavailable offline. These substitutions are recorded in [DECISIONS.md](DECISIONS.md).

## Not implemented

- Phase 2: remote SFTP/SMB/S3-compatible backups; scheduler; notifications; watchdog; crash history; low-disk alerts; realms; sidecar app stacks; Git template repositories; email resets; passkeys.
- Phase 3: UPnP, external reachability probes, Cloudflare route/DNS reconciliation, Nginx Proxy Manager integration, IP blocking, public status page, beacon, self-update, cross-server ban automation, and importers.
- Phase 4: Kvasir and MCP.
- Historical metrics, external identity providers, multi-host management, and offline PWA support.

The remaining areas have no active controls in the UI. The Cloudflare Tunnel template runs a tunnel container, but the panel does not manage DNS records or tunnel routes.

## Environment limits and remaining acceptance work

- Docker CLI and daemon are absent here. A Minecraft server install/start/ready/query/console/graceful-save cycle, Vaultwarden and Uptime Kuma browser access, and app-stack behavior remain unverified.
- This environment denies local TCP/UDP binds, so the network fixture tests are skipped by default. Set `YGGDRASIL_TEST_NETWORK=1` on a host that permits loopback binds to run them.
- `install.sh` syntax is checked but its package installation, systemd setup, and re-run preservation must be tested on a fresh Debian 12 or Ubuntu 24.04 VM.
- No release owner/repository is configured. The installer needs a source checkout, `YGG_BINARY_URL`, `YGG_BINARY_FILE`, or `YGG_REPO` until release artifacts are published.
- The Docklight UI and Backups tab were browser-smoke-tested at the default desktop viewport. Mobile breakpoints still need a separate browser pass.

Before calling Phase 1 accepted, run the Docker and installer acceptance steps from the user brief on a disposable Debian/Ubuntu host and verify the embedded UI in a browser.
