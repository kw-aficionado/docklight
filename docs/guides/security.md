# Access and security

## Accounts and two-factor authentication

The first administrator is created from `admin.username` and the generated bootstrap password. Change that password in the account menu after first sign-in. Passwords are stored as Argon2id hashes. The account menu supports TOTP enrollment, authenticator disable with password/code confirmation, and password changes; password changes and break-glass resets invalidate existing web sessions.

Login attempts are rate limited by client IP and username. A TOTP code is required at each login after enrollment, and the last accepted time counter is recorded to reject code replay.

## Roles, grants, and API tokens

Administrators can create users and grant permissions globally, per template, or per server. The API checks grants on list, control, file, backup, console, query, RCON, and server creation paths; hiding a button in the UI does not grant access.

An account can create opaque API tokens with explicit permission scopes. A token is shown only in the create response. The database stores a SHA-256 hash; the API never lists the token value. Token permissions are intersected with the account's current grants. Admin API tokens need the separate `admin` scope to use administrator endpoints. Revoke a token from the account menu or `DELETE /api/tokens/{id}`.

Use API tokens in the `Authorization: Bearer ygg_…` header. Tokens in URL query parameters are not accepted. WebSocket console/log connections use the same-origin session cookie.

## Stored secrets and audit

Template credentials are encrypted with AES-256-GCM using a key derived from `auth.secret_key`. The same config key also signs sessions. Server responses mask secret environment variables, and install/container log streams redact the stored plaintext values declared by the template. TOTP setup reveals a provisioning secret once so it can be added to an authenticator. API token creation similarly returns the new credential once.

The audit page records the user and server actions implemented in this release, including user/grant changes, token creation/revocation, server lifecycle, settings changes, and file changes. Audit records are not a substitute for host/systemd or Docker logs.

## Host boundary

The `yggdrasil` service account must access Docker's Unix socket, usually through the `docker` group. Anyone who can use that socket can effectively control the host. Keep it local; do not expose it over TCP. Restrict panel port 8080 to trusted networks and use TLS when access crosses an untrusted network.

The service uses an HttpOnly, SameSite=Strict session cookie, same-origin checks for browser mutations, security headers, and a Content Security Policy. The API does not enable cross-origin browser access. Docklight sends no telemetry or beacon in this release.

## Recovery

Run `yggdrasil reset-password USER --config /etc/yggdrasil/config.yaml` or `yggdrasil reset-2fa USER --config /etc/yggdrasil/config.yaml` as root. These commands print a one-time recovery password or clear TOTP enrollment, respectively. Keep `/etc/yggdrasil/config.yaml` and the SQLite data together in protected backups because losing `auth.secret_key` makes encrypted secrets unreadable.
