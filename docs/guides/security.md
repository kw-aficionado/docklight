# Access and security

## Accounts and two-factor authentication

The first administrator is created from `admin.username` and the generated bootstrap password. Change that password in the account menu after first sign-in. Passwords are stored as Argon2id hashes. The account menu supports TOTP enrollment, authenticator disable with password/code confirmation, and password changes; password changes and break-glass resets invalidate existing web sessions.

Login attempts are rate limited by client IP and username. A TOTP code is required at each login after enrollment, and the last accepted time counter is recorded to reject code replay.

Administrators can set a unique email address for each account in **Users & access**. Password recovery sends a one-hour, single-use link through the first enabled global SMTP email channel. The reset endpoint returns the same generic response whether a matching account is eligible or not, and forgot requests are rate limited by IP and identifier. Only a SHA-256 token hash is stored. Resetting a password increments the session version, clears other outstanding reset tokens, and preserves TOTP. Set `server.public_url` to the canonical HTTPS origin when Docklight is behind a reverse proxy; otherwise the request origin is used. The reset page removes the token from the address bar immediately and responses use `Referrer-Policy: no-referrer`.

## Roles, grants, and API tokens

Administrators can create users and grant permissions globally, per realm, per template, or per server. The API checks grants on list, control, file, backup, console, query, RCON, and server creation paths; realm and template grants also cover servers created later in that scope; hiding a button in the UI does not grant access. See [realms and access](realms.md) for the complete scope behavior.

An account can create opaque API tokens with explicit permission scopes. A token is shown only in the create response. The database stores a SHA-256 hash; the API never lists the token value. Token permissions are intersected with the account's current grants. Admin API tokens need the separate `admin` scope to use administrator endpoints. Revoke a token from the account menu or `DELETE /api/tokens/{id}`.

Use API tokens in the `Authorization: Bearer ygg_…` header. Tokens in URL query parameters are not accepted. WebSocket console/log connections use the same-origin session cookie.

## Stored secrets and audit

Template credentials are encrypted with AES-256-GCM using a key derived from `auth.secret_key`. The same config key also signs sessions. Server responses mask secret environment variables, and install/container log streams redact the stored plaintext values declared by the template. TOTP setup reveals a provisioning secret once so it can be added to an authenticator. API token creation similarly returns the new credential once.

Catalog repository tokens and the optional panel-wide GitHub token are also encrypted with `auth.secret_key` and never returned by the API. A saved repository token is used only for its configured repository; the panel-wide GitHub token is sent only to `api.github.com`. Non-GitHub catalog hosts require HTTPS, and catalog requests do not follow redirects.

Private registry passwords and access tokens are encrypted with `auth.secret_key` and exposed only as a `has_secret` flag. Docklight sends them to Docker Engine in the `X-Registry-Auth` header for a pull matched to that registry. A credential is not written to Docker's daemon login store, a host credential file, an image URL, or audit details. The **Test** action uses Docker Engine's auth-check endpoint and discards its response body. Registry saves and removals are audited as `registry_login.save` and `registry_login.delete`.

Notification channel configuration is encrypted with `auth.secret_key` and omitted from list, create, update, and test responses. Telegram requires its documented bot-token URL path; Docklight does not log HTTP request URLs and returns only a generic transport error if a request fails. SMTP uses TLS for remote hosts and does not send credentials before TLS is active.

The audit page records the user and server actions implemented in this release, including user/grant changes, token creation/revocation, server lifecycle, settings changes, and file changes. Audit records are not a substitute for host/systemd or Docker logs.

## IP blocking

The admin-only IP blocking page accepts one public IPv4 or IPv6 address per rule. Set **Protected addresses and ranges** to add IPs or CIDR ranges Docklight must never block, such as an office or VPN network. Existing rules for addresses newly added to this list must be removed first. Docklight also refuses private and reserved networks, published Cloudflare address ranges, CGNAT/Tailscale addresses, documentation and benchmarking ranges, and any address used by an administrator in the last 30 days. Administrator IP history is stored in the panel database and older entries are deleted during admin requests.

Cloudflare rules are created in the configured zone and include a Docklight ownership marker in their note. The reconciler verifies that marker and the saved address before deleting a rule; foreign rules are left alone. These rules affect web requests proxied through Cloudflare for the configured zone. Cloudflare's current guidance recommends custom rules for IP-based blocking; Docklight uses the IP Access Rules API here to provide individually owned, removable, expiring rules. See [Cloudflare's IP Access Rules guidance](https://developers.cloudflare.com/waf/tools/ip-access-rules/).

The optional host backend creates only `inet yggdrasil` and touches only the Docklight-marked input chain and sets inside it. It drops locally delivered TCP ports 80 and 443 for saved addresses. It does not block SSH, game ports, or unrelated nftables tables. Docker-published container traffic normally traverses the `forward` chain and is not blocked by this host-input backend. Enable `CAP_NET_ADMIN` for the service only if host blocking is needed. For the packaged systemd unit, create an override with `sudo systemctl edit yggdrasil` and add:

```ini
[Service]
AmbientCapabilities=CAP_NET_ADMIN
```

The packaged unit permits `AF_NETLINK` for the nftables command but does not grant `CAP_NET_ADMIN`. Then run `sudo systemctl daemon-reload` and `sudo systemctl restart yggdrasil`. Removing Docklight's last nftables IP block removes only its marked rules; Docklight leaves the empty table in place for safe reuse.

## Host boundary

The `yggdrasil` service account must access Docker's Unix socket, usually through the `docker` group. Anyone who can use that socket can effectively control the host. Keep it local; do not expose it over TCP. Restrict panel port 8080 to trusted networks and use TLS when access crosses an untrusted network.

The service uses an HttpOnly, SameSite=Strict session cookie, same-origin checks for browser mutations, security headers, and a Content Security Policy. The API does not enable cross-origin browser access. Docklight sends a disclosed daily beacon by default with only a random instance ID and build version. Administrators can turn it off at first sign-in or later in Beacon settings. The collector does not store source IP addresses; no panel analytics are shipped.

## Recovery

Run `yggdrasil reset-password USER --config /etc/yggdrasil/config.yaml` or `yggdrasil reset-2fa USER --config /etc/yggdrasil/config.yaml` as root. These commands print a one-time recovery password or clear TOTP enrollment, respectively. Keep `/etc/yggdrasil/config.yaml` and the SQLite data together in protected backups because losing `auth.secret_key` makes encrypted secrets unreadable.
