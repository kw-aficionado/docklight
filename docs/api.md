# HTTP API reference

The API is served from the same origin as the browser UI under `/api`. JSON errors use `{"error":"..."}`. The UI calls these server templates; the API retains `/gameskills` and `gameskill_id` for compatibility. Mutating requests from a browser must send a same-origin `Origin` header; cross-origin browser API access is not enabled. Most server/template endpoints require a session or API token.

The optional public status page is available without authentication only when an administrator enables it: `GET /status`, `GET /status.js`, and `GET /api/status`. The JSON response contains only opted-in server names, template names, online/starting/offline state, and a fresh player sample when available; it omits server IDs, ports, addresses, and settings. Responses are cached for 15 seconds.

## Authentication

`POST /api/login` accepts `{"username":"admin","password":"…","totp":"123456"}`. `totp` is needed after two-factor authentication is enabled. A successful login sets the HttpOnly `ygg_token` cookie and returns a session token and user summary. Passwords, hashes, and stored secret values are not included.

`POST /api/auth/forgot` accepts `{"identifier":"username-or-email"}` and always returns the same generic `200` message for unknown accounts, accounts without an email, or missing SMTP configuration. Enabled accounts with an email receive a one-hour reset link through the first enabled global SMTP email channel. `POST /api/auth/reset` accepts `{"token":"…","password":"…"}`; the token is single-use and its SHA-256 hash is stored. A successful reset revokes web sessions and records `user.password_reset` without changing TOTP enrollment.

For non-browser clients, send the returned session token as `Authorization: Bearer <session-token>`. Browser clients use the same-origin cookie. URL query-string tokens are not accepted.

API tokens are created at `POST /api/tokens`; send their value as `Authorization: Bearer ygg_…`. The create response is the only time the clear token is returned. `GET /api/tokens` returns name, scopes, creation time, and last-used time. `DELETE /api/tokens/{id}` revokes a token. Tokens cannot create or revoke other tokens.

Password and TOTP endpoints:

| Method and path | Purpose |
| --- | --- |
| `POST /api/password` | Change own password with `current_password` and `new_password`; revokes web sessions and clears the current cookie. |
| `POST /api/auth/forgot` | Public; request a password reset by username or email without disclosing whether the account exists. |
| `POST /api/auth/reset` | Public; consume a one-hour reset token and choose a new password. |
| `POST /api/logout` | Revoke current account web sessions and clear the cookie. |
| `GET /api/2fa/status` | Read whether TOTP is enabled. |
| `POST /api/2fa/setup` | Create a TOTP secret and provisioning URI before enrollment. |
| `POST /api/2fa/enable` | Confirm enrollment with `{"code":"123456"}`. |
| `POST /api/2fa/disable` | Disable TOTP with `{"password":"…","code":"123456"}`. |
| `GET /api/me` | Current user summary and visible server count. |

Passkey endpoints:

| Method and path | Purpose |
| --- | --- |
| `POST /api/auth/passkey/login/begin` | Public; begin a usernameless passkey sign-in. |
| `POST /api/auth/passkey/login/finish` | Public; verify `{ "session_id": "…", "credential": {…} }`, then issue the normal session cookie and token. |
| `GET /api/passkeys` | List the signed-in user's passkey names, added times, and last-used times. |
| `POST /api/passkeys/register/begin` | Start self-service registration with `{ "name": "MacBook Touch ID" }`. |
| `POST /api/passkeys/register/finish` | Verify `{ "session_id": "…", "credential": {…} }` and save the passkey. |
| `PUT /api/passkeys/{id}` | Rename one of the signed-in user's passkeys with `{ "name": "…" }`. |
| `DELETE /api/passkeys/{id}` | Remove one of the signed-in user's passkeys. |

Registration and sign-in require user verification and discoverable credentials. Each begin response contains WebAuthn `options` and an opaque `session_id`; the server keeps that ceremony state, accepts it once, and expires it after five minutes. Passkeys require HTTPS, with localhost allowed for local setup. The RP ID uses the request hostname and the origin scheme honors `X-Forwarded-Proto`; a reverse proxy should preserve `Host` and set that header. Credential state is encrypted at rest with the panel secret. A passkey sign-in also satisfies account recovery for users who have TOTP enabled.

## IP blocking

| Method and path | Purpose |
| --- | --- |
| `GET /api/settings/blocking` | Admin only; return the master switch, optional nftables fallback, host nftables visibility, and backend counts. |
| `PUT /api/settings/blocking` | Admin only; save `{ "enabled": true, "mode": "off", "nft_enabled": false, "allowlist": ["192.0.2.0/24"] }`. `allowlist` is a list of IP addresses or CIDR ranges Docklight refuses to block; it accepts up to 256 entries. Existing rules must be removed before their IP is added. Turning blocking off first removes Docklight-owned rules and preserves settings if safe cleanup fails. `mode` is reserved for future assistant proposal/automatic workflows; this release supports manual blocks. |
| `GET /api/blocks` | Admin only; list Docklight-managed IP blocks and reconciliation state. |
| `POST /api/blocks` | Admin only; create one public IP rule with `{ "ip": "<public-ip>", "reason": "abuse report", "expires_in_hours": 24 }`. CIDR ranges are not accepted. Expiry may be 1–8760 hours or `0` for no expiry. |
| `DELETE /api/blocks/{id}` | Admin only; remove a saved rule after verifying Docklight ownership at the active backend. |

Blocking starts off. Cloudflare is selected when a configured zone is available and the token can create IP Access Rules for that zone; the required token permission is **Zone → Firewall Services → Edit**. Host nftables is used only when its fallback switch is on. Cloudflare rules affect proxied HTTP/S traffic for the configured zone. Host nftables drops inbound TCP 80 and 443 in the host `input` chain and requires `CAP_NET_ADMIN`; it does not block SSH or game ports. Docker-published container traffic normally traverses `forward` and is not intercepted by this host-input backend. Private, local, link-local, multicast, Cloudflare, CGNAT/Tailscale, documentation, benchmark, reserved, allowlisted, and recent administrator addresses are rejected. Recent administrator source addresses are kept in SQLite for 30 days. Reconciliation and expiry cleanup run at startup and once per minute.

## Beacon

| Method and path | Purpose |
| --- | --- |
| `POST /api/beacon` | Public; receiver returns `404` unless enabled. Accepts exactly `{"instance_id":"<uuid>","version":"<build>"}` and stores no source IP address. |
| `GET /api/beacon/count` | Public; returns `404` unless both the receiver and public count are enabled. Returns `{ "count": null, "window_days": 30 }` below the configured minimum. Cached for 60 seconds. |
| `GET /api/settings/beacon` | Admin only; shows the sender/receiver settings, exact payload, last success and last failure. |
| `PUT /api/settings/beacon` | Admin only; save `enabled`, `url`, `receiver_enabled`, `public_count_enabled`, and `public_count_min` together. Blank URL restores `https://beacon.docklight.app/api/beacon`. Enabling after an explicit opt-out sends immediately. |
| `POST /api/settings/beacon/notice` | Admin only; accepts `{ "keep": true|false }` and acknowledges the first-login disclosure. `false` disables the sender. |
| `POST /api/settings/beacon/test` | Admin only; while the sender is on, send the exact payload to the URL currently in the request body without saving that URL or changing the scheduled-ping record. A disabled sender returns `409`; a collector `404` explains how to check the receiver path and switch. |
| `GET /api/beacon/stats` | Admin only; collector totals, 7/30-day activity, and versions received in the last 30 days. |

## Assistant provider

| Method and path | Purpose |
| --- | --- |
| `GET /api/ai/config` | Admin only; return whether the Assistant is enabled, provider, model, base URL, and whether an API key is configured. The key is never returned; only a fixed mask is shown. |
| `PUT /api/ai/config` | Admin only; save `{ "provider": "openai", "model": "…", "base_url": "…", "api_key": "…", "clear_api_key": false }`. Supported providers: Anthropic, OpenAI, OpenRouter, DeepSeek, Mistral, Ollama, and custom OpenAI-compatible. Blank `api_key` or the returned fixed mask keeps the saved key; `clear_api_key` removes it. Hosted-provider keys are encrypted with `auth.secret_key`. This does not enable the Assistant. |
| `POST /api/ai/config/test` | Admin only; send the saved model a single short connection prompt and discard its response. Does not include panel data and is not added to audit history. Redirects are not followed; provider error bodies are not returned. |
| `PUT /api/ai/enabled` | Admin only; explicitly enable or disable read-only Advisory with `{ "enabled": true }`. Enabling requires a valid provider, model, endpoint, and key when the provider requires one. |
| `GET /api/ai/status` | Authenticated users; return Advisory/Actions switches, the provider host and network classification, and the current chat data level. It does not return a provider key. |
| `PUT /api/ai/chat-scope` | Admin only; save `{ "data_level": 0|1|2 }`. Level 0 is server state and docs; level 1 adds 24-hour metrics, backup summaries, and scheduled outcomes; level 2 also permits explicitly searched redacted log lines. Per-server chat remains limited to its selected server. Panel-wide Advisory includes at most 100 servers visible to the caller. |
| `POST /api/ai/health-digest` | Admin only and requires Advisory enabled. Sends server names/status, host metrics, recent scheduled-failure metadata, and 24-hour per-server averages/peaks to the configured provider. It excludes configuration values, environment variables, secrets, and raw logs. Only successful runs are audited; prompts and replies are not stored. |
| `PUT /api/ai/digest-settings` | Admin only; save `{ "enabled": true, "hour": 8 }` for a host-local daily digest. It is delivered through enabled global notification destinations. |
| `PUT /api/ai/actions-enabled` | Admin only; enable or disable the separate, default-off Actions tier. Advisory must also remain enabled. |
| `POST /api/ai/plan` | Authenticated users; request at most five start/stop/restart proposals. Only servers the caller can control are eligible. The plan does not execute actions. |
| `POST /api/ai/plan/execute` | Authenticated users; execute one to five `{ "server_id": "…", "action": "restart", "proposal_id": "…" }` items returned by `/api/ai/plan`. Proposal IDs are one-use, bound to the operator/server/action, expire after ten minutes, and are invalidated if server state changes. Docklight rechecks the two switches, server permission, installation, and action allow-list. |
| `POST /api/servers/{id}/assistant/chat` | Requires `server.view` for that server. Accepts `{ "question": "…", "history": [], "log_query": "…" }`. Each request is scoped to that single server and relevant embedded docs. History is limited to ten messages and is not stored. `log_query` is optional and only available at level 2; Docklight filters up to 300 recent lines locally and sends at most 20 lines with known template secrets and common credential-shaped fields removed. Other private log content may remain. |
| `GET /api/ai/chat/ws` | Authenticated same-origin WebSocket for panel-wide Advisory. Send `{ "question":"…", "history":[], "log_server_id":"…", "log_query":"…", "confirm_external_logs":true, "confirm_external_host":"…" }`. History is limited to ten messages and is not stored. Each server is filtered by the caller's `server.view` permission before it reaches the provider; at most 100 visible servers are included. `log_server_id` and `log_query` must be supplied together; a log search is optional, available only at level 2, and limited to one visible server. Hosted-provider searches require current-host confirmation. Responses use `{ "type":"answer", "text":"…", "meta":{…} }` or `{ "type":"error", "error":"…" }`. |
| `POST /api/servers/{id}/explain` | Requires `server.view`; ask Advisory to explain a bounded redacted recent log excerpt. |
| `POST /api/servers/{id}/config-advice` | Requires `server.control`; review declared template settings. Secret values are replaced with local strength labels. |
| `POST /api/servers/{id}/watchers/suggest` | Admin only and requires `server.view`; return up to five validated watcher proposals without creating or enabling watchers. |
| `GET /api/watchers` | Admin only; list persistent log watcher rules. |
| `POST /api/watchers` | Admin only; create `{ "server_id":"", "name":"…", "pattern":"…", "threshold":1, "window_secs":60, "action":"notify", "enabled":true }`. Empty `server_id` targets all servers. Patterns use Go RE2; threshold is 1–1000 and the window is 1–3600 seconds. For an enabled `advisory` rule on a hosted provider, include `confirm_external_logs:true` and the displayed `confirm_external_host`; consent is bound to that exact provider host. |
| `PUT /api/watchers/{id}` | Admin only; replace a rule with the same fields as create. Template-seeded rules remain scoped to their server. A provider host change requires fresh external-log consent before Advisory will send a match. |
| `DELETE /api/watchers/{id}` | Admin only; remove a rule. Template-seeded defaults are restored the next time the server is installed. |
| `POST /api/servers/{id}/dayz/mods/suggest` | Requires a compatible DayZ `MODS` setting and `server.view`; suggest checks without changing the configured mod list. |
| `POST /api/admin-log/digest` | Admin only; summarize up to 200 structured audit fields, without audit detail text. |
| `PUT /api/ai/proactive-settings` | Admin only; save monitoring `level` (0–3) and selected `triggers` (`crash`, `slowstart`, `resource`, `host`, `anomalies`). Level 0 disables monitoring. Level 3 requires Advisory and Actions to be enabled before narrowly bounded crash-restart or OOM memory-limit fixes can run. |
| `GET /api/ai/proactive-events` | Signed-in users; return up to 50 undismissed observations limited to servers the user can view. Host-wide observations are admin-only. |
| `DELETE /api/ai/proactive-events/{id}` | Requires access to the observation's server; dismiss it from the active list. |

See [Assistant setup](guides/assistant.md) for provider URL, data handling, monitoring thresholds, and the exact scope of each feature.

## MCP connector and OAuth

| Method and path | Purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | Public RFC 8414 authorization-server metadata. |
| `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/api/mcp` | Public RFC 9728 resource metadata for the MCP endpoint. |
| `POST /oauth/register` | Public RFC 7591 registration for public clients. Send `client_name`, one or more exact `redirect_uris`, and optional supported `response_types`, `grant_types`, and `token_endpoint_auth_method: "none"`. Docklight does not issue client secrets. Registrations are rate limited to 10 per source IP per minute. HTTPS callbacks, loopback HTTP callbacks, and non-opaque app callbacks are accepted; non-loopback HTTP is rejected. |
| `GET /oauth/authorize` | Start an authorization-code request with `client_id`, exact `redirect_uri`, `response_type=code`, `scope=yggdrasil`, `resource=<panel-origin>/api/mcp`, and PKCE `code_challenge` plus `code_challenge_method=S256`. The signed-in user sees a consent page. The request nonce expires in 15 minutes and can be used once. |
| `POST /oauth/authorize` | Same-origin signed-in session required; allow or deny the one-use consent request. Authorization codes expire in 5 minutes and are usable once. |
| `POST /oauth/token` | Exchange `grant_type=authorization_code` with `client_id`, `code`, exact `redirect_uri`, `code_verifier`, and `resource`; or rotate a single-use `refresh_token` with `client_id` and `resource`. PKCE S256 is mandatory. Access tokens last 30 days; refresh tokens last 90 days and rotate on use. A detected refresh replay revokes that connection. |
| `POST /api/mcp` | Streamable HTTP JSON-RPC endpoint. Accepts OAuth connector tokens prefixed `ygg_mcp_` or scoped API tokens prefixed `ygg_`; an ordinary browser session does not grant MCP access. OAuth tokens are accepted only on this exact path. `GET` and `DELETE` return `405`. An unauthenticated request includes a `WWW-Authenticate` resource-metadata challenge. |
| `GET /api/mcp/info` | Signed-in user; return this instance's connector URL, tool count, and a heuristic public-reachability flag. Configure the panel's canonical HTTPS URL for a stable issuer. |
| `GET /api/mcp/connections` | Signed-in user; list that user's active OAuth connections. |
| `DELETE /api/mcp/connections/{id}` | Signed-in user; revoke only that user's connection, immediately invalidating its access and refresh tokens. |

OAuth connector tokens use the single `yggdrasil` scope and are bound to the configured resource URL. Only SHA-256 token hashes are stored. A connector acts as the approving account and follows its current Docklight server permissions. An API token also follows its account permissions and its own scope list. Available tools are `list_servers`, `get_server`, `server_logs` (100 lines by default, at most 500), `start_server`, `stop_server`, `restart_server`, and `panel_status`. Server names must resolve unambiguously. Logs redact configured server secrets but may contain player chat, IP addresses, or other private text. Stop and restart may disconnect players. No file, server-create, server-delete, or settings tools are exposed. Tool calls and control actions are audited as the acting user.

For remote or hosted MCP clients, the panel needs a publicly reachable HTTPS origin. The reachability field flags common LAN, `.lab`, and VPN-only hostnames, but does not make a live external connectivity test. See [MCP connector setup](guides/assistant.md#mcp-connector) for deployment and privacy details.

## Templates and servers

| Method and path | Purpose |
| --- | --- |
| `GET /api/health`, `GET /api/version` | Unauthenticated health and version summaries. |
| `GET /api/status` | Public summary for opted-in servers; returns `404` unless the public status page is enabled. |
| `GET /api/settings/status-page` | Admin only; read the master switch, title, and per-server public opt-ins. |
| `PUT /api/settings/status-page` | Admin only; save `enabled`, `title`, and `server_ids` together. The master switch and each server opt-in are both required for public display. |
| `GET /api/settings/network` | Any signed-in user; return the configured hostname, detected public IP, and effective host. Detection is cached for one hour and falls back to the last successful value if a lookup fails. |
| `PUT /api/settings/network` | Admin only; set or clear `public_hostname`. Scheme and trailing slash are stripped; hostnames containing a path or port and loopback addresses are rejected. |
| `GET /api/settings/unifi`, `PUT /api/settings/unifi` | Admin only; read or save the UniFi controller URL, local account, site (defaults to `default`), and master switch. Username and password are encrypted at rest; responses expose configuration flags only. Disabling or changing controller settings first clears known Docklight rules. |
| `POST /api/unifi/test` | Admin only; authenticate to the saved controller and read the site's port-forward rule count without changing rules. |
| `GET /api/unifi/rules`, `GET /api/unifi/strays` | Admin only; list controller rules and identify Docklight-prefixed rules targeting this host's LAN address whose server tag is missing or no longer matches a local server. |
| `POST /api/unifi/strays/delete` | Admin only; delete explicitly selected IDs only when the live rule is Docklight-prefixed, targets this host's LAN address, and does not match a local server. |
| `GET /api/settings/npm`, `PUT /api/settings/npm` | Admin only; read or save NPM URL, account email, encrypted password, base domain, optional internal host, matching Let's Encrypt contact email, and provider master switch. Saved proxy hosts are cleared before changing connection or routing settings. |
| `POST /api/npm/test` | Admin only; authenticate to NPM and read the proxy-host list without modifying it. |
| `GET /api/servers/{id}/npm` | Requires `server.view`; read the server hostname, saved proxy state, and cleanup status. |
| `PUT /api/servers/{id}/npm` | Requires `server.control`; save a bare subdomain, full hostname, or empty value to clear the server proxy host. This preference is independent of `auto_forward`. |
| `GET /api/settings/cloudflare`, `PUT /api/settings/cloudflare` | Admin only; read or save Tunnel settings. The PUT body accepts `enabled`, `api_token`, `account_id`, `tunnel_id`, `base_domain`, optional `zone_id`, `internal_host`, and `clear_token`. The token is encrypted and never returned; known routes are cleaned before connection or domain settings change. |
| `POST /api/cloudflare/test` | Admin only; read the saved tunnel configuration and resolve/cache the zone ID only when unset. Does not call Cloudflare's token verification endpoint. |
| `GET /api/domains/cloudflare` | Admin only; list hostname/service/path entries from the complete Tunnel ingress configuration, including manually created rules. |
| `GET /api/domains` | Signed-in users; list primary Cloudflare and NPM domains for servers they can view, with provisioning state and a guarded public HTTP probe cached for 30 seconds. |
| `GET /api/servers/{id}/cloudflare` | Requires `server.view`; read the selected hostname, route status, and cleanup status. |
| `PUT /api/servers/{id}/cloudflare` | Requires `server.control`; save `{ "hostname": "app" }`, a full hostname inside the configured base domain, or an empty hostname to remove the route. |
| `GET /api/servers/{id}/routes` | Requires `server.view`; list the primary Cloudflare/NPM hostnames and additional full hostnames, target TCP ports, per-provider state, and cleanup status. |
| `POST /api/servers/{id}/routes` | Admin only; add `{ "hostname": "play.example.com", "port_name": "web" }`. `port_name` is optional and selects the server's web port or first TCP port when empty. Running servers are provisioned immediately. |
| `DELETE /api/servers/{id}/routes/{routeID}` | Admin only; remove the recorded Cloudflare Tunnel and NPM objects before deleting the saved route. Failed cleanup leaves it marked for retry. |
| `GET /api/gameskills` | List templates visible to the caller. |
| `GET /api/gameskills/{id}` | Read one template; secret defaults are omitted. |
| `POST /api/gameskills` | Admin only; upload a YAML template (512 KiB maximum). Replacing a catalog template clears its source metadata. |
| `POST /api/gameskills/import-compose` | Admin only; import a Compose YAML file as a Docklight template. Accepts multipart field `file` (and optional `main` service and `name`) or a raw YAML body with `main` and `name` query parameters. Maximum 1 MiB. Returns `{id,name,warnings}`; built-in ID collisions return `409`. Bind mounts are omitted; administrators can re-add them under Settings → Host mounts after creating the server. Specific host-IP port bindings are omitted, so localhost-only ports are never widened. |
| `POST /api/gameskills/import-egg` | Admin only; import one Pterodactyl egg JSON file using multipart field `file` or a raw JSON body (maximum 1 MiB). Returns `{id,name,warnings}`; secret-looking defaults are removed, and built-in ID collisions return `409`. |
| `POST /api/gameskills/import-xml` | Admin only; import one supported `<gameskill>` XML file using multipart field `file` or a raw XML body (maximum 1 MiB). Returns `{id,name,warnings}`; secret-looking defaults are removed, and built-in ID collisions return `409`. |
| `GET /api/gameskills/github?repo=owner/name&path=...&ref=main` | Admin only; browse a GitHub repository. Lists YAML files up to 512 KiB and folders one level deep; successful listings are cached for 10 minutes. |
| `POST /api/gameskills/install-from-github` | Admin only; install or update a GitHub YAML file with `repo`, `path`, and optional `ref`. Built-in IDs return `409`. |
| `GET /api/gameskills/updates` | Admin only; compare installed non-built-in template versions with saved catalogs. It lists updates and source errors without applying changes. |
| `GET /api/rune-repos` | Admin only; list repositories without returning credentials. |
| `POST /api/rune-repos` | Admin only; save `{name,host,repo,path,ref,token}`. Empty `host` means GitHub; other hosts must be HTTPS base URLs. |
| `PUT /api/rune-repos/{id}` | Admin only; replace a repository. A masked token keeps the saved token; an empty token clears it. |
| `DELETE /api/rune-repos/{id}` | Admin only; remove a repository. Installed templates retain their source record so checks can report the source as gone. |
| `GET /api/rune-repos/{id}/browse?path=...` | Admin only; browse the configured repository, including at most one subfolder level. |
| `POST /api/rune-repos/{id}/install` | Admin only; install or update a YAML file by its returned `path`, with an optional `ref` override for applying an update from its recorded source branch. |
| `GET /api/settings/github` | Admin only; return whether the optional panel-wide GitHub token is configured. |
| `PUT /api/settings/github` | Admin only; save or clear the optional panel-wide GitHub token. The token is never returned. |
| `GET /api/registry-logins` | Admin only; list registry host, username, and `has_secret`; never returns a password or token. |
| `POST /api/registry-logins` | Admin only; save `{registry,username,secret}`. Registry names are normalized, and saving again replaces the login for that registry. |
| `POST /api/registry-logins/{id}/test` | Admin only; ask Docker Engine to verify a saved login without storing it in the daemon. |
| `DELETE /api/registry-logins/{id}` | Admin only; remove the encrypted registry login. |
| `DELETE /api/gameskills/{id}` | Admin only; custom template must be unused. |
| `GET /api/realms` | List realms visible through `server.view` or `server.create`; includes caller-specific `collapsed`, visible `server_count`, and `can_create`. |
| `POST /api/realms` | Admin only; create a realm with `name` and optional `description`. |
| `POST /api/realms/reorder` | Admin only; set the complete order with `{"ids":["…"]}`. |
| `PUT /api/realms/{id}` | Admin only; update `name` and `description`. |
| `DELETE /api/realms/{id}` | Admin only; detach its servers and remove realm grants, scoped schedules, and schedule history. Returns `409` while one of the realm's schedules is running. |
| `PUT /api/realms/{id}/collapsed` | Save the caller's `{"collapsed":true}` preference. |
| `GET /api/realms` | List realms visible through `server.view` or `server.create`; includes caller-specific `collapsed`, visible `server_count`, and `can_create`. |
| `POST /api/realms` | Admin only; create a realm with `name` and optional `description`. |
| `POST /api/realms/reorder` | Admin only; set the complete order with `{"ids":["…"]}`. |
| `PUT /api/realms/{id}` | Admin only; update `name` and `description`. |
| `DELETE /api/realms/{id}` | Admin only; detach its servers and remove realm grants, scoped schedules, and schedule history. Returns `409` while one of the realm's schedules is running. |
| `PUT /api/realms/{id}/collapsed` | Save the caller's `{"collapsed":true}` preference. |
| `GET /api/servers` | List only servers with `server.view`. Secret environment values are masked. |
| `POST /api/servers` | Create from a template. Body: `name`, `gameskill_id`, optional `realm_id`, `env`, `cpu_limit`, `memory_limit_mb`. Without `realm_id`, Docklight uses the template-category realm. |
| `GET /api/servers/{id}` | Read one server; requires `server.view`. |
| `GET /api/host/mounts` | Admin only; list safe host mount points visible to the panel. |
| `GET /api/host/browse?path=/mnt` | Admin only; browse safe host directories. Protected system and Docklight storage paths are filtered. |
| `GET /api/servers/{id}/host-mounts` | Admin only; read the server's host mounts and `applies_on` state. |
| `PUT /api/servers/{id}/host-mounts` | Admin only; replace mounts with `{"mounts":[{"source":"/mnt/media","target":"/media","service":"","write":false}]}`. Empty `service` selects the primary container; a stack service name selects that sidecar. Sources are canonicalized through symlinks, protected host and container paths are rejected, and mounts apply on the next start. |
| `PUT /api/servers/{id}/realm` | Admin only; move the server with `{"realm_id":"…"}` or detach it with an empty ID. |
| `PUT /api/servers/{id}/realm` | Admin only; move the server with `{"realm_id":"…"}` or detach it with an empty ID. |
| `PUT /api/servers/{id}` | Update name, settings, or resource limits; requires `server.control`. |
| `DELETE /api/servers/{id}` | Stop/remove the app and sidecars, private network, server data, local and recorded remote backups, ports, and grants; requires `server.delete`. |
| `POST /api/servers/{id}/install` | Start installation; returns `202` and a log URL. Requires `server.control`. |
| `GET /api/servers/{id}/install/status` | Poll install state and recent lines. Requires `server.view`. |
| `POST /api/servers/{id}/start`, `/stop`, `/restart` | Control lifecycle; requires `server.control`. |
| `GET /api/servers/{id}/stats` | Current Docker CPU and memory sample; requires `server.view`. |
| `GET /api/servers/{id}/metrics?hours=24` | Historical CPU, memory, and player samples; requires `server.view`. `hours` defaults to 24 and accepts 1–168. |
| `GET /api/fleet/metrics?hours=24` | Admin-only per-server averages and peaks over a 1–168 hour window. |
| `GET /api/system/metrics?hours=24` | Admin-only host CPU, memory, and Docklight data-filesystem history over a 1–168 hour window. |
| `GET /api/servers/{id}/query` | Player count for the template's protocol; requires `server.view`. Successful queries refresh the public status page's player sample. |
| `GET /api/servers/{id}/reachability` | Requires `server.view`; check a running or starting server's allocated game/query port at the effective public host. Results are cached for 30 seconds, and loopback targets are refused. |
| `POST /api/servers/{id}/rcon` | Send `{"command":"list"}`; requires `server.console`. |
| `GET /api/servers/{id}/backups` | List encrypted backups and their `storage` (`local`, `s3`, `sftp`, or `smb`) without exposing remote object keys; requires `server.backup`. |
| `POST /api/servers/{id}/backups` | Create a backup while the server is stopped; optional `destination` is `local`, `s3`, `sftp`, or `smb`. Verifies the saved copy before recording it; defaults to local. |
| `POST /api/servers/{id}/backups/prune` | Apply configured retention or a JSON `keep` count from 1 to 100. |
| `POST /api/servers/{id}/backups/{backupID}/verify` | Verify the checksum, encryption, and archive structure. |
| `POST /api/servers/{id}/backups/{backupID}/restore` | Restore after verifying; server must be stopped. |
| `DELETE /api/servers/{id}/backups/{backupID}` | Delete the local file or recorded S3, SFTP, or SMB object and its metadata. |
| `GET /api/backups/target/status` | Authenticated summary with `enabled`, `configured`, and the selected remote `type`. |
| `GET /api/backups/target` | Admin only; return the redacted remote target summary. S3 returns endpoint, bucket, and region; SFTP/SMB return host and port, and SMB also returns share. |
| `PUT /api/backups/target` | Admin only; configure `type` as `s3`, `sftp`, or `smb`, update the matching host or endpoint and credentials, enable/disable, or clear with `{"clear_target":true}`. Secret values are never returned. |
| `POST /api/backups/target/test` | Admin only; upload and delete a temporary object or file to check the configured remote destination. |
| `GET /api/message-templates` | List message templates; command bodies are returned only to administrators. |
| `POST /api/message-templates` | Admin only; create a one-line console-command template. |
| `PUT /api/message-templates/{id}` | Admin only; edit a custom message template. Built-ins are protected. |
| `DELETE /api/message-templates/{id}` | Admin only; delete a custom message template. |
| `GET /api/servers/{id}/schedules` | List per-server backup, start, stop, restart, update, console-command, and message schedules; requires `server.schedule`. |
| `GET /api/servers/{id}/schedule-options` | Return restart warning durations and whether the template supports player-count checks when the caller also has `server.control`; requires `server.schedule`. |
| `POST /api/servers/{id}/schedules` | Create an enabled backup, lifecycle, update, console-command, or message schedule from a five- or six-field cron expression. Requires `server.schedule` plus `server.backup`, `server.control`, or `server.console` for those actions; messages need only `server.schedule`. |
| `PUT /api/servers/{id}/schedules/{scheduleID}` | Change the name, cron expression, or enabled state. Changing cron or enabling a schedule also requires its action permission when that action has one. |
| `DELETE /api/servers/{id}/schedules/{scheduleID}` | Delete a schedule and its run history. |
| `GET /api/servers/{id}/schedules/{scheduleID}/runs` | Read the 50 most recent schedule runs. |
| `GET /api/schedules` | Admin only; list realm and global schedules. |
| `POST /api/schedules` | Admin only; create a schedule with `scope_type` set to `realm` or `global`. Realm schedules also require `scope_id`. The action fields match the per-server schedule API. |
| `PUT /api/schedules/{scheduleID}` | Admin only; change the name, cron expression, or enabled state of a realm or global schedule. |
| `DELETE /api/schedules/{scheduleID}` | Admin only; delete a realm or global schedule and its history. |
| `GET /api/schedules/{scheduleID}/runs` | Admin only; read the 50 most recent per-target run results for a realm or global schedule. |
| `POST /api/schedules/{scheduleID}/run-now` | Admin only; queue any schedule for one immediate run, even when it is disabled. A second request is rejected while it is queued or running. |
| `GET /api/servers/{id}/crashes` | Read the 50 most recent confirmed container exits or missing-container incidents; requires `server.view`. |
| `PUT /api/servers/{id}/watchdog` | Set `{"enabled":true}` or `false` for query-capable templates; requires `server.control`. |
| `GET /api/notifications` | Read admin-only legacy webhook state and masked summaries of saved channels; channel credentials and endpoints are never returned. |
| `PUT /api/notifications` | Save admin-only webhook settings and event filters, including `player.auto_moderation`. |
| `POST /api/notifications/test` | Send a signed test event to the configured webhook; admin only. |
| `POST /api/notifications` | Admin only; create a `discord`, `telegram`, `webhook`, or `email` channel with an optional `server_id` scope and a `config` object. |
| `PUT /api/notifications/{id}` | Admin only; replace a channel configuration and scope. Credentials must be re-entered because they are never returned. |
| `POST /api/notifications/{id}/test` | Admin only; send a test through the saved channel. |
| `DELETE /api/notifications/{id}` | Admin only; remove a saved channel. |
| `GET /api/system/disk` | Read current capacity and low-space alert state for the filesystem containing Docklight data; admin only. |
| `GET /api/bans` | Admin only; list current and revoked central bans with per-server delivery counts. |
| `POST /api/bans` | Admin only; create `{ "player_name": "Player", "player_id": "optional", "server_id": "", "reason": "reason", "expires_at": "optional RFC3339" }`. Empty `server_id` targets all current and future servers. Delivery is queued for templates that declare ban/unban commands or the DayZ ban-file adapter. |
| `DELETE /api/bans/{id}` | Admin only; revoke the central ban and queue unban commands on servers where Docklight applied it. |
| `GET /api/violations` | Admin only; list log violation rules. |
| `POST /api/violations` | Admin only; create a rule with `{ "name": "Spam", "pattern": "... (player) ...", "threshold": 3, "window_minutes": 10, "action": "kick", "scope_global": false, "enabled": true }`. The RE2 regular expression's first capture group must be the player name. |
| `PUT /api/violations/{id}` | Admin only; replace all fields on a violation rule. `action` is `kick` or `ban`; global scope applies bans to every server. |
| `DELETE /api/violations/{id}` | Admin only; remove a violation rule. |
| `GET /api/version` | Public; return the current build, configured GitHub release repository, latest stable `vX.Y.Z` tag, update availability, and whether the installed host can self-update. The latest-release lookup is cached for six hours. |
| `POST /api/system/check-update` | Admin only; refresh the GitHub release lookup immediately and return the version summary. |
| `POST /api/system/update` | Admin only; queue the newer stable release for the installed root systemd updater. Returns `202` after writing the one-shot request. |
| `GET /api/system/update-status` | Admin only; read the last updater state (`idle`, `running`, `done`, or `error`). |
| `GET /api/system/auto-update` | Admin only; read the opt-in flag, local hour, and last automatic queue date. |
| `PUT /api/system/auto-update` | Admin only; set `{ "enabled": true, "hour": 4 }`; `hour` must be 0–23 in the host's local time. |

Self-update requires a release build with its GitHub repository embedded, the standard `/var/lib/yggdrasil` data directory, and the installed `yggdrasil-update` helper plus systemd path and service units. The panel writes only a release tag into `.update-request`; a separate root oneshot downloads the matching architecture asset and `SHA256SUMS`, verifies the checksum and binary version, installs it, then restarts the panel. Automatic updates are disabled by default, check every 20 minutes, and queue at most one release per local day after the configured hour. Containers keep running. Source and custom-binary installs can remain manual if no release repository is configured.

Moderation rules and central bans are admin-only. See the [moderation guide](guides/moderation.md) for template support, command delivery, log matching, and current limits.

Create a backup with `{"action":"backup","name":"Nightly","cron":"0 3 * * *","enabled":true}`. The action defaults to `backup` for compatibility. Lifecycle actions use `"action":"start"` or `"action":"stop"`; a start requires an installed server. A start on an already running server and a stop with no container are recorded as skipped. An update uses `"action":"update"` and requires an installed server with no install or update already running. It stops the server, reruns its template installer against existing data when configured, pulls the current image, and starts a fresh container; the data directory is preserved. Update completion records that the start was initiated, while readiness monitoring continues in the background. A restart can include `"action":"restart"`, `"warn_players":true`, and `"warning_seconds":60`; the countdown must match a warning configured by the server template. Player warnings are enabled by default for restart schedules that support them. Templates with a player-query protocol may also set `"skip_if_players_online":true` on restart or update schedules; when the query reports one or more players, the run is skipped. If the query is unavailable, the action proceeds and its run detail records that the count could not be read. A console-command schedule uses `"action":"command"` with a single-line `"command"` value. It requires `server.console`, is stored encrypted, and is sent through RCON or server stdin when the server is running. A message schedule is available for Minecraft Java and Bedrock. It uses `"action":"message"`, a `"message_template_id"`, and numeric `"values"` for the placeholders in that template (for example `{"minutes":5}`). It needs `server.schedule` but no additional action permission. Five built-in templates are available; administrators can create, edit, and delete custom templates. Bodies are one Minecraft console command and may use `{{server_name}}`, `{{minutes}}`, and `{{seconds}}`. A schedule snapshots its selected template and values in encrypted storage, so later template edits do not change existing schedules. Messages are sent only while the server is running. Command and message contents are omitted from schedule and run-history responses. The enabled field may be omitted; new schedules are enabled by default. Five-field cron uses minute, hour, day of month, month, and weekday. Six-field cron adds seconds first. Times are interpreted in the panel host local timezone. A scheduled backup runs only when the server is stopped; otherwise the failed attempt is recorded and the next cron time remains scheduled. A warned restart runs in the background, sends configured countdown commands through RCON or stdin, then recreates the server. If the server is manually stopped or replaced during the countdown, the scheduled restart is canceled.

An administrator can create a realm schedule with `{"scope_type":"realm","scope_id":"REALM_ID","action":"restart","cron":"0 4 * * *"}` or a global schedule with `{"scope_type":"global","action":"update","cron":"0 5 * * 0"}`. Both use the same action options and encrypted fields as per-server schedules. Realm membership is resolved when the schedule fires; every current target gets an individual run-history row, and an empty scope gets a visible skipped run. Restart warning durations must be supported by every current target. Scoped updates wait for each server to return to running and stop dispatching after three consecutive update failures; player-online skips do not count toward that limit. For warned restarts running in the background, a cron occurrence due before completion is recorded as skipped and advanced to the next cron time. Schedule history retains 100 rows and the API lists the latest 50.

Server objects returned by list, get, create, and update include the caller's effective `permissions` array. For stack templates, they also include `stack_services`, an array of `{name,status,error_message?}` summaries. Sidecar status values are `created`, `running`, `stopped`, or `error`; error messages contain only Docker lifecycle state, not container output or environment values. The backups API requires `server.backup`; schedule management requires `server.schedule`, and backup, lifecycle/update, and console-command schedules additionally require `server.backup`, `server.control`, or `server.console`, respectively. Message-template management requires an administrator. API token permissions are intersected with the account's grants.

The legacy signed-webhook settings accept `enabled`, `endpoint`, `signing_secret`, `events`, `clear_endpoint`, and `clear_signing_secret`. New notification channels accept type-specific config: Discord `{url}`, Telegram `{bot_token,chat_id}`, JSON webhook `{url,signing_secret?}`, or email `{smtp_host,smtp_port?,smtp_username?,smtp_password?,from,to}`. SMTP defaults to port 587. Configs are encrypted at rest and never returned; list summaries include only channel type, scope, enabled state, and `has_config`. A channel with an empty `server_id` receives all server events; a scoped channel receives events for that server only. See [notifications](guides/notifications.md) for delivery and security details.

Example server creation:

```sh
curl -sS http://127.0.0.1:8080/api/servers \
  -H 'Authorization: Bearer SESSION_OR_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Survival","gameskill_id":"minecraft-java","env":{"EULA":"true","RCON_PASSWORD":"a-generated-password"},"cpu_limit":2,"memory_limit_mb":4096}'
```

`POST /api/tokens` accepts a name and a list of scopes from the permission catalog (`server.view`, `server.control`, `server.console`, `server.files`, `server.backup`, `server.schedule`, `server.create`, `server.delete`). Administrators may also select `admin`. A token's permissions never exceed its account grants.

## Files and live streams

| Method and path | Purpose |
| --- | --- |
| `GET /api/servers/{id}/files?path=…` | List a directory; requires `server.files`. |
| `GET /api/servers/{id}/files/content?path=…` | Read a file up to 5 MiB. |
| `PUT /api/servers/{id}/files/content` | JSON `{ "path": "server.properties", "content": "…" }`; writes up to 5 MiB. |
| `DELETE /api/servers/{id}/files/content?path=…` | Remove a file or empty directory. |
| `POST /api/servers/{id}/files/mkdir` | JSON `{ "path": "mods" }`. |
| `POST /api/servers/{id}/files/upload` | Multipart form fields `path` and `file`; maximum request size 64 MiB. |
| `GET /api/servers/{id}/files/download?path=…` | Download a file. |
| `GET /api/servers/{id}/dayz/economy` | Requires `server.view`; summarize the mission's vanilla and registered DayZ types files, cleanup lifetimes, and eligible unregistered XML files. Candidate scanning is bounded to 20,000 entries, 128 MiB read, and 256 candidates; `candidates_truncated` reports when a limit was reached. Available only when `gameskill_id` is `dayz`. |
| `GET /api/servers/{id}/dayz/mod-loot` | Requires `server.view`; scan valid DayZ types XML in top-level installed `@mod` folders, showing the source, derived mission target, imported state, fragment status, and Expansion marker. Scan caps are 20,000 entries, 128 MiB read, and 256 candidates. |
| `POST /api/servers/{id}/dayz/import-mod-types` | Requires `server.control`; accept `{ "source_paths": ["@123/Addons/types.xml"] }` for up to 64 selected files. The panel copies normalized types XML into a sanitized mission folder, registers each file with `cfgeconomycore.xml`, and saves source mappings for reinstall/update recovery. |
| `GET /api/servers/{id}/dayz/mods` | Requires `server.view`; return the compatible Rune's `MODS` list, local `@mod` folders, and one batched public Workshop status lookup. |
| `PUT /api/servers/{id}/dayz/mods/order` | Requires `server.control`; accept `{ "mods": ["@123", "@456"] }` only when it is a permutation of the current list. |
| `POST /api/servers/{id}/dayz/mods/add` | Requires `server.control`; accept `{ "ids": ["123"] }` to append Workshop items to `MODS`. |
| `POST /api/servers/{id}/dayz/mods/remove` | Requires `server.control`; accept `{ "token": "@123" }` to remove one entry from `MODS` without deleting its folder. |
| `POST /api/servers/{id}/dayz/mods/add-orphans` | Requires `server.control`; accept `{ "tokens": ["@123"] }` for existing unlisted folders. |
| `POST /api/servers/{id}/dayz/mods/remove-broken` | Requires `server.control`; remove items confirmed removed from Workshop. Unknown status and missing folders are retained because they may be pending the next update. |
| `GET /api/servers/{id}/dayz/mods/search?q=…` | Requires `server.view`; search DayZ Workshop with the saved key. Returns `{ "needs_key": true }` when no key is configured. |
| `GET /api/settings/dayz/steam-key` | Admin only; returns whether an encrypted key is saved. |
| `PUT /api/settings/dayz/steam-key` | Admin only; save `{ "key": "…" }` or clear with an empty key. The key is never returned. |
| `PUT /api/servers/{id}/dayz/min-lifetime` | Requires `server.control`; accept `{"hours":24}` from 0–8760. Raises only positive type lifetimes below the floor; 0 disables future floor applications but does not undo prior edits. |
| `PUT /api/servers/{id}/dayz/globals` | Requires `server.control`; accept `{"values":{"CleanupLifetimeDefault":86400}}` for allowlisted cleanup globals, in seconds. |
| `POST /api/servers/{id}/dayz/register-types` | Requires `server.control`; accept `{"paths":["MyMod/types.xml"]}` for validated types files under mission subfolders. |
| `POST /api/servers/{id}/dayz/reset` | Requires `server.control`; clear saved reapply settings. Existing mission XML changes remain in place. |
| `GET /api/servers/{id}/logs` | WebSocket with container log output; requires `server.view`. |
| `GET /api/servers/{id}/stack-services/{service}/logs` | WebSocket with up to 2,000 recent lines and live private-service output; requires `server.view`. Template secret values are redacted. |
| `POST /api/servers/{id}/stack-services/{service}/exec` | Run a one-line command in a private service; requires `server.console`. Waits up to 30 seconds and returns at most 64 KiB of redacted output. A timed-out command may continue in its container. |
| `GET /api/servers/{id}/console` | WebSocket for log output and console commands; requires `server.console`. Send `{"type":"command","command":"list"}`. |
| `GET /api/servers/{id}/install/log` | WebSocket for install output; requires `server.view`. |

WebSocket connections are authenticated with the same-origin session cookie. The server sends keepalive pings every 30 seconds. Reverse proxies must pass WebSocket upgrades through.

## Users, grants, and audit

Administrator endpoints are `GET/POST /api/users`, `PUT/DELETE /api/users/{id}`, `GET/PUT /api/users/{id}/permissions`, and `GET /api/permissions/catalog` (authenticated permission metadata). User create and update accept an optional unique `email` for password recovery. User profile changes invalidate that user's sessions; permission updates take effect on the next request without ending the session. `GET /api/audit` returns the most recent 200 audit records and is administrator-only. Grants combine with OR logic across `global`, `realm`, `gameskill`, and `server` scopes. Editing permissions replaces the complete grant set. Realm grants apply to servers currently in that realm and future servers created there.

## Limits

There is no pagination for server or user lists. Audit history returns at most 200 rows. Login attempts are rate limited. File editor and upload limits are documented above. Scheduler actions beyond backup/start/stop/restart/update/command/message and Cloudflare route/DNS management are not implemented yet. See [server backups](guides/backups.md) for schedules and local/remote backup behavior, [app stacks](guides/stacks.md) for private sidecars, [networking](guides/networking.md) for public host detection, reachability probes, UPnP, UniFi, and NPM, [notifications](guides/notifications.md) for delivery transports, [monitoring](guides/monitoring.md) for runtime monitoring and automatic recovery, and [the status-page guide](guides/status-page.md) for public exposure and freshness rules. See [realms and access](guides/realms.md) for server grouping and scoped grants.
