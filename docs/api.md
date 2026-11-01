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
| `PUT /api/settings/blocking` | Admin only; save `{ "enabled": true, "mode": "off", "nft_enabled": false, "allowlist": ["192.0.2.0/24"] }`. `allowlist` is a list of IP addresses or CIDR ranges Docklight refuses to block; it accepts up to 256 entries. Existing rules must be removed before their IP is added. Turning blocking off first removes Docklight-owned rules and preserves settings if safe cleanup fails. `mode` is reserved for Kvasir's future proposal/automatic workflow; this release supports manual blocks. |
| `GET /api/blocks` | Admin only; list Docklight-managed IP blocks and reconciliation state. |
| `POST /api/blocks` | Admin only; create one public IP rule with `{ "ip": "<public-ip>", "reason": "abuse report", "expires_in_hours": 24 }`. CIDR ranges are not accepted. Expiry may be 1–8760 hours or `0` for no expiry. |
| `DELETE /api/blocks/{id}` | Admin only; remove a saved rule after verifying Docklight ownership at the active backend. |

Blocking starts off. Cloudflare is selected when a configured zone is available and the token can create IP Access Rules for that zone; the required token permission is **Zone → Firewall Services → Edit**. Host nftables is used only when its fallback switch is on. Cloudflare rules affect proxied HTTP/S traffic for the configured zone. Host nftables drops inbound TCP 80 and 443 in the host `input` chain and requires `CAP_NET_ADMIN`; it does not block SSH or game ports. Docker-published container traffic normally traverses `forward` and is not intercepted by this host-input backend. Private, local, link-local, multicast, Cloudflare, CGNAT/Tailscale, documentation, benchmark, reserved, allowlisted, and recent administrator addresses are rejected. Recent administrator source addresses are kept in SQLite for 30 days. Reconciliation and expiry cleanup run at startup and once per minute.

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
| `PUT /api/notifications` | Save admin-only webhook settings and event filters for backups, container crashes, and host disk alerts. |
| `POST /api/notifications/test` | Send a signed test event to the configured webhook; admin only. |
| `POST /api/notifications` | Admin only; create a `discord`, `telegram`, `webhook`, or `email` channel with an optional `server_id` scope and a `config` object. |
| `PUT /api/notifications/{id}` | Admin only; replace a channel configuration and scope. Credentials must be re-entered because they are never returned. |
| `POST /api/notifications/{id}/test` | Admin only; send a test through the saved channel. |
| `DELETE /api/notifications/{id}` | Admin only; remove a saved channel. |
| `GET /api/system/disk` | Read current capacity and low-space alert state for the filesystem containing Docklight data; admin only. |

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
