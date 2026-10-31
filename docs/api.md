# HTTP API reference

The API is served from the same origin as the browser UI under `/api`. JSON errors use `{"error":"..."}`. The UI calls these server templates; the API retains `/gameskills` and `gameskill_id` for compatibility. Mutating requests from a browser must send a same-origin `Origin` header; cross-origin browser API access is not enabled. Most server/template endpoints require a session or API token.

## Authentication

`POST /api/login` accepts `{"username":"admin","password":"…","totp":"123456"}`. `totp` is needed after two-factor authentication is enabled. A successful login sets the HttpOnly `ygg_token` cookie and returns a session token and user summary. Passwords, hashes, and stored secret values are not included.

For non-browser clients, send the returned session token as `Authorization: Bearer <session-token>`. Browser clients use the same-origin cookie. URL query-string tokens are not accepted.

API tokens are created at `POST /api/tokens`; send their value as `Authorization: Bearer ygg_…`. The create response is the only time the clear token is returned. `GET /api/tokens` returns name, scopes, creation time, and last-used time. `DELETE /api/tokens/{id}` revokes a token. Tokens cannot create or revoke other tokens.

Password and TOTP endpoints:

| Method and path | Purpose |
| --- | --- |
| `POST /api/password` | Change own password with `current_password` and `new_password`; revokes web sessions and clears the current cookie. |
| `POST /api/logout` | Revoke current account web sessions and clear the cookie. |
| `GET /api/2fa/status` | Read whether TOTP is enabled. |
| `POST /api/2fa/setup` | Create a TOTP secret and provisioning URI before enrollment. |
| `POST /api/2fa/enable` | Confirm enrollment with `{"code":"123456"}`. |
| `POST /api/2fa/disable` | Disable TOTP with `{"password":"…","code":"123456"}`. |
| `GET /api/me` | Current user summary and visible server count. |

## Templates and servers

| Method and path | Purpose |
| --- | --- |
| `GET /api/health`, `GET /api/version` | Unauthenticated health and version summaries. |
| `GET /api/gameskills` | List templates visible to the caller. |
| `GET /api/gameskills/{id}` | Read one template; secret defaults are omitted. |
| `POST /api/gameskills` | Admin only; upload a YAML template (512 KiB maximum). |
| `DELETE /api/gameskills/{id}` | Admin only; custom template must be unused. |
| `GET /api/servers` | List only servers with `server.view`. Secret environment values are masked. |
| `POST /api/servers` | Create from a template. Body: `name`, `gameskill_id`, optional `env`, `cpu_limit`, `memory_limit_mb`. |
| `GET /api/servers/{id}` | Read one server; requires `server.view`. |
| `PUT /api/servers/{id}` | Update name, settings, or resource limits; requires `server.control`. |
| `DELETE /api/servers/{id}` | Stop/remove the container, server data, local backups, ports, and grants; requires `server.delete`. |
| `POST /api/servers/{id}/install` | Start installation; returns `202` and a log URL. Requires `server.control`. |
| `GET /api/servers/{id}/install/status` | Poll install state and recent lines. Requires `server.view`. |
| `POST /api/servers/{id}/start`, `/stop`, `/restart` | Control lifecycle; requires `server.control`. |
| `GET /api/servers/{id}/stats` | Current Docker CPU and memory sample; requires `server.view`. |
| `GET /api/servers/{id}/query` | Player count for the template's protocol; requires `server.view`. |
| `POST /api/servers/{id}/rcon` | Send `{"command":"list"}`; requires `server.console`. |
| `GET /api/servers/{id}/backups` | List encrypted local backups; requires `server.backup`. |
| `POST /api/servers/{id}/backups` | Create a backup while the server is stopped; verifies it before saving. |
| `POST /api/servers/{id}/backups/prune` | Apply configured retention or a JSON `keep` count from 1 to 100. |
| `POST /api/servers/{id}/backups/{backupID}/verify` | Verify the checksum, encryption, and archive structure. |
| `POST /api/servers/{id}/backups/{backupID}/restore` | Restore after verifying; server must be stopped. |
| `DELETE /api/servers/{id}/backups/{backupID}` | Delete a local backup. |
| `GET /api/servers/{id}/schedules` | List per-server backup schedules; requires `server.schedule`. |
| `POST /api/servers/{id}/schedules` | Create an enabled backup schedule from a five- or six-field cron expression; requires `server.schedule` and `server.backup`. |
| `PUT /api/servers/{id}/schedules/{scheduleID}` | Change the name, cron expression, or enabled state. |
| `DELETE /api/servers/{id}/schedules/{scheduleID}` | Delete a schedule and its run history. |
| `GET /api/servers/{id}/schedules/{scheduleID}/runs` | Read the 50 most recent schedule runs. |
| `GET /api/servers/{id}/crashes` | Read the 50 most recent confirmed container exits or missing-container incidents; requires `server.view`. |
| `PUT /api/servers/{id}/watchdog` | Set `{"enabled":true}` or `false` for query-capable templates; requires `server.control`. |
| `GET /api/notifications` | Read admin-only webhook notification state; secrets and endpoint are never returned. |
| `PUT /api/notifications` | Save admin-only webhook settings and event filters for backups, container crashes, and host disk alerts. |
| `POST /api/notifications/test` | Send a signed test event to the configured webhook; admin only. |
| `GET /api/system/disk` | Read current capacity and low-space alert state for the filesystem containing Docklight data; admin only. |

Create a schedule with `{"name":"Nightly","cron":"0 3 * * *","enabled":true}`. The enabled field may be omitted; new schedules are enabled by default. Five-field cron uses minute, hour, day of month, month, and weekday. Six-field cron adds seconds first. Times are interpreted in the panel host local timezone. A scheduled backup runs only when the server is stopped; otherwise the failed attempt is recorded and the next cron time remains scheduled.

Server objects returned by list, get, create, and update include the caller's effective `permissions` array. The backups API requires `server.backup`; schedule management requires `server.schedule`, and creating a backup schedule also requires `server.backup`. API token permissions are intersected with the account's grants.

Webhook notification settings accept `enabled`, `endpoint`, `signing_secret`, `events`, `clear_endpoint`, and `clear_signing_secret`. Supported events are `backup.success`, `backup.failure`, `server.crash`, `server.watchdog`, and `host.disk_low`. Blank endpoint or signing secret fields preserve the saved value; use the `clear_*` flags to remove them. Endpoint and signing secret are encrypted at rest and omitted from every response. See [notifications](guides/notifications.md) for delivery and signature details.

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
| `GET /api/servers/{id}/console` | WebSocket for log output and console commands; requires `server.console`. Send `{"type":"command","command":"list"}`. |
| `GET /api/servers/{id}/install/log` | WebSocket for install output; requires `server.view`. |

WebSocket connections are authenticated with the same-origin session cookie. The server sends keepalive pings every 30 seconds. Reverse proxies must pass WebSocket upgrades through.

## Users, grants, and audit

Administrator endpoints are `GET/POST /api/users`, `PUT/DELETE /api/users/{id}`, `GET/PUT /api/users/{id}/permissions`, and `GET /api/permissions/catalog` (authenticated permission metadata). User profile changes invalidate that user's sessions; permission updates take effect on the next request without ending the session. `GET /api/audit` returns the most recent 200 audit records and is administrator-only.

## Limits

There is no pagination for server or user lists. Audit history returns at most 200 rows. Login attempts are rate limited. File editor and upload limits are documented above. Remote backup targets, schedule actions beyond backup, realm/global schedules, Discord, Telegram, SMTP, sidecars, and external integrations are not implemented yet. See [server backups](guides/backups.md) for local backup behavior and [monitoring](guides/monitoring.md) for runtime monitoring and automatic recovery.
