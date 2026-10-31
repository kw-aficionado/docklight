# HTTP API reference

The API is served from the same origin as the browser UI under `/api`. JSON errors use `{"error":"..."}`. The UI calls these server templates; the API retains `/gameskills` and `gameskill_id` for compatibility. Mutating requests from a browser must send a same-origin `Origin` header; cross-origin browser API access is not enabled. Most server/template endpoints require a session or API token.

The optional public status page is available without authentication only when an administrator enables it: `GET /status`, `GET /status.js`, and `GET /api/status`. The JSON response contains only opted-in server names, template names, online/starting/offline state, and a fresh player sample when available; it omits server IDs, ports, addresses, and settings. Responses are cached for 15 seconds.

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
| `GET /api/status` | Public summary for opted-in servers; returns `404` unless the public status page is enabled. |
| `GET /api/settings/status-page` | Admin only; read the master switch, title, and per-server public opt-ins. |
| `PUT /api/settings/status-page` | Admin only; save `enabled`, `title`, and `server_ids` together. The master switch and each server opt-in are both required for public display. |
| `GET /api/gameskills` | List templates visible to the caller. |
| `GET /api/gameskills/{id}` | Read one template; secret defaults are omitted. |
| `POST /api/gameskills` | Admin only; upload a YAML template (512 KiB maximum). Replacing a catalog template clears its source metadata. |
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
| `DELETE /api/realms/{id}` | Admin only; detach its servers and remove realm grants. |
| `PUT /api/realms/{id}/collapsed` | Save the caller's `{"collapsed":true}` preference. |
| `GET /api/realms` | List realms visible through `server.view` or `server.create`; includes caller-specific `collapsed`, visible `server_count`, and `can_create`. |
| `POST /api/realms` | Admin only; create a realm with `name` and optional `description`. |
| `POST /api/realms/reorder` | Admin only; set the complete order with `{"ids":["…"]}`. |
| `PUT /api/realms/{id}` | Admin only; update `name` and `description`. |
| `DELETE /api/realms/{id}` | Admin only; detach its servers and remove realm grants. |
| `PUT /api/realms/{id}/collapsed` | Save the caller's `{"collapsed":true}` preference. |
| `GET /api/servers` | List only servers with `server.view`. Secret environment values are masked. |
| `POST /api/servers` | Create from a template. Body: `name`, `gameskill_id`, optional `realm_id`, `env`, `cpu_limit`, `memory_limit_mb`. Without `realm_id`, Docklight uses the template-category realm. |
| `GET /api/servers/{id}` | Read one server; requires `server.view`. |
| `PUT /api/servers/{id}/realm` | Admin only; move the server with `{"realm_id":"…"}` or detach it with an empty ID. |
| `PUT /api/servers/{id}/realm` | Admin only; move the server with `{"realm_id":"…"}` or detach it with an empty ID. |
| `PUT /api/servers/{id}` | Update name, settings, or resource limits; requires `server.control`. |
| `DELETE /api/servers/{id}` | Stop/remove the app and sidecars, private network, server data, local and recorded remote backups, ports, and grants; requires `server.delete`. |
| `POST /api/servers/{id}/install` | Start installation; returns `202` and a log URL. Requires `server.control`. |
| `GET /api/servers/{id}/install/status` | Poll install state and recent lines. Requires `server.view`. |
| `POST /api/servers/{id}/start`, `/stop`, `/restart` | Control lifecycle; requires `server.control`. |
| `GET /api/servers/{id}/stats` | Current Docker CPU and memory sample; requires `server.view`. |
| `GET /api/servers/{id}/query` | Player count for the template's protocol; requires `server.view`. Successful queries refresh the public status page's player sample. |
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
| `GET /api/servers/{id}/schedules` | List per-server backup, start, stop, restart, console-command, and message schedules; requires `server.schedule`. |
| `GET /api/servers/{id}/schedule-options` | Return restart warning durations and whether the template supports player-count checks when the caller also has `server.control`; requires `server.schedule`. |
| `POST /api/servers/{id}/schedules` | Create an enabled backup, lifecycle, console-command, or message schedule from a five- or six-field cron expression. Requires `server.schedule` plus `server.backup`, `server.control`, or `server.console` for those actions; messages need only `server.schedule`. |
| `PUT /api/servers/{id}/schedules/{scheduleID}` | Change the name, cron expression, or enabled state. Changing cron or enabling a schedule also requires its action permission when that action has one. |
| `DELETE /api/servers/{id}/schedules/{scheduleID}` | Delete a schedule and its run history. |
| `GET /api/servers/{id}/schedules/{scheduleID}/runs` | Read the 50 most recent schedule runs. |
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

Create a backup with `{"action":"backup","name":"Nightly","cron":"0 3 * * *","enabled":true}`. The action defaults to `backup` for compatibility. Lifecycle actions use `"action":"start"` or `"action":"stop"`; a start requires an installed server. A start on an already running server and a stop with no container are recorded as skipped. A restart can include `"action":"restart"`, `"warn_players":true`, and `"warning_seconds":60`; the countdown must match a warning configured by the server template. Player warnings are enabled by default for restart schedules that support them. Templates with a player-query protocol may also set `"skip_if_players_online":true`; when the query reports one or more players, the run is skipped. If the query is unavailable, the restart proceeds and its run detail records that the count could not be read. This option is valid only for restart schedules. A console-command schedule uses `"action":"command"` with a single-line `"command"` value. It requires `server.console`, is stored encrypted, and is sent through RCON or server stdin when the server is running. A message schedule is available for Minecraft Java and Bedrock. It uses `"action":"message"`, a `"message_template_id"`, and numeric `"values"` for the placeholders in that template (for example `{"minutes":5}`). It needs `server.schedule` but no additional action permission. Five built-in templates are available; administrators can create, edit, and delete custom templates. Bodies are one Minecraft console command and may use `{{server_name}}`, `{{minutes}}`, and `{{seconds}}`. A schedule snapshots its selected template and values in encrypted storage, so later template edits do not change existing schedules. Messages are sent only while the server is running. Command and message contents are omitted from schedule and run-history responses. The enabled field may be omitted; new schedules are enabled by default. Five-field cron uses minute, hour, day of month, month, and weekday. Six-field cron adds seconds first. Times are interpreted in the panel host local timezone. A scheduled backup runs only when the server is stopped; otherwise the failed attempt is recorded and the next cron time remains scheduled. A warned restart runs in the background, sends configured countdown commands through RCON or stdin, then recreates the server. If the server is manually stopped or replaced during the countdown, the scheduled restart is canceled.

Server objects returned by list, get, create, and update include the caller's effective `permissions` array. For stack templates, they also include `stack_services`, an array of `{name,status,error_message?}` summaries. Sidecar status values are `created`, `running`, `stopped`, or `error`; error messages contain only Docker lifecycle state, not container output or environment values. The backups API requires `server.backup`; schedule management requires `server.schedule`, and backup, lifecycle, and console-command schedules additionally require `server.backup`, `server.control`, or `server.console`, respectively. Message-template management requires an administrator. API token permissions are intersected with the account's grants.

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

Administrator endpoints are `GET/POST /api/users`, `PUT/DELETE /api/users/{id}`, `GET/PUT /api/users/{id}/permissions`, and `GET /api/permissions/catalog` (authenticated permission metadata). User profile changes invalidate that user's sessions; permission updates take effect on the next request without ending the session. `GET /api/audit` returns the most recent 200 audit records and is administrator-only. Grants combine with OR logic across `global`, `realm`, `gameskill`, and `server` scopes. Editing permissions replaces the complete grant set. Realm grants apply to servers currently in that realm and future servers created there.

## Limits

There is no pagination for server or user lists. Audit history returns at most 200 rows. Login attempts are rate limited. File editor and upload limits are documented above. Scheduler actions beyond backup/start/stop/restart/command/message, realm/global schedules, and external networking integrations are not implemented yet. See [server backups](guides/backups.md) for local and remote backup behavior, [app stacks](guides/stacks.md) for private sidecars, [notifications](guides/notifications.md) for delivery transports, [monitoring](guides/monitoring.md) for runtime monitoring and automatic recovery, and [the status-page guide](guides/status-page.md) for public exposure and freshness rules. See [realms and access](guides/realms.md) for server grouping and scoped grants.
