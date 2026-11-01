# Assistant setup

Docklight Assistant is an optional provider-backed feature. It starts off and has no model, endpoint, or key configured. Provider setup, a connection check, and the explicit Advisory switch are available to administrators under **Manage → Assistant**. Saving provider details does not turn Advisory on.

## Configure a provider

Choose one of the supported providers, enter the model identifier from that provider, and save. Docklight supplies these default base URLs; an administrator may replace any default with an HTTP(S) endpoint:

| Provider | Default URL | Request format |
| --- | --- | --- |
| Anthropic | `https://api.anthropic.com` | Anthropic Messages API |
| OpenAI | `https://api.openai.com/v1` | OpenAI-compatible chat completions |
| OpenRouter | `https://openrouter.ai/api/v1` | OpenAI-compatible chat completions |
| DeepSeek | `https://api.deepseek.com/v1` | OpenAI-compatible chat completions |
| Mistral | `https://api.mistral.ai/v1` | OpenAI-compatible chat completions |
| Ollama | `http://127.0.0.1:11434/v1` | OpenAI-compatible chat completions |
| Custom | None | OpenAI-compatible chat completions |

Request shapes follow the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) and [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat/create). OpenAI-compatible providers use the chat completions format.

The model name is required. A key is required for hosted providers before testing; Ollama and custom endpoints can be tested without one. The key is encrypted with the panel's `auth.secret_key`. The API returns a fixed mask and a configured flag, never the clear key. Leave the key field blank or send the returned mask to keep the saved key, or check **Remove the saved API key** to clear it.

HTTPS is required for public endpoints. Plain HTTP is accepted for loopback and private-network endpoints, including local Ollama deployments. Provider URLs cannot contain user information, query strings, or fragments. Connection requests have a 12-second timeout, do not follow redirects, and read at most 1 MiB of response data.

## Test the connection

Save the provider settings first. **Test connection** sends only `Reply with the word connected.` and checks for a non-empty text response. Docklight discards that response and does not include server, event, log, player, or configuration data. Test calls work while Assistant is off and are not written to audit history. Failures show the HTTP status when available, without returning the provider's response body or saved key.

## Advisory and server chat

An administrator can enable Advisory after saving a provider. Advisory stays off until explicitly enabled. The manual **Operations digest** sends server names and states, the latest host CPU/memory/data-filesystem sample, recent scheduled failure names and times, and 24-hour per-server CPU, memory, and player averages/peaks. It excludes environment values, saved settings, credentials, and raw logs. Snapshot names and statuses are treated as untrusted prompt data. The returned summary is rendered as text and is not stored.

The per-server **Assistant** tab includes a read-only chat. It requires `server.view` for that server. Docklight embeds its getting-started page, configuration reference, template reference, API reference, and guides in the binary. For each question, it finds up to 12 short relevant documentation excerpts and includes only the selected server's context. Conversation history stays in the browser and the latest ten user and assistant messages are sent with each turn; no chat transcript is stored in SQLite or audit history.

Administrators set **Chat data scope** under **Manage → Assistant**:

- **Level 0** sends the selected server's name, state, template ID, install state, watchdog state, and relevant documentation.
- **Level 1** adds a 24-hour resource summary, backup count/size and latest time, and scheduled outcome counts for that server.
- **Level 2** also permits a separate optional log search. Docklight reads at most 300 recent container log lines, redacts known template secrets locally, and sends at most 20 matching lines (up to 5,000 bytes). The user must enter a separate search phrase; without one, no logs are sent. The filtered excerpt can still contain player chat, IP addresses, or other sensitive text.

The browser displays whether the configured provider is on the local network or hosted. Before sending log-search matches to a hosted provider, it asks the operator to confirm. The prompt includes no other server's state and no configuration values. Chat answers and conversation context are bounded, rendered as text, and never treated as permission to change a server.

The **Advisory** page in the panel sidebar offers a fleet-wide, read-only conversation over an authenticated WebSocket. Every request is filtered to servers the signed-in user can view before any server data reaches the provider. At most 100 visible servers are included per request; the answer reports how many visible servers were included or omitted. Level 0 includes visible server state and relevant embedded documentation. Level 1 adds each included server's resource, backup, and scheduled-outcome summaries. At level 2, the operator may separately select one visible server and search for matching recent log lines. Docklight filters and redacts those lines locally; the excerpt has the same limits and may still contain player chat, IP addresses, or other private text. A hosted provider requires confirmation for every log search, bound to the provider host currently shown. Conversation history is limited to ten messages and stays in the browser tab. Advisory does not perform Actions or save chat transcripts.

## Server and activity advisors

The per-server Assistant tab can explain recent logs and review the template's declared configuration. Log explanation sends up to 8,000 characters from the last 300 container log lines after locally removing known template secrets and common credential-shaped fields. Other private log content, including player chat and IP addresses, may remain. Configuration review requires `server.control`; non-secret declared values are sent to the provider, while secret values are replaced with a local strength label such as `(set, strong)` or `WEAK (default)`. Neither advisor changes settings.

Administrators can request an activity digest from **Audit history**. It sends at most 200 structured event fields and omits audit detail text. A DayZ template with a declared `MODS` setting can request mod suggestions from the **Mods** tab; the provider receives the current mod list and Workshop status, and Docklight does not edit `MODS`.

Administrators can request up to five log-watcher suggestions for a server. The provider receives the same redacted 8,000-character log excerpt used for log explanation. Docklight validates each name, Go-compatible regular expression, threshold, time window, action, and a match against the sample. Suggestions are displayed for review and are not saved or activated.

Administrators manage persistent rules under **Manage → Log watchers**. Rules match new Docker log lines, either for one server or all running servers. The default threshold is one match in 60 seconds; windows are limited to one hour, and each watcher fires at most once every ten minutes. A notification rule sends the watcher and server names. An Advisory rule may send one matching line after Docklight locally removes known template secrets and common credential-shaped fields. Other private log content, including player chat and IP addresses, may remain. Local providers need no external-sharing consent. Before an enabled rule sends logs to a hosted provider, an administrator confirms the transfer; Docklight records the confirmed provider host and refuses to send if the host changes. Rules copied from a template do not carry hosted-provider consent. Template rules are seeded on server creation and installation/update, and a deleted template rule is restored without overwriting operator edits.

## Daily digest and proposed actions

An administrator may schedule a daily digest at a host-local hour. Docklight marks the day's attempt before contacting the provider to avoid duplicate delivery after restarts. The message is sent through enabled global notification channels; for the legacy webhook, enable the `assistant.daily_digest` event. If no eligible delivery destination exists, that day's attempt is not claimed. Provider failures after a claimed attempt are audited without prompt data and are not retried that day.

The optional **Actions** tier is a separate admin switch. It lets an operator with `server.control` ask for a plan containing at most five start, stop, restart, or safe-restart actions. The API accepts only those actions for servers that the operator can control. Each proposal is shown before execution; the operator confirms each action separately. Confirmation IDs are one-use, bound to the operator, server, action, and server state, and expire after ten minutes. Docklight re-checks the user's permission, Advisory and Actions switches, installation state, server state, and allow-list immediately before it runs. Disabling Advisory or Actions invalidates pending confirmations. The chat itself never executes commands or actions.

Successful operations and chat requests are audited using counts and server IDs, not questions, prompts, log text, or provider responses. Chat, digest, advisor, and proposal responses are not saved. Proactive event explanations and suggestions are retained with their event.

## Proactive monitoring

Administrators can configure **Proactive monitoring** after enabling Advisory. It is off by default. Level 1 explains matching observations; level 2 may also return a proposed action; level 3 enables a narrow set of automatic fixes. The selected triggers are confirmed container exits, starts still in progress after 15 minutes, server CPU or memory at 90% or more of its configured limit, host CPU or memory at 95% or more, host data-disk free space at 10% or less, large player-count changes, and log-volume outliers. A player anomaly means either a drop of at least 75% from a baseline of four or more players, or at least eight new players above the 14-day high.

For log volume, Docklight asks Docker for output from the preceding minute and counts bytes and lines without saving or sending log text. It learns a per-server exponential baseline after five samples, then reports a burst only when the sample is at least 1 MiB and meets or exceeds both eight times the baseline and six standard deviations above it. Samples are capped at 8 MiB per server per minute; the event records if it hit the cap. Baseline values are excluded from an outlier so a burst does not immediately become normal, and baselines older than 24 hours are relearned. Log events are deduplicated to one per server per hour. Docker log access errors and empty container IDs are ignored.

Observations are deduplicated, retained for up to 1,000 records, and shown under the fleet **Advisory** page to users who can view the related server. Host-wide observations are admin-only. Dismissed events leave the active list. Provider explanations and suggestions are stored with the event; prompts and provider responses are not separately audited. At level 1, the provider is asked only to explain and return no action. At level 2, a suggestion is informational and makes no change; only start, stop, restart, or safe restart can be requested separately through the confirmed Actions flow.

Level 3 requires the separate Actions switch. It can restart a confirmed crashed server or, after an observed exit code 137, increase the server memory limit by a bounded amount when fresh host metrics show enough headroom. It runs no more than three automatic fixes per server in 30 minutes and writes an audit entry. Other suggested actions are never run automatically. This bounded automatic-fix mode is separate from chat and is not a general autonomous action system.

The monitoring worker samples once per minute and uses the panel's existing Docker and metrics data. It does not run a live player query for the proactive check. The log-volume check reads only timestamped Docker output counts for each running server. Monitoring settings are available through `PUT /api/ai/proactive-settings`; active observations use `GET /api/ai/proactive-events` and can be dismissed with `DELETE /api/ai/proactive-events/{id}`.

## MCP connector

Docklight exposes a Streamable HTTP MCP endpoint at `/api/mcp`. It supports `initialize`, `ping`, `tools/list`, and `tools/call` over JSON-RPC POST requests. Connector tokens are accepted only at this exact path. Ordinary browser session tokens do not grant MCP access; use OAuth consent or a scoped API token.

For a hosted connector, configure the panel's canonical `server.public_url` as the origin where this Docklight instance is actually served, including `https://`. The OAuth issuer and resource URL are derived from that origin; Docklight does not substitute its product domain `docklight.app` for an instance URL. Loopback HTTP is allowed for local development, while remote URLs require HTTPS. Reverse proxies should preserve the public `Host` and set `X-Forwarded-Proto: https`.

MCP discovery is available through `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`. Public clients register at `/oauth/register`; Docklight stores exact redirect URLs and issues no client secret. Authorization uses PKCE S256, the `yggdrasil` scope, and a resource indicator equal to `<panel-origin>/api/mcp`. A same-origin signed-in user must approve the displayed request with its one-use nonce. The consent page states that the connector can read server status and recent logs and can start, stop, or restart servers the account can control. Recent logs can contain player chat, IP addresses, or other private text; stop and restart may disconnect players.

Authorization codes last five minutes and are single-use. Access tokens last 30 days and refresh tokens last 90 days; refresh tokens rotate on every use. Only SHA-256 hashes of OAuth credentials are stored. A refresh-token replay revokes that connection. Each connection acts as the approving user and follows their current server grants. API tokens can also call `/api/mcp`, subject to both account grants and the token's own scopes.

Tools are limited to `list_servers`, `get_server`, `server_logs`, `start_server`, `stop_server`, `restart_server`, and `panel_status`. Server selection accepts an ID or an unambiguous name. Logs redact configured template secrets but may retain player chat or IP addresses; the tool defaults to 100 lines and caps requests at 500. There are no file, settings, create, or delete tools. Tool calls and server actions are recorded in Docklight's audit log as the caller.

Signed-in users can see `/api/mcp/info` and manage their own connections from **Account → MCP connections**. Revoking a connection immediately invalidates its tokens. The reachability indicator detects common local and VPN-only hostnames but does not probe the public internet; hosted clients still need the panel to be reachable from their service over HTTPS.
