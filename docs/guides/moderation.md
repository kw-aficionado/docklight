# Player moderation

Administrators can keep a central ban list and define automatic kick or ban rules from server logs under **Moderation**. A ban can target one server or all current and future servers. Docklight records who created it, the reason, optional player ID and expiry, and whether each server accepted the configured command. Revoking a ban queues an unban for every server where Docklight applied it. Expiry and command retries are handled by the panel worker.

## Template support

A server template can opt into central ban delivery by declaring both commands:

```yaml
gameskill:
  bans:
    ban_command: "ban {{player}} {{reason}}"
    unban_command: "pardon {{player}}"
```

Both commands must include `{{player}}`. They may also use `{{player_id}}` and `{{reason}}`. Docklight removes control characters from the values and sends the single command over RCON when available, then through the server's input stream. A command being accepted by RCON or stdin does not confirm that a game-specific ban file or database was updated.

Templates for DayZ can instead declare `bans.adapter: dayz-ban-file`. Docklight adds or removes a 17-digit SteamID or 44-character UID in `<server data root>/ban.txt`, preserving other entries and replacing the file atomically. DayZ's `disableBanlist` setting must remain false. File bans apply to future join attempts; Docklight does not kick a connected player. The built-in [DayZ server template](dayz-server.md) enables this adapter. The supported UID line format and `disableBanlist` setting follow [Bohemia's server-file guidance](https://forums.dayz.com/topic/239635-dayz-server-files-documentation/) and its [server configuration reference](https://community.bistudio.com/wiki/DayZ%3AServer_Configuration).

## Violation rules

Each rule uses a Go RE2 regular expression. The first capture group must contain the player name; an optional second group can contain the player ID, including a DayZ UID. Docklight watches new output from running containers, counts matches separately by rule, server, and player, and fires when the threshold is reached within the configured time window. Old log history is not replayed on startup. Hit counts are in memory and reset after an action is queued, when Docklight restarts, or when the rule is edited or deleted.

`Kick` sends `kick <player>` to that server and reports only successful command delivery. The DayZ file adapter cannot kick a connected player. `Ban` creates a central ban scoped to that server, or to all servers when **Ban on all servers** is selected. Automatic actions are audited; `player.auto_moderation` is sent when a kick command is accepted or a ban command is accepted on a target server. DayZ auto-ban rules need the optional second capture group to supply the UID. If the worker queue fills, hit counts remain at threshold and Docklight retries when later matching log output arrives. The in-memory tracker is capped at 50,000 rule/server/player keys; additional new keys are skipped and a rate-limited message is written to the process log.

Rules can match text produced by a game or application. Keep patterns specific, test them against the server's actual log format, and avoid a broad expression that could treat unrelated text as a player name. Docklight does not parse a universal game moderation format; templates define the commands each game understands.

## API

The admin-only endpoints are listed in the [HTTP API reference](../api.md): `GET/POST/DELETE /api/bans` and `GET/POST/PUT/DELETE /api/violations`. Ban delivery status is per server. Failed commands are retried after five minutes while the server remains running; offline command-based servers are reconciled when they start, while the DayZ file adapter updates its data file directly.
