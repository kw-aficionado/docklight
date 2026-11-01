# Player moderation

Administrators can keep a central ban list and define automatic kick or ban rules from server logs under **Moderation**. A ban can target one server or all current and future servers. Docklight records who created it, the reason, optional player ID and expiry, and whether each server accepted the configured command. Revoking a ban queues an unban for every server where Docklight applied it. Expiry and command retries are handled by the panel worker.

## Template support

A server template opts into ban delivery by declaring both commands:

```yaml
gameskill:
  bans:
    ban_command: "ban {{player}} {{reason}}"
    unban_command: "pardon {{player}}"
```

Both commands must include `{{player}}`. They may also use `{{player_id}}` and `{{reason}}`. Docklight removes control characters from the values and sends the single command over RCON when available, then through the server's input stream. Templates without `bans` metadata cannot receive central bans; the Moderation page shows delivery errors for them. A command being accepted by RCON or stdin does not confirm that a game-specific ban file or database was updated.

This checkout has no DayZ template or DayZ-specific `ban.txt` writer. The generic command path does not implement DayZ's file format or its distinct rejoin-without-kick behavior.

## Violation rules

Each rule uses a Go RE2 regular expression. The first capture group must contain the player name. Docklight watches new output from running containers, counts matches separately by rule, server, and player, and fires when the threshold is reached within the configured time window. Old log history is not replayed on startup. Hit counts are in memory and reset after an action is queued, when Docklight restarts, or when the rule is edited or deleted.

`Kick` sends `kick <player>` to that server and reports only successful command delivery. `Ban` creates a central ban scoped to that server, or to all servers when **Ban on all servers** is selected. Automatic actions are audited; `player.auto_moderation` is sent when a kick command is accepted or a ban command is accepted on a target server. If the worker queue fills, hit counts remain at threshold and Docklight retries when later matching log output arrives. The in-memory tracker is capped at 50,000 rule/server/player keys; additional new keys are skipped and a rate-limited message is written to the process log.

Rules can match text produced by a game or application. Keep patterns specific, test them against the server's actual log format, and avoid a broad expression that could treat unrelated text as a player name. Docklight does not parse a universal game moderation format; templates define the commands each game understands.

## API

The admin-only endpoints are listed in the [HTTP API reference](../api.md): `GET/POST/DELETE /api/bans` and `GET/POST/PUT/DELETE /api/violations`. Ban delivery status is per server. Failed commands are retried after five minutes while the server remains running; offline servers are reconciled when they start.
