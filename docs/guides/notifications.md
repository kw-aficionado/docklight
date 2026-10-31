# Notifications

Docklight can send backup results, scheduled-action outcomes, confirmed container incidents, and low-disk alerts to Discord, Telegram, email, or a JSON webhook. An administrator can add several channels and scope each one to every server or to one server.

## Configure a webhook

Open **Notifications** as an administrator and choose **Add channel**. Enter the transport settings and select **All servers** or a single server. Each channel receives all supported events for its scope. Use **Test** in the channel list to verify delivery; the panel sends a short Docklight test message. Use **Edit** to replace a channel's complete settings, or **Remove** to delete it.

Channel configuration is encrypted in SQLite with `auth.secret_key`. API responses contain channel type and scope only; URLs, bot tokens, SMTP passwords, and signing secrets are never returned. To replace a channel, enter all of its settings again. Keep the panel secret key with the database because Docklight needs it to decrypt saved configurations. The original signed webhook form remains available for existing installations.

Webhook endpoints must use HTTPS. Plain HTTP is allowed only for `localhost` or a loopback IP. Redirects are not followed. Telegram Bot API requests use Telegram's required HTTPS URL format, which includes the bot token in the request path; Docklight never logs that URL or includes it in a response. SMTP uses STARTTLS when advertised, or implicit TLS on port 465. Remote SMTP without TLS is refused, and authentication is sent only after TLS is established. SMTP defaults to port 587; credentials are optional for trusted local relays.

## Events and request format

Supported event types are `backup.success`, `backup.failure`, `schedule.success`, `schedule.failure`, `server.crash`, `server.watchdog`, and `host.disk_low`. Both manual and scheduled backup attempts are included in the backup events. Schedule events include the schedule ID, action, outcome, and server identity; they omit run details that might contain sensitive information. Successful and failed runs are sent, while skipped runs are not. If both backup and schedule events are enabled, a scheduled backup sends both event types. A confirmed container exit or missing container sends `server.crash` with the server name and recorded incident message. Automatic recovery sends `server.watchdog` when it starts a recovery, cannot restart the server, or pauses after repeated heals. The low-disk event fires when the filesystem containing Docklight's panel data drops below 10% free; it rearms after free space reaches 15%. Its message includes available and total capacity plus the server-data and backup paths to inspect. Delivery runs asynchronously after the panel records the state change. A failed delivery does not change the recorded operation; check the Docklight process log and endpoint availability.

Each request is a JSON `POST` with this shape:

```json
{
  "product": "Docklight",
  "event": "backup.success",
  "occurred_at": "2026-10-31T12:00:00Z",
  "server": {"id": "server-id", "name": "Survival"},
  "message": "A scheduled backup completed and passed integrity verification."
}
```

For a scheduler event, the payload also includes a `schedule` object such as `{"id":"schedule-id","action":"restart","status":"success"}`. Its message is generic and never includes the schedule run's error detail.

When a signing secret is configured, the request includes `X-Docklight-Signature: sha256=<hex>`. The value is the lowercase hexadecimal HMAC-SHA256 of the exact request body. Receivers should compare signatures in constant time and reject a mismatch.

Delivery runs asynchronously without retries or a delivery-history table. Failures are logged with channel ID and transport type; credential-bearing URLs and values are excluded. The panel storage card reports the filesystem that holds Docklight's data directory and does not enumerate every mounted volume.
