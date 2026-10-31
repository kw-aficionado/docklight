# Notifications

Docklight can send backup results, scheduled-action outcomes, confirmed container incidents, and low-disk alerts to one administrator-configured webhook. The receiver can be a small internal service or a webhook URL supplied by another product.

## Configure a webhook

Open **Notifications** as an administrator, enter the endpoint, select the events to receive, then save. Use **Save & send test** to check connectivity. The panel sends `notification.test` even while delivery is disabled, so the endpoint can be verified before enabling automatic events.

The endpoint URL and optional signing secret are encrypted in SQLite with `auth.secret_key`. The API returns only whether each value is configured. Leave a credential field blank to keep its current value; use the clear checkbox to remove it. Keep the panel secret key with the database because Docklight needs it to decrypt webhook settings.

Endpoints must use HTTPS. Plain HTTP is allowed only for `localhost` or a loopback IP, which supports local development and testing. Redirects are not followed. The endpoint is configured by an administrator and can reach any HTTPS host; restrict administrative access accordingly.

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

## Current limits

Only one webhook endpoint can be configured. The panel does not yet provide dedicated Discord, Telegram, or SMTP email channels, retries, or delivery history. The host storage card on this page reports the filesystem that holds Docklight's data directory; it does not enumerate every mounted volume.
