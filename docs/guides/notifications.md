# Notifications

Docklight can send backup results to one administrator-configured webhook. The receiver can be a small internal service or a webhook URL supplied by another product.

## Configure a webhook

Open **Notifications** as an administrator, enter the endpoint, select the backup events, then save. Use **Save & send test** to check connectivity. The panel sends `notification.test` even while delivery is disabled, so the endpoint can be verified before enabling automatic events.

The endpoint URL and optional signing secret are encrypted in SQLite with `auth.secret_key`. The API returns only whether each value is configured. Leave a credential field blank to keep its current value; use the clear checkbox to remove it. Keep the panel secret key with the database because Docklight needs it to decrypt webhook settings.

Endpoints must use HTTPS. Plain HTTP is allowed only for `localhost` or a loopback IP, which supports local development and testing. Redirects are not followed. The endpoint is configured by an administrator and can reach any HTTPS host; restrict administrative access accordingly.

## Events and request format

Supported event types are `backup.success` and `backup.failure`. Both manual and scheduled backup attempts are included. Delivery runs asynchronously after the panel records the result. A failed delivery does not change the backup result; check the Docklight process log and endpoint availability.

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

When a signing secret is configured, the request includes `X-Docklight-Signature: sha256=<hex>`. The value is the lowercase hexadecimal HMAC-SHA256 of the exact request body. Receivers should compare signatures in constant time and reject a mismatch.

## Current limits

Only one webhook endpoint can be configured. The panel does not yet provide dedicated Discord, Telegram, or SMTP email channels, retries, delivery history, or notification events for server crashes and other operations.
