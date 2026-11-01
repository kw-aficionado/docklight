# Beacon and privacy

Docklight includes one small, disclosed usage beacon. It sends this JSON payload:

```json
{"instance_id":"<random installation UUID>","version":"<Docklight build>"}
```

No account names, server names, configuration, addresses, or usage events are included. The request reaches the collector from the panel host's network address, but the collector does not store that address. Docklight ships no panel analytics.

## Sender

The sender is on by default. The first administrator sign-in displays the exact payload and offers **Turn off** or **Keep daily beacon on**. Turning it off is stored in the panel database and upgrades do not turn it back on. The Beacon page lets an administrator change the collector URL, inspect the last accepted ping and last error, or send a test to the URL currently in the form. Clearing the URL restores `https://beacon.docklight.app/api/beacon`.

The first check runs 30 seconds after startup, then every 30 minutes. A ping is considered complete only after a successful 2xx response. Docklight sends at most once per UTC day; a build-version change can trigger another ping. Failed pings retry at the next check. Explicitly re-enabling the sender sends immediately.

Only `http://` and `https://` collector URLs are accepted. Redirects are not followed and requests time out after eight seconds. HTTPS is recommended for a remote collector.

## Self-hosted collector

The receiver is a separate option and is off by default. When enabled, `POST /api/beacon` accepts exactly the two payload fields above and upserts by installation ID. The database keeps the version, first and last seen times, and total ping count. No request IP is read or persisted.

`GET /api/beacon/stats` is admin-only and reports total installations, activity within 7 and 30 days, and versions seen within 30 days. The public endpoint `GET /api/beacon/count` is an independent opt-in. It returns a 30-day installation count only after the configured minimum is reached (25 by default); below that threshold the count is `null`. The public endpoint returns `404` unless both receiver and public-count switches are enabled.

## Administrator API

- `GET` and `PUT /api/settings/beacon` read and save sender, receiver, public-count, and collector URL settings.
- `POST /api/settings/beacon/notice` accepts `{"keep":true}` or `{"keep":false}` to acknowledge the initial disclosure; `false` turns the sender off.
- `POST /api/settings/beacon/test` accepts `{"url":"https://collector.example/api/beacon"}` and sends the current instance payload without saving the URL or updating the scheduled-ping status. It returns `409` while the sender is off.
- `GET /api/beacon/stats` reads self-hosted collector statistics.

The default Docklight collector is `beacon.docklight.app`; a deployment can point its sender at any trusted HTTP or HTTPS collector.
