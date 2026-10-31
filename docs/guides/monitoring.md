# Runtime monitoring

Docklight records an exit if a container stops during startup or after the panel marked it **Running**. The runtime monitor is read-only; it does not remove containers or server data.

## Confirmed exits

The monitor waits 60 seconds after panel startup and first requires the Docker Engine ping to succeed. When Docker says a container is stopped, Docklight waits for the same stopped state to appear again at least 15 seconds later before recording an incident. A missing-container response is handled the same way. This startup grace and second check reduce false incidents while Docker is loading containers or the Engine is briefly unreachable.

If Docker returns another error, Docklight keeps the last known server state and tries again later. It does not treat an Engine timeout as a missing container.

A confirmed incident sets the server to **Needs attention** and records the detected time, incident type, exit code when available, and a restart hint. Server files are preserved. Use the per-server **History** tab to read up to 50 recent incidents; Docklight retains up to 100 per server. Deleting a server also deletes its incident history.

## Low disk space

Docklight checks the filesystem that contains its data directory every five minutes. If available space falls below 10%, it marks the alert active and sends `host.disk_low` to enabled notification channels. The legacy signed webhook sends it when that event is selected. The alert rearms when free space reaches 15%, so a continuing low-space condition does not send a message every five minutes. The Notifications page shows current capacity and alert state. The message identifies the server-data and local-backup paths to inspect. Only the Docklight data filesystem is measured; other mounted volumes are not enumerated, and Docklight never deletes files automatically.

## Automatic recovery

Automatic recovery is an opt-in server setting. It is available only for templates with a player-query protocol and requires `server.control`. Docklight probes the local published query port every 20 seconds with a 3-second timeout. Three consecutive failed probes trigger a container recreate and start; another attempt is held back for four minutes. A successful recovery is recorded in audit history and can send the `server.watchdog` webhook event.

After five successful automatic recoveries in a rolling 30-minute window, Docklight pauses automatic recovery and marks the server as quarantined. The server is left running if the last start is still progressing. Manually starting or stopping the server clears the quarantine and recovery counters. A failed start is retried up to three times with 15 seconds between attempts; a final failure is recorded and sent through the watchdog webhook event when enabled.

## Current limits

The confirmed-exit monitor does not restart a stopped or missing container, and Docklight does not retain Docker logs as crash artifacts. Automatic recovery only checks query-capable servers that an operator enabled. Review the Console and host Docker logs after an incident. Enable `server.crash` under Notifications to receive confirmed exit events. Docker Engine acceptance for automatic recovery requires a Docker-enabled host.
