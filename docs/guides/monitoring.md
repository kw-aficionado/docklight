# Runtime monitoring

Docklight records an exit if a container stops during startup or after the panel marked it **Running**. The runtime monitor is read-only; it does not remove containers or server data.

## Confirmed exits

The monitor waits 60 seconds after panel startup and first requires the Docker Engine ping to succeed. When Docker says a container is stopped, Docklight waits for the same stopped state to appear again at least 15 seconds later before recording an incident. A missing-container response is handled the same way. This startup grace and second check reduce false incidents while Docker is loading containers or the Engine is briefly unreachable.

If Docker returns another error, Docklight keeps the last known server state and tries again later. It does not treat an Engine timeout as a missing container.

A confirmed incident sets the server to **Needs attention** and records the detected time, incident type, exit code when available, and a restart hint. Server files are preserved. Use the per-server **History** tab to read up to 50 recent incidents; Docklight retains up to 100 per server. Deleting a server also deletes its incident history.

## Low disk space

Docklight checks the filesystem that contains its data directory every five minutes. If available space falls below 10%, it marks the alert active and sends `host.disk_low` to the configured webhook when that event is enabled. The alert rearms when free space reaches 15%, so a continuing low-space condition does not send a message every five minutes. The Notifications page shows current capacity and alert state. The message identifies the server-data and local-backup paths to inspect. Only the Docklight data filesystem is measured; other mounted volumes are not enumerated, and Docklight never deletes files automatically.

## Current limits

The runtime monitor does not restart containers automatically, send crash notifications, or retain Docker logs as crash artifacts. Review the Console and host Docker logs, then restart a server after addressing the cause.
