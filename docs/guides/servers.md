# Server operations

## Create and install

Choose a rune from **Runes**, create a server, fill its declared settings, and set optional CPU and memory limits. The panel reserves a host port from the configured range, creates a per-server data directory, and writes environment settings to SQLite. Rune fields declared secret (or named like a password, token, secret, credential, or private key) are encrypted with AES-GCM before storage.

An install-enabled rune runs its shell script in a temporary Docker container with the server data mounted at `/data`. The panel captures and redacts declared secret values from install output, removes the installer container, repairs data ownership, and starts the server. Runes without an install script proceed directly to start.

## Readiness and lifecycle

The panel sets status to **Starting** after Docker starts the container. It scans recent logs for `startup.done_regex`; when a rune declares a TCP `web` port, that port must also accept a local connection. After ten minutes without readiness the status changes to **Needs attention** with guidance to review the console and rune settings. It does not claim a timed-out process is ready.

Stopping sends `startup.save_command` and `startup.stop` to container input when set, then asks Docker to stop gracefully using `startup.stop_timeout` (30 seconds when unset). The Minecraft Java rune sends `save-all flush` followed by `stop` before Docker's stop request.

Changing server settings or CPU/RAM limits while running recreates and starts its container with the existing data directory. Deleting a server removes its container, data directory, port reservations, and server-scoped grants after Docker confirms the container is absent or removed.

## Console, query, and files

The Console tab streams Docker output over WebSocket and sends commands through RCON when configured, then falls back to the container's standard input if RCON is unavailable. Minecraft Java and Bedrock, plus Source A2S runes, can expose player counts when their query protocol is defined.

The Files tab supports listing, editing files up to 5 MiB, uploads up to 64 MiB, downloads, folder creation, and removal of files or empty directories. Paths are confined to the server data directory, and existing symlinks are resolved before access. It is not a general-purpose shell or recursive delete tool.

## Resource limits and ports

CPU limits are configured in cores, memory limits in MiB; zero means unlimited. Host ports are published on all interfaces except a port named `rcon`, which is bound to `127.0.0.1`. The panel reserves numbers in SQLite and checks host port availability during allocation; another process can still race and take a port before Docker binds it. A Docker bind conflict returns an actionable error.

## Current boundaries

There is no automatic update/reinstall path, backup, scheduler, sidecar network, watchdog, external reachability probe, or history of resource metrics in this release. The container can still be inspected with Docker on the host, and server files remain under the configured database directory.
