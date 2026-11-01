# Getting started

This guide assumes a single Debian 12 or Ubuntu 24.04+ host. Docklight manages containers through the Docker Engine socket and stores the panel database and server files under the directory containing the configured SQLite database.

## Install

For a source checkout with Go 1.27 or newer:

```sh
sudo env YGG_SOURCE_DIR="$PWD" bash install.sh
```

For a published release, provide its GitHub repository and tag (or `latest`):

```sh
sudo env YGG_REPO="OWNER/REPOSITORY" YGG_VERSION="latest" bash install.sh
```

The release path verifies the downloaded binary against the release `SHA256SUMS`. For a direct binary URL, optionally provide `YGG_SHA256`; local `YGG_BINARY_FILE` input is trusted as supplied. The installer installs Docker if the `docker` command is missing, creates the service account, preserves `/etc/yggdrasil/config.yaml`, installs the systemd service, and restarts it.

On first install, the script prints `http://<host>:8080` and a generated one-time administrator password. Sign in, change the password in the account menu, and enroll an authenticator there. To enable self-service password recovery, add a unique email to each account under **Users & access**, add a global SMTP email channel under **Notifications**, and set `server.public_url` in `/etc/yggdrasil/config.yaml` when the panel is behind a proxy or public hostname. API tokens can also be created in the account menu; copy the token at creation because it is not shown again.

## Deploy an app

1. Choose **Templates** in the panel.
2. Pick a built-in template and select **Create server**.
3. Fill out the settings and choose CPU and memory limits. Secret fields are encrypted in SQLite and shown as masked values after save.
4. Select **Install**. Install output streams to the Console tab and install status.
5. Wait for the server readiness check. It remains in **Starting** until its startup pattern or game query responds. Templates with a `web` port must also accept a local TCP connection on that port.
6. Use the server tabs to view metrics, query player counts, issue console commands, edit files, manage backups, and change settings.

The built-in Minecraft Java and Bedrock templates require accepting the Minecraft EULA. Minecraft Java also has a generated RCON password; the host RCON mapping is loopback-only. Vaultwarden and Uptime Kuma publish a web port. WordPress + MariaDB is a single app stack: the database stays on the server's private network, and Docklight backs up both services' data. See the [app-stack guide](guides/stacks.md). Steam-enabled templates need an administrator-authorized Steam account when they do not use anonymous login; see [Steam account setup](guides/steam.md). The built-in DayZ template uses UDP ports 2302, 2304, and 2305 by default; see the [DayZ server guide](guides/dayz-server.md). Cloudflare Tunnel runs `cloudflared` with a required encrypted tunnel token; route and DNS reconciliation is not included in this release.

## Reverse proxy

The default listener is `0.0.0.0:8080`. You can set `server.host` to a specific trusted interface. For an external proxy, enable TLS at the proxy, preserve same-origin host and scheme headers, forward WebSocket `Upgrade` and `Connection` headers, and disable buffering for console/log streams. The session cookie becomes `Secure` when the request is TLS or carries `X-Forwarded-Proto: https`.

Restrict inbound access with a host firewall. The service account has Docker socket access, which is effectively root access on the host; do not expose the Docker socket over TCP.

## Recover access and inspect failures

```sh
sudo journalctl -u yggdrasil -n 200 --no-pager
sudo systemctl status yggdrasil
sudo /usr/local/bin/yggdrasil reset-password admin --config /etc/yggdrasil/config.yaml
sudo /usr/local/bin/yggdrasil reset-2fa admin --config /etc/yggdrasil/config.yaml
```

Both reset commands require root and invalidate existing web sessions. The generated reset password is printed to the terminal. For server-specific failures, open the server Console tab and read its status message before changing template settings.

See [configuration](configuration.md), [HTTP API](api.md), [offline app shell](guides/offline-pwa.md), [server operations](guides/servers.md), [access and security](guides/security.md), and [templates](templates.md).
