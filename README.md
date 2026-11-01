# Docklight

![Docklight logo](web/brand.svg)

Docklight is a self-hosted control panel for Docker game servers and apps. It runs as one Go binary, stores panel state in SQLite, and embeds its browser interface and six built-in server templates.

Official product domain: [docklight.app](https://docklight.app).

The browser and product identity use **Docklight**. The current binary, CLI, service, and default filesystem paths still use `yggdrasil` while the implementation transitions from its original internal name.

The current checkout contains the Phase 1 core plus local, S3-compatible, SFTP, and SMB encrypted backups, scoped schedules, Discord, Telegram, SMTP, and signed JSON webhook alerts, confirmed container crash history and alerts, low-disk monitoring, a public status page with double opt-in, a disclosed daily version beacon with an optional self-hosted collector, verified panel self-updates, central player bans and log-based moderation rules including a DayZ ban-file adapter for compatible templates, template-declared anti-cheat guidance, DayZ Economy controls, installed-mod loot imports and a compatible-template Workshop mod manager with encrypted search credentials, public host detection and server reachability checks, Cloudflare Tunnel routes and DNS, managed IP blocking through Cloudflare or optional host nftables, realm grouping with scoped access, private app stacks, Docker Compose and Pterodactyl egg/XML template imports, GitHub/Gitea/Forgejo template catalogs, encrypted per-registry credentials for private images, and disabled-by-default Assistant provider setup with encrypted keys and connection tests. See [STATUS.md](STATUS.md) for implemented behavior, remaining work, and environment limits.

## Install on Debian or Ubuntu

The installer supports Debian 12 and Ubuntu 24.04 or newer on amd64 and arm64. It installs Docker when needed, creates a `yggdrasil` service account, installs a systemd service, and preserves the existing configuration and data when run again.

From a source checkout with Go 1.27 or newer:

```sh
sudo env YGG_SOURCE_DIR="$PWD" bash install.sh
```

For a published GitHub release, set the repository that owns the release:

```sh
sudo env YGG_REPO="OWNER/REPOSITORY" YGG_VERSION="latest" bash install.sh
```

You can also provide `YGG_BINARY_URL` or `YGG_BINARY_FILE`. The installer prints the panel URL and the one-time administrator password on first install. Sign in at `http://<host>:8080`, change the password, and enroll an authenticator from the account menu.

A release repository is not configured in this source checkout. Until binaries are published, use the source-checkout or explicit-binary option.

## First server

1. Open **Templates** and choose a built-in template.
2. Create the server, fill its declared settings, and set optional CPU and memory limits.
3. Select **Install**. The Console shows install output while the installer runs.
4. The status changes to **Running** only after the server is ready; web apps must also answer on their published web port.
5. Use **Console**, **Files**, **Backups**, **Schedules**, and **Settings** on the server page. Stop a server before creating, restoring, or scheduling a backup.

The built-in templates are Minecraft Java, Minecraft Bedrock, Uptime Kuma, Vaultwarden, WordPress + MariaDB, and Cloudflare Tunnel. WordPress and its database run as one server on a private network; only the WordPress web port is published. See the [app-stack guide](docs/guides/stacks.md). Minecraft Java RCON is bound to loopback on the host. The panel allocates ports from `ports.range_min` through `ports.range_max`.

## Service and CLI

```sh
sudo systemctl status yggdrasil
sudo journalctl -u yggdrasil -f
sudo /usr/local/bin/yggdrasil version
```

The CLI also provides:

- `gen-config [PATH]` — write a new config and one-time admin password; refuses to overwrite an existing file.
- `reset-password USER [--config PATH]` — root-only break-glass password reset; generates a password unless one is supplied.
- `reset-2fa USER [--config PATH]` — root-only break-glass authenticator reset.

See [brand direction](docs/brand.md), [configuration](docs/configuration.md), [getting started](docs/getting-started.md), [HTTP API](docs/api.md), [Assistant setup](docs/guides/assistant.md), [anti-cheat guidance](docs/guides/anti-cheat.md), [moderation](docs/guides/moderation.md), [panel updates](docs/guides/updates.md), [server backups](docs/guides/backups.md), [app stacks](docs/guides/stacks.md), [networking](docs/guides/networking.md), [monitoring](docs/guides/monitoring.md), [public status page](docs/guides/status-page.md), [beacon and privacy](docs/guides/beacon.md), [realms and access](docs/guides/realms.md), [notifications](docs/guides/notifications.md), and the [template schema](docs/templates.md).

## Network and security

The default listener is `0.0.0.0:8080`. Restrict it with the host firewall or set `server.host` to a trusted interface. If you put a reverse proxy in front, terminate TLS there and pass WebSocket `Upgrade` and `Connection` headers without buffering. The panel uses same-origin checks for browser mutations and does not enable cross-origin API access.

The service account belongs to Docker's `docker` group so it can manage containers through the Engine socket. Docker access is effectively root access on the host; protect the panel account, its credentials, and network exposure accordingly. Do not expose the Docker socket over TCP.

Docklight sends a disclosed daily beacon by default with only a random instance ID and build version. The first administrator sign-in offers a one-click opt-out, and the choice is saved. The beacon collector does not store source IP addresses. Docklight ships no panel analytics; Docker pulls images when servers are installed or started.

## Development

```sh
GOCACHE=/tmp/docklight-gocache GOMODCACHE="$HOME/go/pkg/mod" GOPROXY=off GOSUMDB=off go test -count=1 ./...
GOCACHE=/tmp/docklight-gocache GOMODCACHE="$HOME/go/pkg/mod" GOPROXY=off GOSUMDB=off go vet ./...
node --test web/ui-utils.test.mjs
node --check --input-type=module < web/app.js
```

The project uses Go's standard library for its browser utility tests; no npm install is required. Docker acceptance still needs a Debian or Ubuntu host with Docker Engine.
