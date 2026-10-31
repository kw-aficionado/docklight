# Yggdrasil

Yggdrasil is a self-hosted panel for Docker game servers and homelab apps. It runs as one Go binary, keeps panel state in SQLite, and embeds its browser interface and five built-in runes.

The current checkout implements the Phase 1 core. See [STATUS.md](STATUS.md) for what works, what still needs Docker-host verification, and what is not implemented.

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

1. Open **Runes** and choose a built-in rune.
2. Create the server and adjust its settings and resource limits.
3. Select **Install**. The console shows install output while the installer runs.
4. The status changes to **Running** only after the rune readiness pattern is seen; web runes also need to answer on their published web port.
5. Use **Console**, **Files**, and **Settings** on the server page.

The built-in runes are Minecraft Java, Minecraft Bedrock, Uptime Kuma, Vaultwarden, and Cloudflare Tunnel. Minecraft Java RCON is bound to loopback on the host. The panel allocates ports from `ports.range_min` through `ports.range_max`.

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

See [configuration](docs/configuration.md), [getting started](docs/getting-started.md), [HTTP API](docs/api.md), and the [rune schema](docs/runes.md).

## Network and security

The default listener is `0.0.0.0:8080`. Restrict it with the host firewall or set `server.host` to a trusted interface. If you put a reverse proxy in front, terminate TLS there and pass WebSocket `Upgrade` and `Connection` headers without buffering. The panel uses same-origin checks for browser mutations and does not enable cross-origin API access.

The service account belongs to Docker's `docker` group so it can manage containers through the Engine socket. Docker access is effectively root access on the host; protect the panel account, its credentials, and network exposure accordingly. Do not expose the Docker socket over TCP.

Yggdrasil has no telemetry or beacon in this release. The panel itself makes no outbound analytics requests; Docker pulls images when servers are installed or started.

## Development

```sh
GOCACHE=/tmp/yggdrasil-gocache GOMODCACHE="$HOME/go/pkg/mod" GOPROXY=off GOSUMDB=off go test -count=1 ./...
GOCACHE=/tmp/yggdrasil-gocache GOMODCACHE="$HOME/go/pkg/mod" GOPROXY=off GOSUMDB=off go vet ./...
node --test web/ui-utils.test.mjs
node --check --input-type=module < web/app.js
```

The project uses Go's standard library for its browser utility tests; no npm install is required. Local Docker acceptance tests still need a Debian or Ubuntu host with Docker Engine.
