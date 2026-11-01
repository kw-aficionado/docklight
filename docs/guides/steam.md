# Steam-enabled templates

Steam-enabled templates use SteamCMD in their install script. Docklight supplies the persistent cache, account authorization flow, and port mapping needed by those templates; the template author remains responsible for the SteamCMD commands and app ID.

## Authorize an account

1. Open **Templates → Steam account** as an administrator.
2. Enter the Steam account name and password. Docklight starts a short-lived SteamCMD container and asks Steam to send a Guard code.
3. Enter the code from Steam Support email or the Steam Mobile app to finish authorization.

The password stays in panel memory only while waiting for the code, for up to five minutes. Docklight does not save or return the password or Guard code. SQLite stores the account name, authorization flag, and authorization time. The panel's persistent `steam-cache/` directory holds SteamCMD's sentry data so future runs can reuse the authorization. Remove the account from the same dialog to revoke the saved status and clear that cache. Remove the old account before switching to a different username.

SteamCMD access requires Docker and outbound network access to Steam. Docklight uses the `steamcmd/steamcmd:debian-12` image for the authorization helper and requests its `linux/amd64` variant. The upstream image currently publishes that tag for amd64; on an ARM64 Docker host, install and enable working x86-64 emulation first. The game server image has its own architecture requirements. Steam Guard login follows Valve's [Steamworks SteamCMD instructions](https://partner.steamgames.com/doc/sdk/uploading).

## Template behavior

Add a `steam` block to the Rune:

```yaml
gameskill:
  id: sample-steam-server
  name: Sample Steam Server
  category: Games
  version: 1
  docker:
    image: example/server:latest
    keep_entrypoint: true
  install:
    script: steamcmd +force_install_dir /data +login "$STEAM_USER" +app_update 123456 validate +quit
  startup:
    exec: ["./server", "-port={{GAME_PORT}}"]
  ports:
    - name: game
      default: 27015
      protocol: udp
  steam:
    app_id: 123456
    anonymous: false
```

The panel does not interpret `app_id`; the install script passes it to SteamCMD. `anonymous: false` requires the authorized account and injects its username as `STEAM_USER`. Without authorization, installation stops with:

> This game requires an authorized Steam account. Authorize one under Settings → Steam first.

When `anonymous: true`, the installer can log in anonymously and receives no `STEAM_USER`. The Steam cache is still mounted at `/steamcache`, and install-time `HOME` is set to that path. Docklight prefixes the install script with `chmod -R a+rwX /data 2>/dev/null || true` and sets the host app-data directory mode to `0777` for games whose container user writes the mounted data.

Each declared port is published on the same host port as its container port. Choose unique ports that are free on the host; Docklight reports a conflict if the number is already reserved or bound. For Steam templates, using the game port in the startup command keeps the advertised and published ports aligned.

See the full [template schema](../templates.md) and [Steam account API](../api.md#steam-account). The SteamCMD image's available Debian tags are listed in its [official source repository](https://github.com/steamcmd/docker).
