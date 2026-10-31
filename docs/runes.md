# Rune schema

A rune (stored and exposed as a `gameskill`) describes a container image, settings, ports, lifecycle and optional protocols. It is a YAML document with one top-level `gameskill:` mapping. Imports are limited to 512 KiB.

## Supported shape

```yaml
gameskill:
  id: sample-app
  name: Sample App
  category: Apps
  version: 1
  description: Example containerized app
  docker:
    image: example/app:1
    data_path: /data
    user: "0:0"
    keep_entrypoint: true
    env:
      APP_MODE: "{{MODE}}"
    extra_volumes: [/var/lib/app]
  variables:
    - key: MODE
      name: App mode
      type: select
      options: [production, maintenance]
      default: production
      required: true
  startup:
    exec: [serve]
    done_regex: "ready on"
    stop: stop
    save_command: save-all
    stop_timeout: 30
  ports:
    - name: web
      default: 8080
      protocol: tcp
  query:
    type: a2s
  rcon:
    enabled: false
```

`docker.image` is required. At least one of `startup.command`, `startup.exec`, or `docker.keep_entrypoint: true` is required.

| Field | Behavior |
| --- | --- |
| `id`, `name`, `category`, `version`, `description` | Rune metadata. IDs use lowercase letters, digits, hyphens, and underscores. |
| `docker.image` | Image to pull for server startup. |
| `docker.data_path` | Container path backed by the server data directory; defaults to `/data`. |
| `docker.user` | Optional container UID:GID or username. Without `keep_entrypoint`, the panel sets a UID and mounts a minimal passwd shim. |
| `docker.keep_entrypoint` | If true, Docker keeps the image entrypoint and `startup.exec` is passed as its arguments. Otherwise the command replaces the image command. The passwd shim is skipped. |
| `docker.env` | Additional environment values with literal `{{KEY}}` substitutions. Declared variables and panel-reserved values are also injected. |
| `docker.extra_volumes` | Extra container paths backed by subdirectories in this server's data directory. Protected system paths are rejected. |
| `docker.capabilities` | Restricted allowlist: `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, `SYS_NICE`. |
| `docker.devices` | Restricted host device allowlist: `/dev/net/tun`, `/dev/dri`, `/dev/fuse`; optional container path and `rwm` permissions. |
| `docker.sysctls` | Restricted allowlist for selected forwarding sysctls. |
| `variables` | Form fields of type `string`, `int`, `bool`, or `select`; optional default, required, min/max, pattern, secret, and hint. |
| `install.image`, `install.script` | Optional temporary install container and shell script. The script runs as root with the data mounted at `/data`. |
| `startup.command` | Shell string run with `/bin/sh -c` when the image entrypoint is replaced. |
| `startup.exec` | Argument list for the container command. When `keep_entrypoint` is true these are entrypoint arguments. |
| `startup.done_regex` | Regular expression searched in recent container output to mark startup ready. |
| `startup.stop`, `startup.save_command` | Commands sent to container input before Docker's graceful stop. |
| `startup.stop_timeout` | Grace period in seconds before Docker kills the container. Defaults to 30. |
| `ports` | Container ports to publish. Protocol is `tcp`, `udp`, or `tcp+udp`; a free host port is allocated from config. A port named `rcon` binds to loopback. |
| `query.type` | `minecraft`, `minecraft-java`, `minecraft-bedrock`, `a2s`, or `source`. |
| `rcon` | Enables RCON commands using a declared `password_var`. The host mapping is loopback-only when its port is named `rcon`. |

Variable keys that conflict with panel-injected names (including `SERVER_NAME`, `HOME`, `PUID`, `PGID`, `UID`, `GID`, `PUBLIC_URL`, `PORT_*`, and `*_PORT`) are rejected. Secret variables are encrypted at rest and masked in API responses. Password/token/secret/private-key-like variable names are treated as secret even without `secret: true`.

## Validation and limits

The reader supports nested mappings, sequences, scalar values, inline lists, and literal/folded block strings. It is a bounded subset parser rather than a general YAML 1.2 implementation. Unknown fields are ignored, so use only fields listed here.

Container capabilities, devices, mounts, and sysctls are allowlisted to limit host access. `steam` installation metadata and `config_files` shortcuts are rejected because their behavior is not implemented; use the Files tab for editing data. Sidecars, backup hooks, importers, and registry credentials are not supported in this release.

Five built-in runes are embedded in the binary: Minecraft Java, Minecraft Bedrock, Uptime Kuma, Vaultwarden, and Cloudflare Tunnel. Built-in IDs cannot be overwritten or deleted. Community runes can be imported from the Runes page, subject to the same validation.
