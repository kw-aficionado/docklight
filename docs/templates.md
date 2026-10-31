# Template schema

A server template describes a container image, settings, ports, lifecycle and optional protocols. For API compatibility, it is stored under the `gameskill` resource name and uses one top-level `gameskill:` YAML mapping. Imports are limited to 512 KiB.

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
  stack:
    services:
      - name: database
        image: mariadb:11
        data_path: /var/lib/mysql
        user: "0:0"
        resource_weight: 1
        env:
          MARIADB_DATABASE: "{{DB_NAME}}"
          MARIADB_PASSWORD: "{{DB_PASSWORD}}"
  query:
    type: a2s
  rcon:
    enabled: false
  restart:
    warnings:
      - at: 5m
        msg: say Server restart in 5 minutes.
      - at: 1m
        msg: say Server restart in 1 minute.
```

`docker.image` is required. At least one of `startup.command`, `startup.exec`, or `docker.keep_entrypoint: true` is required.

| Field | Behavior |
| --- | --- |
| `id`, `name`, `category`, `version`, `description` | Template metadata. IDs use lowercase letters, digits, hyphens, and underscores. |
| `docker.image` | Image to pull for server startup. |
| `docker.data_path` | Container path backed by the server app-data directory; defaults to `/data`. For stack templates the main app gets only `<server data directory>/_app`, leaving sidecar data outside its mount. |
| `docker.user` | Optional container UID:GID or username. Without `keep_entrypoint`, the panel sets a UID and mounts a minimal passwd shim. |
| `docker.keep_entrypoint` | If true, Docker keeps the image entrypoint and `startup.exec` is passed as its arguments. Otherwise the command replaces the image command. The passwd shim is skipped. |
| `docker.env` | Additional main-app environment values with literal `{{KEY}}` substitutions. Single-container templates also receive declared variables; stack templates should map the variables the main app needs here. Panel-reserved values are injected in both cases. |
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
| `restart.warnings[]` | Optional countdown points for scheduled restarts. `at` is a Go duration up to 24 hours; `msg` is a complete console command sent through RCON when available, then stdin. `{{server_name}}`, `{{minutes}}`, and `{{seconds}}` are available. |
| `ports` | Container ports to publish. Protocol is `tcp`, `udp`, or `tcp+udp`; a free host port is allocated from config. A port named `rcon` binds to loopback. |
| `stack.services[]` | Optional list of 1–8 sidecars started on a dedicated network for this server. Each service requires a DNS-safe `name` and `image`. `data_path` is optional for stateless workers; when present it binds persistent, backup-covered data. `enabled`, `user`, `command`, `env`, and `resource_weight` are optional. |
| `stack.services[].enabled` | Optional templated boolean. Empty means enabled; true/1/yes/on and false/0/no/off are accepted. An unresolved placeholder disables the service so new opt-in services stay off for older servers. |
| `stack.services[].env` | Sidecar-only environment values. `{{KEY}}` references declared template variables; secret values are decrypted only for the containers that use them. Secrets are rejected from image references and command arguments. |
| `stack.services[].resource_weight` | Relative CPU and memory share when server limits are set. Main app weight is 3; sidecars default to 1 and may set 1–100. All containers share the one server limit. |
| `query.type` | `minecraft`, `minecraft-java`, `minecraft-bedrock`, `a2s`, or `source`. |
| `rcon` | Enables RCON commands using a declared `password_var`. The host mapping is loopback-only when its port is named `rcon`. |

Variable keys that conflict with panel-injected names (including `SERVER_NAME`, `HOME`, `PUID`, `PGID`, `UID`, `GID`, `PUBLIC_URL`, `PORT_*`, and `*_PORT`) are rejected. Secret variables are encrypted at rest and masked in API responses. Password/token/secret/private-key-like variable names are treated as secret even without `secret: true`.

## Validation and limits

The reader supports nested mappings, sequences, scalar values, inline lists, and literal/folded block strings. It is a bounded subset parser rather than a general YAML 1.2 implementation. Unknown fields are ignored, so use only fields listed here.

Container capabilities, devices, mounts, and sysctls are allowlisted to limit host access. `steam` installation metadata and `config_files` shortcuts are rejected because their behavior is not implemented; use the Files tab for editing data. Backup hooks, importers, and registry credentials are not supported in this release.

Six built-in templates are embedded in the binary: Minecraft Java, Minecraft Bedrock, Uptime Kuma, Vaultwarden, WordPress + MariaDB, and Cloudflare Tunnel. Built-in IDs cannot be overwritten or deleted. Community templates can be imported from the Templates page, subject to the same validation.

Sidecars receive a stable DNS alias equal to their service name, share only their server's user-defined bridge with the main app, and currently do not publish host ports. The main app receives only its `_app` data bind; persistent sidecar data stays under `_stack/<service name>`, outside the main app's filesystem and Files tab. Backups archive the full server data root and include both. The panel starts enabled sidecars in declaration order before the main app, stops them after the main app in reverse order, and removes them with the server. Startup install containers do not join the stack network; app initialization that needs a database belongs in the main app's runtime startup.
