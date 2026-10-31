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
| `stack.services[]` | Optional list of 1–8 sidecars started on a dedicated network for this server. Each service requires a DNS-safe `name` and `image`. `data_path` is optional for stateless workers; when present it binds persistent, backup-covered data. `extra_volumes` adds more persistent container paths. `enabled`, `user`, `command`, `env`, and `resource_weight` are optional. |
| `stack.services[].extra_volumes` | Additional absolute, validated container paths backed by `_stack/<service>/_extra/<path>`; included in server backups and kept outside the main app's file root. Duplicate and protected system paths are rejected. |
| `stack.services[].enabled` | Optional templated boolean. Empty means enabled; true/1/yes/on and false/0/no/off are accepted. An unresolved placeholder disables the service so new opt-in services stay off for older servers. |
| `stack.services[].env` | Sidecar-only environment values. `{{KEY}}` references declared template variables; secret values are decrypted only for the containers that use them. Secrets are rejected from image references and command arguments. |
| `stack.services[].resource_weight` | Relative CPU and memory share when server limits are set. Main app weight is 3; sidecars default to 1 and may set 1–100. All containers share the one server limit. |
| `query.type` | `minecraft`, `minecraft-java`, `minecraft-bedrock`, `a2s`, or `source`. |
| `rcon` | Enables RCON commands using a declared `password_var`. The host mapping is loopback-only when its port is named `rcon`. |

Variable keys that conflict with panel-injected names (including `SERVER_NAME`, `HOME`, `PUID`, `PGID`, `UID`, `GID`, `PUBLIC_URL`, `PORT_*`, and `*_PORT`) are rejected. Secret variables are encrypted at rest and masked in API responses. Password/token/secret/private-key-like variable names are treated as secret even without `secret: true`.

## Validation and limits

The reader supports nested mappings, sequences, scalar values, inline lists, and literal/folded block strings. It is a bounded subset parser rather than a general YAML 1.2 implementation. Unknown fields are ignored, so use only fields listed here.

Container capabilities, devices, mounts, and sysctls are allowlisted to limit host access. `steam` installation metadata and `config_files` shortcuts are rejected because their behavior is not implemented; use the Files tab for editing data. Rune-defined app-data import steps and backup hooks are not supported in this release. Private image access is managed by an administrator under **Templates → Registry access**; saved logins cover runtime images, sidecars, install images, and update pulls.

Six built-in templates are embedded in the binary: Minecraft Java, Minecraft Bedrock, Uptime Kuma, Vaultwarden, WordPress + MariaDB, and Cloudflare Tunnel. Built-in IDs cannot be overwritten or deleted. Community templates can be imported from the Templates page, subject to the same validation.

Sidecars receive a stable DNS alias equal to their service name, share only their server's user-defined bridge with the main app, and currently do not publish host ports. The main app receives only its `_app` data bind; persistent sidecar data stays under `_stack/<service name>`, outside the main app's filesystem and Files tab. Backups archive the full server data root and include both. The panel starts enabled sidecars in declaration order before the main app, stops them after the main app in reverse order, and removes them with the server. Startup install containers do not join the stack network; app initialization that needs a database belongs in the main app's runtime startup.

## Catalog repositories

Administrators can save GitHub, Gitea, and Forgejo repositories from **Templates → Catalog repositories**. An empty host selects GitHub. Other hosts must be HTTPS base URLs; Docklight contacts only hosts named by saved repositories and does not follow redirects. A repository can set its own folder, branch or tag, and optional access token. Repository tokens and the optional panel-wide GitHub token are encrypted with `auth.secret_key`; a repository token is used only for that repository, and the panel-wide GitHub token is sent only to GitHub's API host.

The browser lists `.yaml` and `.yml` files up to 512 KiB and folders at the repository root plus one subfolder level. Successful folder listings are cached for 10 minutes. Catalog YAML passes the same parser and privilege checks as an upload. Installing a known ID updates that community template; built-in IDs are rejected. Each installed catalog template records its host, repository, file path, and ref. A manual YAML or Compose import of an existing catalog template clears that provenance and becomes the locally managed version.

## Docker Compose import

Administrators can import one Compose YAML document from **Templates → Import Compose**. The API accepts a multipart `file` field and optional `main` service and display `name`; raw YAML is also accepted with `main` and `name` query parameters. Files are limited to 1 MiB. Docklight chooses a main service from published ports and common service names, or the administrator can name it explicitly. Other services with pullable images become sidecars on the private per-server network.

Short-form main-service ports are converted to container ports and Docklight allocates free host ports. Specific host-IP bindings are dropped because the panel cannot preserve them; localhost-only ports are never widened to all interfaces. Named volumes become Docklight-managed persistent paths on the main service and sidecars, but existing Compose volume contents are not copied. Bind mounts are reported as warnings and omitted. This checkout does not yet expose per-server host-mount controls, so copy required files into Docklight-managed storage before installing the imported template. The importer also reports dropped `build`, network, command, environment-file, health-check, dependency, and other unsupported settings. Compose interpolation is not evaluated. Values for environment keys that look secret are not stored; the template prompts for those values when creating a server. The importer validates and round-trips the generated template before saving it. Re-importing a non-built-in ID updates the existing template; built-in IDs are protected.

**Check updates** compares versions by template ID and reports a missing saved source or network error instead of treating it as current. It only lists; applying an update is an explicit administrator action. Checks do not run on startup or on a timer. No remote catalog is preconfigured: add a repository you trust before browsing or checking templates that do not have recorded source metadata. See the [API reference](api.md) for repository and GitHub token routes.

## Private container registries

Administrators manage private image credentials from **Templates → Registry access**. Save one username and password or access token per registry hostname; Docker Hub spellings normalize to `docker.io`, and hostnames are lowercased. Docker image references are matched using Docker's registry split rules, so `nginx:latest` and `team/nginx:latest` use the Docker Hub login while `ghcr.io/team/nginx:latest` uses a `ghcr.io` login. Host and port must match for private registries.

Credentials are encrypted with `auth.secret_key`. Runtime app images, stack sidecars, temporary install images, and the ownership helper's Docker Hub image use the same per-pull lookup. The login test calls Docker Engine's auth-check endpoint. See [access and security](guides/security.md) and the [API reference](api.md).
