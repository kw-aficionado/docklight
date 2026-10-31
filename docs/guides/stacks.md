# App stacks

An app stack turns one template and one server into a small, private Docker deployment. The server's main application and up to eight sidecars share a dedicated bridge network. Sidecar service names resolve as DNS names inside that network; for example, the WordPress template connects to `database:3306`.

## Included example

Choose **WordPress + MariaDB** from Templates, then create a server. Set separate, unique database and root passwords of at least 20 characters. Docklight encrypts these secrets in the panel database. The main WordPress container receives only the values mapped by its `docker.env`; MariaDB receives its own `stack.services[].env` values.

The main application's configured ports are published on the host. Sidecars have no host port bindings, so MariaDB is reachable only by containers on this server's network and by a host administrator with Docker access. Each bridge is isolated from other Docklight servers but retains normal outbound network access; it is not Docker's `internal` network mode.

## Lifecycle and data

- Docklight creates a deterministically named bridge with an ownership label for this server.
- It starts sidecars in template order, then starts the main application on the same network.
- Stop sends the configured graceful commands to the main application, stops it, then stops sidecars in reverse order.
- Restart removes and recreates the containers while keeping the network and persistent data.
- Delete removes sidecars and the network before deleting the server's data. If Docker cannot confirm cleanup, the server data remains for a safe retry.
- The main app binds only `<server data directory>/_app`; sidecar data binds below `<server data directory>/_stack/<service name>`. This keeps raw database files out of the main app's filesystem and Files tab.
- Backups archive the full server data root, so both `_app` and `_stack` are included in the same local and S3-compatible snapshot.
- CPU and memory limits apply to the whole stack. The main app receives weight 3; sidecars default to weight 1 and can set a value from 1 to 100.

Sidecar status is refreshed by the runtime monitor. If Docker cannot be reached, Docklight keeps the last known status. A confirmed missing or exited sidecar appears as **Needs attention** in the server overview; it does not silently change the main container's state.

This release does not allocate public ports for sidecars or wait for Docker health checks before starting the main app. Select **Logs** beside a service in the overview for its recent and live output. Log access requires `server.view`, verifies Docker ownership labels, and redacts template secret values. Sidecar command input is not exposed.

## Template authoring

Add `stack.services` to a template. Each service needs a DNS-safe name and an image. Set an absolute writable `data_path` for persistent services; leave it empty for stateless workers. The `enabled` value can use a declared boolean variable to make a sidecar optional; an unset placeholder keeps the sidecar off for existing servers. Sidecar environment values can interpolate declared variables with `{{KEY}}`; image references and command arguments may use non-secret variables. Flag credentials `secret: true` and map them through `env`; Docklight rejects secret interpolation into images and commands. Sidecar `env` is isolated to that sidecar. Main app variables must be mapped through `docker.env`.

`install.script` runs in a temporary container before the stack starts and does not have sidecar DNS access. Put runtime database initialization in the main app's startup or in the app image's own entrypoint. Sidecar logs are available from the overview; command input and sidecar health-check readiness waits are not exposed yet.

See [Template schema](../templates.md) for the complete field list and validation rules.
