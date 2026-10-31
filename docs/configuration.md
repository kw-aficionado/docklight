# Configuration reference

The installer creates `/etc/yggdrasil/config.yaml`. `yggdrasil gen-config [PATH]` creates the same block-style YAML format and refuses to overwrite an existing file. The installer sets the file to `root:yggdrasil` mode `0640`; the daemon needs read access, not write access during normal operation.

The config reader supports scalar block-style YAML for these keys. Unknown keys fail startup with a line number. Quotes around scalar values are accepted; nested objects and general YAML features are not supported.

| Key | Default | Meaning |
| --- | --- | --- |
| `server.host` | `0.0.0.0` | Listener interface. Set to a trusted host address to avoid listening on every interface. |
| `server.port` | `8080` | HTTP listener port, from 1 through 65535. |
| `database.path` | `/var/lib/yggdrasil/yggdrasil.db` | SQLite database path. Server directories are stored beside the database in `servers/`. |
| `auth.secret_key` | generated | At least 32 characters. Used for signed sessions and AES-GCM secret encryption. Keep it stable and back it up with the database. |
| `auth.session_ttl_hours` | `168` | Session lifetime in hours; must be at least 1. |
| `admin.username` | `admin` | Username created when the database has no enabled administrator. |
| `admin.password` | generated on first config | One-time bootstrap password. It is removed from the config after the administrator is created. |
| `docker.socket` | `unix:///var/run/docker.sock` | Docker Engine Unix socket. The daemon account must have permission to use it. |
| `docker.api_version` | `v1.45` | Versioned Docker Engine HTTP API prefix. |
| `backups.path` | `<database directory>/backups` | Local encrypted backup directory. Relative paths resolve against the database directory. Keep it outside `servers/`. |
| `backups.retention` | `10` | Number of recent local and S3 backups retained per server; from 1 through 100. |
| `ports.range_min` | `25000` | First host port eligible for allocation; minimum is 1024. |
| `ports.range_max` | `30000` | Exclusive upper bound for allocated host ports; maximum is 65535. |

`server.demo_mode` is accepted but ignored for compatibility with early generated configs. It is not written by the current generator.

## Example

```yaml
server:
  host: 192.168.1.20
  port: 8080
database:
  path: /var/lib/yggdrasil/yggdrasil.db
auth:
  secret_key: replace-with-a-generated-secret-at-least-32-characters
  session_ttl_hours: 168
admin:
  username: admin
docker:
  socket: unix:///var/run/docker.sock
  api_version: v1.45
backups:
  path: /var/lib/yggdrasil/backups
  retention: 10
ports:
  range_min: 25000
  range_max: 30000
```

Do not change `auth.secret_key` after servers or TOTP have been configured: encrypted secrets will no longer decrypt and existing sessions will stop validating. To rotate it safely, a future migration/rotation command is required; it is not available in this release.

Local backup files use the same key. Keep `auth.secret_key` with the SQLite database and backup directory so a restored installation can decrypt them.
