# Server backups

Docklight stores encrypted local snapshots of each server's data directory. Open a server's **Backups** tab to create, verify, restore, delete, or prune snapshots.

## Create and restore

Stop the server before creating or restoring a backup. Docklight checks the saved server state and, when a container is recorded, asks Docker to confirm that it is stopped. This avoids copying a live database or world save midway through a write.

A backup is written to a temporary file, compressed, encrypted in authenticated chunks, checksummed, and verified before Docklight records it. The server data is never staged in memory as one large archive. Symlinks and special filesystem objects are refused. Restore verifies the checksum and encrypted archive before extracting to a staging directory, then swaps the restored directory into place while preserving the current data until activation succeeds.

Backups are stored under `<database directory>/backups/<server id>/` by default. Set `backups.path` to another local directory to place them on a mounted disk or filesystem. The panel creates backup directories with owner-only access and files with mode `0600`.

## Encryption key and recovery

Backup encryption derives its key from `auth.secret_key`. Keep that value, the SQLite database, and the backup files together. A new installation cannot decrypt these backups without the same secret key; changing or losing it also prevents decryption of stored server credentials and TOTP secrets.

## Retention

The default policy keeps the 10 most recent backups per server. Set `backups.retention` to a value from 1 to 100. Creating a backup applies retention automatically. The **Prune to retention** action can also be run at any time. The API accepts an optional `keep` value from 1 to 100 for a one-off prune.

Deleting a server also removes its local backups. Export or copy the backup directory before deleting a server if those snapshots must be retained.

## Schedules

Open a server's **Schedules** tab to schedule a backup, start, stop, or restart. Cron expressions accept five fields (`minute hour day month weekday`) or six fields with seconds first. Times use the panel host's local timezone. Schedules are enabled when created; they retain their history until deleted. The latest 50 runs are shown per schedule. A run records its outcome, and retention applies after a successful backup. The server must be stopped when a backup schedule fires; a running server produces a recorded failure and the next cron occurrence remains scheduled. A start on an already running server and a stop with no container are recorded as skipped.

Restart schedules can warn players using countdown commands declared in the template's `restart.warnings`. Choose a warning duration configured by that template, or turn warnings off to restart immediately. A warned restart runs in the background. If a manual action stops or replaces the server during its countdown, Docklight cancels the scheduled restart. Start, stop, and restart schedules need `server.schedule` and `server.control`; backup schedules need `server.schedule` and `server.backup`. Deleting the server removes its schedules and run history.

## Current limits

Backups are local only. SFTP, SMB, S3-compatible storage, Discord, Telegram, SMTP, and schedule-run notifications are not implemented yet. A generic signed webhook can report backup success and failure; see [notifications](notifications.md). Schedules are per-server; realm and global schedules are not available. Restore replaces the entire server data directory, not only selected files.
