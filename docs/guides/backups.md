# Server backups

Docklight stores encrypted snapshots of each server's data directory. Open a server's **Backups** tab to create, verify, restore, delete, or prune snapshots. Backups can be written to local panel storage or to one configured S3-compatible destination.

## Create and restore

Stop the server before creating or restoring a backup. Docklight checks the saved server state and, when a container is recorded, asks Docker to confirm that it is stopped. This avoids copying a live database or world save midway through a write.

A backup is written to a temporary file, compressed, encrypted in authenticated chunks, checksummed, and verified before Docklight records it. The server data is never staged in memory as one large archive. Symlinks and special filesystem objects are refused. Restore verifies the checksum and encrypted archive before extracting to a staging directory. It overlays archived files onto the existing data directory and leaves files absent from the archive untouched. If a file or directory conflicts with the archived path, or an unsafe filesystem object is present, restore stops and rolls back changes already made.

Local backups are stored under `<database directory>/backups/<server id>/` by default. Set `backups.path` to another local directory to place them on a mounted disk or filesystem. The panel creates backup directories with owner-only access and files with mode `0600`.

## S3-compatible destination

Administrators configure S3 storage from **Backup storage** in the Docklight sidebar. Create the bucket first, then enter its HTTPS endpoint, bucket name, region, optional object prefix, access key, and secret key. Plain HTTP is accepted only for a loopback endpoint used by a local emulator. Docklight uses path-style requests and Signature Version 4; verify that the provider supports this S3 API mode.

The endpoint and credentials are encrypted with `auth.secret_key`. API responses show the endpoint and bucket but never return the access key or secret. The connection check uploads and deletes a temporary object under the configured prefix. Allow `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, and `s3:AbortMultipartUpload` for that prefix; create the bucket separately. Provider policy syntax may differ for S3-compatible services.

The server's **Backups** tab offers the S3 destination after an administrator enables it. Docklight streams the archive into a signed upload, uses multipart upload for larger archives, then downloads and verifies the remote copy before saving its database record. Verification and restore download into a mode-`0600` temporary file under panel server-data storage before checking the saved checksum and encrypted archive. Ensure that filesystem has enough temporary space for the backup being restored.

Retention uses `server_backups` database records, never a bucket listing. Automatic and manual prune remove the recorded S3 object before deleting its row. Deleting a server removes its local and recorded remote backups; if a remote delete fails, server-data cleanup stops and the error identifies the affected backup. While S3 backup records exist, Docklight locks the endpoint, bucket, region, and prefix so those records continue to identify their objects. You can rotate credentials without changing that target identity. Delete the S3 backup records first if you need to move to another bucket or prefix.

When creating a backup schedule, choose panel storage or the enabled S3-compatible destination. The selected destination is retained with the schedule; if S3 is later disabled or its credentials stop working, the run is recorded as a failure. Choose S3 from the server's Backups tab for a manual remote copy.

## Encryption key and recovery

Backup encryption derives its key from `auth.secret_key`. Keep that value, the SQLite database, and the backup files together. A new installation cannot decrypt these backups without the same secret key; changing or losing it also prevents decryption of stored server credentials and TOTP secrets.

## Retention

The default policy keeps the 10 most recent backups per server. Set `backups.retention` to a value from 1 to 100. Creating a backup applies retention automatically. The **Prune to retention** action can also be run at any time. The API accepts an optional `keep` value from 1 to 100 for a one-off prune.

Deleting a server also removes its recorded backups from local and S3 storage. Export any copies that must outlive the server before deleting it.

## Schedules

Open a server's **Schedules** tab to schedule a backup, start, stop, restart, console command, or message. Cron expressions accept five fields (`minute hour day month weekday`) or six fields with seconds first. Times use the panel host's local timezone. Schedules are enabled when created; they retain their history until deleted. The latest 50 runs are shown per schedule. A run records its outcome, and retention applies after a successful backup. The server must be stopped when a backup schedule fires; a running server produces a recorded failure and the next cron occurrence remains scheduled. A start on an already running server and a stop with no container are recorded as skipped.

Restart schedules can warn players using countdown commands declared in the template's `restart.warnings`. Choose a warning duration configured by that template, or turn warnings off to restart immediately. Templates with a player-query protocol also offer **Skip the restart if players are online**. If the query reports players, that run is skipped; if the query cannot return a count, Docklight proceeds with the restart and records the unavailable count. A warned restart runs in the background. If a manual action stops or replaces the server during its countdown, Docklight cancels the scheduled restart. A console-command schedule accepts one line, encrypts it at rest, and sends it through RCON or server stdin only while the server is running; the command itself is not shown in schedule or run-history responses. A message schedule is available on Minecraft Java and Bedrock; it selects a built-in or admin-created template and supplies its numeric placeholders. Template bodies are single Minecraft console commands and may use `{{server_name}}`, `{{minutes}}`, and `{{seconds}}`. Docklight snapshots the selected body and values in encrypted storage; editing or deleting a template does not change an existing schedule. Messages send only while the server is running and are not shown in schedule or run-history responses. Start, stop, and restart schedules need `server.schedule` and `server.control`; backup schedules need `server.schedule` and `server.backup`; console-command schedules need `server.schedule` and `server.console`; message schedules need only `server.schedule`. Admins manage custom message templates from **Templates**. Deleting the server removes its schedules and run history.

## Current limits

SFTP and SMB destinations are not implemented yet. The S3 integration uses an in-repository REST client; run the gated emulator acceptance in `internal/backup/s3_test.go` by setting `DOCKLIGHT_S3_TEST_ENDPOINT`, `DOCKLIGHT_S3_TEST_BUCKET`, `DOCKLIGHT_S3_TEST_REGION`, `DOCKLIGHT_S3_TEST_ACCESS_KEY`, and `DOCKLIGHT_S3_TEST_SECRET_KEY`. A generic signed webhook can report backup and scheduled-action success or failure; see [notifications](notifications.md). Schedules are per-server; realm and global schedules are not available.
