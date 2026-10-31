# Server backups

Docklight stores encrypted snapshots of each server's data directory. Open a server's **Backups** tab to create, verify, restore, delete, or prune snapshots. Backups can be written to local panel storage or one configured remote destination: S3-compatible, SFTP, or SMB.

## Create and restore

Stop the server before creating or restoring a backup. Docklight checks the saved server state and, when a container is recorded, asks Docker to confirm that it is stopped. This avoids copying a live database or world save midway through a write.

A backup is compressed, encrypted in authenticated chunks, checksummed, and verified before Docklight records it. Server data is streamed; the panel does not load one complete archive into memory. Symlinks and special filesystem objects are refused. Restore verifies the checksum and encrypted archive before extracting to a staging directory. It overlays archived files onto the existing data directory and leaves files absent from the archive untouched. If a file or directory conflicts with the archived path, or an unsafe filesystem object is present, restore stops and rolls back changes already made.

Local backups are stored under `<database directory>/backups/<server id>/` by default. Set `backups.path` to another local directory to place them on a mounted disk or filesystem. The panel creates backup directories with owner-only access and files with mode `0600`.

## Remote destinations

Administrators configure one remote destination from **Backup storage** in the Docklight sidebar. Only one protocol can be active at a time: S3-compatible storage, SFTP, or SMB. The connection check uploads a temporary test file and removes it again. Credentials and the host or endpoint are encrypted with `auth.secret_key`; API summaries report whether credentials are saved without returning them.

SFTP uses password authentication on port `22` by default. Enter the server host, username, password, and optional path prefix. Docklight currently does not validate SSH host keys, so connect only across a trusted network or tunnel.

SMB uses NTLMv2 authentication on port `445` by default. Enter the host, share name, username, password, and optional path prefix. Create the share and grant the account access before testing the destination.

S3-compatible storage uses an HTTPS endpoint, bucket name, region, access key, secret key, and optional object prefix. Plain HTTP is accepted only for a loopback endpoint used by a local emulator. Docklight uses path-style requests and Signature Version 4; verify that the provider supports this S3 API mode. Allow `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, and `s3:AbortMultipartUpload` for the configured prefix; create the bucket separately.

The server's **Backups** tab offers the configured remote protocol after an administrator enables it. Docklight streams the encrypted archive to the destination, then downloads and verifies its checksum and archive contents before adding the database record. S3 uses multipart uploads for larger archives. Verification and restore use a mode-`0600` temporary file under panel server-data storage. Ensure that filesystem has enough temporary space for the backup being restored.

While remote backup records exist, Docklight locks the configured protocol, host, port, bucket or share, region, and prefix. Credentials can be rotated. Delete those remote backup records before moving to another destination. Retention uses database records rather than listing remote storage, and server deletion removes each recorded remote object before deleting server data.

## Encryption key and recovery

Backup encryption derives its key from `auth.secret_key`. Keep that value, the SQLite database, and the backup files together. A new installation cannot decrypt these backups without the same secret key; changing or losing it also prevents decryption of stored server credentials and TOTP secrets.

## Retention

The default policy keeps the 10 most recent backups per server across local and remote storage. Set `backups.retention` to a value from 1 to 100. Creating a backup applies retention automatically. The **Prune to retention** action can also be run at any time. The API accepts an optional `keep` value from 1 to 100 for a one-off prune.

Deleting a server also removes its recorded backups from local and remote storage. Export any copies that must outlive the server before deleting it.

## Schedules

Open a server's **Schedules** tab to schedule a backup, start, stop, restart, update, console command, or message. Cron expressions accept five fields (`minute hour day month weekday`) or six fields with seconds first. Times use the panel host's local timezone. Schedules are enabled when created; they retain their history until deleted. The latest 50 runs are shown per schedule. A run records its outcome, and retention applies after a successful backup. A backup schedule keeps its selected destination; if the remote destination is disabled, changed to another protocol, or unreachable, the run is recorded as a failure. The server must be stopped when a backup schedule fires; a running server produces a recorded failure and the next cron occurrence remains scheduled. A start on an already running server and a stop with no container are recorded as skipped.

Restart schedules can warn players using countdown commands declared in the template's `restart.warnings`. Choose a warning duration configured by that template, or turn warnings off to restart immediately. Templates with a player-query protocol also offer **Skip if players are online** for restart and update schedules. If the query reports players, that run is skipped; if the query cannot return a count, Docklight proceeds and records the unavailable count. A warned restart runs in the background. If a manual action stops or replaces the server during its countdown, Docklight cancels the scheduled restart. An update stops the server, reruns its template installer against the existing data directory when one is configured, pulls the current server image, and creates a fresh container. Server data is retained. The update run waits for the installer and container start request to complete; readiness monitoring continues in the background.

A console-command schedule accepts one line, encrypts it at rest, and sends it through RCON or server stdin only while the server is running; the command itself is not shown in schedule or run-history responses. A message schedule is available on Minecraft Java and Bedrock; it selects a built-in or admin-created template and supplies its numeric placeholders. Template bodies are single Minecraft console commands and may use `{{server_name}}`, `{{minutes}}`, and `{{seconds}}`. Docklight snapshots the selected body and values in encrypted storage; editing or deleting a template does not change an existing schedule. Messages send only while the server is running and are not shown in schedule or run-history responses. Start, stop, restart, and update schedules need `server.schedule` and `server.control`; backup schedules need `server.schedule` and `server.backup`; console-command schedules need `server.schedule` and `server.console`; message schedules need only `server.schedule`. Updates can be created only for installed servers. Admins manage custom message templates from **Templates**. Deleting the server removes its schedules and run history.

## Current limits

SFTP has been tested with an in-process SSH/SFTP server and the panel's backup lifecycle has fake-store coverage. SMB has client configuration, fake-store create/verify/delete, and target-management coverage. Neither protocol has been accepted against a separate live host in this environment. The S3 integration uses an in-repository REST client; run the gated emulator acceptance in `internal/backup/s3_test.go` by setting `DOCKLIGHT_S3_TEST_ENDPOINT`, `DOCKLIGHT_S3_TEST_BUCKET`, `DOCKLIGHT_S3_TEST_REGION`, `DOCKLIGHT_S3_TEST_ACCESS_KEY`, and `DOCKLIGHT_S3_TEST_SECRET_KEY`. A generic signed webhook can report backup and scheduled-action success or failure; see [notifications](notifications.md). Schedules are per-server; realm and global schedules are not available.
