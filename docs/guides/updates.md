# Docklight panel updates

Panel updates apply to the Docklight control panel binary. They do not update game server images or server data; use each server's **Update** action for that.

## Check a release

Sign in as an administrator and open **Manage → Panel updates**. Docklight checks the GitHub repository embedded in the release build and shows the installed version, latest stable release, update capability, and last updater result. The public `GET /api/version` result is cached for six hours. **Check now** forces a fresh GitHub lookup.

Docklight compares only stable semantic tags in the form `vX.Y.Z`. A prerelease, malformed tag, equal version, or older version is not offered for installation.

## Install manually

When the installed build has the updater helper and systemd units, choose **Install**. The panel writes the selected version to `/var/lib/yggdrasil/.update-request`; it does not run a privileged command. A root-owned systemd path unit starts the separate oneshot updater. The updater downloads the architecture-matched binary and `SHA256SUMS` from the configured GitHub release over HTTPS, checks the SHA-256 value, verifies the binary reports the requested version, saves the previous binary, installs the new one, and restarts Docklight. It records progress in `/var/lib/yggdrasil/.update-status`, visible on the updates screen.

If the service restart fails, the helper tries to restore and restart the saved binary. The status reports whether rollback recovered the service. Back up the Docklight database, configuration, and secret key before major host maintenance as part of normal operations.

## Enable automatic updates

Automatic updates are off by default. An administrator can opt in and select a local hour from 0 to 23. The panel checks every 20 minutes, queues at most one newer release per local day after that hour, and leaves running game containers alone. The same release validation and root updater path are used as for a manual install.

## Configure the release repository

Official release builds embed their `OWNER/REPOSITORY`. When installing from a source checkout, the installer detects a GitHub `origin`, or accepts an explicit repository:

```sh
sudo env YGG_SOURCE_DIR="$PWD" YGG_REPO="OWNER/REPOSITORY" bash install.sh
```

The installer writes the repository for the root updater and installs its systemd units. A source build with no repository, a custom binary without embedded repository metadata, a non-release version such as `dev`, or a nonstandard data path remains manually updated. The **Panel updates** page shows the reason self-update is unavailable. `YGG_BINARY_URL` and `YGG_BINARY_FILE` remain supported for manual/custom installations.

## API

See [the HTTP API reference](../api.md#templates-and-servers) for `GET /api/version`, release check and queue actions, updater status, and automatic-update settings. The version summary is public; queueing and settings are administrator-only.
