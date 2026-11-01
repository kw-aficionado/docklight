# DayZ dedicated server

Docklight's built-in `dayz` Rune installs the Linux dedicated server with SteamCMD and runs it as the Docklight service UID. It needs an amd64 Docker host or working x86-64 emulation on ARM64.

## Install and start

1. As an administrator, authorize a Steam account under **Templates → Steam account**. The DayZ server app requires an authorized account; see [Steam account setup](steam.md).
2. Create a server from the **DayZ** template. Set the in-game name, optional join password, admin password, player limit, and third-person preference.
3. Select **Install**. Docklight downloads and validates the DayZ Dedicated Server app (Steam app ID `223350`) in the persistent server data directory.
4. Leave the server in **Starting** until its Steam A2S query on UDP 2305 responds. First launch can take several minutes.

By default, the template publishes UDP 2302 for the game, UDP 2304 for client connections, and UDP 2305 for the Steam query. Allow them through the host firewall and any router/NAT. Steam templates preserve their declared host ports, so these defaults allow one DayZ instance per host. See [Bohemia's Linux hosting guide](https://community.bistudio.com/wiki/DayZ:Hosting_a_Linux_Server) and [server configuration reference](https://community.bistudio.com/wiki/DayZ:Server_Configuration).

## Configuration and access

Docklight generates `serverDZ.cfg` each time the container starts. Rune settings control the hostname, join password, admin password, player limit, third-person view, client port, query port, and default Chernarus mission. Edits to this generated file are replaced on the next start; change the Rune settings instead.

The join and admin passwords are encrypted in panel storage, but the generated config file contains them as plain text. Limit `server.files` access and protect server backups accordingly. The Rune starts the bundled BattlEye directory and keeps signature verification enabled. Docklight's **Moderation**, **Economy**, and **Mods** tabs are available for servers using this template. DayZ file bans apply to future join attempts and do not disconnect a player already online.

## Mods

Set `MODS` to a comma, semicolon, or whitespace-separated list of existing mod folder names or numeric Workshop IDs. Numeric IDs map to `@<id>` folder names. Folder names cannot contain spaces. Startup stops with a clear message if a listed folder is missing.

Docklight does not download or remove Workshop files in this template. Stage each `@mod` directory and its trusted `.bikey` file in the server data directory before adding it to `MODS`; the **Mods** tab can then change load order and add existing folders. See [DayZ mods](dayz-mods.md).

Mod files are included in server backups and can be large, so account for their storage and recovery time. More detail on supported settings and file access is in the [template schema](../templates.md).
