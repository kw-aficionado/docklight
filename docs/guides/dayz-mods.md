# DayZ mods

Servers using a DayZ Rune with a `MODS` variable have a **Mods** tab. Reading it requires `server.view`; editing the list requires `server.control`. Docklight does not assume that a compatible third-party Rune uses this variable: the page explains when its template does not expose `MODS`.

## Load order and files

Docklight parses `MODS` values separated by semicolons, commas, or whitespace. It shows each token's matching `@mod` folder in the server data directory, plus any unlisted `@mod` folders found there. Folder scans are bounded to 10,000 entries and ignore symlinks. Orphan folders can be added without copying or changing their files.

Move entries up and down to save a permutation of the current list. **Remove broken** removes only items Steam confirms were removed; unknown status and missing folders stay because they may be waiting for the next update. The per-entry **Remove** action removes a token from `MODS` and leaves its folder untouched. Docklight applies the changed `MODS` value through the Rune on its next Update or Reinstall; the Mods tab does not download or delete mod content itself.

## Workshop status and search

Workshop status checks send all numeric IDs in the list in one public Steam API request, with a six-second deadline. An unavailable response is shown as unknown (`?`). DayZ Workshop search requires an administrator-saved Steam Web API key. Docklight encrypts the key in SQLite, masks it in the UI, and sends it only to Steam from the panel backend. A search result can be added to `MODS`, but Workshop files and signing keys must be staged in the server data directory separately before the server starts. See the [built-in DayZ setup guide](dayz-server.md).

Steam's official API documents the public [published-file detail request](https://partner.steamgames.com/doc/webapi/ISteamRemoteStorage) and the authenticated [Workshop search query](https://partner.steamgames.com/doc/webapi/IPublishedFileService). DayZ's server `-mod` option accepts semicolon-separated folder paths, as described in [Bohemia's server configuration reference](https://community.bistudio.com/wiki/DayZ:Server_Configuration).
