# DayZ Economy

The server detail page shows an **Economy** tab for a server using a Rune with the ID `dayz`. Reading the summary requires `server.view`; changing settings requires `server.control`. The panel reads the configured `MISSION` variable, defaulting to `dayzOffline.chernarusplus`, beneath `<server data root>/mpmissions`.

## Review the mission

The summary counts named types and finds the shortest positive `<lifetime>` in `db/types.xml` plus `types` files registered by the mission's `cfgeconomycore.xml`. A lifetime below one hour is flagged. Other registered files carry a **Modded** badge. The scanner lists additional valid XML files in mission subfolders, skips `storage*` directories, never follows a file symlink, and stops after 20,000 entries, 128 MiB read, or 256 candidates. The page warns when a scan limit is reached.

## Adjust lifetimes

**Minimum lifetime** accepts 0–8760 hours. A positive floor raises only numeric `<lifetime>` values where the current value is greater than zero and below the floor. The panel changes only those number spans, preserving the rest of each XML file. Setting the floor to zero stops later floor applications; it does not restore the older values.

**Cleanup lifetimes** edits only these `globals.xml` variables, in seconds: `CleanupLifetimeDefault`, `CleanupLifetimeRuined`, `CleanupLifetimeDeployed`, `CleanupLifetimeDeadPlayer`, `CleanupLifetimeLimit`, `CleanupLifetimeDeadAnimal`, and `CleanupLifetimeDeadInfected`. Values must be non-negative 32-bit integers.

## Register mission files

Select a candidate to add its `<file name="…" type="types" />` entry to the mission's `<ce folder="…">` registration block. The panel requires a valid `<types>` root and named type entries with numeric lifetimes. Existing registrations and unrelated mission XML are retained.

Changes are written to mission files immediately; restart DayZ to load them. The selected minimum lifetime, cleanup variables, and registered file paths are saved by Docklight and reapplied after a successful install or scheduled template update. Missing saved registration files cause a clear install/update error so a fresh mission is not started with a broken CE reference. **Clear saved automation** deletes Docklight's saved settings only; it does not undo the XML changes.

Docklight does not run Norn, install mods, or manage Workshop load order in this slice. Mission file names and registration structure follow [Bohemia's Central Economy mission-file guide](https://community.bistudio.com/wiki/DayZ:Central_Economy_mission_files_modding); cleanup variables follow its [Central Economy configuration reference](https://community.bistudio.com/wiki/DayZ:Central_Economy_Configuration).
