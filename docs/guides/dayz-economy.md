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

## Import loot from installed mods

The **Loot from installed mods** section scans top-level `@mod` folders for XML documents with named `<type>` entries and integer `<lifetime>` values. The scan skips links and `storage*` directories and stops at 20,000 entries, 128 MiB read, or 256 candidates. It reads the displayed name from `meta.cpp` when available, sanitizes it for a mission folder, and otherwise uses the mod folder name. Expansion candidates are marked as managing their own economy; that is informational and does not block import.

Select files to copy them beneath `<MISSION>/<SanitizedModName>/`, preserving their path within the mod folder, and register them in `cfgeconomycore.xml`. A loose fragment of direct `<type>` elements is wrapped in `<types>`; a complete valid `<types>` document is retained. Existing mission target files and target collisions are skipped. The configured minimum lifetime floor is applied after copying and registration.

Docklight stores each source-to-target mapping with the registered paths. After a successful install or scheduled update, it restores missing imported copies first, rewrites CE registrations, then reapplies cleanup globals and the lifetime floor. It does not overwrite an existing imported target during recovery. **Clear saved automation** forgets these mappings but leaves both source and mission files in place. Restart DayZ to load mission changes. File layout and CE registration follow [Bohemia's Central Economy mission-file guide](https://community.bistudio.com/wiki/DayZ:Central_Economy_mission_files_modding) and its [Central Economy configuration reference](https://community.bistudio.com/wiki/DayZ:Central_Economy_Configuration).

Docklight does not download mod content or change Workshop load order here. The separate **Mods** tab edits only the compatible Rune's declared load-order setting.
