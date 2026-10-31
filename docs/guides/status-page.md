# Public status page

Docklight can publish a small read-only status page at `/status`. It is disabled on a fresh install and stays unavailable until an administrator enables it.

## Choose what visitors can see

Open **Public status** in the administrator sidebar. Set a page title, enable the master switch, and select the servers to publish. A server appears only when both the master switch and its individual checkbox are on. The page returns `404` while the master switch is off, including its script and JSON endpoint.

The public summary contains a server's display name, template name when available, and one of three states: `online`, `starting`, or `offline`. Uninstalled servers always appear offline. The summary does not include server IDs, ports, connection addresses, environment variables, or panel settings. Visitors can still see the names and template names you selected, so opt in only the servers you want to identify publicly.

## Player counts and freshness

Docklight records a sample after a successful player query from the authenticated panel. The public page displays the latest `online` and `max` counts only while that sample is less than 15 minutes old. Unknown, failed, and stale counts are omitted. The status endpoint never performs a live query against game servers.

The public JSON at `/api/status` has a 15-second cache lifetime. The page refreshes every 30 seconds. Changing the title, master switch, selected servers, or a newly recorded player sample clears Docklight's in-process cache.

## Public routes

- `/status` serves the branded, responsive Docklight page.
- `/status.js` serves its same-origin refresh script.
- `/api/status` returns `title`, `updated_at`, and a `servers` array.
- `GET` and `PUT /api/settings/status-page` are administrator-only settings endpoints. The update body contains `enabled`, `title`, and a complete `server_ids` selection.

The page includes `noindex,nofollow` metadata and an `X-Robots-Tag` header. This asks compliant search engines not to index the page; it does not restrict access. Keep the master switch off if the selected service names should remain private.
