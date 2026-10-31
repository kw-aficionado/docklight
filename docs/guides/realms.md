# Realms and access

Realms group servers in the Docklight overview and provide a permission scope for teams. Administrators manage them from **Manage → Realms**. Realm names are trimmed, required, limited to 80 characters, and unique; names that differ only by ASCII letter case are treated as a clash. Descriptions can contain up to 500 characters.

## Placement and migration

When a server is created without `realm_id`, Docklight places it in a realm named after the template category. The realm is created the first time it is needed. Existing servers are assigned during database migration 19 using their template category; servers whose template is missing or has no category use **Default**. Servers can be left unassigned by deleting a realm or moving them to **Unassigned**.

Administrators can move a server between realms from the realm manager. Moving a server changes which realm-scoped grants apply to it. It does not change the server's data, container, port reservations, or template.

## Permissions

Access grants are combined with OR logic across global, realm, template (`gameskill`), and server scopes. A grant on a realm or template also applies to servers created there later. API-token scopes further restrict the account's effective permissions. Administrators bypass grants, subject to their token scopes.

`server.create` is checked against the selected realm and template. A user with a realm-only create grant must choose that realm; automatic template-category placement requires a global or matching template create grant. Realm-level `server.view`, control, console, file, backup, schedule, and delete grants apply to the servers currently in that realm.

The admin **Users & access** editor can set global, realm, template, and server grants. Saving replaces the selected user's complete grant set. Deleting a realm detaches its servers and removes grants and per-user collapse preferences associated with it.

## Per-user grouping

Each user can collapse a realm in the server overview. Docklight stores this preference on the server per user, so one person's layout does not change another person's view. Non-admin realm listings include only realms with at least one visible server or a create grant; server counts reflect only servers visible to that caller.

## API

- `GET /api/realms` returns visible realms with `server_count`, `can_create`, and the caller's `collapsed` preference.
- `PUT /api/realms/{id}/collapsed` accepts `{"collapsed":true}` for the caller's preference.
- Admin-only `POST /api/realms`, `PUT /api/realms/{id}`, `DELETE /api/realms/{id}`, and `POST /api/realms/reorder` create, edit, delete, and reorder realms.
- Admin-only `PUT /api/servers/{id}/realm` accepts `{"realm_id":"…"}`; an empty ID leaves the server unassigned.
- `POST /api/servers` accepts optional `realm_id`; omit it to use template-category placement.
