# Decisions

## 2026-10-31: first implementation slice

- The workspace was empty, so this is a new implementation rather than an extension of an existing checkout.
- The local environment has no Docker executable or daemon, and DNS lookup for `proxy.golang.org` fails. Docker-dependent acceptance checks cannot run here, and dependencies are limited to modules already present in the Go cache.
- The Docker Engine is accessed through its versioned HTTP API over the configured Unix socket instead of the Docker SDK. This keeps builds reproducible offline and CGO-free while retaining the same Engine behavior.
- JWT HS256, WebSocket framing, and the small YAML subset needed by the template schema are implemented in this repository because their upstream modules were unavailable during the first slice. These boundaries are documented and covered by local tests; browser passkeys were postponed from that slice and are now implemented with the vetted WebAuthn module below.
- The web interface is a self-contained embedded HTML/CSS/JavaScript app rather than Svelte/Tailwind. No frontend packages are cached and the machine has no package-registry DNS. The shipped interface has no CDN or runtime network dependency.
- The initial release targets the functional Phase 1 core. Phase 2-4 features remain out of scope and will be listed in STATUS.md rather than shown as working controls.

## Additional Phase 1 decisions

- API tokens use 256-bit random opaque values with a `ygg_` prefix. Only a SHA-256 hash and the token name/scope metadata are stored; the plaintext is returned only by the create response. Every API-token permission is intersected with the owner's current RBAC grants.
- Schema changes use a numbered `schema_migrations` table. The second migration adds a safe startup error field and the API-token lookup index; old tables are upgraded in place.
- The standalone browser app uses a small ES module for shared escaping/number formatting and Node's built-in test runner. This gives the UI logic a dependency-free test path while package registries are unreachable.
- `PUBLIC_URL` is derived at runtime from an explicitly configured listener host or a current non-loopback host address, so DHCP changes are not persisted into template settings.
- Readiness is a state transition, not an optimistic default. A timeout or Docker inspection failure sets an actionable error state and leaves the container record intact for diagnosis.


## 2026-10-31: Docklight identity and local backups

- The public product name is **Docklight**. Its visual language is dark graphite with aqua accents and a warm light point; the geometric mark represents a lit container bay. User-facing template terminology replaces mythology-themed labels.
- **Relay** and **Launchdeck** are alternate naming directions; Docklight is selected because it evokes container operations and clear status without tying the product to a region or game genre. The name and logo direction are also recorded in `docs/brand.md`.
- The `yggdrasil` binary, CLI, systemd service, Go module, database tables, and `/api/gameskills` resource names remain intact during this implementation so the rebrand does not break existing deployment paths or stored data.
- The official product domain is `docklight.app`; it is recorded in the brand guide, repository overview, and browser application metadata.
- The first Phase 2 vertical slice is local encrypted backups. Archives stream through gzip and chunked AES-GCM, use the existing `auth.secret_key`, and require a stopped server for consistent copies. Retention defaults to 10. Restore verifies the full archive before overlaying its files, preserving paths absent from the backup and rolling back writes if an overlay operation fails. The later S3-compatible destination is tracked in `STATUS.md`.
- Schedules support server, realm, and global scopes for backups, starts, stops, restarts, updates, console commands, and templated messages. Server schedules use effective scoped permissions; only admins can create, edit, run now, or delete realm/global schedules. Realm membership is resolved at every firing, and scoped run history records each target separately while retaining 100 records per schedule and returning the latest 50. A fleet update waits for each target to return to running and stops dispatching after three consecutive update failures; player-online skips do not count toward the limit. Numeric cron expressions use host-local time. Console commands and snapshotted message templates/values are encrypted at rest with `auth.secret_key`, and are omitted from API responses, run history, and audit details. Five built-in message templates are seeded; only admins can manage custom templates. Templates declare their own restart-warning commands and durations; a restart schedule can select one duration shared by every current target or run without warnings. Query-capable templates can skip a restart or update when a player query reports anyone online; query failure proceeds and is recorded rather than risking a false skip. Countdown execution is cancellable when the server is manually changed. Signed webhook events report schedule success and failure with schedule identity and action, but exclude run details and do not notify skipped actions.
- The outgoing webhook supports backup outcomes, confirmed container crashes, and low-disk alerts. Administrators control it; endpoint and signing key are encrypted with `auth.secret_key`, and optional HMAC signatures let receivers verify requests. HTTPS is required except localhost loopback testing, and redirects are disabled so request signatures or URL tokens are not forwarded. Dedicated Discord, Telegram, and SMTP channels remain separate work.
- Runtime crash history waits 60 seconds after panel startup, requires Docker Engine ping to succeed, and confirms stopped or missing state with two matching inspections at least 15 seconds apart. This avoids turning a slow Docker boot or an unreachable Engine into a false incident. Confirmed exits move the server to an attention state and preserve its data; automatic restart is separate work.
- Low-disk alerts monitor the filesystem containing Docklight's data directory every five minutes. They fire below 10% free, persist an active latch across restarts, and rearm at 15% free. The webhook names the server-data and backup paths; the monitor does not walk a potentially large filesystem or delete data, and other mounts are outside this first slice.
- Automatic recovery is opt-in per query-capable server. The watchdog checks every 20 seconds with a 3-second timeout, requires three consecutive failures, and applies a four-minute cooldown. It retries a failed restart three times with 15-second spacing. The brief's appendix gives conflicting quarantine limits (“more than five” versus “five”); the implementation quarantines after the fifth successful recovery in 30 minutes. Cooldown timestamps, heal history, opt-in, and quarantine persist across panel restarts. A manual start or stop clears the quarantine and counters.

## 2026-10-31: S3-compatible backup destination

- The first remote target is S3-compatible storage with a small in-repository REST client and Signature Version 4. Path-style requests work with Amazon S3 and common self-hosted implementations without adding an SDK dependency to the offline build.
- Signed requests use HTTPS, except for loopback HTTP endpoints used by a local emulator. Redirects are rejected so signatures and credentials cannot be forwarded to another host. Administrators create buckets out of band; the connectivity check tests object upload and deletion only.
- S3 uploads stream from the archive producer through a bounded multipart uploader; they do not spool the finished archive to local disk. Docklight downloads the just-written object and validates its checksum, encryption, and archive contents before adding the retention record.
- Endpoint and access credentials are encrypted with `auth.secret_key` and omitted from API responses. Existing object identity (endpoint, bucket, region, prefix) is fixed while S3 backup rows exist; key rotation stays allowed. Scheduled backups persist either `local` or `s3`, require an enabled S3 target when created, and record a failed run if that target is disabled later.
- The API and lifecycle use an injected object store for deterministic tests. A gated test performs real Put/Get/Delete against a user-provided S3-compatible emulator; it remains pending until an emulator is available.

## 2026-10-31: private per-server app stacks

- A template may declare 1–8 sidecars. Docklight gives the server a dedicated ownership-labeled user-defined bridge; sidecar names become private DNS aliases and no sidecar publishes host ports. The bridge is not Docker's `internal` network, so apps retain normal outbound access while their sidecars remain isolated from other Docklight servers.
- The main app mounts only `<server data root>/_app`; sidecar data lives in `<server data root>/_stack/<service>`, outside the main app filesystem and Files tab. Existing full-directory local and S3 backups already cover both. Install containers do not join the runtime network; apps that need a database should initialize during runtime startup.
- CPU and memory ceilings are allocated once across the stack: main app weight 3, sidecars weight 1 by default or a template-defined weight. This prevents a stack from multiplying the server's configured limits.
- Secret environment values are materialized only into the containers whose template environment maps reference them. Sidecar state and container IDs are persisted in SQLite; confirmed missing or exited services are surfaced in the server overview while an unknown Docker error preserves the last known state.
- Sidecars may omit `data_path` when they are stateless and may use a templated `enabled` boolean. An unresolved enabled placeholder evaluates false to avoid unexpectedly starting a newly added optional service on servers created from an older template version.
- Sidecar logs use the existing WebSocket log channel with the same secret redaction. The handler checks `server.view`, verifies the service name against the template, and confirms Docker ownership labels before streaming. It does not accept commands.
- Sidecar images with a Docker healthcheck must report healthy within one two-minute window before the main app starts. Services without a declared healthcheck do not delay startup; health failure rolls back the stack before the app container is created.
- A deterministic fake Docker Engine test covers the lifecycle and rollback path. The private-services overview supports permission-scoped logs and one-shot commands. Live image compatibility, networking, app readiness, and the browser review still require a Docker-host acceptance run.

## 2026-10-31: public Docklight status page

- The public page is disabled on fresh installs and requires both an administrator's panel-wide switch and a per-server opt-in. This prevents a public route from revealing server names by default.
- The public payload contains only the selected server's display name, template name, normalized availability, and an optional recent player count. It omits IDs, ports, addresses, and configuration.
- Player counts are sampled when an authenticated panel user successfully queries a server. Public requests never open game-protocol connections; counts older than 15 minutes are omitted.
- The HTML and refresh script are embedded with the panel. The JSON cache lasts 15 seconds and is invalidated by title, selection, master-switch, and player-sample changes. The page is marked `noindex`, which requests that compliant crawlers skip it but does not act as access control.

## 2026-10-31: realms and scoped access

- Existing servers are assigned to realms during migration 19 using their template category; missing templates and blank categories fall back to `Default`. New servers without an explicit realm use the category realm, while realm-only `server.create` grants require the caller to choose their realm.
- Realm names are unique without regard to ASCII letter case. Deleting a realm detaches servers, removes realm grants, and cascades per-user collapsed preferences; it does not alter server data or runtime state.
- Server grants combine with OR logic across global, realm, template, and server scopes. Realm listings omit inaccessible metadata and calculate counts from the caller's visible servers. API-token scopes remain an additional upper bound.
- Collapsed sections are stored per user. The admin realm manager owns CRUD, ordering, and server moves; the server overview groups authorized servers by realm.

## 2026-10-31: WebAuthn passkeys

- Passkeys use `github.com/go-webauthn/webauthn` for ceremony and signature verification rather than custom cryptography. Discoverable credentials and required user verification support username-free sign-in and account recovery when TOTP is enabled.
- Each account gets an opaque random 64-byte WebAuthn user handle on first passkey registration; usernames and email addresses are not used as handles. Credential records are encrypted with the existing panel secret, while the credential ID remains indexed for credential lookup.
- Challenges and library session state live in server memory, are one-use, and expire within five minutes. The RP ID is derived from the request hostname; the origin is bound to the matching host and HTTPS (or localhost). `X-Forwarded-Proto` supplies the external scheme behind TLS termination.
- Browser flows are implemented with the existing embedded JavaScript app. A physical authenticator and a live HTTPS deployment are still required for full device-level acceptance.

## 2026-10-31: SFTP and SMB backup protocols

- The existing single remote target now supports S3-compatible, SFTP, or SMB storage. The selected protocol and connection fields are stored in the existing target row; endpoint and credentials remain encrypted with `auth.secret_key`. Migration 20 adds protocol and port fields while defaulting existing target rows to S3.
- SFTP uses the Go SSH/SFTP libraries with password authentication. SSH host-key verification remains disabled to match the supplied brief; use a trusted network or tunnel. SMB uses the native SMB2 client with NTLMv2 authentication.
- Remote records lock the protocol, host, port, bucket or share, region, and prefix. Credentials can rotate without changing the object key identity. One remote destination is configured at a time.
- The SFTP integration test uses an in-process SSH/SFTP server over buffered `net.Pipe`; SMB has constructor and target-management coverage. No separate live SFTP or SMB server was available for acceptance.

## 2026-10-31: Docklight template catalogs

- No public catalog organization was provided for Docklight, so the app does not invent or hard-code one. Administrators explicitly save the repositories they trust; unsourced templates are checked against those saved catalogs.
- GitHub uses its HTTPS API host. Gitea and Forgejo use an administrator-saved HTTPS base URL. Redirects are stopped, YAML downloads are bounded to 512 KiB, browse results are cached for ten minutes, and browsing exposes only the configured folder plus one child level.
- Repository access tokens and the optional panel-wide GitHub API token are encrypted using `auth.secret_key`. Repository tokens are loaded only for the exact saved repository and host; the panel-wide token is never attached to non-GitHub requests.
- Installed templates keep source host, repository, file path, and ref. Update checks compare versions by template ID and only report candidates; applying an update remains an explicit admin action. Removing a repository leaves provenance intact so checks can report that the source is gone.

## 2026-10-31: private image registry credentials

- Store one encrypted credential per normalized registry. Docker Hub aliases use `docker.io`; image matching follows Docker's rule that a registry is explicit in the first path component only when it contains a dot, a port, or is `localhost`.
- Send the selected credential only in Docker Engine's `X-Registry-Auth` header for that individual image pull. The auth-check route uses `POST /auth`; the panel does not call `docker login` or persist auth in Docker's daemon/host credential store.
- Use the same app pull helper for runtime, sidecars, install containers, and the BusyBox ownership helper so no pull path silently bypasses saved logins. Tests use an injected Engine HTTP client; live private-registry pulls remain part of host acceptance.

## 2026-10-31: multiple notification transports

- Preserve the original signed webhook settings and add encrypted channel records for Discord, Telegram, generic JSON webhooks, and SMTP rather than breaking the existing webhook API. A channel can be global or server-scoped; delivery remains asynchronous without retries or stored history.
- Remote SMTP must establish TLS before auth; STARTTLS is used when advertised and port 465 uses implicit TLS. Telegram's Bot API requires its token in the HTTPS request path, so failures use generic messages and request URLs are never logged or returned.
- Channel editing re-enters credentials because saved configuration is never returned. Existing event filters remain attached to the original webhook; new channels receive all supported events within their scope.

## 2026-10-31: email password recovery

- Reuse the first enabled global SMTP email channel for account recovery, overriding only its configured notification recipient with the account's unique email. Server-scoped channels are excluded.
- Forgot requests use one generic response and IP/identifier rate limits. Store a SHA-256 token hash for one hour, consume it once in the same transaction as the password/session-version update, and preserve TOTP.
- Set `server.public_url` to the canonical origin so reset links do not trust a forwarded request Host. If absent, fall back to the validated request origin as specified. The login UI strips the token query parameter as soon as it loads and the panel uses `no-referrer`.

## 2026-11-01: Docker Compose import

- The importer accepts one Compose YAML document up to 1 MiB and uses `go.yaml.in/yaml/v3`; generated Docklight templates are marshaled, parsed by the panel rune parser, and validated before storage.
- When multiple services publish ports, explicit `main` wins, then a conventional `web`/`app`/`server`/`main`/`game`/`frontend` name, then Compose file order. If no service publishes ports, the first declared service is used. The browser exposes an optional main-service override.
- Host ports are not preserved because Docklight owns conflict-free allocation. Named Compose volumes map to Docklight-managed `_app` and `_stack` storage; Compose volume contents are not migrated. Additional sidecar paths live under `_stack/<service>/_extra/<container-path>` and are included by the existing server-root backup archive.
- Host-IP port bindings cannot be represented by the current port model. The importer therefore drops explicit non-wildcard bindings, including localhost-only ports, instead of widening them to all interfaces.
- Bind mounts are omitted with warnings. Administrators can re-add them after creating the server, choosing the matching main or sidecar container in Settings → Host mounts.
- Values whose environment-key names signal passwords, tokens, secrets, keys, DSNs, or credential-bearing URLs are discarded during import and represented by secret template variables with no default. Operators enter those values when creating a server; this keeps them out of template YAML and import responses.
- Compose interpolation, `build`, custom commands and entrypoints, dependency health ordering, and service networks are not translated. The importer returns specific warnings and does not attempt to execute a Compose project or read its `.env` files.

## 2026-11-01: Pterodactyl egg and XML imports

- Keep both importers as data-only translators. Never run egg install entrypoints/scripts during import; the XML and egg outputs must pass the Docklight rune validator before storage.
- Sort Pterodactyl `docker_images` and `config.files` keys so repeated imports of the same JSON produce the same selected image and path order, despite JSON object ordering.
- Keep the XML importer limited to the documented `<gameskill>` subset; ignore unrelated elements and reject malformed fields through the shared rune validator.
- Strip defaults for variables whose names look like credentials before the generated YAML is marshaled. Return only a generic warning so secret values cannot escape through responses or audit details.
- Treat imports like manual local edits: upsert non-built-in IDs, clear catalog provenance, and refuse any built-in ID collision in a transaction.
- Make validated `config_files` useful in the server UI: list only existing paths as Files-tab shortcuts, keep edits behind the existing `server.files` permission, and preserve comments/unsupported lines when the key/value form editor is used.

## 2026-11-01: public host detection and reachability probes

- Store the optional public hostname in a singleton database row rather than startup config so administrators can change it from the Network page without restarting the panel.
- Use the user brief's ipify JSON endpoint with a three-second timeout, one-hour successful cache, and a short retry backoff. Keep the last successful address after a failed refresh; do not replace a usable value with an empty result.
- Probe only the server's declared query/game port, use its Rune query protocol when present and TCP otherwise, with a four-second deadline and a 30-second cache.
- Resolve the host before connecting and never send a probe to loopback, unspecified, or multicast addresses. Report that NAT loopback can make an otherwise reachable public service look offline.


## 2026-11-01: administrator host mounts

- Store mounts in `servers.host_mounts` and expose them only through admin-only routes, because host paths reveal filesystem layout and bind mounts grant a container host access.
- Resolve symlinks before applying the source denylist; also exclude Docklight data and backup roots. Validate sources again at container start.
- Keep mounts read-only unless `write` is explicitly enabled. Store container selection so a stack mount is only shared with the chosen sidecar; an empty service targets the primary container. Apply saved changes on the next start.
- Docker Engine bind sources are interpreted on the daemon host, so the panel's browse results are useful only when the daemon sees the same absolute path.

## 2026-11-01: UPnP router port forwarding

- Keep UPnP disabled globally on fresh installs; new and migrated servers keep a separate per-server auto-forward preference enabled by default. Only the admin can change the global gate.
- Implement only the IPv4 UPnP IGD WANIPConnection v1/v2 and WANPPPConnection v1 actions Docklight needs, using the Go standard library so offline builds do not acquire another network dependency.
- Restrict SSDP `LOCATION` to the private IPv4 address that sent the response, prohibit redirects, cap description/SOAP bodies, and require service control URLs to stay on the discovered router authority.
- Check the exact external port/protocol before adding a rule. Persist Docklight's intended target and marker before changing the router; cleanup re-reads the current rule and deletes only if the remote host, protocol, ports, LAN client, and marker still match.
- Use permanent leases as requested. Skip RCON and names that indicate admin, management, or console ports. A router outage leaves mapping records for retry; uncertain container state never triggers rule deletion.
- A real router and public-NAT path were not available in the sandbox, so protocol fixtures verify SOAP/SSDP handling and fake gateways verify mapping ownership and lifecycle policy.

## 2026-11-01: UniFi port forwarding

- Store the controller URL and site in migration 30, encrypt the local username and password with the panel secret, and keep a distinct admin master switch. Reuse each server's existing `auto_forward` preference across UPnP and UniFi.
- Use the controller's local cookie login and classic site `rest/portforward` API with redirects disabled. The brief explicitly allows self-signed HTTPS certificates. Ubiquiti documents local APIs per installed Network version, so the classic endpoint must remain isolated and real-controller acceptance must confirm compatibility.
- Tag generated entries with `Docklight: [docklight:<server-id>]`. Delete only rules whose parsed tag exactly equals the server ID; do not infer ownership from port numbers or targets. An admin can explicitly remove selected unmatched Docklight-prefixed rules, while other rules remain untouched.
- Before replacing credentials, site, or controller URL, and before disabling the integration, remove exact-tagged rules using the saved configuration. If cleanup fails, preserve the old settings and report the conflict.
- Fake-controller HTTP fixtures cover login, rule listing, creation, and deletion. No live UniFi controller is present for end-to-end acceptance.

## 2026-11-01: Nginx Proxy Manager

- Keep NPM independent of UPnP and UniFi: NPM has its own admin master switch and per-server hostname, and does not use `auto_forward`.
- Encrypt the NPM password with the panel secret. Keep saved host IDs and cleanup errors per server so stop, deletion, setting changes, and retries operate only on Docklight's recorded host.
- Create and persist the plain proxy host before requesting a certificate, so its NPM ID is known even if ACME fails. Clear Docklight metadata while NPM creates the certificate because NPM passes proxy-host metadata into the certificate record, then restore the marker on the host. Keep the saved plain host on certificate failure and surface a warning.
- Use the connected NPM account's profile email for Let's Encrypt. NPM's current API does not accept a separate contact address; the optional Docklight contact field must match the account email or remain blank.
- Prefer the declared TCP `web` port and then the first declared TCP port; skip UDP-only servers. Forward to the configured internal host or the host LAN IPv4 address selected by the route to NPM.
- The fake API covers token authentication, bearer requests, proxy creation and deletion, certificate fallback, and pending-cleanup retry. A live NPM controller, public DNS, and reachable ACME HTTP challenge were unavailable.

## 2026-11-01: Cloudflare Tunnel routes and DNS

- Store the API token encrypted in a dedicated settings row. Test the account by reading the remote tunnel configuration and resolving the configured zone only when the operator has not supplied a zone ID; never call the token verification endpoint.
- Keep the full tunnel `config` object as raw JSON fields and replace only `ingress`. Preserve unmanaged rules and config properties, put Docklight's HTTP host rule before the terminal `http_status:404`, and avoid PUT when the desired route is already present.
- Record each server's hostname and HTTP service so cleanup removes only its unchanged ingress rule. Delete DNS only after listing the hostname and confirming the CNAME still points to `<configured tunnel ID>.cfargotunnel.com`; never delete a foreign target.
- Save the route before upserting proxied DNS, as requested. A DNS conflict or API failure leaves the tunnel route active with a warning so periodic reconciliation can retry. A tunnel configuration read/write failure prevents DNS provisioning.
- Run reconciliation at panel startup and every ten minutes. Server lifecycle cleanup failures keep the saved server route state for retry and block server deletion when ownership cannot be checked safely.
- Forward to the allocated TCP web port or first TCP port. An unset internal host uses the LAN IPv4 address selected by the route to Cloudflare. A configured IP no longer assigned to a local interface falls back to that current LAN address and emits a log warning.
- The first slice includes the admin Network settings card, per-server hostname field, lifecycle integration, encrypted settings migration 32, and an admin-only endpoint listing all configured Tunnel hostnames. The Domains page also lists primary Cloudflare/NPM routes with RBAC filtering, guarded public probes, conflict labels, and 30-second caching. Extra route rows, IP blocking, and live Cloudflare account acceptance remain outstanding.

## 2026-11-01: managed IP blocking

- Default the global IP-blocking switch off. Accept only one globally routable IPv4/IPv6 address per rule; refuse private, local, link-local, Cloudflare, CGNAT/Tailscale, documentation, benchmarking, reserved, administrator-allowlisted, and recently used administrator addresses. Keep the recent-admin safety history for 30 days and support up to 256 explicit IP/CIDR entries as an additional block guard.
- Prefer a zone-scoped Cloudflare IP Access Rule and use its note as Docklight ownership proof. Never delete a rule solely because its IP matches; require the Docklight marker and verify the saved address and `block` mode. Reject pre-existing foreign IP rules instead of claiming them.
- Make host nftables opt-in and bind it to the Docklight-marked `inet yggdrasil` table only. Drop web ingress TCP 80/443 without touching SSH or game ports; require explicit `CAP_NET_ADMIN`, and refuse an unmarked existing table.
- Keep expiration and external state in SQLite and reconcile at startup and every minute. Persist pending Cloudflare intent before API creation so a timeout can be recovered by ownership note rather than creating duplicates.
- The `off`/`propose`/`auto` mode is reserved for the planned Kvasir workflow; manual blocks are the only source implemented here. No Cloudflare account or privileged host-firewall acceptance was available.
