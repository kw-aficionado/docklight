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
- The installable Docklight app uses a dependency-free web manifest and service worker. The worker caches only the embedded static shell, keeps API and session data network-only, and versions its cache from the embedded shell contents.
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
- At the time the first remote backup targets were added, SFTP used password authentication without host-key verification; a later decision below replaces that behavior with an administrator-pinned SHA-256 fingerprint. SMB uses the native SMB2 client with NTLMv2 authentication.
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
- The `off`/`propose`/`auto` mode is reserved for future Assistant workflows; manual blocks are the only source implemented here. No Cloudflare account or privileged host-firewall acceptance was available.

## 2026-11-01: additional server hostnames

- Store each additional full hostname and optional declared TCP port in a separate `server_routes` row, with independent Cloudflare and NPM ownership, error, and cleanup state. Primary hostnames continue to use their existing server settings.
- Check hostname collisions against primary and additional routes before provisioning. Cloudflare hostnames must fit its configured base domain; NPM accepts the full hostname and does not create DNS records.
- Record the Cloudflare ingress service and DNS record ID before deleting owned objects. Delete DNS only when that ID still names the recorded CNAME and it still targets the configured Tunnel. Do not adopt or remove an unrecorded pre-existing DNS record just because it points at the same Tunnel.
- Mark NPM proxy hosts with Docklight server and route IDs. Use saved host IDs plus those markers for cleanup and recovery, leaving foreign hosts untouched.
- Keep route rows when provider cleanup fails, then retry at server lifecycle changes and the ten-minute provider reconcilers. Extra hostnames require live Cloudflare, NPM, and public-DNS acceptance; those services were not available in this environment.

## 2026-11-01: Docklight usage beacon

- Send exactly a random installation UUID and build version, and disclose the literal payload on the first administrator sign-in. Keep the sender on by default as specified, but store the one-click opt-out in SQLite so upgrades cannot silently re-enable it.
- Use `https://beacon.docklight.app/api/beacon` as the Docklight-branded default collector instead of the original Yggdrasil domain in the brief. The collector stores instance ID, version, timestamps, and a ping count; it does not persist source IP addresses.
- Keep collection and publication independent: the receiver is off by default, and the public count is a second opt-in with a minimum population threshold. Do not ship panel analytics.
- Schedule the first check 30 seconds after startup and subsequent checks every 30 minutes. Record a day only after a successful response, retry failures, and bypass the daily limit only when a build version changes or an administrator explicitly opts back in.

## 2026-11-01: Docklight panel self-update

- Keep privilege separation explicit: the sandboxed panel may create one validated version request in the standard data directory, while a dedicated root oneshot performs network retrieval, checksum/version validation, installation, and service restart.
- Embed the GitHub repository into official release builds and allow `YGG_REPO` or a GitHub source remote to configure an installation. Do not infer a repository from an arbitrary binary URL.
- Restrict requests to strictly newer stable `vX.Y.Z` tags. Follow only HTTPS redirects to GitHub release assets, verify the release `SHA256SUMS`, and run the downloaded binary's `--version` before replacing the installed binary.
- Save a rollback copy before installation and attempt to restore and restart it if the new panel fails to restart. Keep atomic status for the admin UI and make automatic updates opt-in, host-local-hour based, and limited to one queue per day.
- The current source checkout has no GitHub release owner configured, and no Debian/Ubuntu systemd host was available for live updater acceptance.

## 2026-11-01: central player moderation

- Keep the ban list authoritative in Docklight SQLite and track desired/applied state per ban and server. Global bans include current servers and are discovered for servers created later; revoked or expired bans queue unban commands only where delivery state indicates one may have been applied.
- Let templates declare one-line `ban_command` and `unban_command` strings rather than assuming a shared game command. Substitute only player, player ID, and reason after removing control characters. A successful RCON/stdin send is an acknowledgement of command delivery, not proof that the game persisted its ban.
- Watch only newly streamed log output, parse patterns with Go's linear-time RE2 implementation, and count threshold hits per rule/server/player. Keep counters in memory and reset them after restart or rule edits so stored text is not replayed as an action.
- Record violation actions in Docklight audit history and expose them as an opt-in legacy webhook event. Keep DayZ's `ban.txt` file format in an explicit `dayz-ban-file` adapter, not a console command, and require a validated player UID.
- At the time this moderation adapter was added, the checkout had no built-in DayZ template and no live game-server acceptance. The adapter preserves other UID lines and atomically replaces the root `ban.txt`; DayZ's `disableBanlist` setting must stay false. It adds rejoin protection and cannot kick connected players.

## 2026-11-01: template anti-cheat guidance

- Read anti-cheat capability notes only from the selected template and show them as escaped plain text in a server detail tab gated by `server.files`.
- Keep the feature informational. Do not infer installed protection from the template alone, install plugins, or change user-owned config files.
- The Minecraft Java note follows Paper's official docs: Anti-Xray is a Paper feature, disabled by default, and configured in `config/paper-world-defaults.yml`; the template makes it conditional on selecting Paper.

## 2026-11-01: DayZ Economy controls

- Use the neutral product name **Economy** in Docklight instead of the brief's mythological feature label; require the Rune ID `dayz` and enforce `server.view` for summaries and `server.control` for edits.
- Patch only numeric lifetime/global value spans so comments and surrounding XML remain intact. Restrict cleanup edits to the seven named lifetime globals and reject links, special files, path traversal, and oversized XML.
- Save the minimum floor, cleanup values, and registered type paths in SQLite and reapply them after successful installs and scheduled updates. Reset clears that saved state without attempting to reverse XML edits.
- This is a compatible-template feature, not a built-in DayZ Rune. Workshop management and importing mod loot remain separate follow-up work; no live DayZ server acceptance was available.

## 2026-11-01: DayZ Mods manager

- Work only through a compatible DayZ Rune's declared `MODS` value; keep folder downloads under that Rune's Update/Reinstall behavior rather than introducing a second downloader.
- Restrict file discovery to top-level safe `@mod` directories and never follow symlinks. Save only a permutation for reordering; automatic cleanup removes only items Steam confirms are removed. A missing folder can be waiting for the next template update, so an operator removes that entry explicitly.
- Use Steam's public batched detail request for status. Keep search separate behind an admin-saved encrypted Steam Web API key; unknown API results do not count as broken.
- At the time this DayZ Mods slice was added, there was no built-in DayZ Rune or live DayZ/Steam acceptance in this checkout.

## 2026-11-01: DayZ mod loot imports

- Scan only validated XML types under installed top-level `@mod` folders. Bound traversal and total reads, skip symlinks and storage directories, and accept only a complete `<types>` document or direct `<type>` fragments that pass the same integer-lifetime parser used by Economy.
- Use the `meta.cpp` name when present, sanitize it into a mission directory, preserve the path inside the mod folder, and flag Expansion by its displayed name or folder token without preventing import.
- Copy into the mission and register through `cfgeconomycore.xml`; persist source/target mappings with Economy settings. During successful install/update recovery, restore only missing copies before rewriting registrations, globals, and the lifetime floor. Reset removes saved automation only and does not delete imported mission files.
- At the time this DayZ mod-loot slice was added, there was no built-in DayZ Rune or live DayZ acceptance. The implementation is bounded to compatible templates and the mod content already installed by their Rune.

## 2026-11-01: Docklight Assistant provider setup

- Use **Assistant** as the neutral, international product label. Keep provider setup administrator-only and the feature off by default until chat, scopes, data controls, and action confirmations are implemented.
- Support Anthropic Messages and OpenAI-compatible endpoints for OpenAI, OpenRouter, DeepSeek, Mistral, Ollama, and custom providers. Store keys encrypted with the panel secret and return only a configured flag and fixed mask.
- Let administrators test saved settings while Assistant is off. Send one fixed prompt without panel context, discard the model response, avoid audit logging, refuse redirects, bound timeout/response size, and do not expose provider error bodies.
- At this point, this slice only established provider storage and a connection check; the later Assistant, proactive monitoring, and MCP entries record the follow-up implementation.

## 2026-11-01: Docklight fleet Advisory

- Keep the public product identity as Docklight and use Advisory as the read-only assistant label; do not expose the original mythological feature name in the UI.
- Provide the fleet conversation over the same-origin authenticated WebSocket, filtering by the current account's server-view grants before building provider context. Cap each turn at 100 visible servers and report omitted counts.
- Revalidate the session, role, API-token scope, and account status for each WebSocket question so open connections do not retain access after a revocation or role change.
- Keep log search separate, limited to one selected visible server, and gated by the administrator's level-2 scope. Require per-search confirmation bound to the provider host when it is hosted.
- Keep history only in browser memory, do not implement transcript storage, and never execute actions from chat.

## 2026-11-01: Docklight proactive monitoring

- Keep proactive monitoring off by default and expose levels 0–3 with administrator-selected triggers for confirmed crashes, slow starts, resource thresholds, host pressure, and player-count anomalies.
- Build observations from the panel's existing crash records and metric history. Do not query live player counts. The later proactive log-volume decision permits count-only Docker log sampling with a persisted, bounded baseline.
- Preserve server-view scoping for event history and restrict host-wide events to admins. Bound stored history to 1,000 events and rate-limit automatic fixes to three per server in 30 minutes.
- Level 2 suggestions are informational. Level 3 requires both Advisory and Actions and can only restart a confirmed failed server or raise memory after exit 137 when fresh host metrics show enough headroom. Keep every other proposed action manual.
- Store event explanations and suggestions for operator review, but do not persist prompts or write their contents to audit details.

## 2026-11-01: Docklight MCP connector

- Provide Streamable HTTP JSON-RPC at the exact `/api/mcp` path with seven inspection and server-control tools. Keep file, settings, create, and delete operations out of the connector.
- Use the panel as its own OAuth 2.1 authorization server: public clients only, exact registered callbacks, PKCE S256, explicit same-origin consent, a single `yggdrasil` scope, and resource-bound tokens. Require HTTPS for non-loopback issuers.
- Store only hashes of authorization nonces, codes, access tokens, and refresh tokens. Keep codes short-lived and single-use, rotate refresh credentials, revoke a connection on replay, and let the approving user revoke connections immediately.
- Preserve the approving account's current server grants and intersect API-token calls with the API token's own scopes. Do not accept ordinary browser sessions as a substitute for MCP consent. Audit tool and control calls as the actual caller.
- Show the connector's log-data and player-disconnection risks on the consent screen. The public-reachability flag is a hostname heuristic, not a live external probe.

## 2026-11-01: Template app updates

- Keep app updates distinct from installer-based server updates. A Rune `update` block provides the temporary tool image/script, button label, and app-data paths that may receive group-write permission.
- Restrict manual app updates to administrators and serialize the operation with the shared server data lock. Audit the start and result without writing script output or secrets to audit details.
- Stop only the main app before its update so working sidecars remain available on the private network. Start stopped or missing sidecars when needed, then attach the update container to that network.
- Chown updated data to the panel user while preserving group ownership and existing modes; apply group write only to validated `app_writable` paths. Attempt to recreate the app after script failures so the update result does not suppress a deployment attempt.
- Use the Rune app-update script for scheduled Update actions only while the server is running; keep the legacy installer-based scheduled update for templates without an `update` block.

## 2026-11-01: Proactive log-volume monitoring

- Keep log-volume checks under the existing `anomalies` trigger so administrators have one switch for player and output anomalies.
- Read Docker output counts for a one-minute window, but never retain or send raw log lines for this check. Cap reads at 8 MiB per server per sample.
- Learn a per-server exponential baseline after five observations; relearn when it is older than 24 hours. Report only bursts that exceed an absolute 1 MiB floor and both an eight-times-baseline and six-standard-deviation threshold. Exclude outlier samples from the baseline and deduplicate events hourly to reduce noise.
- Store only the rolling numeric baseline and remove it when its server is deleted. Ignore Docker log access failures rather than treating them as zero output.

## 2026-11-01: Steam account authorization

- Use the upstream `steamcmd/steamcmd:debian-12` image for account verification and request `linux/amd64` explicitly because the published SteamCMD image is x86-64. ARM hosts therefore need Docker x86-64 emulation; game image architecture is independent.
- Keep the password only in process memory while a Steam Guard code is pending, expire that state after five minutes, and send password/code to the ephemeral helper over its stdin instead of Docker `Cmd` or `Env`.
- Persist only the username and authorization metadata in SQLite. Keep SteamCMD's sentry cache in the panel data directory and clear it when the account is removed.
- Preserve Steam template port numbers as host ports so published and container ports match; keep the required writable data-directory behavior scoped to Steam templates.

## 2026-11-01: Built-in DayZ server template

- The built-in `dayz` Rune now provides the compatible base for the existing Economy and Mods features; older status notes describing those features as requiring an imported Rune predate this template and are historical.
- Require an admin-authorized Steam account, publish DayZ's declared UDP ports directly on the host, and wait for the game's A2S query response before marking the server ready.
- Generate `serverDZ.cfg` on every start so mutable settings apply without reinstalling. Saved passwords stay encrypted in Docklight, but DayZ requires their generated config-file values in plaintext on disk.
- Keep Workshop content staging explicit: the Mods view controls `MODS` load order, while server files and signing keys must be staged by the operator and are included in the server backup.
- The local environment has no Docker daemon, so template parsing, lifecycle configuration and readiness are tested with fakes; live SteamCMD and DayZ acceptance remains pending on a Docker host.

## 2026-11-01: SFTP backup host-key pinning

- Require the administrator to enter the SFTP server's SHA-256 host-key fingerprint from an authenticated, out-of-band source. Do not learn trust from the same network connection being verified.
- Verify the SSH host key before password authentication and fail closed on a mismatch. Expose the public fingerprint in the admin target summary while keeping the existing credential-encryption behavior.
- Leave upgraded SFTP settings and backup records in place, but treat a legacy target without a pin as unconfigured until an administrator supplies the verified fingerprint. Do not rewrite remote backup rows during migration.

## 2026-11-01: Azure Blob backup target

- Implement Azure Blob with the in-repository REST client so large archive uploads can stream as bounded 16 MiB blocks without buffering the complete object or adding a cloud SDK dependency.
- Support Shared Key account credentials and SAS tokens; encrypt the account name and secret material at rest, redact both from API responses, and refuse HTTP except for loopback endpoint tests.
- Use a fixed Blob REST API version, pin endpoint redirects off, and ensure request failures never include the SAS-bearing URL. Accept a custom account endpoint for sovereign clouds and derive the standard Azure endpoint when the field is blank.
- Lock the account, endpoint, container, and prefix while Azure backup records remain, while allowing credential and authentication-mode rotation. Keep Azure settings in a numbered migration that preserves existing remote-target rows.
- Keep Azure live-account acceptance separate from request-fixture and fake-store tests; no live account is available in the local environment.
