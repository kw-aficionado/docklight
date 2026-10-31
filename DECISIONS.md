# Decisions

## 2026-10-31: first implementation slice

- The workspace was empty, so this is a new implementation rather than an extension of an existing checkout.
- The local environment has no Docker executable or daemon, and DNS lookup for `proxy.golang.org` fails. Docker-dependent acceptance checks cannot run here, and dependencies are limited to modules already present in the Go cache.
- The Docker Engine is accessed through its versioned HTTP API over the configured Unix socket instead of the Docker SDK. This keeps builds reproducible offline and CGO-free while retaining the same Engine behavior.
- JWT HS256, WebSocket framing, and the small YAML subset needed by the template schema are implemented in this repository because their upstream modules are not available locally. These boundaries are documented and covered by local tests; broader YAML 1.2 compatibility and browser passkeys are not claimed.
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
- The first Phase 2 vertical slice is local encrypted backups. Archives stream through gzip and chunked AES-GCM, use the existing `auth.secret_key`, and require a stopped server for consistent copies. Retention defaults to 10. Restore verifies before swapping the full data directory. Remote drivers remain separate work.
- Scheduled local backups are the second operations slice: numeric cron expressions run in host-local time, only server scope is exposed, and the scheduler uses a `server.schedule` grant plus `server.backup` for new schedules. Other scheduler actions and realm/global scheduling remain separate work.
- The outgoing webhook supports backup outcomes, confirmed container crashes, and low-disk alerts. Administrators control it; endpoint and signing key are encrypted with `auth.secret_key`, and optional HMAC signatures let receivers verify requests. HTTPS is required except localhost loopback testing, and redirects are disabled so request signatures or URL tokens are not forwarded. Dedicated Discord, Telegram, and SMTP channels remain separate work.
- Runtime crash history waits 60 seconds after panel startup, requires Docker Engine ping to succeed, and confirms stopped or missing state with two matching inspections at least 15 seconds apart. This avoids turning a slow Docker boot or an unreachable Engine into a false incident. Confirmed exits move the server to an attention state and preserve its data; automatic restart is separate work.
- Low-disk alerts monitor the filesystem containing Docklight's data directory every five minutes. They fire below 10% free, persist an active latch across restarts, and rearm at 15% free. The webhook names the server-data and backup paths; the monitor does not walk a potentially large filesystem or delete data, and other mounts are outside this first slice.
- Automatic recovery is opt-in per query-capable server. The watchdog checks every 20 seconds with a 3-second timeout, requires three consecutive failures, and applies a four-minute cooldown. It retries a failed restart three times with 15-second spacing. The brief's appendix gives conflicting quarantine limits (“more than five” versus “five”); the implementation quarantines after the fifth successful recovery in 30 minutes. Cooldown timestamps, heal history, opt-in, and quarantine persist across panel restarts. A manual start or stop clears the quarantine and counters.
