# Decisions

## 2026-10-31: first implementation slice

- The workspace was empty, so this is a new implementation rather than an extension of an existing checkout.
- The local environment has no Docker executable or daemon, and DNS lookup for `proxy.golang.org` fails. Docker-dependent acceptance checks cannot run here, and dependencies are limited to modules already present in the Go cache.
- The Docker Engine is accessed through its versioned HTTP API over the configured Unix socket instead of the Docker SDK. This keeps builds reproducible offline and CGO-free while retaining the same Engine behavior.
- JWT HS256, WebSocket framing, and the small YAML subset needed by the rune schema are implemented in this repository because their upstream modules are not available locally. These boundaries are documented and covered by local tests; broader YAML 1.2 compatibility and browser passkeys are not claimed.
- The web interface is a self-contained embedded HTML/CSS/JavaScript app rather than Svelte/Tailwind. No frontend packages are cached and the machine has no package-registry DNS. The shipped interface has no CDN or runtime network dependency.
- The initial release targets the functional Phase 1 core. Phase 2-4 features remain out of scope and will be listed in STATUS.md rather than shown as working controls.

## Additional Phase 1 decisions

- API tokens use 256-bit random opaque values with a `ygg_` prefix. Only a SHA-256 hash and the token name/scope metadata are stored; the plaintext is returned only by the create response. Every API-token permission is intersected with the owner's current RBAC grants.
- Schema changes use a numbered `schema_migrations` table. The second migration adds a safe startup error field and the API-token lookup index; old tables are upgraded in place.
- The standalone browser app uses a small ES module for shared escaping/number formatting and Node's built-in test runner. This gives the UI logic a dependency-free test path while package registries are unreachable.
- `PUBLIC_URL` is derived at runtime from an explicitly configured listener host or a current non-loopback host address, so DHCP changes are not persisted into rune settings.
- Readiness is a state transition, not an optimistic default. A timeout or Docker inspection failure sets an actionable error state and leaves the container record intact for diagnosis.
