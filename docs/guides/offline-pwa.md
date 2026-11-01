# Install and use Docklight offline

Docklight provides a web app manifest and a service worker for the browser app shell. In a supporting browser, use its **Install** or **Add to Home Screen** command to add Docklight to your device.

## Secure connection

Browsers register service workers only in a secure context. Serve Docklight over HTTPS, such as behind a TLS reverse proxy. `localhost` is treated as secure for development; a plain HTTP connection to a remote host cannot install the worker.

## What works offline

Docklight uses a network-first strategy for the app entry page and its static files. If the network request fails, the browser can open the last cached app shell and shows an offline notice. When a new app build changes the embedded shell, the worker creates a new cache and removes older Docklight shell caches.

The cache contains only the HTML entry page, JavaScript modules, CSS, the Docklight SVG mark, and the app manifest. It does **not** store API responses, sign-in or reset responses, account data, server data, the public status page, OAuth pages, console or log streams, or WebSocket traffic. Signing in and controlling servers require a reachable Docklight host. An already-open tab may still show the data already rendered in that tab's memory, but a reload cannot restore it from the service-worker cache.

## Check the app shell

Run the browser logic checks with Node.js:

```sh
node --test web/*.test.mjs
```

The tests cover the app-shell allowlist, cache update and cleanup, offline fallback, and API/status bypass. Confirm the browser's install flow and offline reload on the HTTPS host where you deploy Docklight.
