const CACHE_PREFIX = 'docklight-shell-';
const CACHE_NAME = `${CACHE_PREFIX}__DOCKLIGHT_CACHE_VERSION__`;
const SHELL_URLS = [
  '/',
  '/app.js',
  '/ui-utils.mjs',
  '/style.css',
  '/config-editor.css',
  '/brand.svg',
  '/manifest.webmanifest',
];
const SHELL_PATHS = new Set(SHELL_URLS.filter((path) => path !== '/'));

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(SHELL_URLS);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names
      .filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
      .map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname === '/' && url.search !== '') return;

  const isShellDocument = request.mode === 'navigate' && url.pathname === '/';
  const isShellAsset = SHELL_PATHS.has(url.pathname);
  if (!isShellDocument && !isShellAsset) return;

  const cacheKey = isShellDocument ? '/' : url.pathname;
  event.respondWith((async () => {
    let response;
    try {
      response = await fetch(request);
    } catch {
      try {
        const cache = await caches.open(CACHE_NAME);
        return await cache.match(cacheKey) || Response.error();
      } catch {
        return Response.error();
      }
    }

    if (response.ok) {
      try {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(cacheKey, response.clone());
      } catch {
        // A cache failure should not replace a successful network response.
      }
    }
    return response;
  })());
});
