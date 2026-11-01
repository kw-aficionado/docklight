import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const origin = 'https://panel.example';
const shellPaths = [
  '/',
  '/app.js',
  '/ui-utils.mjs',
  '/style.css',
  '/config-editor.css',
  '/brand.svg',
  '/manifest.webmanifest',
];
const source = (await readFile(new URL('./service-worker.js', import.meta.url), 'utf8'))
  .replace('__DOCKLIGHT_CACHE_VERSION__', 'test-version');

function createWorker(fetchImpl) {
  const listeners = new Map();
  const stores = new Map();
  const normalize = (input) => new URL(typeof input === 'string' ? input : input.url, origin).pathname;
  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async addAll(paths) {
          const responses = await Promise.all(paths.map(async (path) => {
            const response = await fetchImpl(path);
            if (!response.ok) throw new Error(`failed to precache ${path}`);
            return [normalize(path), response.clone()];
          }));
          for (const [path, response] of responses) store.set(path, response);
        },
        async put(key, response) { store.set(normalize(key), response.clone()); },
        async match(key) { return store.get(normalize(key))?.clone(); },
      };
    },
    async keys() { return [...stores.keys()]; },
    async delete(name) { return stores.delete(name); },
  };
  let claimed = false;
  const self = {
    location: { origin },
    clients: { async claim() { claimed = true; } },
    async skipWaiting() {},
    addEventListener(name, callback) { listeners.set(name, callback); },
  };
  vm.runInNewContext(source, { self, caches, fetch: fetchImpl, URL, Response });

  async function dispatch(name, request) {
    let pending;
    const event = {
      request,
      waitUntil(promise) { pending = promise; },
      respondWith(promise) { pending = promise; },
    };
    listeners.get(name)(event);
    if (pending) return await pending;
    return undefined;
  }
  return { caches, dispatch, stores, get claimed() { return claimed; } };
}

test('precache contains only the static Docklight app shell', async () => {
  const calls = [];
  const worker = createWorker(async (request) => {
    const path = new URL(typeof request === 'string' ? request : request.url, origin).pathname;
    calls.push(path);
    return new Response(`shell:${path}`, { status: 200 });
  });

  await worker.dispatch('install');
  assert.deepEqual(calls, shellPaths);
  assert.deepEqual([...worker.stores.get('docklight-shell-test-version').keys()].sort(), [...shellPaths].sort());
  assert.equal(calls.some((path) => path.startsWith('/api/') || path.startsWith('/oauth/')), false);
});

test('offline navigation can load the shell while API and status requests bypass the cache', async () => {
  let online = true;
  const worker = createWorker(async (request) => {
    const path = new URL(typeof request === 'string' ? request : request.url, origin).pathname;
    if (!online) throw new Error('offline');
    return new Response(`network:${path}`, { status: 200 });
  });
  await worker.dispatch('install');
  online = false;

  const home = await worker.dispatch('fetch', { url: `${origin}/`, method: 'GET', mode: 'navigate' });
  assert.equal(await home.text(), 'network:/');
  const api = await worker.dispatch('fetch', { url: `${origin}/api/me`, method: 'GET', mode: 'cors' });
  const status = await worker.dispatch('fetch', { url: `${origin}/status`, method: 'GET', mode: 'navigate' });
  const reset = await worker.dispatch('fetch', { url: `${origin}/?reset=secret-token`, method: 'GET', mode: 'navigate' });
  const login = await worker.dispatch('fetch', { url: `${origin}/api/login`, method: 'POST', mode: 'cors' });
  assert.equal(api, undefined, 'API requests must bypass the service worker');
  assert.equal(status, undefined, 'the public status page must bypass the service worker');
  assert.equal(reset, undefined, 'password-reset URLs must bypass the service worker');
  assert.equal(login, undefined, 'login submissions must bypass the service worker');
});

test('shell assets are refreshed from the network and have an offline cache fallback', async () => {
  let online = true;
  const worker = createWorker(async (request) => {
    const path = new URL(typeof request === 'string' ? request : request.url, origin).pathname;
    if (!online) throw new Error('offline');
    return new Response(`fresh:${path}`, { status: 200 });
  });
  await worker.dispatch('install');
  worker.stores.set('docklight-shell-old', new Map());
  worker.stores.set('unrelated-cache', new Map());
  await worker.dispatch('activate');

  const script = await worker.dispatch('fetch', { url: `${origin}/app.js`, method: 'GET', mode: 'no-cors' });
  assert.equal(await script.text(), 'fresh:/app.js');
  online = false;
  const offlineScript = await worker.dispatch('fetch', { url: `${origin}/app.js`, method: 'GET', mode: 'no-cors' });
  assert.equal(await offlineScript.text(), 'fresh:/app.js');
  assert.equal(worker.claimed, true);
  assert.deepEqual((await worker.caches.keys()).sort(), ['docklight-shell-test-version', 'unrelated-cache']);
});
