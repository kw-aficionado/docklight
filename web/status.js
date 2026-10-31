(() => {
  const title = document.querySelector('#page-title');
  const overall = document.querySelector('#overall');
  const servers = document.querySelector('#servers');
  const updated = document.querySelector('#updated');
  const announcement = document.querySelector('#refresh-status');

  function render(payload) {
    title.textContent = payload.title || 'Server Status';
    document.title = `${title.textContent} · Docklight`;
    const items = Array.isArray(payload.servers) ? payload.servers : [];
    const online = items.filter(item => item.status === 'online').length;
    const starting = items.filter(item => item.status === 'starting').length;
    const state = items.length === 0 ? 'empty' : items.length === online ? 'online' : online + starting > 0 ? 'starting' : 'offline';
    overall.dataset.state = state;
    const summary = document.createElement('span');
    if (!items.length) {
      summary.textContent = 'No services are currently shared on this page.';
    } else {
      const strong = document.createElement('b');
      strong.textContent = online === items.length ? `All ${online} ${online === 1 ? 'service is' : 'services are'} online` : `${online} of ${items.length} ${items.length === 1 ? 'service is' : 'services are'} online`;
      summary.append(strong);
      if (starting && online !== items.length) summary.append(document.createTextNode(` · ${starting} starting`));
    }
    overall.replaceChildren(overall.querySelector('i'), summary);
    servers.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'This page is enabled. Add a server in Public status settings to display it here.';
      servers.append(empty);
    }
    for (const item of items) {
      const card = document.createElement('article');
      card.className = 'server';
      const main = document.createElement('div');
      main.className = 'server-main';
      const name = document.createElement('span');
      name.className = 'server-name';
      name.textContent = item.name || 'Server';
      main.append(name);
      if (item.game) {
        const game = document.createElement('span');
        game.className = 'server-game';
        game.textContent = item.game;
        main.append(game);
      }
      const meta = document.createElement('div');
      meta.className = 'server-meta';
      if (item.players && Number.isInteger(item.players.online) && Number.isInteger(item.players.max)) {
        const players = document.createElement('span');
        players.className = 'server-players';
        players.textContent = `${item.players.online} / ${item.players.max} players`;
        meta.append(players);
      }
      const badge = document.createElement('span');
      badge.className = 'badge';
      const status = ['online', 'starting', 'offline'].includes(item.status) ? item.status : 'offline';
      badge.dataset.status = status;
      badge.textContent = status[0].toUpperCase() + status.slice(1);
      meta.append(badge);
      card.append(main, meta);
      servers.append(card);
    }
    const time = new Date(payload.updated_at);
    updated.textContent = Number.isNaN(time.getTime()) ? 'Updated just now' : `Updated ${time.toLocaleString()}`;
    announcement.textContent = `Status refreshed. ${online} of ${items.length} services online.`;
  }

  async function refresh() {
    try {
      const response = await fetch('/api/status', { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) throw new Error(response.status === 404 ? 'This status page is not available.' : 'Status could not be loaded.');
      render(await response.json());
    } catch (error) {
      servers.replaceChildren();
      const message = document.createElement('div');
      message.className = 'error';
      message.textContent = error.message || 'Status could not be loaded.';
      servers.append(message);
      overall.dataset.state = 'offline';
      overall.querySelector('span').textContent = 'Status unavailable';
    }
  }

  refresh();
  window.setInterval(refresh, 30000);
})();
