(function () {
    'use strict';
    const asset = document.querySelector('script[src*="/plexauth/assets/auth.js"]');
    const root = new URL(asset.src).pathname.split('/plexauth/assets/')[0];
    const page = document.getElementById('plexauth-page');
    async function start(code) {
        const response = await fetch(root + '/plexauth/start', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ quickConnectCode: code || null })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Plex login unavailable.');
        window.location.assign(data.url);
    }
    function inject() {
        const login = document.querySelector('#loginPage, .page[data-type="login"]');
        if (!login || login.querySelector('[data-plexauth]')) return;
        const target = login.querySelector('.manualLoginForm, form, .readOnlyContent');
        if (!target) return;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'plexauth-button';
        button.dataset.plexauth = 'true';
        const mark = document.createElement('img');
        mark.className = 'plexauth-mark';
        mark.src = root + '/plexauth/assets/plex.svg';
        mark.alt = '';
        mark.width = 22;
        mark.height = 22;
        button.append(mark, document.createTextNode('Login with Plex'));
        button.addEventListener('click', async () => {
            button.disabled = true;
            try { await start(); }
            catch (error) { button.textContent = error.message; button.disabled = false; }
        });
        target.appendChild(button);
        const connect = document.createElement('a');
        connect.href = root + '/plexauth/connect';
        connect.className = 'plexauth-link';
        connect.append(mark.cloneNode(), document.createTextNode('Plex Quick Connect'));
        target.appendChild(connect);
    }
    if (!page) {
        new MutationObserver(inject).observe(document.documentElement, { childList: true, subtree: true });
        inject();
        return;
    }
    const form = document.getElementById('plexauth-form');
    const status = document.getElementById('status');
    const state = new URLSearchParams(location.search).get('state');
    if (!state) {
        const code = document.getElementById('code');
        if (location.pathname.endsWith('/connect')) code.required = true;
        form.addEventListener('submit', async event => {
            event.preventDefault();
            form.querySelector('button').disabled = true;
            try { await start(code.value); }
            catch (error) { status.textContent = error.message; form.querySelector('button').disabled = false; }
        });
        return;
    }
    form.hidden = true;
    let deviceId = localStorage.getItem('_deviceId2');
    if (!deviceId) { deviceId = crypto.randomUUID(); localStorage.setItem('_deviceId2', deviceId); }
    async function complete() {
        status.textContent = 'Waiting for Plex approval...';
        try {
            const response = await fetch(root + '/plexauth/complete', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json; profile="CamelCase"' },
                body: JSON.stringify({ state, deviceId, deviceName: 'Web Browser' })
            });
            const result = await response.json();
            if (response.status === 202) { setTimeout(complete, 1500); return; }
            if (!response.ok) throw new Error(result.error || 'Login failed.');
            history.replaceState(null, '', location.pathname);
            if (result.connected) { status.textContent = 'Device authorized.'; return; }
            const token = result.AccessToken || result.accessToken;
            const serverId = result.ServerId || result.serverId;
            const user = result.User || result.user;
            if (!token || !serverId || !(user.Id || user.id)) throw new Error('Invalid Jellyfin session.');
            let credentials;
            try { credentials = JSON.parse(localStorage.getItem('jellyfin_credentials') || '{}'); }
            catch (_) { credentials = {}; }
            if (!credentials || typeof credentials !== 'object') credentials = {};
            if (!Array.isArray(credentials.Servers)) credentials.Servers = [];
            let server = credentials.Servers.find(server => server.Id === serverId);
            if (!server) { server = {}; credentials.Servers.push(server); }
            Object.assign(server, { Id: serverId, ManualAddress: location.origin + root, LastConnectionMode: 2,
                AccessToken: token, UserId: user.Id || user.id, DateLastAccessed: Date.now() });
            localStorage.setItem('jellyfin_credentials', JSON.stringify(credentials));
            localStorage.setItem('enableAutoLogin', 'true');
            location.replace(root + '/web/index.html#/home');
        } catch (error) { status.textContent = error.message; }
    }
    complete();
})();