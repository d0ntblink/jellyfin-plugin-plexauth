import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, writeFile, copyFile, readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { setDefaultCACertificates, getCACertificates } from 'node:tls';
import { chromium } from 'playwright';

const directory = process.env.PLEXAUTH_TEST_DIR;
assert(directory && resolve(directory) === directory, 'Set PLEXAUTH_TEST_DIR to an absolute disposable directory containing server binaries.');
const root = resolve(import.meta.dirname, '..');
const manifest = JSON.parse(await readFile(join(root, 'meta.json'), 'utf8'));
const dotnet = process.env.DOTNET_ROOT + '/dotnet';
const profile = await mkdtemp(join(directory, 'profile-'));
const config = join(profile, 'config');
const plugins = join(profile, 'plugins');
const pluginDirectory = join(plugins, 'PlexAuth_' + manifest.version);
const adminPassword = randomBytes(32).toString('hex');
const control = randomBytes(32).toString('hex');
const address = 'https://127.0.0.1:18443';
const origin = 'https://127.0.0.1:18443';
const libraryIds = Array.from({ length: 5 }, (_, index) => `00000000-0000-0000-0000-00000000000${index + 1}`);
for (const folder of [config, join(config, 'plugins'), pluginDirectory, join(profile, 'cache'), join(profile, 'logs')]) await mkdir(folder, { recursive: true, mode: 0o700 });
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(profile, 'key.pem'), '-out', join(profile, 'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-days', '1'], { stdio: 'ignore' });
execFileSync('openssl', ['pkcs12', '-export', '-out', join(profile, 'server.pfx'), '-inkey', join(profile, 'key.pem'), '-in', join(profile, 'cert.pem'), '-passout', 'pass:' + adminPassword], { stdio: 'ignore' });
setDefaultCACertificates([...getCACertificates('default'), await readFile(join(profile, 'cert.pem'), 'utf8')]);
await writeFile(join(config, 'network.xml'), `<?xml version="1.0"?><NetworkConfiguration><InternalHttpPort>18096</InternalHttpPort><InternalHttpsPort>18443</InternalHttpsPort><EnableHttps>true</EnableHttps><CertificatePath>${join(profile, 'server.pfx')}</CertificatePath><CertificatePassword>${adminPassword}</CertificatePassword><EnableIPv4>true</EnableIPv4><EnableIPv6>false</EnableIPv6><LocalNetworkAddresses><string>127.0.0.1</string></LocalNetworkAddresses><AutoDiscovery>false</AutoDiscovery><EnableUPnP>false</EnableUPnP><EnableRemoteAccess>false</EnableRemoteAccess></NetworkConfiguration>`);
await writeFile(join(config, 'plugins', 'Jellyfin.Plugin.PlexAuth.xml'), `<?xml version="1.0"?><PluginConfiguration><Enabled>true</Enabled><PublicUrl>${origin}</PublicUrl><MachineId>isolated-server</MachineId><ClientIdentifier>isolated-test-client</ClientIdentifier><LibraryIds>${libraryIds.map(id => `<guid>${id}</guid>`).join('')}</LibraryIds></PluginConfiguration>`);
await copyFile(join(root, 'src/Jellyfin.Plugin.PlexAuth/bin/Debug/net10.0/Jellyfin.Plugin.PlexAuth.dll'), join(pluginDirectory, 'Jellyfin.Plugin.PlexAuth.dll'));
await copyFile(join(root, 'tests/PlexAuth.TestProvider/bin/Debug/net10.0/PlexAuth.TestProvider.dll'), join(pluginDirectory, 'PlexAuth.TestProvider.dll'));
manifest.assemblies.push('PlexAuth.TestProvider.dll');
await writeFile(join(pluginDirectory, 'meta.json'), JSON.stringify(manifest));
const server = spawn(join(directory, 'server/jellyfin'), ['--datadir', profile, '--configdir', config, '--cachedir', join(profile, 'cache'), '--logdir', join(profile, 'logs'), '--webdir', join(directory, 'server/jellyfin-web')],
    { env: { ...process.env, PLEXAUTH_ISOLATED_TEST: 'yes', PLEXAUTH_TEST_CONTROL: control }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = '';
server.stdout.on('data', chunk => { log += chunk; });
server.stderr.on('data', chunk => { log += chunk; });
async function call(path, { method = 'GET', body, token, cookie, extra = {} } = {}) {
    const headers = { Accept: 'application/json', ...extra };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `MediaBrowser Client="PlexAuth Isolated Test", Device="Test", DeviceId="isolated-admin", Version="1.0", Token="${token}"`;
    if (cookie) headers.Cookie = cookie;
    return fetch(address + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10000) });
}
try {
    const deadline = Date.now() + 40000;
    while (true) {
        try {
            const response = await call('/System/Info/Public');
            if (response.ok && (await response.json()).Version === '12.4.0') break;
        } catch (_) { }
        if (server.exitCode !== null || Date.now() > deadline) {
            const diagnostics = log.split('\n').filter(line => /\[ERR\]|\[FTL\]|Exception:|not found|No usable|You must install|Framework:|\.NET location:|FFmpeg|ffmpeg/i.test(line)).slice(-8).join('\n');
            throw new Error('Isolated server did not become healthy. Startup diagnostics:\n' + diagnostics);
        }
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    assert.equal((await (await call('/System/Info/Public')).json()).Version, '12.4.0');
    assert.equal((await call('/Startup/User')).status, 200);
    assert.equal((await call('/Startup/User', { method: 'POST', body: { Name: 'plex-local-admin', Password: adminPassword } })).status, 204);
    assert.equal((await call('/Startup/Complete', { method: 'POST' })).status, 204);
    const adminLogin = await call('/Users/AuthenticateByName', { method: 'POST', body: { Username: 'plex-local-admin', Pw: adminPassword }, extra: { Authorization: 'MediaBrowser Client="Isolated Test", Device="Test", DeviceId="isolated-admin", Version="1.0"' } });
    assert.equal(adminLogin.status, 200);
    const admin = await adminLogin.json();
    const pluginId = '679e3ea6-3b13-4ebf-8b60-e8eab13e9ecd';
    const saved = await call('/Plugins/' + pluginId + '/Configuration', { method: 'POST', token: admin.AccessToken, body: { Enabled: true, PublicUrl: origin, MachineId: 'isolated-server', ClientIdentifier: 'isolated-test-client', LibraryIds: libraryIds } });
    assert(saved.ok, 'Plugin configuration endpoint returned ' + saved.status + '. Load diagnostics:\n' + log.split('\n').filter(line => /Loaded plugin:|Loaded assembly|Could not load|Failed to load|Unable to load/i.test(line)).join('\n'));
    assert.equal((await call('/plexauth/start', { method: 'POST', body: {}, extra: { Origin: 'https://attacker.example' } })).status, 403);
    const qc = await call('/QuickConnect/Initiate', { method: 'POST', extra: { Authorization: 'MediaBrowser Client="Finamp", Device="Phone", DeviceId="isolated-finamp", Version="1.0"' } });
    assert.equal(qc.status, 200);
    const challenge = await qc.json();
    const started = await call('/plexauth/start', { method: 'POST', body: { quickConnectCode: challenge.Code }, extra: { Origin: origin } });
    assert.equal(started.status, 200);
    const cookie = started.headers.get('set-cookie').split(';')[0];
    const authUrl = new URL((await started.json()).url);
    assert.equal(new URLSearchParams(authUrl.hash.slice(2)).get('code'), 'isolated-pin', 'The test-only Plex transport must be active.');
    const state = new URL(new URLSearchParams(authUrl.hash.slice(2)).get('forwardUrl')).searchParams.get('state');
    const completed = await call('/plexauth/complete', { method: 'POST', cookie, body: { state, deviceId: 'isolated-approval' }, extra: { Origin: origin } });
    assert.equal(completed.status, 200);
    assert.equal((await completed.json()).connected, true);
    assert.equal((await call('/plexauth/complete', { method: 'POST', cookie, body: { state, deviceId: 'isolated-approval' }, extra: { Origin: origin } })).status, 400);
    const nativeLogin = await call('/Users/AuthenticateWithQuickConnect', { method: 'POST', body: { Secret: challenge.Secret }, extra: { Authorization: 'MediaBrowser Client="Finamp", Device="Phone", DeviceId="isolated-finamp", Version="1.0"' } });
    assert.equal(nativeLogin.status, 200);
    const app = await nativeLogin.json();
    assert.equal(app.User.Name, 'plex-123');
    assert.equal(app.User.Policy.IsAdministrator, false);
    assert.equal(app.User.Policy.EnableAllFolders, false);
    assert.equal(app.User.Policy.EnabledFolders.length, 5);
    assert.equal((await call('/Users/Me', { token: app.AccessToken })).status, 200);
    assert.equal((await call('/Users/AuthenticateByName', { method: 'POST', body: { Username: 'plex-123', Pw: '' } })).status, 401);
    assert.equal((await call('/_plexauth-test/profile', { method: 'POST', extra: { 'X-Test-Control': control } })).status, 200);
    const updatedProfile = await (await call('/Users/Me', { token: app.AccessToken })).json();
    assert.equal(updatedProfile.Id, app.User.Id);
    assert.equal(updatedProfile.Name, 'isolated-alice');
    assert.equal(updatedProfile.Policy.IsAdministrator, false);
    assert.deepEqual(updatedProfile.Policy.EnabledFolders, app.User.Policy.EnabledFolders);
    assert(updatedProfile.PrimaryImageTag);
    assert.equal((await call('/UserImage?userId=' + app.User.Id)).status, 200);
    assert.equal((await call('/Users/AuthenticateByName', { method: 'POST', body: { Username: 'isolated-alice', Pw: '' } })).status, 401);
    const index = await (await call('/web/index.html')).text();
    assert(index.includes('/plexauth/assets/auth.js'));
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
        const page = await context.newPage();
        const errors = [];
        const completionRequests = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('request', request => {
            if (request.url().endsWith('/plexauth/complete')) {
                const body = request.postDataJSON();
                completionRequests.push({ stateLength: body.state?.length, deviceLength: body.deviceId?.length });
            }
        });
        await page.route('https://app.plex.tv/auth**', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><script>location.replace(new URLSearchParams(location.hash.slice(2)).get("forwardUrl"));</script>' }));
        await page.goto(address + '/web/index.html#/login');
        await page.locator('button[data-plexauth]').waitFor({ state: 'visible' });
        const plexStyle = await page.evaluate(async () => {
            await document.fonts.ready;
            const style = getComputedStyle(document.querySelector('button[data-plexauth]'));
            return { color: style.backgroundColor, family: style.fontFamily, fontLoaded: document.fonts.check('16px "Plex Auth Open Sans"') };
        });
        assert.equal(plexStyle.color, 'rgb(229, 160, 13)');
        assert(plexStyle.family.includes('Plex Auth Open Sans') && plexStyle.fontLoaded);
        await page.screenshot({ path: join(directory, 'login-desktop.png'), fullPage: true });
        await page.locator('button[data-plexauth]').click();
        try { await page.waitForURL('**/web/index.html#/home'); }
        catch (_) {
            await page.screenshot({ path: join(directory, 'callback-failure.png'), fullPage: true });
            const cookies = await context.cookies(address);
            throw new Error('Browser completion failed: ' + await page.locator('#status').textContent() + '; proofCookie=' + cookies.some(cookie => cookie.name === '__Host-plexauth') + '; requests=' + JSON.stringify(completionRequests) + '; script errors: ' + errors.join('; '));
        }
        const credentials = await page.evaluate(() => JSON.parse(localStorage.getItem('jellyfin_credentials')));
        assert(credentials.Servers.some(server => server.UserId === app.User.Id && server.AccessToken));
        await context.close();
        const mobile = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 } });
        const mobilePage = await mobile.newPage();
        await mobilePage.goto(address + '/plexauth/connect');
        await mobilePage.locator('#plexauth-form').waitFor({ state: 'visible' });
        assert(await mobilePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await mobilePage.locator('img[alt="Jellyfin"]').waitFor({ state: 'visible' });
        assert(await mobilePage.evaluate(() => [...document.images].every(image => image.complete && image.naturalWidth > 0)));
        assert(await mobilePage.evaluate(async () => { await document.fonts.ready; return document.fonts.check('16px "Plex Auth Open Sans"'); }));
        await mobilePage.screenshot({ path: join(directory, 'connect-mobile.png'), fullPage: true });
        await mobile.close();
        assert.deepEqual(errors, []);
    } finally { await browser.close(); }
    assert.equal((await call('/_plexauth-test/revoke', { method: 'POST', extra: { 'X-Test-Control': control } })).status, 200);
    assert.equal((await call('/Users/Me', { token: app.AccessToken })).status, 401);
    assert.equal((await call('/Users/Me', { token: admin.AccessToken })).status, 200);
    console.log('PASS: real Jellyfin 12.4 native Quick Connect/token revocation, admin preservation, web button/browser login, mobile layout/screenshots, and CSRF/replay/password denial.');
} finally {
    server.kill('SIGTERM');
    await new Promise(resolve => { if (server.exitCode !== null) resolve(); else { server.once('exit', resolve); setTimeout(() => server.kill('SIGKILL'), 5000).unref(); } });
    await writeFile(join(directory, 'server-test.log'), log, { mode: 0o600 });
}