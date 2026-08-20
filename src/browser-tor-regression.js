/**
 * Browser Tor-routing regression (ANONYMITY.md Phase 2), wired into `npm test`.
 *
 * The browser cannot do per-connection SOCKS in-page, so its Tor path is a
 * BROWSER-level SOCKS5 proxy (the Tor Browser mechanism, exposed here as
 * tools/messenger-tor.mjs). This test proves the mechanism with a mock SOCKS5
 * CONNECT proxy standing in for Tor:
 *
 *   1. the relay is reachable ONLY through the proxy — the browser dials the
 *      non-resolvable name `relay.local`, which the proxy alone can resolve to
 *      the real loopback relay, so any successful delivery proves the traffic
 *      traversed the proxy;
 *   2. the mock proxy records the CONNECT destination, asserting the browser's
 *      WebSocket actually left through it (not a direct link);
 *   3. a full A→B→A conversation still delivers end-to-end through the tunnel;
 *   4. resolveTorProxy() fails closed — it throws when Tor is unreachable
 *      rather than returning a config that would silently expose the IP.
 *
 * Self-contained: spawns its own relay + static server + mock proxy on loopback
 * ports. Skips gracefully (exit 0) when the headless browser is not resolvable.
 */
import { spawn } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { resolveChromium, launchBrowser } from './chromium.js';
import { resolveTorProxy } from './tor.js';

const RELAY_PORT = Number(process.env.BT_TCP_PORT || 7997);
const WS_PORT = Number(process.env.BT_WS_PORT || 8097);
const UI_PORT = Number(process.env.BT_UI_PORT || 8012);
const PROXY_PORT = Number(process.env.BT_PROXY_PORT || 9051);
const RELAY_NAME = 'relay.local';

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

function waitForTcp(port, ms) {
  const deadline = Date.now() + ms;
  return new Promise((res, rej) => {
    const tryOnce = () => {
      const s = connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); res(); });
      s.once('error', () => { s.destroy(); Date.now() > deadline ? rej(new Error('timeout ' + port)) : setTimeout(tryOnce, 200); });
    };
    tryOnce();
  });
}

async function waitForHttp(url, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { const r = await fetch(url); if (r.ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('ui timeout ' + url);
}

/**
 * Minimal SOCKS5 (RFC 1928) CONNECT proxy. Records every destination it is asked
 * to reach and pipes bytes bidirectionally, resolving hostnames through
 * `resolveHost` (so `relay.local` maps to the real loopback relay — the ONLY
 * route to it). No auth: a local test stand-in for Tor's SOCKS5 listener.
 */
function createSocks5Proxy({ port, resolveHost }) {
  const destinations = [];
  const server = createServer((socket) => {
    let stage = 'greeting';
    let buf = Buffer.alloc(0);
    let upstream = null;

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 'greeting') {
        if (buf.length < 2) return;
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;
        socket.write(Buffer.from([0x05, 0x00])); // no-auth
        buf = buf.slice(2 + nmethods);
        stage = 'request';
      }
      if (stage === 'request') {
        if (buf.length < 4) return;
        const cmd = buf[1];
        const atyp = buf[3];
        let host, port, consumed;
        if (atyp === 0x01) { // IPv4
          if (buf.length < 10) return;
          host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          port = buf.readUInt16BE(8);
          consumed = 10;
        } else if (atyp === 0x03) { // domain
          const len = buf[4];
          if (buf.length < 5 + len + 2) return;
          host = buf.slice(5, 5 + len).toString('utf8');
          port = buf.readUInt16BE(5 + len);
          consumed = 5 + len + 2;
        } else if (atyp === 0x04) { // IPv6
          if (buf.length < 22) return;
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(buf.slice(4 + i * 2, 6 + i * 2).toString('hex'));
          host = parts.join(':');
          port = buf.readUInt16BE(20);
          consumed = 22;
        } else {
          socket.destroy();
          return;
        }
        const rest = buf.slice(consumed);
        buf = Buffer.alloc(0);
        stage = 'pipe';
        destinations.push({ host, port });

        if (cmd !== 0x01) { // CONNECT only
          socket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          socket.end();
          return;
        }
        const target = resolveHost ? resolveHost(host) : host;
        upstream = connect(port, target);
        upstream.on('connect', () => {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (rest.length) upstream.write(rest);
        });
        upstream.on('data', (d) => socket.write(d));
        upstream.on('error', () => socket.destroy());
        upstream.on('close', () => socket.end());
      } else if (stage === 'pipe') {
        if (upstream) upstream.write(chunk);
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => { if (upstream) upstream.destroy(); });
  });
  return new Promise((res, rej) => {
    server.once('error', rej);
    server.listen(port, '127.0.0.1', () => res({ server, destinations }));
  });
}

const chromium = resolveChromium();
if (!chromium) {
  console.log('[browser-tor-regression] SKIP: headless browser (patchright) not resolvable.');
  process.exit(0);
}

// ---- Fail-closed unit check (no browser needed): a dead proxy must throw. ----
try {
  await resolveTorProxy({ host: '127.0.0.1', port: 1 });
  check('resolveTorProxy fails closed when Tor is unreachable', false, 'returned a config instead of throwing');
} catch (err) {
  check('resolveTorProxy fails closed when Tor is unreachable', /refusing to launch/.test(err.message), err.message);
}

const relay = spawn(process.execPath, ['src/server.js'], {
  env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
const ui = spawn(process.execPath, ['tools/serve.mjs'], {
  env: { ...process.env, UI_PORT: String(UI_PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let relayOut = '', relayErr = '', uiErr = '';
relay.stdout.on('data', (d) => { relayOut += d; });
relay.stderr.on('data', (d) => { relayErr += d; });
ui.stderr.on('data', (d) => { uiErr += d; });

const consoleErrors = [];
let proxy = null;
let browser = null;

try {
  await waitForTcp(RELAY_PORT, 15000);
  await waitForHttp(`http://127.0.0.1:${UI_PORT}/messenger.html`, 15000);

  // The mock SOCKS5 proxy is the only thing that can resolve `relay.local`.
  proxy = await createSocks5Proxy({
    port: PROXY_PORT,
    resolveHost: (h) => (h === RELAY_NAME ? '127.0.0.1' : h),
  });

  browser = await launchBrowser(chromium, {
    // Explicit loopback bypass mirrors the real shell: the UI stays direct, only
    // the remote relay (relay.local) rides the proxy. Tor cannot exit to this
    // machine's loopback, so without the bypass the local UI could never load.
    proxy: { server: `socks5://127.0.0.1:${PROXY_PORT}`, bypass: '127.0.0.1,localhost,::1' },
  });

  const relayUrl = `wss://${RELAY_NAME}:${WS_PORT}`;
  const uiUrl = `http://127.0.0.1:${UI_PORT}/messenger.html?relay=${encodeURIComponent(relayUrl)}`;
  const ready = (p) => p.waitForFunction(() =>
    document.getElementById('my-address').textContent.length === 44 &&
    document.getElementById('status').textContent.includes('connected'), null, { timeout: 120000 });

  const ctxA = await browser.newContext(); const A = await ctxA.newPage();
  const ctxB = await browser.newContext(); const B = await ctxB.newPage();
  A.on('console', (m) => { if (m.type() === 'error') consoleErrors.push('A: ' + m.text()); });
  B.on('console', (m) => { if (m.type() === 'error') consoleErrors.push('B: ' + m.text()); });
  await A.goto(uiUrl, { timeout: 120000 }); await ready(A);
  await B.goto(uiUrl, { timeout: 120000 }); await ready(B);
  check('both contexts register with the relay through the SOCKS tunnel', true);

  const addrA = await A.evaluate(() => document.getElementById('my-address').textContent);
  await B.evaluate((addr) => {
    document.getElementById('peer-input').value = addr;
    document.getElementById('connect').click();
  }, addrA);
  await B.waitForFunction(() => !document.getElementById('send').disabled, null, { timeout: 30000 });
  await B.evaluate(() => { document.getElementById('msg-input').value = 'tor hello A'; document.getElementById('send').click(); });
  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), 'tor hello A', { timeout: 60000 });
  check('A decrypts B -> A through the tunnel', true);

  await A.evaluate(() => { document.getElementById('msg-input').value = 'reply from A'; document.getElementById('send').click(); });
  await B.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), 'reply from A', { timeout: 60000 });
  check('B decrypts A -> B through the tunnel', true);

  // The instrumented proxy must have seen the relay dial — the proof that the
  // browser's WebSocket left through the proxy rather than a direct link.
  const sawRelay = proxy.destinations.some((d) => d.host === RELAY_NAME && d.port === WS_PORT);
  check('browser WebSocket traversed the SOCKS proxy (CONNECT recorded)', sawRelay,
    proxy.destinations.map((d) => `${d.host}:${d.port}`).join(', '));

  // The loopback UI must stay direct (bypassed), not ride the proxy — otherwise
  // a real Tor exit could never reach this machine's own loopback.
  const uiViaProxy = proxy.destinations.some((d) => d.port === UI_PORT);
  check('loopback UI bypasses the proxy (stays direct)', !uiViaProxy,
    proxy.destinations.map((d) => `${d.host}:${d.port}`).join(', '));

  // The tunnel must be the ONLY route: the mock only ever resolved `relay.local`
  // to loopback, and nothing connected to the relay directly (the name does not
  // resolve on this machine).
  const onlyViaProxy = proxy.destinations.length > 0 &&
    proxy.destinations.every((d) => d.port !== RELAY_PORT || d.host === RELAY_NAME);
  check('no direct relay TCP connection bypassed the proxy', onlyViaProxy,
    proxy.destinations.map((d) => `${d.host}:${d.port}`).join(', '));

  check('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));

  await ctxA.close(); await ctxB.close(); await browser.close(); browser = null;
} catch (err) {
  console.error('[browser-tor-regression] ERROR:', err.message);
  if (consoleErrors.length) console.error('[browser-tor-regression] page console errors:', consoleErrors.slice(0, 8).join(' | '));
  if (relayOut.trim()) console.error('[browser-tor-regression] relay log:', relayOut.trim().split('\n').slice(-8).join(' | '));
  if (relayErr.trim()) console.error('[browser-tor-regression] relay stderr:', relayErr.trim().slice(0, 400));
  if (uiErr.trim()) console.error('[browser-tor-regression] ui stderr:', uiErr.trim().slice(0, 400));
  failures++;
} finally {
  if (browser) browser.close().catch(() => {});
  if (proxy) proxy.server.close();
  relay.kill('SIGTERM');
  ui.kill('SIGTERM');
}

console.log(failures === 0 ? '\nBROWSER TOR REGRESSION PASSED' : `\n${failures} BROWSER TOR CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
