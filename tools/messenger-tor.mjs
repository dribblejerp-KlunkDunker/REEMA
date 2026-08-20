/**
 * Launch the messenger with the browser routed through Tor (`npm run messenger-tor`).
 *
 * This is the browser twin of the CLI's Tor path (src/tor.js). A page cannot do
 * per-connection SOCKS the way src/client.js does, so the equivalent is to
 * launch the browser itself with `--proxy-server=socks5://127.0.0.1:9050` and
 * let Chromium route the relay WebSocket through the Tor SOCKS proxy. Only the
 * RELAY traffic is meant to leave the device: the static UI is served loopback
 * and stays on Chromium's implicit loopback bypass.
 *
 * Honest constraints (ANONYMITY.md — fail closed, never overclaim):
 *
 *   - Requires a RUNNING Tor daemon. If Tor is not reachable the launcher
 *     refuses to start rather than silently opening a direct (IP-exposing)
 *     connection.
 *   - Requires a REMOTE relay via MESSENGER_TOR_RELAY (wss:// only). Routing a
 *     loopback relay through Tor buys nothing — the relay is already local — and
 *     Tor cannot reach your own loopback anyway, so the launcher refuses that
 *     instead of pretending it helps.
 *   - The remote relay must present a CA-trusted certificate. The browser has no
 *     TOFU fingerprint pin for a raw WebSocket, so it falls back to standard TLS
 *     validation: a self-signed relay is refused (fail closed), not silently
 *     trusted. That browser-pinning gap is recorded in ANONYMITY.md.
 *
 * Usage:
 *   MESSENGER_TOR_RELAY=wss://<onion-or-public-host>:<port> npm run messenger-tor
 */
import { spawn } from 'node:child_process';
import { resolveTorProxy } from '../src/tor.js';
import { resolveChromium } from '../src/chromium.js';

const UI_PORT = Number(process.env.MESSENGER_UI_PORT || 8000);
const RELAY = process.env.MESSENGER_TOR_RELAY || '';

// A remote relay must be wss:// and must NOT be loopback (a loopback relay is
// already local; routing it through Tor is meaningless).
const REMOTE_RELAY_RE = /^wss:\/\/[^/\s]+(:\d+)?(\/?|$)/;
const LOOPBACK_RELAY_RE = /^wss?:\/\/(127\.0\.0\.1|localhost)(:\d+)?(\/?|$)/;

function fail(msg) {
  console.error('[messenger-tor] ' + msg);
  process.exit(1);
}

if (!RELAY) {
  fail(
    'MESSENGER_TOR_RELAY is required (the relay URL as reachable through Tor, e.g. ' +
    'wss://<onion-or-public-host>:<port>).\n' +
    'A loopback relay through Tor buys nothing — use tools/messenger.mjs for the local demo.'
  );
}
if (!REMOTE_RELAY_RE.test(RELAY)) {
  fail('MESSENGER_TOR_RELAY must be a wss:// URL (plaintext to a remote host would expose the traffic).');
}
if (LOOPBACK_RELAY_RE.test(RELAY)) {
  fail(
    'MESSENGER_TOR_RELAY must be a REMOTE relay, not loopback: routing a local relay through Tor ' +
    'provides no anonymity and Tor cannot reach your own loopback anyway.'
  );
}

const proxy = await resolveTorProxy().catch((err) => fail(err.message));
console.log(`[messenger-tor] Tor SOCKS proxy: ${proxy.server}`);

const chromium = resolveChromium();
if (!chromium) {
  fail('no Chromium driver resolvable (install the CodeGPT extension, or add patchright + `npx patchright install chromium`).');
}

const ui = spawn(process.execPath, ['tools/serve.mjs'], {
  env: { ...process.env, UI_PORT: String(UI_PORT) },
  stdio: 'inherit',
});

async function waitForHttp(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const res = await fetch(url); if (res.ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`static server did not answer ${url}`);
}

let browser = null;
let shuttingDown = false;
function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  if (browser) browser.close().catch(() => {});
  ui.kill('SIGTERM');
  setTimeout(() => process.exit(code), 200);
}
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
ui.on('exit', () => shutdown(1));

try {
  await waitForHttp(`http://127.0.0.1:${UI_PORT}/messenger.html`);

  // Route the WHOLE browser through Tor; loopback stays direct (implicit bypass)
  // so the local UI loads normally while the remote relay rides the onion.
  browser = await chromium.launch({
    headless: false,
    // Explicit loopback bypass: the UI is served locally and must stay direct —
    // Tor cannot exit to this machine's own loopback, so a UI request routed
    // through the proxy would never load. Only the (remote) relay rides Tor.
    proxy: { server: proxy.server, bypass: '127.0.0.1,localhost,::1' },
  });
  const page = await browser.newPage();

  const uiUrl = `http://127.0.0.1:${UI_PORT}/messenger.html?relay=${encodeURIComponent(RELAY)}`;
  await page.goto(uiUrl, { waitUntil: 'domcontentloaded' });

  console.log(`\nMessenger (Tor) ready. Relay ${RELAY} is routed through ${proxy.server}.`);
  console.log(`UI: ${uiUrl}`);
  console.log('');
  console.log('🔒 Transport honesty (what this does and does NOT hide):');
  console.log('   • Your IP is hidden from the relay — traffic leaves only through Tor.');
  console.log('   • Content is end-to-end encrypted regardless of transport.');
  console.log('   • The relay still sees who-talks-to-whom metadata (sealed sender hides the');
  console.log('     sender; private directory lookup, Phase 1\'s other half, is not yet built).');
  console.log('   • This does NOT make you untraceable: a compromised device, a malicious');
  console.log('     peer, or physical-world correlation still identifies you (ANONYMITY.md §6).');
  console.log('');
  console.log('Press Ctrl+C to stop.\n');

  await new Promise(() => {}); // keep running until a signal arrives
} catch (err) {
  console.error('[messenger-tor] failed to start:', err.message);
  shutdown(1);
}
