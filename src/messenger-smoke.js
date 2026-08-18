/**
 * Headless messenger smoke test (protocol v6), wired into `npm test`.
 *
 * Loads the minimal two-party client (`public/messenger.html`) in two
 * incognito contexts and drives a real A→B→A flow through the real relay —
 * the same core and relay the dashboard's E2EE tab uses, but through the
 * clean test client. This exercises the key-directory path (address mode +
 * one-time-prekey consumption) end to end against the actual `src/server.js`,
 * not a mock.
 *
 * Self-contained: spawns its own relay + static server on dedicated loopback
 * ports. Skips gracefully (exit 0) when the headless browser is not resolvable
 * (patchright lives inside a VS Code extension, so `npm test` must not depend
 * on it). When the browser IS available, failures are real (exit 1).
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { createRequire } from 'node:module';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const RELAY_PORT = Number(process.env.M_RELAY_PORT || 7996);
const WS_PORT = Number(process.env.M_WS_PORT || 8096);
const UI_PORT = Number(process.env.M_UI_PORT || 8011);
const UI_URL = `http://127.0.0.1:${UI_PORT}/messenger.html?relay=ws://127.0.0.1:${WS_PORT}`;

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
      s.once('error', () => { s.destroy(); Date.now() > deadline ? rej(new Error('relay timeout')) : setTimeout(tryOnce, 200); });
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

// Resolve patchright the same way browser-e2e.js does (it ships inside the
// CodeGPT extension; there is no npm dependency to install).
function resolveChromium() {
  const bases = ['C:/Users/dribb/.vscode/extensions/', 'C:/Users/dribb/.vscode-insiders/extensions/'];
  for (const base of bases) {
    if (!existsSync(base)) continue;
    const dirs = readdirSync(base).filter((d) => d.startsWith('danielsanmedium.dscodegpt-'))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    if (!dirs.length) continue;
    try {
      const mod = createRequire(join(base, dirs[dirs.length - 1], 'standalone') + '/')('patchright');
      const c = mod?.chromium ?? mod?.default?.chromium;
      if (c) return c;
    } catch { /* try next */ }
  }
  return null;
}

const chromium = resolveChromium();
if (!chromium) {
  console.log('[messenger-smoke] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension to enable this test.');
  process.exit(0);
}

const relay = spawn(process.execPath, ['src/server.js'], {
  env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1' },
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

try {
  await waitForTcp(RELAY_PORT, 15000);
  await waitForHttp(`http://127.0.0.1:${UI_PORT}/messenger.html`, 15000);

  const browser = await chromium.launch({ headless: true });
  const ready = (p) => p.waitForFunction(() =>
    document.getElementById('my-address').textContent.length === 44 &&
    document.getElementById('status').textContent.includes('connected'), null, { timeout: 120000 });

  const ctxA = await browser.newContext(); const A = await ctxA.newPage();
  const ctxB = await browser.newContext(); const B = await ctxB.newPage();
  A.on('console', (m) => { if (m.type() === 'error') consoleErrors.push('A: ' + m.text()); });
  B.on('console', (m) => { if (m.type() === 'error') consoleErrors.push('B: ' + m.text()); });
  await A.goto(UI_URL, { timeout: 120000 }); await ready(A);
  await B.goto(UI_URL, { timeout: 120000 }); await ready(B);
  check('both messenger contexts boot and register with the relay', true);

  const addrA = await A.evaluate(() => document.getElementById('my-address').textContent);
  check('A has a 44-char bound routing address', addrA.length === 44, addrA);

  // B connects to A by address (directory lookup), then sends the first message.
  await B.evaluate((addr) => {
    document.getElementById('peer-input').value = addr;
    document.getElementById('connect').click();
  }, addrA);
  await B.waitForFunction(() => !document.getElementById('send').disabled, null, { timeout: 30000 });
  await B.evaluate(() => { document.getElementById('msg-input').value = 'hello A from B'; document.getElementById('send').click(); });

  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), 'hello A from B', { timeout: 60000 });
  check('A decrypts B -> A first message (one-time prekey bootstrap)', true);

  // A replies; B is already the active peer from the first contact.
  await A.evaluate(() => { document.getElementById('msg-input').value = 'reply from A'; document.getElementById('send').click(); });
  await B.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), 'reply from A', { timeout: 60000 });
  check('B decrypts A -> B reply (full A-B-A flow)', true);

  check('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));

  await ctxA.close(); await ctxB.close(); await browser.close();
} catch (err) {
  console.error('[messenger-smoke] ERROR:', err.message);
  if (consoleErrors.length) console.error('[messenger-smoke] page console errors:', consoleErrors.slice(0, 8).join(' | '));
  if (relayOut.trim()) console.error('[messenger-smoke] relay log:', relayOut.trim().split('\n').slice(-8).join(' | '));
  if (relayErr.trim()) console.error('[messenger-smoke] relay stderr:', relayErr.trim().slice(0, 400));
  if (uiErr.trim()) console.error('[messenger-smoke] ui stderr:', uiErr.trim().slice(0, 400));
  failures++;
} finally {
  relay.kill('SIGTERM');
  ui.kill('SIGTERM');
}

console.log(failures === 0 ? '\nMESSENGER SMOKE PASSED' : `\n${failures} MESSENGER SMOKE CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
