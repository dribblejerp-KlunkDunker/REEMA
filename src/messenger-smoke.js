/**
 * Headless messenger smoke test (protocol v6), wired into `npm test`.
 *
 * Loads the minimal two-party client (`public/messenger.html`) in two
 * incognito contexts and drives a real A→B→A flow through the real relay —
 * the same core and relay the dashboard's E2EE tab uses, but through the
 * clean test client. This exercises the key-directory path (address mode +
 * one-time-prekey consumption) end to end against the actual `src/server.js`,
 * not a mock. It also proves GroupSession channels over WebSocket: A creates
 * a group inviting B, B joins from the Welcome, and both contexts exchange
 * epoch-0 messages fanned out by the relay (ROADMAP §7).
 *
 * Self-contained: spawns its own relay + static server on dedicated loopback
 * ports. Skips gracefully (exit 0) when the headless browser is not resolvable
 * (patchright lives inside a VS Code extension, so `npm test` must not depend
 * on it). When the browser IS available, failures are real (exit 1).
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { resolveChromium, launchBrowser } from './chromium.js';

const RELAY_PORT = Number(process.env.M_RELAY_PORT || 7996);
const WS_PORT = Number(process.env.M_WS_PORT || 8096);
const UI_PORT = Number(process.env.M_UI_PORT || 8011);
const UI_URL = `http://127.0.0.1:${UI_PORT}/messenger.html?relay=wss://127.0.0.1:${WS_PORT}`;

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

const chromium = resolveChromium();
if (!chromium) {
  console.log('[messenger-smoke] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension, or add patchright plus `npx patchright install chromium`, to enable this test.');
  process.exit(0);
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

try {
  await waitForTcp(RELAY_PORT, 15000);
  await waitForHttp(`http://127.0.0.1:${UI_PORT}/messenger.html`, 15000);

  const browser = await launchBrowser(chromium);
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

  // Deferred-bootstrap guard: the E2EE identity must NOT exist at first paint.
  // messenger.html records FCP (paint PerformanceObserver, first-rAF fallback)
  // and the moment identity creation completes; identity must land no earlier
  // than first paint. An eager bootstrap would create the identity at
  // module-eval time, well before FCP, and fail this check.
  const timing = await A.evaluate(() => {
    const raw = localStorage.getItem('__e2ee_timing');
    return raw ? JSON.parse(raw) : null;
  });
  const probeOk = !!timing && timing.fcpMs !== null && timing.identityMs !== null;
  check('messenger painted before the E2EE identity existed (idle-deferred bootstrap)',
    probeOk && timing.identityMs >= timing.fcpMs,
    probeOk ? `FCP ${timing.fcpMs.toFixed(1)}ms, identity ${timing.identityMs.toFixed(1)}ms`
            : timing ? `probe incomplete (fcp=${timing.fcpMs}, identity=${timing.identityMs})` : 'probe missing');

  // Lazy-load lock-in (same as the dashboard): the first @noble/post-quantum
  // fetch must land at/after first paint — the modules are pulled by the
  // deferred bootstrap's crypto work, never during initial module evaluation.
  // A static @noble import would fetch before FCP and fail this.
  const lazyOk = !!timing && timing.firstNobleMs !== null && timing.fcpMs !== null;
  check('messenger fetched no @noble/post-quantum modules during the initial load (lazy-load win)',
    lazyOk && timing.firstNobleMs >= timing.fcpMs,
    lazyOk ? `first @noble fetch ${timing.firstNobleMs.toFixed(1)}ms (FCP ${timing.fcpMs.toFixed(1)}ms)`
           : timing ? `probe incomplete (fcp=${timing.fcpMs}, firstNoble=${timing.firstNobleMs})` : 'probe missing');

  // Same lazy treatment for libsodium: it is injected by browser-crypto.js on
  // the idle bootstrap, so its first fetch must also land at/after FCP.
  const sodiumOk = !!timing && timing.firstSodiumMs !== null && timing.fcpMs !== null;
  check('messenger vendored libsodium (WASM) not fetched during the initial parse (lazy-load win)',
    sodiumOk && timing.firstSodiumMs >= timing.fcpMs,
    sodiumOk ? `first libsodium fetch ${timing.firstSodiumMs.toFixed(1)}ms (FCP ${timing.fcpMs.toFixed(1)}ms)`
             : timing ? `probe incomplete (fcp=${timing.fcpMs}, firstSodium=${timing.firstSodiumMs})` : 'probe missing');

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

  // Hostile plaintext: B sends a message packed with ESC/OSC-8/bidi/zero-width
  // controls. The feed must render the printable payload while stripping every
  // control — no terminal escapes and no Trojan-Source reordering/hiding can
  // survive into the DOM (browser twin of VULN-006).
  const hostile = 'HOSTILE-MARKER ' + '\x1b[2J\x1b]8;;https://evil.example\x1b\\' + '\u202e\u2066\u2067\u2068\u2069\u061c\u200e\u200f';
  await B.evaluate((h) => { document.getElementById('msg-input').value = h; document.getElementById('send').click(); }, hostile);
  await A.waitForFunction((m) => document.getElementById('feed').textContent.includes(m), 'HOSTILE-MARKER', { timeout: 60000 });
  check('A rendered the hostile message printable payload', true);
  const feedText = await A.evaluate(() => document.getElementById('feed').textContent);
  check('A feed DOM is escape-free (no ESC/OSC)', !feedText.includes('\x1b'));
  check('A feed DOM has no C0 controls', !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(feedText));
  check('A feed DOM resists Trojan-Source bidi/format controls', !/[\p{Cf}]/u.test(feedText));

  // ---- Group channels over WebSocket (ROADMAP §7): two browser contexts
  // join the SAME group through the real relay and exchange epoch-0 messages
  // — the GroupSession encrypts under the shared epoch key, the relay fans the
  // opaque envelope out to both subscribers, and each client trial-decrypts
  // into its own GroupSession (exactly the pair flow's transport). ----
  const addrB = await B.evaluate(() => document.getElementById('my-address').textContent);
  check('B exposes its routing address', typeof addrB === 'string' && addrB.length === 44);
  await A.evaluate(({ addr, label }) => {
    document.getElementById('group-label').value = label;
    document.getElementById('group-members').value = addr;
    document.getElementById('new-group').click();
  }, { addr: addrB, label: 'smoke-' + Date.now() });
  await A.waitForFunction(() => document.getElementById('group-tabs').children.length === 1, null, { timeout: 30000 });
  check('A created a group channel and subscribed to its group_id', true);
  const welcome = await A.evaluate(() => document.getElementById('group-welcome-out').value);
  const wObj = (() => { try { return JSON.parse(welcome); } catch { return null; } })();
  check('group Welcome carries the roster (B is a member)',
    !!(wObj && Array.isArray(wObj.members) && wObj.members.includes(addrB)));

  await B.evaluate((w) => {
    document.getElementById('group-welcome').value = w;
    document.getElementById('join-group').click();
  }, welcome);
  await B.waitForFunction(() => document.getElementById('group-tabs').children.length === 1, null, { timeout: 30000 });
  check('B joined the same group from the Welcome (membership enforced)', true);

  // A sends an epoch-0 group message; the relay fans out; B renders it.
  const gMsg = 'epoch-0 group hello ' + Date.now();
  await A.evaluate((t) => { document.getElementById('msg-input').value = t; document.getElementById('send').click(); }, gMsg);
  await B.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), gMsg, { timeout: 60000 });
  check('B rendered A\'s epoch-0 group message', true);
  const bFeed = await B.evaluate(() => document.getElementById('feed').textContent);
  check('group messages are tagged in the feed', /group · received/.test(bFeed));

  // B replies into the group; A renders it (self-echo suppressed on B).
  const gReply = 'epoch-0 group reply ' + Date.now();
  await B.evaluate((t) => { document.getElementById('msg-input').value = t; document.getElementById('send').click(); }, gReply);
  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes(t), gReply, { timeout: 60000 });
  check('A rendered B\'s epoch-0 group reply', true);
  const aGroupCount = await A.evaluate(() =>
    (document.getElementById('feed').textContent.match(/epoch-0 group hello/g) || []).length);
  check('sender does not double-render its own group message (self-echo suppressed)',
    aGroupCount === 1, aGroupCount + ' occurrence(s)');
  console.log('[mark] group channels over WS verified');

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
