/**
 * Headless E2E for the AEGIS brain on the Reema spine (Phase 3).
 *
 * Drives the real messenger (public/messenger.html) through the real relay in
 * two incognito contexts and proves the three Phase 3 surfaces:
 *
 *   1. Pre-send gate — a flagged claim is intercepted with a reason and an
 *      explicit "Send anyway" confirmation; nothing leaves until confirmed.
 *   2. Inbound flags — the recipient renders the claim with a client-side risk
 *      flag (the relay never sees the analysis).
 *   3. Signed rebuttal — the recipient's DID-signed prebunk rebuttal arrives at
 *      the sender and verifies in place, proving identity reconciliation.
 *
 * Also asserts the XSS property: a claim carrying markup renders as inert text,
 * never as a live node.
 *
 * Self-contained (spawns relay + static server on loopback ports) and skips
 * gracefully (exit 0) when the headless driver is not resolvable, exactly like
 * messenger-smoke.js.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { resolveChromium, launchBrowser } from './chromium.js';

const RELAY_PORT = Number(process.env.MV_RELAY_PORT || 7997);
const WS_PORT = Number(process.env.MV_WS_PORT || 8097);
const UI_PORT = Number(process.env.MV_UI_PORT || 8012);
const UI_URL = `http://127.0.0.1:${UI_PORT}/messenger.html?relay=wss://127.0.0.1:${WS_PORT}`;
// The AEGIS dashboard is mounted by tools/serve.mjs on the SAME origin (see the
// /dashboard/ route) precisely so this page can read the messenger's attempt log.
const DASH_URL = `http://127.0.0.1:${UI_PORT}/dashboard/`;

const HOSTILE = 'HOSTILE-MARKER URGENT BREAKING: the corrupt deep state cabal is covering up a deadly poison in the water that will kill your innocent children! Share immediately before it is too late, traitor! 100% proven beyond all doubt!';
const NEUTRAL = 'NEUTRAL-MARKER The city council approved the quarterly budget on Tuesday by a vote of six to three.';
const XSS_CLAIM = 'XSS-MARKER <img src=x onerror=alert(1)> totally harmless budget note';

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

// Read the messenger's local append-only attempt log (the SAME schema AEGIS's
// attemptlog.js writes). Opens with the same version + onupgradeneeded so the
// probe can never wedge the messenger's own IndexedDB initialisation.
const readAttempts = (page) => page.evaluate(() => new Promise((resolve) => {
  let req;
  try { req = indexedDB.open('sovereign-aegis-attempts', 1); }
  catch { resolve(null); return; }
  req.onupgradeneeded = () => {
    if (!req.result.objectStoreNames.contains('attempts')) req.result.createObjectStore('attempts');
  };
  req.onerror = () => resolve(null);
  req.onsuccess = () => {
    const db = req.result;
    try {
      const tx = db.transaction('attempts', 'readonly');
      const g = tx.objectStore('attempts').getAll();
      g.onsuccess = () => { db.close(); resolve(g.result || []); };
      g.onerror = () => { db.close(); resolve(null); };
    } catch { db.close(); resolve(null); }
  };
}));

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
  console.log('[messenger-verdad] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension, or add patchright plus `npx patchright install chromium`, to enable this test.');
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

  const addrA = await A.evaluate(() => document.getElementById('my-address').textContent);
  check('A has a 44-char bound routing address', addrA.length === 44, addrA);

  // B connects to A by address and establishes the session with a neutral
  // message first (the neutral claim passes the gate untouched).
  await B.evaluate((addr) => {
    document.getElementById('peer-input').value = addr;
    document.getElementById('connect').click();
  }, addrA);
  await B.waitForFunction(() => !document.getElementById('send').disabled, null, { timeout: 30000 });
  await B.evaluate((t) => { document.getElementById('msg-input').value = t; document.getElementById('send').click(); }, NEUTRAL);
  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes('NEUTRAL-MARKER'), 'NEUTRAL-MARKER', { timeout: 60000 });
  check('neutral claim sent without a gate and decrypted by A', true);
  check('neutral message carries no risk flag on A', await A.evaluate(() => document.querySelectorAll('#feed .flag').length === 0));

  // ---- Phase 4: an un-gated message must write no attempt. ----
  const attemptsAfterNeutral = await readAttempts(B);
  check('an un-gated (neutral) message writes no attempt',
    !!attemptsAfterNeutral && attemptsAfterNeutral.length === 0,
    attemptsAfterNeutral ? `${attemptsAfterNeutral.length} attempt(s)` : 'db unreadable');

  // ---- 1. Pre-send gate: a flagged claim is intercepted, not sent. ----
  await B.evaluate((t) => { document.getElementById('msg-input').value = t; document.getElementById('send').click(); }, HOSTILE);
  await B.waitForFunction(() => document.querySelector('[data-gate="blocked"]'), null, { timeout: 30000 });
  check('B\'s flagged claim triggers the VERDAD gate', true);
  const gateText = await B.evaluate(() => document.querySelector('[data-gate="blocked"]').textContent);
  check('gate names a reason (risk %, not just "no")', /manipulation risk \d+%/i.test(gateText), gateText.slice(0, 80));
  check('gated claim did not reach A', await A.evaluate(() => !document.getElementById('feed').textContent.includes('HOSTILE-MARKER')));

  // ---- Phase 4: the near-share wrote exactly one attempt, tagged to the
  // "stop" skill, as a miss (correct=false), device-local (context messenger). ----
  let bAttempts = null;
  for (let i = 0; i < 50 && (!bAttempts || bAttempts.length < 1); i++) {
    bAttempts = await readAttempts(B);
    if (!bAttempts || bAttempts.length < 1) await new Promise((r) => setTimeout(r, 100));
  }
  const totalAttempts = bAttempts ? bAttempts.length : 0;
  const nearShare = (bAttempts || []).find((a) => a.context === 'messenger');
  check('near-share wrote exactly one attempt', totalAttempts === 1, `${totalAttempts} attempt(s)`);
  check('attempt is tagged skill.sift.stop', !!nearShare && nearShare.skillId === 'skill.sift.stop', nearShare && nearShare.skillId);
  check('attempt is a miss (correct=false) and not held out',
    !!nearShare && nearShare.correct === false && nearShare.heldOut === false);
  check('attempt context is messenger (device-local)', !!nearShare && nearShare.context === 'messenger');

  // ---- Shared origin => the dashboard reads the messenger's log. ----
  // B's near-share landed in `sovereign-aegis-attempts` on this origin. Open the
  // dashboard in B's OWN context (same origin + same context = same IndexedDB) and
  // prove the near-share count is visible and the stop-skill mastery moved off its
  // 0.5 "no evidence yet" prior. This is the whole point of the /dashboard/ mount.
  const dash = await ctxB.newPage();
  // The dashboard boot is heavy (telemetry, fonts, onboarding); it can emit
  // resource-load noise that is not a verdict-logic failure, so its console is
  // collected separately and only reported — the waitForFunction below is the
  // real assertion that the panel rendered from the shared log.
  const dashConsole = [];
  dash.on('console', (m) => { if (m.type() === 'error') dashConsole.push(m.text()); });
  await dash.goto(DASH_URL, { timeout: 120000 });
  await dash.waitForFunction(() => {
    const el = document.getElementById('mastery-panel');
    return el && /MESSENGER NEAR-SHARES CAUGHT BY THE GATE:\s*1/.test(el.textContent);
  }, null, { timeout: 60000 });
  const masteryText = await dash.evaluate(() => document.getElementById('mastery-panel').textContent);
  check('dashboard mastery panel shows the messenger near-share count',
    /MESSENGER NEAR-SHARES CAUGHT BY THE GATE:\s*1/.test(masteryText));
  const heroPct = await dash.evaluate(() => {
    const panel = document.getElementById('mastery-panel');
    const hero = [...panel.querySelectorAll('div')].find((d) => d.style.fontSize === '1.9rem');
    return hero ? parseInt(hero.textContent, 10) : null;
  });
  check('stop-skill mastery moved below the 50% prior',
    Number.isFinite(heroPct) && heroPct < 50,
    heroPct === null ? 'missing' : (Number.isFinite(heroPct) ? `${heroPct}%` : 'unparseable'));
  if (dashConsole.length) console.log('  (dashboard console:', dashConsole.slice(0, 3).join(' | '), ')');
  await dash.close();

  // Explicit confirmation sends it through (advisory, never silently enforced).
  await B.evaluate(() => document.querySelector('[data-gate-action="confirm"]').click());
  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes('HOSTILE-MARKER'), 'HOSTILE-MARKER', { timeout: 60000 });

  // ---- 2. Inbound flag: A renders the claim with a client-side verdict. ----
  await A.waitForFunction(() => document.querySelector('#feed [data-verdict]'), null, { timeout: 30000 });
  const verdict = await A.evaluate(() => {
    const f = document.querySelector('#feed [data-verdict]');
    return f ? { verdict: f.dataset.verdict, risk: Number(f.dataset.risk) } : null;
  });
  check('A flags the received claim with a verdict', !!verdict && ['block', 'caution'].includes(verdict.verdict), JSON.stringify(verdict));
  check('A\'s flag risk matches the offline analysis (>= 40)', !!verdict && verdict.risk >= 40, String(verdict && verdict.risk));

  // ---- 3. Signed rebuttal: A signs a prebunk and B verifies it in place. ----
  await A.waitForFunction(() => [...document.querySelectorAll('#feed button')].some((b) => b.textContent.includes('Send rebuttal')), null, { timeout: 30000 });
  await A.evaluate(() => [...document.querySelectorAll('#feed button')].find((b) => b.textContent.includes('Send rebuttal')).click());
  await B.waitForFunction(() => document.querySelector('#feed [data-rebuttal]'), null, { timeout: 60000 });
  const rebuttal = await B.evaluate(() => {
    const el = document.querySelector('#feed [data-rebuttal]');
    return el ? { state: el.dataset.rebuttal, text: el.textContent } : null;
  });
  check('B received the rebuttal and verified it in place', !!rebuttal && rebuttal.state === 'verified', rebuttal && rebuttal.text.slice(0, 80));
  check('verified rebuttal names the signer DID', !!rebuttal && /did:key:/.test(rebuttal.text));

  // ---- XSS: markup in a claim stays inert text, never a live node. ----
  await B.evaluate((t) => { document.getElementById('msg-input').value = t; document.getElementById('send').click(); }, XSS_CLAIM);
  await A.waitForFunction((t) => document.getElementById('feed').textContent.includes('XSS-MARKER'), 'XSS-MARKER', { timeout: 60000 });
  check('markup-laden claim renders as inert text (no img node)', await A.evaluate(() =>
    document.getElementById('feed').querySelectorAll('img').length === 0 &&
    document.getElementById('feed').textContent.includes('<img')));

  check('no console errors across both contexts', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));

  await ctxA.close(); await ctxB.close(); await browser.close();
} catch (err) {
  console.error('[messenger-verdad] ERROR:', err.message);
  if (consoleErrors.length) console.error('[messenger-verdad] page console errors:', consoleErrors.slice(0, 8).join(' | '));
  if (relayOut.trim()) console.error('[messenger-verdad] relay log:', relayOut.trim().split('\n').slice(-8).join(' | '));
  if (relayErr.trim()) console.error('[messenger-verdad] relay stderr:', relayErr.trim().slice(0, 400));
  if (uiErr.trim()) console.error('[messenger-verdad] ui stderr:', uiErr.trim().slice(0, 400));
  failures++;
} finally {
  relay.kill('SIGTERM');
  ui.kill('SIGTERM');
}

console.log(failures === 0 ? '\nMESSENGER VERDAD PASSED' : `\n${failures} MESSENGER VERDAD CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
