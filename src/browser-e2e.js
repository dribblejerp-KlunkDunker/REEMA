/**
 * Headless two-context browser E2E (protocol v6), wired into `npm test`.
 *
 * Fully self-contained: it spawns its own relay (TCP + WebSocket) and static
 * UI server on dedicated loopback ports, then drives a real conversation
 * between two incognito browser contexts through the real relay:
 *
 *   1. A -> B first message and B -> A reply (full A-B-A flow)
 *   2. steady-state envelopes still decrypt in the browser AND are the
 *      shrunk size (< 8 KB — the per-epoch omission rule)
 *   3. reload A: session restored from localStorage, ratchet continues
 *   4. reload B: same on the other side
 *   5. Node-vs-browser differential: a pure-Node peer (TCP) and the browser
 *      peer (WS) exchange envelopes through the relay in both directions,
 *      proving the two stacks share one wire format
 *   6. zero console errors, zero failed requests
 *
 * The page's relay endpoint is pointed at this test's instance via the
 * ?relay=ws://host:port query parameter (default remains ws://127.0.0.1:8080).
 *
 * Skips gracefully (exit 0) when the headless browser cannot be resolved —
 * patchright lives inside a VS Code extension, so `npm test` must not depend
 * on it. When the browser IS available, failures are real failures (exit 1).
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { createRequire } from 'node:module';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { init, Identity, Session, encodeBundle, decodeBundle, isReceipt } from './crypto.js';

// Dedicated ports so the test never collides with dev servers (7980/8080/8000)
// or other scratch harnesses (7983/8083).
const RELAY_PORT = Number(process.env.E2E_RELAY_PORT || 7994);
const WS_PORT = Number(process.env.E2E_WS_PORT || 8094);
const UI_PORT = Number(process.env.E2E_UI_PORT || 8009);
const UI_URL = `http://127.0.0.1:${UI_PORT}/?relay=ws://127.0.0.1:${WS_PORT}`;

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

function waitForTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const socket = connect(port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`relay did not listen on ${port}`));
        else setTimeout(tryOnce, 200);
      });
    };
    tryOnce();
  });
}

async function waitForHttp(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`UI server did not answer ${url}`);
}

/** Minimal newline-delimited TCP client (the relay's line protocol). */
function connectTcp(port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const socket = connect(port, host);
    socket.setEncoding('utf8');
    let buffer = '';
    const handlers = {};
    socket.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line) {
          const msg = JSON.parse(line);
          if (handlers[msg.type]) handlers[msg.type](msg);
        }
      }
    });
    socket.once('connect', () => resolve({
      socket,
      send: (obj) => socket.write(JSON.stringify(obj) + '\n'),
      once: (t) => new Promise((res) => { handlers[t] = (m) => { delete handlers[t]; res(m); }; }),
    }));
    socket.once('error', reject);
  });
}

function withTimeout(label, p, ms = 30000) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${label}`)), ms)),
  ]);
}

// Resolve patchright the same way the browser-automation skill does (it ships
// inside the CodeGPT extension; there is no npm dependency to install).
function resolveChromium() {
  const bases = [
    'C:/Users/dribb/.vscode/extensions/',
    'C:/Users/dribb/.vscode-insiders/extensions/',
  ];
  const roots = [];
  for (const base of bases) {
    if (!existsSync(base)) continue;
    const dirs = readdirSync(base)
      .filter((d) => d.startsWith('danielsanmedium.dscodegpt-'))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    if (dirs.length) roots.push(join(base, dirs[dirs.length - 1], 'standalone') + '/');
  }
  for (const root of roots) {
    try {
      const mod = createRequire(root)('patchright');
      const chromium = mod?.chromium ?? mod?.default?.chromium;
      if (chromium) return chromium;
    } catch { /* try next */ }
  }
  return null;
}

async function main() {
  const sodium = await init();
  const ORIG = sodium.base64_variants.ORIGINAL;
  const b64 = (u) => sodium.to_base64(u, ORIG);

  const chromium = resolveChromium();
  if (!chromium) {
    console.log('[browser-e2e] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension to enable this test.');
    return;
  }

  // ---- Spawn this test's own relay + UI server ----
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
  const failedRequests = [];

  try {
    await waitForTcp(RELAY_PORT, 15000);
    await waitForHttp(UI_URL.split('?')[0], 15000);

    const browser = await chromium.launch({ headless: true });

    const waitReady = (p) => p.waitForFunction(
      () => localStorage.getItem('e2ee_identity') &&
        document.getElementById('relay-status')?.textContent.includes('RELAY CONNECTED'),
      null, { timeout: 120000 }
    );

    const newPage = async (ctx, tag) => {
      const page = await ctx.newPage();
      page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${tag}: ${m.text()}`); });
      page.on('requestfailed', (r) => failedRequests.push(`${tag}: ${r.url()}`));
      await page.goto(UI_URL, { timeout: 120000 });
      await waitReady(page);
      return page;
    };

    // Rebuild each context's identity in Node to mint the shareable bundle
    // the other side pastes in (same as a user sharing their link).
    const rebuild = (keys) => new Identity({
      signSk: sodium.from_base64(keys.signSk, ORIG), signPk: sodium.from_base64(keys.signPk, ORIG),
      sk: sodium.from_base64(keys.dhSk, ORIG), pk: sodium.from_base64(keys.dhPk, ORIG),
      signedDhSk: sodium.from_base64(keys.signedDhSk, ORIG), signedDhPk: sodium.from_base64(keys.signedDhPk, ORIG),
      kemSk: sodium.from_base64(keys.kemSk, ORIG), kemPk: sodium.from_base64(keys.kemPk, ORIG),
    });

    // Click the SEND button rather than calling window.uiSendE2EEMessage:
    // page.evaluate runs in an isolated world, where main-world globals like
    // the inline-onclick handler target are not visible. The button's inline
    // onclick fires in the main world and is the real user path anyway.
    const send = (page, bundle, text) => page.evaluate(({ b, t }) => {
      document.getElementById('peer-key-input').value = b;
      document.getElementById('chat-input').value = t;
      [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('SEND')).click();
    }, { b: bundle, t: text });

    const waitForFeed = (page, text) => page.waitForFunction(
      (needle) => document.getElementById('chat-feed').textContent.includes(needle),
      text, { timeout: 60000 }
    );

    const feedSize = (page) => page.evaluate(() => {
      const m = [...document.getElementById('chat-feed').textContent.matchAll(/([\d,]+) bytes/g)];
      return m.length ? Number(m[m.length - 1][1].replace(/,/g, '')) : 0;
    });

    const tabs = (page) => page.evaluate(() => document.getElementById('session-tabs').children.length);

    // The active session is now persisted (e2ee_active_peer) and auto-restored
    // on reload; the click below is idempotent and still exercises the real
    // user path (switchSession fills the peer input too).
    const activateSession = (page) => page.evaluate(() => {
      const tab = document.querySelector('.session-tab');
      if (tab) tab.click();
      return !!tab;
    });

    const activatePeerTab = (page, pkB64) => page.evaluate((pk) => {
      const tab = [...document.querySelectorAll('.session-tab')].find((t) => t.dataset.pk === pk);
      if (tab) tab.click();
      return !!tab;
    }, pkB64);

    try {
      // ---- Two incognito contexts (separate localStorage = separate identities) ----
      const ctxA = await browser.newContext();
      const pageA = await newPage(ctxA, 'A');
      const keysA = await pageA.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
      const bundleA = encodeBundle(rebuild(keysA).makeBundle());

      const ctxB = await browser.newContext();
      const pageB = await newPage(ctxB, 'B');
      const keysB = await pageB.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
      const bundleB = encodeBundle(rebuild(keysB).makeBundle());
      console.log('[mark] both contexts ready');

      // ---- Full A -> B -> A flow ----
      await send(pageA, bundleB, 'A1 hello from Alice');
      await waitForFeed(pageB, 'A1 hello from Alice');
      check('A->B first message decrypted by Bob', true);

      await send(pageB, bundleA, 'B1 reply from Bob');
      await waitForFeed(pageA, 'B1 reply from Bob');
      check('B->A reply decrypted by Alice', true);

      // ---- Steady-state (shrunk) envelope in the real browser ----
      // A2 opens a new ratchet epoch (after B's reply), so it must still carry
      // pq_pk/pq_ct; A3 is the same epoch's SECOND message and must omit them.
      await send(pageA, bundleB, 'A2 opens new epoch');
      await waitForFeed(pageB, 'A2 opens new epoch');
      const sizeA2 = await feedSize(pageB);
      await send(pageA, bundleB, 'A3 same epoch');
      await waitForFeed(pageB, 'A3 same epoch');
      const sizeA3 = await feedSize(pageB);
      check('same-epoch second message uses the shrink (omits per-epoch fields)', sizeA3 > 0 && sizeA3 < 6000, `${sizeA3} bytes vs epoch-first ${sizeA2}`);
      console.log('[mark] shrink verified, reloading A');

      // ---- Reload A: session must survive and the ratchet must continue ----
      await pageA.reload({ timeout: 120000 });
      await waitReady(pageA);
      const tabsA = await tabs(pageA);
      check('Alice session restored from localStorage after reload', tabsA >= 1, `${tabsA} tab(s)`);
      const activeRestoredA = await pageA.evaluate(() => {
        const pk = localStorage.getItem('e2ee_active_peer');
        return !!pk && document.getElementById('peer-key-input').value === pk;
      });
      check('Alice active session auto-restored after reload (UX gap fixed)', activeRestoredA);
      const activatedA = await activateSession(pageA);
      check('Alice reactivated her session', activatedA, String(activatedA));
      await send(pageA, bundleB, 'A4 after Alice reload');
      await waitForFeed(pageB, 'A4 after Alice reload');
      check('A->B message after Alice reload (sender ratchet persisted)', true);
      console.log('[mark] A reload verified, reloading B');

      // ---- Reload B: same on the receiver side ----
      await pageB.reload({ timeout: 120000 });
      await waitReady(pageB);
      const tabsB = await tabs(pageB);
      check('Bob session restored from localStorage after reload', tabsB >= 1, `${tabsB} tab(s)`);
      const activatedB = await activateSession(pageB);
      check('Bob reactivated his session', activatedB, String(activatedB));
      console.log('[mark] B reloaded, sending B2');
      await send(pageB, bundleA, 'B2 after Bob reload');
      await waitForFeed(pageA, 'B2 after Bob reload');
      check('B->A message after Bob reload (receiver ratchet persisted)', true);
      console.log('[mark] B2 delivered');

      // ---- Node-vs-browser differential: both stacks share one wire format ----
      // Both clients run the SAME core (public/crypto-core.js), so a byte-level
      // output differential is moot by construction — that was the point of the
      // dedup. The residual divergence risk is the two environments themselves
      // (libsodium-wrappers + npm @noble in Node vs vendored libsodium +
      // import-mapped @noble in the browser). This leg closes that gap by
      // exchanging real envelopes through the relay: a pure-Node peer over TCP
      // and the live browser context over WebSocket, in both directions.
      const carolNode = new Identity();
      carolNode.newOneTimePrekeys(5);
      const carolBundle = encodeBundle(carolNode.makeBundle());
      const carolAddr = b64(Identity.deriveAddress(carolNode.signPk, carolNode.pk));
      const carolDhPk = b64(carolNode.pk);
      const bobAddr = b64(Identity.deriveAddress(rebuild(keysB).signPk, rebuild(keysB).pk));

      const node = await connectTcp(RELAY_PORT);
      const carolReg = node.once('published');
      const carolOtks = [...carolNode.oneTimePrekeys.values()].map((kp) => ({
        id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
      }));
      node.send({ type: 'publish', address: carolAddr, bundle: carolNode.makeBundle(), oneTimePrekeys: carolOtks });
      await withTimeout('carol publish', carolReg, 10000);

      // Carol resolves Bob from the REAL key directory (bundle + one one-time
      // prekey), exercising the relay's serve-and-consume path through the
      // actual server rather than a mock. A regression here once dropped the
      // OTK id on publish, so a served prekey failed verification.
      const bobDirP = node.once('directory');
      node.send({ type: 'fetch-directory', address: bobAddr });
      const bobDir = await withTimeout('bob directory fetch', bobDirP, 10000);
      const bobPeer = Identity.verifyBundle(bobDir.bundle);
      if (bobDir.oneTimePrekey && !Identity.verifyOneTimePrekey(bobPeer.signPk, bobDir.oneTimePrekey)) {
        throw new Error('relay served an invalid one-time prekey');
      }
      const nodeSession = new Session(carolNode, bobDir.bundle, bobDir.oneTimePrekey || null);

      // Node -> browser: the browser establishes from the first message's own
      // bundle (TOFU) and renders a new session tab; activate it so the live
      // feed shows the message, then assert it decrypted.
      const nodeToBrowser = 'interop from node stack';
      // B auto-receipts Carol's first message; capture it — it is the epoch-first
      // message whose ML-KEM material the human reply below omits.
      const receiptP = node.once('message');
      node.send({
        type: 'send', toPk: bobAddr,
        envelope: nodeSession.encrypt(new TextEncoder().encode(nodeToBrowser)),
        fromPk: carolAddr,
      });
      await pageB.waitForFunction(
        (pk) => [...document.querySelectorAll('.session-tab')].some((t) => t.dataset.pk === pk),
        carolDhPk, { timeout: 60000 }
      );
      const activatedCarol = await activatePeerTab(pageB, carolDhPk);
      check('browser opened the Node peer\'s session tab', activatedCarol, String(activatedCarol));
      await waitForFeed(pageB, nodeToBrowser);
      check('Node -> browser: browser peer decrypts a Node-stack envelope', true);

      // B's delivery receipt establishes Carol's receiving chain and carries the
      // epoch-first ML-KEM material the next same-epoch message relies on.
      const receiptMsg = await withTimeout('browser delivery receipt', receiptP, 10000);
      const receiptPlain = nodeSession.decrypt(receiptMsg.envelope);
      check('Node peer receives the browser delivery receipt', isReceipt(receiptPlain), String(receiptPlain));

      // Browser -> Node: the browser replies with its stack, Node decrypts.
      const browserToNode = 'interop from browser stack';
      const nodeMsgP = node.once('message');
      await send(pageB, carolBundle, browserToNode);
      const recv = await withTimeout('browser->node delivery', nodeMsgP);
      const nodePlain = nodeSession.decrypt(recv.envelope);
      check('browser -> Node: Node peer decrypts a browser-stack envelope', nodePlain === browserToNode, String(nodePlain));
      node.socket.destroy();
      console.log('[mark] Node<->browser interop verified');

      check('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
      check('no failed requests', failedRequests.length === 0, failedRequests.slice(0, 3).join(' | '));

      await ctxA.close();
      await ctxB.close();
    } finally {
      await browser.close();
    }
  } catch (err) {
    console.error('[browser-e2e] ERROR:', err.message);
    if (consoleErrors.length) console.error('[browser-e2e] page console errors:', consoleErrors.slice(0, 8).join(' | '));
    if (failedRequests.length) console.error('[browser-e2e] failed requests:', failedRequests.slice(0, 5).join(' | '));
    if (relayOut.trim()) console.error('[browser-e2e] relay log:', relayOut.trim().split('\n').slice(-14).join(' | '));
    if (relayErr.trim()) console.error('[browser-e2e] relay stderr:', relayErr.trim().slice(0, 600));
    if (uiErr.trim()) console.error('[browser-e2e] ui stderr:', uiErr.trim().slice(0, 600));
    failures++;
  } finally {
    relay.kill('SIGTERM');
    ui.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nBROWSER E2E PASSED' : `\n${failures} BROWSER E2E CHECK(S) FAILED`);
}

await main();
process.exit(failures === 0 ? 0 : 1);
