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
 *   6. the dashboard paints BEFORE the E2EE identity exists — the deferred
 *      (idle-time) bootstrap must not block first paint (a probe in index.html
 *      records FCP vs identity-creation timestamps)
 *   7. lazy post-quantum loading is locked in: no @noble/vendor module is
 *      fetched during the initial page load (first fetch lands after first
 *      paint), and on a returning-user reload (full OTK pool + cached bundle)
 *      ZERO @noble modules are requested until a session message is actually
 *      sent — the resource-timing probe in index.html records firstNobleMs
 *   8. the vendored libsodium (WASM) is likewise not fetched during the
 *      initial parse — browser-crypto.js injects it on the idle bootstrap
 *      (firstSodiumMs in the probe)
 *   9. zero console errors, zero failed requests
 *
 * The page's relay endpoint is pointed at this test's instance via the
 * ?relay=ws://host:port query parameter (default remains ws://127.0.0.1:8080).
 *
 * Skips gracefully (exit 0) when the headless browser cannot be resolved —
 * patchright lives inside a VS Code extension, so `npm test` must not depend
 * on it. When the browser IS available, failures are real failures (exit 1).
 */
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveChromium, launchBrowser } from './chromium.js';
import { init, Identity, Session, encodeBundle, decodeBundle, loadPQ, isReceipt, directoryShard, selectOneTimePrekey } from './crypto.js';
import { connectRelay } from './test-tls.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** The project-local Go age CLI installed by tools/fetch-age-cli.mjs, if present. */
function projectAgeCli() {
  const bin = join(ROOT, 'tools', '.age-cli', 'bin', process.platform === 'win32' ? 'age.exe' : 'age');
  return existsSync(bin) ? bin : null;
}

let ageCliVersion = null; // set when detectAgeCli() finds a CLI

/**
 * Real age CLI for the browser<->Go-age interop cross-check. Prefers the
 * project-local install (tools/fetch-age-cli.mjs — pinned + SHA-256 verified),
 * then $AGE_CLI, then `age` on PATH (filippo.io/age — the Go implementation).
 * Returns the binary name/path or null. Skipping is deliberate: `npm test`
 * must not depend on a system age install, so the vault legs only cross-check
 * when one exists.
 */
function detectAgeCli() {
  const candidates = [projectAgeCli(), process.env.AGE_CLI, 'age'].filter(Boolean);
  for (const c of candidates) {
    try {
      const r = spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 10000 });
      if (r.status !== 0) continue;
      const out = String(r.stdout || '');
      if (!/\d+\.\d+/.test(out)) continue; // must print a version
      // The project-local install and $AGE_CLI are explicit trust; PATH
      // candidates must be named age-ish.
      if (c === projectAgeCli() || (process.env.AGE_CLI && c === process.env.AGE_CLI)) {
        ageCliVersion = out.trim();
        return c;
      }
      if (/age/i.test(c)) { ageCliVersion = out.trim(); return c; }
    } catch { /* not found or not runnable */ }
  }
  return null;
}

/** The Go age CLI only gained hybrid (mlkem768x25519) recipients in v1.2.0. */
function ageCliSupportsHybrid() {
  if (!ageCliVersion) return false;
  const m = ageCliVersion.match(/(\d+)\.(\d+)/);
  if (!m) return false;
  return Number(m[1]) > 1 || (Number(m[1]) === 1 && Number(m[2]) >= 2);
}

/**
 * Decrypt an armored age vault with the real Go age CLI and assert the
 * plaintext matches byte-for-byte. The armored file + secret key go to a
 * throwaway temp dir; age never sees the browser. Returns {ok, detail}.
 */
function ageCliDecrypt(ageCli, armored, secretKey, expectedPlain) {
  const dir = mkdtempSync(join(tmpdir(), 'bv-agecli-'));
  try {
    const armoredFile = join(dir, 'vault.age');
    const keyFile = join(dir, 'key.txt');
    writeFileSync(armoredFile, armored);
    writeFileSync(keyFile, secretKey.replace(/\r?\n$/, '') + '\n');
    const dec = spawnSync(ageCli, ['--decrypt', '-i', keyFile, armoredFile], {
      encoding: 'utf8',
      timeout: 30000,
    });
    if (dec.status !== 0) {
      return { ok: false, detail: (dec.stderr || '').trim().slice(0, 200) || `age exited ${dec.status}` };
    }
    if (dec.stdout !== expectedPlain) {
      return { ok: false, detail: `plaintext mismatch (${dec.stdout.length} vs ${expectedPlain.length} bytes)` };
    }
    return { ok: true, detail: `${dec.stdout.length} bytes round-tripped` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * ENCRYPT plaintext with the real Go age CLI to an age recipient and return
 * the armored ciphertext — the reverse direction of ageCliDecrypt, proving the
 * browser can open files produced by the reference implementation. Recipient
 * encryption is non-interactive (no tty passphrase), so it is scriptable.
 * Returns {ok, armored?, detail}.
 */
function ageCliEncrypt(ageCli, recipient, plaintext) {
  const dir = mkdtempSync(join(tmpdir(), 'bv-agecli-enc-'));
  try {
    const plainFile = join(dir, 'plain.bin');
    const armoredFile = join(dir, 'vault.age');
    writeFileSync(plainFile, plaintext);
    const enc = spawnSync(ageCli, ['--encrypt', '-r', recipient, '-a', '-o', armoredFile, plainFile], {
      encoding: 'utf8',
      timeout: 30000,
    });
    if (enc.status !== 0) {
      return { ok: false, detail: (enc.stderr || '').trim().slice(0, 200) || `age exited ${enc.status}` };
    }
    const armored = readFileSync(armoredFile, 'utf8');
    if (!armored.startsWith('-----BEGIN AGE ENCRYPTED FILE-----')) {
      return { ok: false, detail: 'output is not an armored age file' };
    }
    return { ok: true, armored, detail: `${plaintext.length} bytes encrypted to ${recipient.slice(0, 14)}…` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Dedicated ports so the test never collides with dev servers (7980/8080/8000)
// or other scratch harnesses (7983/8083).
const RELAY_PORT = Number(process.env.E2E_RELAY_PORT || 7994);
const WS_PORT = Number(process.env.E2E_WS_PORT || 8094);
const UI_PORT = Number(process.env.E2E_UI_PORT || 8009);
// memory=0 pins the loopback Hindsight sidecar OFF so this test stays
// hermetic — a sidecar running on the dev machine must not change feed output.
const UI_URL = `http://127.0.0.1:${UI_PORT}/?relay=wss://127.0.0.1:${WS_PORT}&memory=0`;

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

/** TLS client pinned to the dev cert (the relay's line protocol). */
const connectTcp = (port, host = '127.0.0.1') => connectRelay(port, host);

function withTimeout(label, p, ms = 30000) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${label}`)), ms)),
  ]);
}

async function main() {
  const sodium = await init();
  await loadPQ(); // the differential peer needs keygen + session ops
  const ORIG = sodium.base64_variants.ORIGINAL;
  const b64 = (u) => sodium.to_base64(u, ORIG);
  const ageCli = detectAgeCli();
  if (ageCli) console.log(`[age-cli] cross-checking browser<->Go age interop in both directions: ${ageCli}${ageCliSupportsHybrid() ? '' : ' (pre-1.2.0: hybrid checks skipped)'}`);
  else console.log('[age-cli] SKIP: no Go age CLI — run `node tools/fetch-age-cli.mjs` (or set AGE_CLI=/path/to/age) to enable browser<->age interop checks');

  const chromium = resolveChromium();
  if (!chromium) {
    console.log('[browser-e2e] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension, or add patchright plus `npx patchright install chromium`, to enable this test.');
    return;
  }

  // ---- Spawn this test's own relay + UI server ----
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
  const allConsole = []; // every console line (any type) — for the sanitize audit
  const failedRequests = [];

  try {
    await waitForTcp(RELAY_PORT, 15000);
    await waitForHttp(UI_URL.split('?')[0], 15000);

    const browser = await launchBrowser(chromium);

    const waitReady = (p) => p.waitForFunction(
      () => localStorage.getItem('e2ee_identity') &&
        document.getElementById('relay-status')?.textContent.includes('RELAY CONNECTED'),
      null, { timeout: 120000 }
    );

    const newPage = async (ctx, tag) => {
      const page = await ctx.newPage();
      page.on('console', (m) => {
        allConsole.push(`${tag}: ${m.text()}`);
        if (m.type() === 'error') consoleErrors.push(`${tag}: ${m.text()}`);
      });
      page.on('requestfailed', (r) => failedRequests.push(`${tag}: ${r.url()}`));
      await page.goto(UI_URL, { timeout: 120000 });
      await waitReady(page);
      // Deferred-bootstrap guard: the E2EE identity must NOT exist at first
      // paint. index.html records FCP (paint PerformanceObserver, first-rAF
      // fallback) and the moment identity creation completes; identity must
      // land no earlier than first paint. An eager bootstrap would create the
      // identity at module-eval time, well before FCP, and fail this check.
      const timing = await page.evaluate(() => {
        const raw = localStorage.getItem('__e2ee_timing');
        return raw ? JSON.parse(raw) : null;
      });
      const probeOk = !!timing && timing.fcpMs !== null && timing.identityMs !== null;
      check(`${tag}: dashboard painted before the E2EE identity existed (idle-deferred bootstrap)`,
        probeOk && timing.identityMs >= timing.fcpMs,
        probeOk ? `FCP ${timing.fcpMs.toFixed(1)}ms, identity ${timing.identityMs.toFixed(1)}ms`
                : timing ? `probe incomplete (fcp=${timing.fcpMs}, identity=${timing.identityMs})` : 'probe missing');
      // Lazy-load lock-in: the first @noble/post-quantum fetch must land at or
      // after first paint — the modules are pulled by the deferred bootstrap's
      // crypto work (keygen/session), never during initial module evaluation.
      // A static @noble import would fetch before FCP and fail this.
      const lazyOk = !!timing && timing.firstNobleMs !== null && timing.fcpMs !== null;
      check(`${tag}: no @noble/post-quantum modules fetched during the initial page load (lazy-load win)`,
        lazyOk && timing.firstNobleMs >= timing.fcpMs,
        lazyOk ? `first @noble fetch ${timing.firstNobleMs.toFixed(1)}ms (FCP ${timing.fcpMs.toFixed(1)}ms)`
               : timing ? `probe incomplete (fcp=${timing.fcpMs}, firstNoble=${timing.firstNobleMs})` : 'probe missing');
      // Same lazy treatment for libsodium: it is injected by browser-crypto.js
      // on the idle bootstrap, so its first fetch must also land at/after FCP.
      // A re-added <script defer> tag would fetch it during initial load and
      // fail this.
      const sodiumOk = !!timing && timing.firstSodiumMs !== null && timing.fcpMs !== null;
      check(`${tag}: vendored libsodium (WASM) is not fetched during the initial parse (lazy-load win)`,
        sodiumOk && timing.firstSodiumMs >= timing.fcpMs,
        sodiumOk ? `first libsodium fetch ${timing.firstSodiumMs.toFixed(1)}ms (FCP ${timing.fcpMs.toFixed(1)}ms)`
                 : timing ? `probe incomplete (fcp=${timing.fcpMs}, firstSodium=${timing.firstSodiumMs})` : 'probe missing');
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
      // Lazy-load lock-in (returning user): A's OTK pool is full (20) and its
      // signed bundle is cached, so the reload bootstrap — identity restore,
      // session restore, authenticated registration — must fetch ZERO
      // @noble/post-quantum modules. The graph is first requested only when
      // A4 below actually establishes/sends on a session.
      const reloadTimingA = await pageA.evaluate(() => {
        const raw = localStorage.getItem('__e2ee_timing');
        return raw ? JSON.parse(raw) : null;
      });
      check('A reload: no @noble/post-quantum modules fetched until a session is established',
        !!reloadTimingA && reloadTimingA.firstNobleMs === null,
        reloadTimingA ? `firstNoble=${reloadTimingA.firstNobleMs}` : 'probe missing');
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
      // ... and that first session message is exactly what finally pulls the
      // post-quantum graph in (session establishment: bundle verify + ML-KEM).
      const afterSendTimingA = await pageA.evaluate(() => {
        const raw = localStorage.getItem('__e2ee_timing');
        return raw ? JSON.parse(raw) : null;
      });
      check('A reload: @noble/post-quantum modules fetched once a session message is sent',
        !!afterSendTimingA && afterSendTimingA.firstNobleMs !== null,
        afterSendTimingA ? `firstNoble=${afterSendTimingA.firstNobleMs?.toFixed(1)}ms` : 'probe missing');
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

      // Carol resolves Bob from the REAL key directory via a private SHARD
      // fetch (whole shard, no address on the wire), then selects the target
      // entry client-side. A regression here once dropped the OTK id on
      // publish, so a served prekey failed verification.
      const bobDirP = node.once('directory-shard');
      node.send({ type: 'fetch-shard', shard: directoryShard(bobAddr, 1) });
      const bobDir = await withTimeout('bob shard fetch', bobDirP, 10000);
      const bobEntry = bobDir.entries.find((e) => e.address === bobAddr);
      if (!bobEntry) throw new Error('bob not in served shard');
      const bobPeer = Identity.verifyBundle(bobEntry.bundle);
      const bobOtk = selectOneTimePrekey(carolAddr, bobAddr, bobEntry.oneTimePrekeys);
      if (bobOtk && !Identity.verifyOneTimePrekey(bobPeer.signPk, bobOtk)) {
        throw new Error('relay served an invalid one-time prekey');
      }
      const nodeSession = new Session(carolNode, bobEntry.bundle, bobOtk || null);

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

      // ---- Scoped vault legs: active-session ratchet + arbitrary note ----
      // The BACK UP selector chooses WHAT gets encrypted. Run BEFORE the
      // identity vault legs (which replace identities / clear sessions).
      // Session: A exports its active session's full ratchet state, re-imports
      // it (replacing the live session with the restored one), and must STILL
      // decrypt a fresh B->A message — proving Session.serialize() survived the
      // age round-trip. Note: arbitrary text encrypts and decrypts verbatim.
      // (Local click helper — the vault leg's clickBtn is defined later.)
      const clickInA = (label) => pageA.evaluate((l) => {
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes(l));
        if (b) b.click();
        return !!b;
      }, label);
      check('scoped-leg keygen button present', await clickInA('GENERATE AGE KEYPAIR'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-age-key').dataset.full || '').startsWith('AGE-SECRET-KEY-'),
        { timeout: 60000 }
      );
      const scopedAgeKey = await pageA.evaluate(() => document.getElementById('vault-age-key').dataset.full);
      const tabsBeforeSessionVault = await tabs(pageA);
      await pageA.evaluate(() => {
        const sel = document.getElementById('vault-scope');
        sel.value = 'session';
        sel.dispatchEvent(new Event('change'));
        document.getElementById('vault-passphrase').value = '';
      });
      check('session scope export button present', await clickInA('EXPORT VAULT'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-export-out').value || '').startsWith('-----BEGIN AGE ENCRYPTED FILE-----'),
        { timeout: 60000 }
      );
      const sessionVault = await pageA.evaluate(() => document.getElementById('vault-export-out').value);
      check('session-scope export produced an armored age vault', /^-----BEGIN AGE ENCRYPTED FILE-----/.test(sessionVault));
      await pageA.evaluate((armored) => {
        document.getElementById('vault-import-in').value = armored;
        document.getElementById('vault-import-key').value = document.getElementById('vault-age-key').dataset.full;
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
        if (b) b.click();
      }, sessionVault);
      await pageA.waitForFunction(
        (n) => document.getElementById('session-tabs').children.length >= n,
        tabsBeforeSessionVault, { timeout: 60000 }
      );
      check('session vault restored the active session tab', true);
      const afterSessionVault = 'decrypted after session-vault restore';
      await send(pageB, bundleA, afterSessionVault);
      await waitForFeed(pageA, afterSessionVault);
      check('restored session still decrypts a fresh peer message (ratchet survived the age round-trip)', true);

      // Note scope: arbitrary text encrypts and decrypts verbatim.
      const noteText = 'blackvault note backup ' + Date.now();
      await pageA.evaluate((txt) => {
        const sel = document.getElementById('vault-scope');
        sel.value = 'note';
        sel.dispatchEvent(new Event('change'));
        document.getElementById('vault-note-input').value = txt;
        document.getElementById('vault-passphrase').value = '';
      }, noteText);
      await clickInA('EXPORT VAULT');
      await pageA.waitForFunction(
        () => (document.getElementById('vault-export-out').value || '').startsWith('-----BEGIN AGE ENCRYPTED FILE-----'),
        { timeout: 60000 }
      );
      const noteVault = await pageA.evaluate(() => document.getElementById('vault-export-out').value);
      check('note-scope export produced an armored age vault', /^-----BEGIN AGE ENCRYPTED FILE-----/.test(noteVault));
      await pageA.evaluate((armored) => {
        document.getElementById('vault-import-in').value = armored;
        document.getElementById('vault-import-key').value = document.getElementById('vault-age-key').dataset.full;
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
        if (b) b.click();
      }, noteVault);
      await pageA.waitForFunction(
        (txt) => document.getElementById('vault-export-out').value === txt,
        noteText, { timeout: 60000 }
      );
      check('note vault decrypts back to the exact original text', true);
      // The SAME note vault must decrypt with the real Go age CLI, byte-for-byte.
      if (ageCli) {
        const notePlain = JSON.stringify({ kind: 'note', v: 1, data: noteText });
        const r = ageCliDecrypt(ageCli, noteVault, scopedAgeKey, notePlain);
        check('Go age CLI decrypts the browser-exported note byte-for-byte', r.ok, r.detail);
      }
      // Reset the panel for the identity vault legs that follow: scope back to
      // identity, clear the note + export box.
      await pageA.evaluate(() => {
        const sel = document.getElementById('vault-scope');
        sel.value = 'identity';
        sel.dispatchEvent(new Event('change'));
        document.getElementById('vault-note-input').value = '';
        document.getElementById('vault-export-out').value = '';
      });
      console.log('[mark] scoped vault round-trips verified (session + note)');

      // ---- Group-mode over WebSocket (ROADMAP §7) ----
      // The relay's group fan-out is transport-agnostic: one `handleLine`
      // serves TCP and WebSocket alike (the groups map holds client objects,
      // not sockets). Two browser clients open raw WebSockets to the relay in
      // their own incognito contexts, subscribe to one group_id, a third
      // browser WS sends a group-mode envelope, and BOTH browsers must
      // receive the byte-identical opaque envelope — while a Node TCP
      // subscriber to the SAME group receives it too, proving the fan-out
      // code path is literally the one the TCP group tests exercise.
      const groupId = b64(sodium.randombytes_buf(32));
      const otherGroup = b64(sodium.randombytes_buf(32));
      const groupEnv = { v: 6, mode: 'group', ciphertext: Buffer.from('group-ws-fanout#1').toString('base64') };
      const wsRelay = `wss://127.0.0.1:${WS_PORT}`;

      // Each browser client: open a raw WS, subscribe, and buffer every frame
      // into a hidden DOM node (the shared channel evaluate can read across
      // worlds). Resolves once the subscribe ack arrives.
      const setupGroupSub = (page, tag) => page.evaluate(async ({ relayUrl, group, tag: t }) => {
        const d = document.createElement('div');
        d.id = `__grp_${t}`;
        d.style.display = 'none';
        document.body.appendChild(d);
        const recv = [];
        const ws = new WebSocket(relayUrl);
        await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws open failed')); });
        ws.onmessage = (e) => { recv.push(e.data); d.dataset.recv = JSON.stringify(recv); };
        ws.send(JSON.stringify({ type: 'subscribe', group }));
        const t0 = Date.now();
        while (Date.now() - t0 < 15000) {
          if (recv.some((l) => { try { return JSON.parse(l).type === 'subscribed'; } catch { return false; } })) return true;
          await new Promise((r) => setTimeout(r, 50));
        }
        throw new Error(`${t} subscribe ack timeout`);
      }, { relayUrl: wsRelay, group: groupId, tag });

      const readGroupRecv = (page, tag) => page.evaluate((t) => {
        const d = document.getElementById(`__grp_${t}`);
        return d ? JSON.parse(d.dataset.recv) : [];
      }, tag);

      const waitGroupMsg = async (page, tag, ms = 20000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) {
          const recv = await readGroupRecv(page, tag);
          const hit = recv.map((l) => { try { return JSON.parse(l); } catch { return null; } })
            .find((m) => m && m.type === 'message');
          if (hit) return hit;
          await new Promise((r) => setTimeout(r, 100));
        }
        throw new Error(`group message not received by ${tag}`);
      };

      const [subA, subB] = await Promise.all([
        setupGroupSub(pageA, 'A'),
        setupGroupSub(pageB, 'B'),
      ]);
      check('both browser clients subscribed to the group over WS', subA && subB);

      // Cross-transport proof: a Node TCP client subscribes to the SAME
      // group_id — one fan-out must serve both transports at once.
      const tcpSub = await connectTcp(RELAY_PORT);
      const tcpSubAck = tcpSub.once('subscribed');
      tcpSub.send({ type: 'subscribe', group: groupId });
      await withTimeout('tcp subscriber joined the same group', tcpSubAck, 10000);

      // Register the TCP subscriber's listener BEFORE the send — the relay
      // fans out immediately, so a late once() would miss the delivery.
      const tcpMsgP = tcpSub.once('message');

      // A third browser WS sends the group envelope. Sealed sender: it sends
      // fromPk as a deliberate probe — the relay must IGNORE it and never echo
      // a sender identity to subscribers.
      const fromPk = 'ws-group-sender';
      await pageA.evaluate(async ({ relayUrl, group, envelope, fp }) => {
        const ws = new WebSocket(relayUrl);
        await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws open failed')); });
        ws.send(JSON.stringify({ type: 'send', toPk: group, envelope, fromPk: fp }));
        await new Promise((r) => setTimeout(r, 300));
      }, { relayUrl: wsRelay, group: groupId, envelope: groupEnv, fp: fromPk });

      const msgA = await waitGroupMsg(pageA, 'A');
      const msgB = await waitGroupMsg(pageB, 'B');
      const msgT = await withTimeout('tcp group subscriber', tcpMsgP, 10000);

      check('browser A received the group-mode envelope over WS', !!(msgA.envelope && msgA.envelope.mode === 'group'));
      check('browser B received the group-mode envelope over WS', !!(msgB.envelope && msgB.envelope.mode === 'group'));
      check('TCP subscriber to the same group received it too (same fan-out as TCP)',
        !!(msgT.envelope && msgT.envelope.mode === 'group'));
      const opaqueOk = [msgA, msgB, msgT].every((m) => JSON.stringify(m.envelope) === JSON.stringify(groupEnv));
      check('group envelope stayed byte-identical and opaque (no pair fields added) on WS', opaqueOk);
      check('sealed sender: relay does NOT echo fromPk through the WS fan-out',
        msgA.fromPk === undefined && msgB.fromPk === undefined && msgT.fromPk === undefined);
      const paddedOk = [msgA, msgB, msgT].every((m) => typeof m.pad === 'string' && m.pad.length > 0);
      check('WS group delivery is padded to a fixed bucket like TCP (sendPadded path)', paddedOk);

      // Negative: a client subscribed to a DIFFERENT group must not see it.
      const subOther = await pageA.evaluate(async ({ relayUrl, group }) => {
        const recv = [];
        const ws = new WebSocket(relayUrl);
        await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws open failed')); });
        ws.onmessage = (e) => recv.push(e.data);
        ws.send(JSON.stringify({ type: 'subscribe', group }));
        await new Promise((r) => setTimeout(r, 1200));
        return recv;
      }, { relayUrl: wsRelay, group: otherGroup });
      check('a WS client on a different group_id receives no group envelope',
        !subOther.some((l) => { try { return JSON.parse(l).type === 'message'; } catch { return false; } }),
        `${subOther.length} frame(s)`);
      tcpSub.socket.destroy();
      console.log('[mark] group-mode fan-out verified over WebSocket (browser A + B + TCP)');

      // ---- Group UI leg (ROADMAP §7): the dashboard's create/join flow — a
      // real GroupSession, relay subscribe fan-out, and group chat rendered in
      // the shared feed alongside the pair sessions. ----
      const groupSend = (page, text) => page.evaluate((t) => {
        document.getElementById('chat-input').value = t;
        [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('SEND')).click();
      }, text);

      // A creates a group and invites B by routing address (the roster is what
      // makes the epoch-0 Welcome valid for B — fromWelcome enforces it).
      const bAddr = await pageB.evaluate(() => document.getElementById('my-address-key').dataset.full);
      check('dashboard shows the routing address', typeof bAddr === 'string' && bAddr.length === 44);
      await pageA.evaluate(({ label, member }) => {
        document.getElementById('group-label-input').value = label;
        document.getElementById('group-members-input').value = member;
        [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('NEW GROUP')).click();
      }, { label: 'bv-ui-' + Date.now(), member: bAddr });
      await pageA.waitForFunction(
        () => document.getElementById('group-tabs').children.length === 1,
        { timeout: 60000 }
      );
      check('NEW GROUP created a group channel tab on A', true);
      await pageA.waitForFunction(
        () => (document.getElementById('group-welcome-out').value || '').includes('group-welcome'),
        { timeout: 60000 }
      );
      const welcome = await pageA.evaluate(() => document.getElementById('group-welcome-out').value);
      const welcomeObj = (() => { try { return JSON.parse(welcome); } catch { return null; } })();
      check('creator can export the group Welcome',
        !!(welcomeObj && welcomeObj.type === 'group-welcome'), (welcome || '').slice(0, 40));
      const gid = welcomeObj && welcomeObj.groupId;
      check('group_id is a 44-char relay routing address',
        typeof gid === 'string' && gid.length === 44, String(gid).length + ' chars');

      // B joins out-of-band with the Welcome (JOIN pastes it in).
      await pageB.evaluate((w) => {
        document.getElementById('group-welcome-input').value = w;
        [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('JOIN')).click();
      }, welcome);
      await pageB.waitForFunction(
        () => document.getElementById('group-tabs').children.length === 1,
        { timeout: 60000 }
      );
      check('JOIN with the Welcome created a group channel tab on B', true);

      // A sends into the group; the relay fans out; B renders it in the feed.
      const groupMsg1 = 'hello from the group UI ' + Date.now();
      await groupSend(pageA, groupMsg1);
      await waitForFeed(pageB, groupMsg1);
      check('group message rendered in B\'s chat feed', true);
      const bFeed = await pageB.evaluate(() => document.getElementById('chat-feed').textContent);
      check('group stamp marks the epoch', /Group · epoch 0/.test(bFeed), bFeed.slice(0, 60));

      // Self-echo suppression: the relay fans out to EVERY subscriber (sender
      // included); the sender rendered once on send and must not re-render.
      await waitForFeed(pageA, groupMsg1);
      await new Promise((r) => setTimeout(r, 900)); // let the echo land
      const aBubbleCount = await pageA.evaluate(() =>
        (document.getElementById('chat-feed').textContent.match(/hello from the group UI/g) || []).length);
      check('sender does not double-render its own group message (self-echo suppressed)',
        aBubbleCount === 1, aBubbleCount + ' bubble(s)');

      // B replies; A receives it, stamped with the (sanitized) sender address.
      const groupMsg2 = 'echo from B ' + Date.now();
      await groupSend(pageB, groupMsg2);
      await waitForFeed(pageA, groupMsg2);
      check('group reply rendered in A\'s chat feed', true);
      const aFeed = await pageA.evaluate(() => document.getElementById('chat-feed').textContent);
      check('received group message stamps the sender address', /from [A-Za-z0-9+/=]{8,}/.test(aFeed));

      // VULN-006 regression: a group member forges env.sender to hostile
      // markup. Because the AEAD nonce derives FROM the sender field, the
      // forged sender still decrypts on A — the stamp must render it as
      // literal text (textContent), never as an injected element. Forge in
      // Node from the Welcome's epoch key (the evaluate's isolated world gets
      // a separate module graph, so patching the page's GroupSession
      // prototype from evaluate is unreliable) and inject over a raw WS — the
      // exact channel the fan-out leg above used, keeping this on the real
      // relay path into A's receive handler.
      const { GroupSession, useSodium } = await import('../public/group-core.js');
      useSodium(sodium);
      const forged = new GroupSession({
        groupId: gid,
        epoch: welcomeObj.epoch,
        epochKey: sodium.from_base64(welcomeObj.epochKey, sodium.base64_variants.ORIGINAL),
        members: welcomeObj.members,
        creator: welcomeObj.creator || null,
        myAddress: '<svg/onload=alert(1)>HOSTILE',
      });
      const hostileMsg = 'hostile-sender probe ' + Date.now();
      const hostileEnv = forged.encrypt(hostileMsg);
      await pageA.evaluate(async ({ relayUrl, group, envelope }) => {
        const ws = new WebSocket(relayUrl);
        await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws open failed')); });
        ws.send(JSON.stringify({ type: 'send', toPk: group, envelope }));
        await new Promise((r) => setTimeout(r, 300));
      }, { relayUrl: wsRelay, group: gid, envelope: hostileEnv });
      await waitForFeed(pageA, hostileMsg);
      const hostileDom = await pageA.evaluate(() => {
        const feed = document.getElementById('chat-feed');
        return {
          hasSvg: !!feed.querySelector('svg'),
          hasImg: !!feed.querySelector('img'),
          hasScript: !!feed.querySelector('script'),
          text: feed.textContent,
        };
      });
      check('forged group sender injected no element (stamp renders sender as text)',
        !hostileDom.hasSvg && !hostileDom.hasImg && !hostileDom.hasScript);
      check('forged sender appears as literal text in A\'s feed',
        hostileDom.text.includes('from <svg/onload'), hostileDom.text.slice(-90).replace(/\n/g, '|'));

      // Persistence + resubscribe: A reloads, the group tab comes back from
      // storage, and a fresh group message from B still decrypts — proving
      // the epoch key survived the round-trip and the reload re-subscribed.
      await pageA.reload();
      await pageA.waitForFunction(
        () => document.getElementById('group-tabs').children.length === 1,
        { timeout: 60000 }
      );
      check('group channel restored after reload (epoch key persisted)', true);
      await pageA.evaluate(() => { const t = document.querySelector('[data-group]'); if (t) t.click(); });
      const groupMsg3 = 'after reload ' + Date.now();
      await groupSend(pageB, groupMsg3);
      await waitForFeed(pageA, groupMsg3);
      check('restored group still decrypts after reload (epoch key + resubscribe)', true);
      console.log('[mark] group UI create/join/chat verified');

      // ---- Vault at rest (age) leg: export in A, decrypt & restore in B ----
      // Proves the vendored age-encryption works in the real browser through
      // the import map, and that a vault backup restores the messenger
      // identity (all 8 keypairs) exactly in a different context.
      const clickBtn = (page, label) => page.evaluate((l) => {
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes(l));
        if (b) b.click();
        return !!b;
      }, label);

      check('vault keygen button present', await clickBtn(pageA, 'GENERATE AGE KEYPAIR'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-age-key').dataset.full || '').startsWith('AGE-SECRET-KEY-'),
        { timeout: 60000 }
      );
      check('browser age keypair generated (vendored age-encryption loaded)', true);

      check('vault export button present', await clickBtn(pageA, 'EXPORT VAULT'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-export-out').value || '').startsWith('-----BEGIN AGE ENCRYPTED FILE-----'),
        { timeout: 60000 }
      );
      const exported = await pageA.evaluate(() => ({
        armored: document.getElementById('vault-export-out').value,
        ageKey: document.getElementById('vault-age-key').dataset.full,
      }));
      check('vault export produced PEM-armored age', /^-----BEGIN AGE ENCRYPTED FILE-----/.test(exported.armored));
      const exportKeys = await pageA.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));

      // Browser <-> Go age interop, byte-for-byte: the real `age` CLI must
      // decrypt the browser-produced armored vault to EXACTLY the identity
      // JSON the page exported (not just a semantically-equal parse).
      if (ageCli) {
        const r = ageCliDecrypt(ageCli, exported.armored, exported.ageKey, JSON.stringify(exportKeys));
        check('Go age CLI decrypts the browser-exported vault to the exact identity bytes', r.ok, r.detail);
      }

      // Decrypt & restore into pageB (a different context with a different
      // identity): B must become A, key-for-key.
      await pageB.evaluate(({ armored, ageKey }) => {
        document.getElementById('vault-import-in').value = armored;
        document.getElementById('vault-import-key').value = ageKey;
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
        if (b) b.click();
      }, exported);
      await pageB.waitForFunction(
        (sk) => { const d = JSON.parse(localStorage.getItem('e2ee_identity') || 'null'); return !!d && d.signSk === sk; },
        exportKeys.signSk, { timeout: 60000 }
      );
      const restored = await pageB.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
      const keyFields = ['signSk', 'signPk', 'dhSk', 'dhPk', 'signedDhSk', 'signedDhPk', 'kemSk', 'kemPk'];
      check('vault import restores the exact exported identity keys',
        keyFields.every((f) => restored[f] === exportKeys[f]),
        keyFields.every((f) => restored[f] === exportKeys[f]) ? 'all 8 keypairs match' : 'key mismatch');
      const restoredAddr = b64(Identity.deriveAddress(rebuild(restored).signPk, rebuild(restored).pk));
      const exportedAddr = b64(Identity.deriveAddress(rebuild(exportKeys).signPk, rebuild(exportKeys).pk));
      check('restored identity has the same routing address as the export',
        restoredAddr === exportedAddr, `${restoredAddr.slice(0, 12)}... vs ${exportedAddr.slice(0, 12)}...`);
      console.log('[mark] vault export/import round-trip verified');

      // ---- Hybrid PQ vault leg (X25519 + ML-KEM-768 at rest, in the browser) ----
      // Re-keygen with the PQ hybrid checkbox, export A's identity to the
      // hybrid recipient, then re-import it back into A with the PQ identity:
      // a full encrypt->decrypt round-trip through the vendored hybrid path.
      await pageA.evaluate(() => { document.getElementById('vault-hybrid').checked = true; });
      check('hybrid keygen button present', await clickBtn(pageA, 'GENERATE AGE KEYPAIR'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-age-key').dataset.full || '').startsWith('AGE-SECRET-KEY-PQ-1'),
        { timeout: 60000 }
      );
      check('browser hybrid PQ age keypair generated', true);
      const pqExport = await pageA.evaluate(() => {
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('EXPORT VAULT'));
        if (b) b.click();
        return true;
      });
      check('hybrid export button present', pqExport);
      // The armored export cannot be inspected for the binary mlkem768x25519
      // stanza tag (armor re-encodes it as base64); the node test asserts the
      // stanza on the raw format, and the PQ prefixes here prove the hybrid
      // keypair was used. The decrypt+restore below proves the hybrid path.
      await pageA.waitForFunction(
        () => (document.getElementById('vault-export-out').value || '').startsWith('-----BEGIN AGE ENCRYPTED FILE-----'),
        { timeout: 60000 }
      );
      const pqVault = await pageA.evaluate(() => ({
        armored: document.getElementById('vault-export-out').value,
        ageKey: document.getElementById('vault-age-key').dataset.full,
        recipient: document.getElementById('vault-age-recipient').dataset.full,
      }));
      check('hybrid keypair + export used the PQ recipient',
        pqVault.ageKey.startsWith('AGE-SECRET-KEY-PQ-1') && pqVault.recipient.startsWith('age1pq1'));

      // Hybrid interop, direction 1 (browser → Go CLI): the real age CLI
      // (v1.2.0+) must decrypt the browser's X25519 + ML-KEM-768 vault to the
      // same identity bytes.
      const hybridOk = ageCli && ageCliSupportsHybrid();
      if (hybridOk) {
        const r = ageCliDecrypt(ageCli, pqVault.armored, pqVault.ageKey, JSON.stringify(exportKeys));
        check('Go age CLI decrypts the browser-exported HYBRID (ML-KEM) vault byte-for-byte', r.ok, r.detail);
      }

      // Decrypt & restore A's own hybrid vault back into A: keys must survive.
      await pageA.evaluate(({ armored, ageKey }) => {
        document.getElementById('vault-import-in').value = armored;
        document.getElementById('vault-import-key').value = ageKey;
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
        if (b) b.click();
      }, pqVault);
      await pageA.waitForFunction(
        (sk) => { const d = JSON.parse(localStorage.getItem('e2ee_identity') || 'null'); return !!d && d.signSk === sk; },
        exportKeys.signSk, { timeout: 60000 }
      );
      const restoredHybrid = await pageA.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
      check('hybrid vault decrypts & restores the identity in the browser',
        keyFields.every((f) => restoredHybrid[f] === exportKeys[f]));

      // Hybrid interop, direction 2 (Go CLI → browser): the CLI ENCRYPTS the
      // identity JSON to the browser's hybrid recipient, and the browser must
      // decrypt it back to the exact identity bytes — proving the browser can
      // open hybrid files produced by the reference implementation.
      if (hybridOk) {
        const enc = ageCliEncrypt(ageCli, pqVault.recipient, JSON.stringify(exportKeys));
        if (enc.ok) {
          await pageA.evaluate(({ armored, ageKey }) => {
            document.getElementById('vault-import-in').value = armored;
            document.getElementById('vault-import-key').value = ageKey;
            const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
            if (b) b.click();
          }, { armored: enc.armored, ageKey: pqVault.ageKey });
          await pageA.waitForFunction(
            (sk) => { const d = JSON.parse(localStorage.getItem('e2ee_identity') || 'null'); return !!d && d.signSk === sk; },
            exportKeys.signSk, { timeout: 60000 }
          );
          const restoredCliHybrid = await pageA.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
          check('browser decrypts a Go-CLI-encrypted HYBRID vault byte-for-byte',
            keyFields.every((f) => restoredCliHybrid[f] === exportKeys[f]),
            keyFields.every((f) => restoredCliHybrid[f] === exportKeys[f]) ? 'all 8 keypairs match' : 'key mismatch');
        } else {
          check('Go age CLI encrypts to the browser hybrid recipient', false, enc.detail);
        }
      }
      console.log('[mark] hybrid PQ vault round-trip verified');

      // Encrypt an arbitrary note to a PASTED recipient — the standard age
      // flow. The TO: field must win over the generated keypair, tag hybrid
      // recipients as PQ, and the note must decrypt back byte-for-byte with
      // the hybrid secret key — proving notes aren't limited to the identity
      // JSON or the in-memory keypair.
      const hybridNote = 'hybrid recipient note ' + Date.now();
      await pageA.evaluate((txt) => {
        document.getElementById('vault-export-out').value = '';
        document.getElementById('vault-recipient-input').value = document.getElementById('vault-age-recipient').dataset.full;
        document.getElementById('vault-recipient-input').dispatchEvent(new Event('input'));
        document.getElementById('vault-note-input').value = txt;
        document.getElementById('vault-scope').value = 'note';
        document.getElementById('vault-scope').dispatchEvent(new Event('change'));
        document.getElementById('vault-passphrase').value = '';
      }, hybridNote);
      check('pasted hybrid recipient is tagged PQ', await pageA.evaluate(() =>
        (document.getElementById('vault-recipient-tag').textContent || '').includes('PQ hybrid')));
      check('note export button present', await clickBtn(pageA, 'EXPORT VAULT'));
      await pageA.waitForFunction(
        () => (document.getElementById('vault-export-out').value || '').startsWith('-----BEGIN AGE ENCRYPTED FILE-----'),
        { timeout: 60000 }
      );
      const hybridNoteVault = await pageA.evaluate(() => document.getElementById('vault-export-out').value);
      check('arbitrary note encrypted to the pasted hybrid recipient', true);
      await pageA.evaluate(({ armored, ageKey }) => {
        document.getElementById('vault-import-in').value = armored;
        document.getElementById('vault-import-key').value = ageKey;
        const b = [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('DECRYPT & RESTORE'));
        if (b) b.click();
      }, { armored: hybridNoteVault, ageKey: pqVault.ageKey });
      await pageA.waitForFunction(
        (txt) => document.getElementById('vault-export-out').value === txt,
        hybridNote, { timeout: 60000 }
      );
      check('pasted-hybrid-recipient note decrypts back byte-for-byte', true);
      // A malformed pasted recipient must be rejected without touching the
      // export box (early guard, not a thrown error).
      await pageA.evaluate(() => {
        document.getElementById('vault-recipient-input').value = 'age1garbage';
        document.getElementById('vault-recipient-input').dispatchEvent(new Event('input'));
      });
      check('malformed recipient is tagged as invalid', await pageA.evaluate(() =>
        (document.getElementById('vault-recipient-tag').textContent || '').includes('not an age1')));
      await clickBtn(pageA, 'EXPORT VAULT');
      await new Promise((r) => setTimeout(r, 500));
      check('malformed recipient blocks export (box untouched)',
        (await pageA.evaluate(() => document.getElementById('vault-export-out').value)) === hybridNote);
      await pageA.evaluate(() => {
        document.getElementById('vault-recipient-input').value = '';
        document.getElementById('vault-recipient-input').dispatchEvent(new Event('input'));
        document.getElementById('vault-scope').value = 'identity';
        document.getElementById('vault-scope').dispatchEvent(new Event('change'));
        document.getElementById('vault-note-input').value = '';
      });
      console.log('[mark] pasted-recipient note encryption verified');

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
