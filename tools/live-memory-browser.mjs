// tools/live-memory-browser.mjs
// Live end-to-end proof that the browser dashboard's memory layer works:
// a real headless browser loads public/index.html (served by tools/serve.mjs),
// establishes its E2EE identity, and exchanges messages through the real relay
// with an in-process peer — while the loopback Hindsight sidecar
// (tools/memory-sidecar.mjs) + daemon record and recall the memory.
//
// Prereqs (like the CLI demo):
//   1. A Hindsight daemon on 127.0.0.1:8877 (see tools/live-memory-demo.mjs
//      for the exact uvx profile/env commands).
//   2. `npm run memory-sidecar` running on 127.0.0.1:8878.
//
// Usage:
//   node tools/live-memory-browser.mjs
//
// Exit 0 + bank dump = the dashboard's retain/recall wiring is proven live.

import { spawn } from 'node:child_process';
import netMod from 'node:net';
import { createHash } from 'node:crypto';
import { resolveChromium } from '../src/chromium.js';
import { init, loadPQ, Identity, Session } from '../src/crypto.js';

const RELAY_PORT = Number(process.env.LMB_RELAY_PORT || 7995);
const WS_PORT = Number(process.env.LMB_WS_PORT || 8095);
const UI_PORT = Number(process.env.LMB_UI_PORT || 8011);
const SIDECAR_URL = process.env.HINDSIGHT_URL ? 'http://127.0.0.1:8878' : 'http://127.0.0.1:8878';
const UI_URL = `http://127.0.0.1:${UI_PORT}/?relay=ws://127.0.0.1:${WS_PORT}&memory=${SIDECAR_URL}`;

let failures = 0;
const ok = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

function waitForTcp(port, ms = 20000) {
  const deadline = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const t = setInterval(() => {
      const c = netMod.connect(port, '127.0.0.1');
      c.on('connect', () => { c.end(); clearInterval(t); resolve(); });
      c.on('error', () => { if (Date.now() > deadline) { clearInterval(t); reject(new Error('tcp never up')); } });
    }, 150);
  });
}

async function waitForHttp(url, ms = 20000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { if ((await fetch(url)).ok) return; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`http never up: ${url}`);
}

function connectTcp(port) {
  return new Promise((resolve, reject) => {
    const sock = netMod.connect(port, '127.0.0.1', () => {
      sock.setEncoding('utf8');
      let buffer = '';
      const pending = [];
      sock.on('data', (chunk) => {
        buffer += chunk;
        let idx;
        while ((idx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, idx).trim();
          buffer = buffer.slice(idx + 1);
          if (!line) continue;
          let msg;
          try { msg = JSON.parse(line); } catch { continue; }
          const waiters = pending.filter((w) => w.type === msg.type);
          pending.splice(0, pending.length, ...pending.filter((w) => w.type !== msg.type));
          for (const w of waiters) w.resolve(msg);
          if (sock._onmsg) sock._onmsg(msg);
        }
      });
      resolve({
        send: (m) => sock.write(JSON.stringify(m) + '\n'),
        once: (type) => new Promise((resolveOnce) => pending.push({ type, resolve: resolveOnce })),
        onmsg: (fn) => { sock._onmsg = fn; },
        end: () => sock.end(),
      });
    });
    sock.on('error', reject);
  });
}

const relay = spawn(process.execPath, ['src/server.js'], {
  // TLS is default-on; this demo keeps plaintext loopback for convenience.
  env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', TLS_OFF: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
const ui = spawn(process.execPath, ['tools/serve.mjs'], {
  env: { ...process.env, UI_PORT: String(UI_PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let relayOut = '';
relay.stdout.on('data', (d) => (relayOut += d));
relay.stderr.on('data', (d) => (relayOut += d));

const sodium = await init();
await loadPQ();
const ORIG = sodium.base64_variants.ORIGINAL;
const b64 = (u) => sodium.to_base64(u, ORIG);
const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({ id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature) }));

let browser = null;
try {
  await waitForTcp(RELAY_PORT);
  await waitForHttp(`http://127.0.0.1:${UI_PORT}/`);
  const side = await fetch(`${SIDECAR_URL}/health`).then((r) => r.json()).catch(() => null);
  ok('sidecar + daemon reachable (run `npm run memory-sidecar` first)', !!(side && side.sidecar === 'ok' && side.daemon));

  const chromium = resolveChromium();
  if (!chromium) throw new Error('patchright chromium not resolvable');
  browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  await page.goto(UI_URL, { timeout: 120000 });
  await page.waitForFunction(
    () => localStorage.getItem('e2ee_identity') &&
      document.getElementById('relay-status')?.textContent.includes('RELAY CONNECTED'),
    null, { timeout: 120000 },
  );
  console.log('[lmb] dashboard ready (identity + relay)');

  // The dashboard derived its bank from its own address — recompute it here
  // from the persisted identity (same derivation as the CLI).
  const keys = await page.evaluate(() => JSON.parse(localStorage.getItem('e2ee_identity')));
  const identity = new Identity({
    signSk: sodium.from_base64(keys.signSk, ORIG), signPk: sodium.from_base64(keys.signPk, ORIG),
    sk: sodium.from_base64(keys.dhSk, ORIG), pk: sodium.from_base64(keys.dhPk, ORIG),
    signedDhSk: sodium.from_base64(keys.signedDhSk, ORIG), signedDhPk: sodium.from_base64(keys.signedDhPk, ORIG),
    kemSk: sodium.from_base64(keys.kemSk, ORIG), kemPk: sodium.from_base64(keys.kemPk, ORIG),
  });
  const myAddr = addr(identity);
  const bankId = `bv-${createHash('sha256').update(myAddr).digest('hex').slice(0, 16)}`;
  console.log(`[lmb] dashboard address: ${myAddr.slice(0, 16)}...  bank: ${bankId}`);

  const memStatus = await page.evaluate(() => document.getElementById('memory-status').textContent);
  ok('dashboard shows MEMORY ON', memStatus.includes('MEMORY ON'), memStatus);

  // In-process peer publishes so the dashboard can resolve it by address.
  const peer = new Identity();
  peer.newOneTimePrekeys(5);
  const peerAddr = addr(peer);
  const peerSock = await connectTcp(RELAY_PORT);
  const peerPublished = peerSock.once('published');
  peerSock.send({ type: 'publish', address: peerAddr, bundle: peer.makeBundle(), oneTimePrekeys: otksOf(peer) });
  await peerPublished;

  // ---- Dashboard -> peer (retain on send) ----
  const sentText = 'Browser memory demo: Alice stored her recovery phrase offline.';
  await page.evaluate(({ b, t }) => {
    document.getElementById('peer-key-input').value = b;
    document.getElementById('chat-input').value = t;
    [...document.querySelectorAll('button')].find((x) => (x.textContent || '').includes('SEND')).click();
  }, { b: peerAddr, t: sentText });
  const t1 = Date.now();
  let got = null;
  const incoming = [];
  peerSock.onmsg((m) => { if (m.type === 'message') incoming.push(m); });
  while (Date.now() - t1 < 15000) {
    if (incoming.length) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  ok('relay delivered the dashboard send to the peer', incoming.length > 0);

  // ---- peer -> dashboard (retain on receive + recall hint) ----
  // The dashboard sent FIRST (address mode), so it consumed the peer's own
  // one-time prekey and carried its bundle in the message. The peer builds
  // its session receiver-style — its consumed OTK + the message's bundle —
  // exactly like the receiver path in src/client.js.
  const env = incoming[0].envelope;
  const otk = peer.oneTimePrekeys.get(env.header.otk_id);
  ok('dashboard consumed a peer one-time prekey (first-message forward secrecy)', !!otk);
  const pSession = new Session(peer, env.header.bundle, { id: otk.id, sk: otk.sk, pk: otk.pk });
  peer.oneTimePrekeys.delete(otk.id);
  pSession.decrypt(env); // establishes the peer's receiving chain
  const receivedText = 'Browser memory demo reply: a hardware wallet is the best home for keys.';
  peerSock.send({ type: 'send', toPk: myAddr, envelope: pSession.encrypt(Buffer.from(receivedText, 'utf8')), fromPk: peerAddr });

  await page.waitForFunction(
    (needle) => document.getElementById('chat-feed').textContent.includes(needle),
    receivedText, { timeout: 60000 },
  );
  ok('dashboard decrypted + rendered the received message', true);
  const hintSeen = await page.waitForFunction(
    () => document.getElementById('chat-feed').textContent.includes('🧠 memory:'),
    null, { timeout: 60000 },
  ).then(() => true).catch(() => false);
  ok('dashboard surfaced a [🧠 memory:] related hint (recall wired)', hintSeen);
  // Diagnostic when the hint is missing: dump page console errors, the feed
  // tail, and a page-side recall probe against the sidecar.
  if (!hintSeen) {
    console.error('[lmb] console errors:', JSON.stringify(consoleErrors, null, 1));
    const probe = await page.evaluate(async ({ bank, q }) => {
      const feed = document.getElementById('chat-feed').textContent.slice(-400);
      let sidecarProbe = null;
      try {
        const r = await fetch('http://127.0.0.1:8878/v1/memory/recall', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bank, query: q, limit: 5 }),
        });
        sidecarProbe = await r.json();
      } catch (e) { sidecarProbe = 'FETCH FAILED: ' + e.message; }
      return { feed, sidecarProbe };
    }, { bank: bankId, q: receivedText });
    console.error('[lmb] feed tail:', JSON.stringify(probe.feed));
    console.error('[lmb] page-side sidecar probe:', JSON.stringify(probe.sidecarProbe));
  }

  // ---- Prove the daemon bank actually holds both sides (poll; retains land async) ----
  let texts = [];
  const tPoll = Date.now();
  while (Date.now() - tPoll < 30000) {
    const mem = await fetch(`http://127.0.0.1:8877/v1/default/banks/${bankId}/memories/list?limit=20`).then((r) => r.json());
    texts = (mem.items || []).map((i) => i.text);
    if (texts.some((t) => t.includes(sentText.slice(0, 30))) &&
        texts.some((t) => t.includes(receivedText.slice(0, 30)))) break;
    await new Promise((r) => setTimeout(r, 1500));
  }
  console.log(`\n[lmb] bank '${bankId}' holds ${texts.length} item(s):`);
  for (const t of texts) console.log(`  - ${t.slice(0, 90)}`);
  ok('dashboard send retained', texts.some((t) => t.includes(sentText.slice(0, 30))));
  ok('dashboard receive retained', texts.some((t) => t.includes(receivedText.slice(0, 30))));

  // E2EE boundary: none of the memory texts appear in the relay's logs. (The
  // byte-level wire capture lives in tools/live-memory-demo.mjs — this harness
  // asserts the relay side, which is where a leak would surface.)
  const leaks = [];
  for (const t of [sentText, receivedText]) {
    if (relayOut.includes(t)) leaks.push(`relaylog:${t.slice(0, 20)}`);
  }
  ok('memory plaintext never in relay logs', leaks.length === 0);
  if (leaks.length) console.error('[lmb] LEAKED:', leaks);

  console.log(`\n[lmb] browser memory wiring proven end-to-end (${failures === 0 ? 'ALL PASS' : failures + ' FAILURES'})`);
} finally {
  if (browser) await browser.close().catch(() => {});
  relay.kill();
  ui.kill();
}
process.exit(failures === 0 ? 0 : 1);
