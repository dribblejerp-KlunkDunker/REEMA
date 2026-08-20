// tools/live-memory-demo.mjs
// Live end-to-end prototype: the real relay + the real CLI client
// (src/client.js) with the Hindsight memory layer enabled, driven by an
// in-process peer over the same wire protocol the test suite uses.
//
// Prereqs:
//   1. A Hindsight daemon on 127.0.0.1:8877 (the prototype profile):
//        uvx hindsight-embed -p bv-memory profile create bv-memory --merge --port 8877 \
//          --env HINDSIGHT_API_LLM_PROVIDER=none \
//          --env HINDSIGHT_API_EMBEDDINGS_LOCAL_FORCE_CPU=1 \
//          --env HINDSIGHT_API_RERANKER_LOCAL_FORCE_CPU=1 \
//          --env HINDSIGHT_EMBED_DAEMON_IDLE_TIMEOUT=0
//        uvx hindsight-embed -p bv-memory daemon start
//   2. An existing project identity (or run `node src/index.js keygen`).
//
// Usage:
//   node tools/live-memory-demo.mjs [--hindsight-url=http://127.0.0.1:8877]
//
// Exit 0 + a memory-bank dump = full wiring proof.

import { spawn } from 'node:child_process';
import netMod from 'node:net';
import { createHash } from 'node:crypto';
import { init, loadPQ, Session, Identity, isReceipt, directoryShard, selectOneTimePrekey } from '../src/crypto.js';

const RELAY_PORT = Number(process.env.DEMO_RELAY_PORT || 7997);
const WS_PORT = Number(process.env.DEMO_WS_PORT || 7998);
const PROXY_PORT = Number(process.env.DEMO_PROXY_PORT || 7996);
const HINDSIGHT_URL = (process.argv.find((a) => a.startsWith('--hindsight-url=')) || '').split('=')[1]
  || process.env.HINDSIGHT_URL || 'http://127.0.0.1:8877';

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

function waitForTcp(port, ms = 15000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const t = setInterval(() => {
      const c = netMod.connect(port, '127.0.0.1');
      c.on('connect', () => { c.end(); clearInterval(t); resolve(); });
      c.on('error', () => { if (Date.now() - start > ms) { clearInterval(t); reject(new Error('relay never came up')); } });
    }, 150);
  });
}

// A transparent byte-capturing tee proxy. Every byte between the clients and
// the relay passes through here in both directions, so the E2EE-boundary
// assertion can prove memory plaintext never appears ANYWHERE on the wire —
// including the client's own publish/directory traffic, which the harness
// otherwise never sees. Envelope-agnostic by design: when the age-encrypted
// memory-sync snapshots land on this channel, the same check covers them.
function teeProxy(listenPort, targetPort, onBytes) {
  const server = netMod.createServer((client) => {
    const target = netMod.connect(targetPort, '127.0.0.1');
    client.on('data', (chunk) => { onBytes(chunk); target.write(chunk); });
    target.on('data', (chunk) => { onBytes(chunk); client.write(chunk); });
    client.on('end', () => target.end());
    target.on('end', () => client.end());
    client.on('error', () => target.destroy());
    target.on('error', () => client.destroy());
  });
  return new Promise((resolve) => server.listen(listenPort, '127.0.0.1', () => resolve(server)));
}

const ok = (label, cond) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) process.exitCode = 1;
};

const relay = spawn(process.execPath, ['src/server.js'], {
  // TLS is default-on; this demo keeps plaintext loopback for convenience.
  env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', TLS_OFF: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let relayOut = '';
relay.stdout.on('data', (d) => (relayOut += d));
relay.stderr.on('data', (d) => (relayOut += d));
const wireChunks = [];
let proxy = null;

// The client's identity file lives at the project root; the in-process peer is
// fresh in memory, so only the CLI client touches .identity.json/.sessions.json.
const sodium = await init();
await loadPQ(); // keygen + bundle signing need ML-KEM/ML-DSA (lazy-PQ contract)
const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({ id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature) }));

try {
  await waitForTcp(RELAY_PORT);
  console.log(`[demo] relay up on 127.0.0.1:${RELAY_PORT}`);
  proxy = await teeProxy(PROXY_PORT, RELAY_PORT, (chunk) => wireChunks.push(chunk));
  console.log(`[demo] wire-capture proxy on 127.0.0.1:${PROXY_PORT} -> ${RELAY_PORT}`);

  // Peer publishes so the CLI client can resolve it from the key directory.
  // Both the peer and the CLI client connect THROUGH the proxy, so every
  // wire byte (publish, directory, envelopes, deliveries) is captured.
  const peer = new Identity();
  peer.newOneTimePrekeys(5);
  const peerAddr = addr(peer);
  const peerSock = await connectTcp(PROXY_PORT);
  const peerPublished = peerSock.once('published');
  peerSock.send({ type: 'publish', address: peerAddr, bundle: peer.makeBundle(), oneTimePrekeys: otksOf(peer) });
  await peerPublished;
  console.log(`[demo] in-process peer published: ${peerAddr.slice(0, 16)}...`);

  // Spawn the real CLI client with memory enabled, stdin piped so we can send.
  const client = spawn(process.execPath, ['src/client.js', peerAddr, '--no-tor'], {
    env: { ...process.env, HINDSIGHT_URL, RELAY_PORT: String(PROXY_PORT), RELAY_HOST: '127.0.0.1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let clientOut = '';
  client.stdout.on('data', (d) => { clientOut += d; process.stdout.write(`[client] ${d}`); });
  client.stderr.on('data', (d) => { clientOut += d; process.stdout.write(`[client-err] ${d}`); });

  // Wait for the client's own address + registration.
  const t0 = Date.now();
  while (!clientOut.includes('[client] my address')) {
    if (Date.now() - t0 > 20000) throw new Error('client never printed its address');
    await new Promise((r) => setTimeout(r, 100));
  }
  const myAddrLine = clientOut.match(/my address\s*: (\S+)/);
  ok('client printed its address', !!myAddrLine);
  const clientAddr = myAddrLine[1];
  ok('client enabled memory (bank line)', clientOut.includes(`@ ${HINDSIGHT_URL}`));
  const bankId = `bv-${createHash('sha256').update(clientAddr).digest('hex').slice(0, 16)}`;
  console.log(`[demo] client address: ${clientAddr.slice(0, 16)}...  memory bank: ${bankId}`);
  while (!clientOut.includes('published + registered')) {
    if (Date.now() - t0 > 30000) throw new Error('client never registered');
    await new Promise((r) => setTimeout(r, 100));
  }

  // Peer resolves the client from the key directory (bundle + OTK) and sends a
  // first-contact message. The client must decrypt, print, and retain 'received'.
  // NOTE: like a real client, the peer must process EVERY inbound message in
  // order — the client's automatic delivery receipt establishes its epoch, so
  // a later same-epoch message can be authenticated.
  const dirReq = peerSock.once('directory-shard');
  peerSock.send({ type: 'fetch-shard', shard: directoryShard(clientAddr, 1) });
  const dir = await dirReq;
  const entry = dir.entries.find((e) => e.address === clientAddr);
  const otk = selectOneTimePrekey(peerAddr, clientAddr, entry.oneTimePrekeys);
  ok('directory shard served the client bundle + one-time prekey pool', !!entry?.bundle && entry.oneTimePrekeys.length > 0);
  const peerSession = new Session(peer, entry.bundle, otk);
  const incoming = [];
  peerSock.onmsg((m) => { if (m.type === 'message') incoming.push(m); });

  const hello = 'Hello from the memory demo — this is a first-contact message.';
  peerSock.send({ type: 'send', toPk: clientAddr, envelope: peerSession.encrypt(Buffer.from(hello, 'utf8')), fromPk: peerAddr });

  const t1 = Date.now();
  while (!clientOut.includes(`<<< ${hello}`)) {
    if (Date.now() - t1 > 15000) throw new Error('client never printed the received plaintext');
    await new Promise((r) => setTimeout(r, 100));
  }
  ok('client decrypted + printed the received plaintext', true);
  await new Promise((r) => setTimeout(r, 1500)); // let the async retain land + index

  // Send from the CLI client: write to its stdin; the peer decrypts in order.
  const reply = 'Reply from the CLI client, retained on the send path.';
  client.stdin.write(reply + '\n');
  const t2 = Date.now();
  let got = null;
  while (Date.now() - t2 < 15000) {
    while (incoming.length) {
      const m = incoming.shift();
      try {
        const decrypted = peerSession.decrypt(m.envelope);
        if (decrypted === reply) got = m;
      } catch { /* receipt-epoch bookkeeping; keep going */ }
    }
    if (got) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  ok('relay delivered the CLI client send to the peer', !!got);
  ok(`peer decrypted the client's reply ("${reply.slice(0, 40)}...")`, !!got);
  await new Promise((r) => setTimeout(r, 1500)); // let retain-on-send land

  // A second received message: the bank now holds the earlier exchange, so the
  // client's recall-on-receive must surface a [memory] related hint. (The first
  // receive had an empty bank — nothing to recall yet.)
  const followUp = 'Following up: dark mode was the preference we discussed.';
  peerSock.send({ type: 'send', toPk: clientAddr, envelope: peerSession.encrypt(Buffer.from(followUp, 'utf8')), fromPk: peerAddr });
  const t3 = Date.now();
  while (!clientOut.includes(`<<< ${followUp}`)) {
    if (Date.now() - t3 > 15000) throw new Error('client never printed the follow-up');
    await new Promise((r) => setTimeout(r, 100));
  }
  ok('client decrypted + printed the follow-up', true);
  const t4 = Date.now();
  while (!clientOut.includes('[memory] related:') && Date.now() - t4 < 15000) {
    await new Promise((r) => setTimeout(r, 250));
  }
  ok('client surfaced a [memory] related hint (recall wired)', clientOut.includes('[memory] related:'));

  // Prove the memory bank actually holds both sides.
  const mem = await fetch(`${HINDSIGHT_URL}/v1/default/banks/${bankId}/memories/list?limit=20`).then((r) => r.json());
  const texts = (mem.items || []).map((i) => i.text);
  console.log(`\n[demo] memory bank '${bankId}' holds ${texts.length} item(s):`);
  for (const t of texts) console.log(`  - ${t.slice(0, 90)}`);
  ok('received message retained', texts.some((t) => t.includes(hello.slice(0, 30))));
  ok('sent message retained', texts.some((t) => t.includes(reply.slice(0, 30))));

  // ---- E2EE boundary: memory content must never reach the relay ----
  // The memory plaintexts exist only (a) in the client's own terminal output
  // and (b) inside the local Hindsight daemon. The relay's logs, every byte
  // that crossed the wire (all envelopes, publishes, directory responses),
  // and the served bundle/OTK must contain none of them. The wire check is
  // envelope-agnostic: it will equally cover age-encrypted memory-sync
  // snapshots when they land on this channel (age encrypts, so they can't
  // contain the texts either — this locks the boundary so a regression that
  // adds a plaintext field to an envelope fails loudly).
  const memoryTexts = [hello, reply, followUp];
  const wireBuf = Buffer.concat(wireChunks);
  const bundleBlobs = [
    JSON.stringify(entry.bundle),
    JSON.stringify(otk),
  ];
  const leaks = [];
  for (const t of memoryTexts) {
    const tb = Buffer.from(t, 'utf8');
    if (wireBuf.includes(tb)) leaks.push(`wire:${t.slice(0, 24)}`);
    if (relayOut.includes(t)) leaks.push(`relaylog:${t.slice(0, 24)}`);
    for (const b of bundleBlobs) {
      if (b.includes(t)) leaks.push(`bundle:${t.slice(0, 24)}`);
    }
  }
  ok('memory plaintext never in wire envelopes (all captured bytes)', !leaks.some((l) => l.startsWith('wire:')));
  ok('memory plaintext never in relay logs', !leaks.some((l) => l.startsWith('relaylog:')));
  ok('memory plaintext never in served bundles/one-time prekeys', !leaks.some((l) => l.startsWith('bundle:')));
  // Self-validation of the capture: the client's own registration traffic
  // (publish with its address) must be in the capture — otherwise the wire
  // check would silently cover only the harness side.
  ok('wire capture includes the client publish (proxy covers client traffic)',
    wireBuf.includes(Buffer.from(clientAddr, 'utf8')));
  if (leaks.length) {
    console.error('[demo] E2EE boundary LEAKED:', leaks);
  } else {
    console.log(`[demo] E2EE boundary intact: ${wireBuf.length} wire bytes, ${relayOut.length} relay-log chars, 2 bundle blobs clean`);
  }

  client.kill();
  peerSock.end();
  console.log('\n[demo] memory wiring proven end-to-end');
} finally {
  if (proxy) proxy.close();
  relay.kill();
}
