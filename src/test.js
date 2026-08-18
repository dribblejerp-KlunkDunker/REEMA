import { createServer, connect } from 'node:net';
import { init, Identity, Session } from './crypto.js';

/**
 * Integration test: full E2EE messaging through a relay (protocol v6).
 *
 * Runs a minimal in-process relay (same line protocol as src/server.js),
 * connects Alice and Bob, and verifies that:
 *   - the relay only ever sees ciphertext
 *   - the key directory serves a bundle + one one-time prekey, consumed
 *     server-side on fetch and burned client-side on first receive
 *   - messages round-trip in both directions across a ratchet step
 *   - a third party cannot decrypt a relayed envelope
 *   - queued (offline) delivery works by derived routing address
 */

const PORT = 7999;

let failures = 0;
function assert(label, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}`);
  if (!condition) failures++;
}

function startRelay(onMessage) {
  const inbox = new Map();
  const online = new Map();
  const directory = new Map();

  const server = createServer((socket) => {
    socket.setEncoding('utf8');
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line) handle(socket, JSON.parse(line));
      }
    });
    socket.on('close', () => {
      for (const [pk, s] of online) if (s === socket) online.delete(pk);
    });
    socket.on('error', () => {});
  });

  function handle(socket, msg) {
    onMessage(msg);
    switch (msg.type) {
      case 'publish': {
        directory.set(msg.address, { bundle: msg.bundle, oneTimePrekeys: new Map((msg.oneTimePrekeys || []).map((o) => [o.id, o])) });
        online.set(msg.address, socket);
        const queued = inbox.get(msg.address) || [];
        inbox.delete(msg.address);
        for (const item of queued) {
          socket.write(JSON.stringify({ type: 'message', envelope: item.envelope, fromPk: item.fromPk }) + '\n');
        }
        socket.write(JSON.stringify({ type: 'published', address: msg.address }) + '\n');
        break;
      }
      case 'fetch-directory': {
        const entry = directory.get(msg.address);
        if (!entry) { socket.write(JSON.stringify({ type: 'error', error: 'unknown address' }) + '\n'); break; }
        let oneTimePrekey = null;
        if (entry.oneTimePrekeys.size > 0) {
          const firstId = entry.oneTimePrekeys.keys().next().value;
          oneTimePrekey = entry.oneTimePrekeys.get(firstId);
          entry.oneTimePrekeys.delete(firstId);
        }
        socket.write(JSON.stringify({ type: 'directory', address: msg.address, bundle: entry.bundle, oneTimePrekey }) + '\n');
        break;
      }
      case 'send': {
        const target = online.get(msg.toPk);
        if (target && !target.destroyed) {
          target.write(JSON.stringify({ type: 'message', envelope: msg.envelope, fromPk: msg.fromPk }) + '\n');
        } else {
          const list = inbox.get(msg.toPk) || [];
          list.push({ envelope: msg.envelope, fromPk: msg.fromPk });
          inbox.set(msg.toPk, list);
        }
        socket.write(JSON.stringify({ type: 'sent', toPk: msg.toPk }) + '\n');
        break;
      }
    }
  }

  return new Promise((resolve) => server.listen(PORT, '127.0.0.1', () => resolve(server)));
}

function connectClient() {
  return new Promise((resolve, reject) => {
    const socket = connect(PORT, '127.0.0.1');
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
      on: (t, fn) => { handlers[t] = fn; },
      once: (t) => new Promise((res) => { handlers[t] = (m) => { delete handlers[t]; res(m); }; }),
    }));
    socket.once('error', reject);
  });
}

async function main() {
  const sodium = await init();
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
  const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));

  console.log('=== Integration Test: E2EE messaging through relay (protocol v6) ===\n');

  // Capture everything the relay observes so we can prove it never sees plaintext.
  const relaySaw = [];
  const server = await startRelay((msg) => {
    if (msg.type === 'send') relaySaw.push(JSON.stringify(msg));
  });
  console.log(`[test] relay started on 127.0.0.1:${PORT}`);

  const alice = new Identity();
  alice.newOneTimePrekeys(5);
  const bob = new Identity();
  bob.newOneTimePrekeys(5);
  const mallory = new Identity();
  const carol = new Identity();
  carol.newOneTimePrekeys(5);

  const aliceAddr = addr(alice);
  const bobAddr = addr(bob);
  const carolAddr = addr(carol);
  console.log(`[test] Alice address: ${aliceAddr.slice(0, 16)}...`);
  console.log(`[test] Bob   address: ${bobAddr.slice(0, 16)}...`);

  console.log('[test] connecting clients...');
  const aliceClient = await connectClient();
  const bobClient = await connectClient();
  console.log('[test] clients connected');

  const bobPublished = bobClient.once('published');
  const alicePublished = aliceClient.once('published');
  console.log('[test] publishing...');
  aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice) });
  bobClient.send({ type: 'publish', address: bobAddr, bundle: bob.makeBundle(), oneTimePrekeys: otksOf(bob) });
  await Promise.all([alicePublished, bobPublished]);
  console.log('[test] published');

  // ---- Alice resolves Bob from the key directory (bundle + one-time prekey) ----
  const bobDir = await (async () => {
    const p = aliceClient.once('directory');
    aliceClient.send({ type: 'fetch-directory', address: bobAddr });
    return p;
  })();
  assert('directory returned Bob bundle + one one-time prekey', !!bobDir.bundle && !!bobDir.oneTimePrekey);
  const bobBundle = bobDir.bundle;
  const bobOtk = bobDir.oneTimePrekey;
  const bobPoolBefore = bob.oneTimePrekeys.size;
  assert('directory one-time prekey is signed by Bob', Identity.verifyOneTimePrekey(bob.signPk, bobOtk));

  // A second fetch must return a DIFFERENT prekey (consumed server-side).
  const bobDir2 = await (async () => {
    const p = aliceClient.once('directory');
    aliceClient.send({ type: 'fetch-directory', address: bobAddr });
    return p;
  })();
  assert('directory never serves the same one-time prekey twice',
    !!bobDir2.oneTimePrekey && bobDir2.oneTimePrekey.id !== bobOtk.id);

  // ---- Alice -> Bob (first message, post-quantum + OTK bootstrap) ----
  const aliceSession = new Session(alice, bobBundle, bobOtk);
  const secret = 'Hello Bob — this traveled through the relay as ciphertext only.';
  console.log(`\n[test] Alice plaintext: "${secret}"`);

  const bobInbound = bobClient.once('message');
  aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(secret, 'utf8')), fromPk: aliceAddr });

  const received = await bobInbound;
  const envelope = received.envelope;
  console.log(`[test] Bob received ciphertext: ${envelope.ciphertext.slice(0, 40)}...`);
  assert('first message carries the consumed one-time prekey id', envelope.header.otk_id === bobOtk.id);

  // Bob establishes from the first message's own bundle + his consumed OTK.
  const otk = bob.oneTimePrekeys.get(envelope.header.otk_id);
  assert('Bob still holds the OTK the sender used', !!otk);
  const bobSession = new Session(bob, alice.makeBundle(), { id: otk.id, sk: otk.sk, pk: otk.pk });
  bob.oneTimePrekeys.delete(otk.id);
  const decrypted = bobSession.decrypt(envelope);
  console.log(`[test] Bob decrypted: "${decrypted}"`);
  assert('Bob consumed the one-time prekey after first receive', bob.oneTimePrekeys.size === bobPoolBefore - 1);

  // ---- Bob -> Alice (exercises a full ratchet step over the wire) ----
  const reply = 'Got it Alice — replying through the same relay.';
  const aliceInbound = aliceClient.once('message');
  bobClient.send({ type: 'send', toPk: aliceAddr, envelope: bobSession.encrypt(Buffer.from(reply, 'utf8')), fromPk: bobAddr });

  const replyMsg = await aliceInbound;
  const decryptedReply = aliceSession.decrypt(replyMsg.envelope);
  console.log(`[test] Alice decrypted reply: "${decryptedReply}"`);

  // ---- Mallory ----
  let malloryBlocked = false;
  try {
    new Session(mallory, alice.makeBundle()).decrypt(envelope);
  } catch { malloryBlocked = true; }

  // ---- Offline queueing (by derived address) ----
  const aliceToCarol = new Session(alice, carol.makeBundle());
  aliceClient.send({ type: 'send', toPk: carolAddr, envelope: aliceToCarol.encrypt(Buffer.from('queued while offline', 'utf8')), fromPk: aliceAddr });
  await new Promise((r) => setTimeout(r, 50));

  const carolClient = await connectClient();
  const carolInbound = carolClient.once('message');
  carolClient.send({ type: 'publish', address: carolAddr, bundle: carol.makeBundle(), oneTimePrekeys: otksOf(carol) });
  const carolMsg = await carolInbound;
  const carolPlain = new Session(carol, alice.makeBundle()).decrypt(carolMsg.envelope);
  console.log(`[test] Carol received queued message: "${carolPlain}"`);

  console.log('\n=== Results ===');
  assert('relay never saw plaintext', !relaySaw.some((s) => s.includes(secret) || s.includes(reply)));
  assert('Bob decrypted Alice message correctly', decrypted === secret);
  assert('Alice decrypted Bob reply correctly', decryptedReply === reply);
  assert('Mallory cannot decrypt relayed message', malloryBlocked);
  assert('queued offline message delivered and decrypted', carolPlain === 'queued while offline');

  console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`}`);

  aliceClient.socket.destroy();
  bobClient.socket.destroy();
  carolClient.socket.destroy();
  server.close();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
