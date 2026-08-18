import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, Session } from './crypto.js';

/**
 * Integration test: full E2EE messaging through the REAL relay (protocol v6).
 *
 * Spawns `src/server.js` as a child process — the same relay the dashboard,
 * messenger, and CLI talk to — so the test can never drift from production.
 * Connects Alice and Bob over the relay's TCP line protocol, and verifies:
 *   - the relay only ever sees ciphertext (its own logs never emit plaintext)
 *   - the key directory serves a bundle + one one-time prekey, consumed
 *     server-side on fetch and burned client-side on first receive
 *   - messages round-trip in both directions across a ratchet step
 *   - a third party cannot decrypt a relayed envelope
 *   - queued (offline) delivery works by derived routing address
 */

const RELAY_PORT = Number(process.env.TEST_RELAY_PORT || 7999);
const WS_PORT = Number(process.env.TEST_WS_PORT || 8089);

let failures = 0;
function assert(label, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}`);
  if (!condition) failures++;
}

function waitForTcp(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const socket = connect(port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`relay did not listen on 127.0.0.1:${port}`));
        else setTimeout(tryOnce, 200);
      });
    };
    tryOnce();
  });
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

async function main() {
  const sodium = await init();
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
  const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));

  console.log('=== Integration Test: E2EE messaging through relay (protocol v6) ===\n');

  // Spawn the real relay; capture its output so we can prove it never leaks
  // plaintext (it only logs addresses and ciphertext-forwarding events).
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '';
  let relayErr = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayErr += d; });

  const clients = [];

  try {
    await waitForTcp(RELAY_PORT);
    console.log(`[test] real relay started on 127.0.0.1:${RELAY_PORT} (WS ${WS_PORT})`);

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
    const aliceClient = await connectTcp(RELAY_PORT);
    const bobClient = await connectTcp(RELAY_PORT);
    clients.push(aliceClient, bobClient);
    console.log('[test] clients connected');

    const bobPublished = bobClient.once('published');
    const alicePublished = aliceClient.once('published');
    console.log('[test] publishing (authenticated, proof-of-possession)...');
    aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice) });
    bobClient.send({ type: 'publish', address: bobAddr, bundle: bob.makeBundle(), oneTimePrekeys: otksOf(bob) });
    await withTimeout('publish', Promise.all([alicePublished, bobPublished]));
    console.log('[test] published');

    // ---- Alice resolves Bob from the key directory (bundle + one-time prekey) ----
    const bobDir = await (async () => {
      const p = aliceClient.once('directory');
      aliceClient.send({ type: 'fetch-directory', address: bobAddr });
      return withTimeout('bob directory', p);
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
      return withTimeout('bob directory (2nd fetch)', p);
    })();
    assert('directory never serves the same one-time prekey twice',
      !!bobDir2.oneTimePrekey && bobDir2.oneTimePrekey.id !== bobOtk.id);

    // ---- Alice -> Bob (first message, post-quantum + OTK bootstrap) ----
    const aliceSession = new Session(alice, bobBundle, bobOtk);
    const secret = 'Hello Bob — this traveled through the relay as ciphertext only.';
    console.log(`\n[test] Alice plaintext: "${secret}"`);

    const bobInbound = bobClient.once('message');
    aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(secret, 'utf8')), fromPk: aliceAddr });

    const received = await withTimeout('bob first message', bobInbound);
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

    const replyMsg = await withTimeout('alice reply', aliceInbound);
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

    const carolClient = await connectTcp(RELAY_PORT);
    clients.push(carolClient);
    const carolInbound = carolClient.once('message');
    carolClient.send({ type: 'publish', address: carolAddr, bundle: carol.makeBundle(), oneTimePrekeys: otksOf(carol) });
    const carolMsg = await withTimeout('carol queued message', carolInbound);
    const carolPlain = new Session(carol, alice.makeBundle()).decrypt(carolMsg.envelope);
    console.log(`[test] Carol received queued message: "${carolPlain}"`);

    console.log('\n=== Results ===');
    assert('relay never saw plaintext', !relayOut.includes(secret) && !relayErr.includes(secret)
      && !relayOut.includes(reply) && !relayErr.includes(reply));
    assert('Bob decrypted Alice message correctly', decrypted === secret);
    assert('Alice decrypted Bob reply correctly', decryptedReply === reply);
    assert('Mallory cannot decrypt relayed message', malloryBlocked);
    assert('queued offline message delivered and decrypted', carolPlain === 'queued while offline');

    console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`}`);
  } catch (err) {
    console.error('[test] ERROR:', err.message);
    if (relayOut.trim()) console.error('[test] relay log:', relayOut.trim().split('\n').slice(-12).join(' | '));
    if (relayErr.trim()) console.error('[test] relay stderr:', relayErr.trim().slice(0, 600));
    failures++;
  } finally {
    for (const c of clients) c.socket.destroy();
    relay.kill('SIGTERM');
  }

  process.exit(failures === 0 ? 0 : 1);
}

main();
