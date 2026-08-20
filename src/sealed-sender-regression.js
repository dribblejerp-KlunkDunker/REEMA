import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, Session, loadPQ, directoryShard, selectOneTimePrekey } from './crypto.js';
import { connectRelay } from './test-tls.js';

/**
 * Sealed sender + per-session delivery tokens (ANONYMITY.md Phase 1).
 *
 * Acceptance test from DESIGN-sealed-sender.md: instrument the REAL relay's own
 * code path (its verbose operator log + the messages it emits) and prove it
 * cannot answer "who sent this message?".
 *
 *   - `send` carries NO `fromPk` — the relay routes by `toPk` alone, and its
 *     `message` delivery contains no sender field and never contains the
 *     sender's routing address.
 *   - The envelope carries an opaque per-session `deliveryToken`, derived from
 *     the bootstrap DH secrets so it is identical on both sides (replies need
 *     no negotiation) yet unlinkable to the sender's address, and it rotates
 *     per session (it mixes in the one-time prekey).
 *   - Delivery still decrypts + verifies the sender end-to-end (the Double
 *     Ratchet property is not weakened).
 *   - A hostile client flooding an offline recipient is rate-limited by the
 *     relay's queue cap WITHOUT the relay learning the sender's address.
 */

const RELAY_PORT = Number(process.env.SEALED_RELAY_PORT || 7995);
const WS_PORT = Number(process.env.SEALED_WS_PORT || 8085);

let failures = 0;
function assert(label, condition, detail = '') {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
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

/** TLS client pinned to the dev cert (the relay's line protocol). */
const connectTcp = (port, host = '127.0.0.1') => connectRelay(port, host);

function withTimeout(label, p, ms = 20000) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${label}`)), ms)),
  ]);
}

async function main() {
  const sodium = await init();
  await loadPQ(); // keygen + session work
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
  const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));

  console.log('=== Sealed sender + delivery tokens (instrumented relay) ===\n');

  // ---- Token rotation (in-process, no relay): the one-time prekey is mixed
  // into the token, so two sessions to the same peer get different tokens. ----
  {
    const alice = new Identity();
    const bob = new Identity();
    const otkA = bob.makeOneTimePrekey();
    const otkB = bob.makeOneTimePrekey();
    const otkOf = (otk) => ({ id: otk.id, dhPk: b64(otk.pk), signature: b64(otk.signature) });
    const sA = new Session(alice, bob.makeBundle(), otkOf(otkA));
    const sB = new Session(alice, bob.makeBundle(), otkOf(otkB));
    assert('delivery token is a 44-char base64 id (32 bytes)',
      /^[A-Za-z0-9+/]{43}=$/.test(b64(sA.deliveryToken)));
    assert('delivery token rotates per session (different one-time prekeys)',
      b64(sA.deliveryToken) !== b64(sB.deliveryToken));
    // Same session, two messages: the token is stable (it does not ratchet).
    const e1 = sA.encrypt(Buffer.from('one'));
    const e2 = sA.encrypt(Buffer.from('two'));
    assert('delivery token is stable across messages within a session',
      e1.deliveryToken === e2.deliveryToken && e1.deliveryToken === b64(sA.deliveryToken));
  }

  // Spawn the real relay, verbose so its operator log records every identity
  // event it CAN observe — the test then proves none of that reveals who sent.
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: {
      ...process.env,
      PORT: String(RELAY_PORT),
      WS_PORT: String(WS_PORT),
      HOST: '127.0.0.1',
      MIX_OFF: '1',
      RELAY_VERBOSE: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayLog = '';
  relay.stdout.on('data', (d) => { relayLog += d; });
  relay.stderr.on('data', (d) => { relayLog += d; });

  const clients = [];
  try {
    await waitForTcp(RELAY_PORT);
    console.log(`[sealed] real relay started on 127.0.0.1:${RELAY_PORT} (verbose, mixing OFF)`);

    const alice = new Identity();
    alice.newOneTimePrekeys(5);
    const bob = new Identity();
    bob.newOneTimePrekeys(5);
    const aliceAddr = addr(alice);
    const bobAddr = addr(bob);
    console.log(`[sealed] Alice: ${aliceAddr.slice(0, 16)}...  Bob: ${bobAddr.slice(0, 16)}...`);

    const aliceClient = await connectTcp(RELAY_PORT);
    const bobClient = await connectTcp(RELAY_PORT);
    clients.push(aliceClient, bobClient);

    const alicePublished = aliceClient.once('published');
    const bobPublished = bobClient.once('published');
    aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice) });
    bobClient.send({ type: 'publish', address: bobAddr, bundle: bob.makeBundle(), oneTimePrekeys: otksOf(bob) });
    await withTimeout('publish', Promise.all([alicePublished, bobPublished]));

    // Alice resolves Bob's bundle + one-time prekey via a PRIVATE shard fetch
    // (Phase 1's other half): the relay only learns the shard, never the address.
    const bobDirP = aliceClient.once('directory-shard');
    aliceClient.send({ type: 'fetch-shard', shard: directoryShard(bobAddr, 1) });
    const bobDir = await withTimeout('bob shard', bobDirP);
    const bobEntry = bobDir.entries.find((e) => e.address === bobAddr);
    assert('shard returned Bob bundle + one-time prekey pool', !!bobEntry?.bundle && bobEntry.oneTimePrekeys.length > 0);
    const aliceOtk = selectOneTimePrekey(aliceAddr, bobAddr, bobEntry.oneTimePrekeys);

    const aliceSession = new Session(alice, bobEntry.bundle, aliceOtk);
    const secret = 'sealed — the relay never learns who sent this';

    // ---- Sealed send: NO fromPk on the wire. ----
    const bobInbound = bobClient.once('message');
    aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(secret, 'utf8')) });
    const recv = await withTimeout('bob sealed message', bobInbound);

    assert('sealed delivery carries NO fromPk field', recv.fromPk === undefined);
    assert('sealed delivery never contains the sender routing address',
      !JSON.stringify(recv).includes(aliceAddr));
    const tokenB64 = recv.envelope.deliveryToken;
    assert('envelope carries a per-session delivery token (44-char base64)',
      !!tokenB64 && /^[A-Za-z0-9+/]{43}=$/.test(tokenB64));

    // Bob establishes from the first message's bundle + his consumed OTK and
    // must derive the SAME token (symmetric bootstrap secrets).
    const otkId = recv.envelope.header.otk_id;
    const bobOtk = bob.oneTimePrekeys.get(otkId);
    assert('Bob still holds the one-time prekey the sender used', !!bobOtk);
    const bobSession = new Session(bob, alice.makeBundle(), { id: bobOtk.id, sk: bobOtk.sk, pk: bobOtk.pk });
    bob.oneTimePrekeys.delete(otkId);
    assert('recipient derives the same delivery token from the bootstrap secrets',
      b64(bobSession.deliveryToken) === tokenB64);
    const decrypted = bobSession.decrypt(recv.envelope);
    assert('sealed message still decrypts + verifies the sender end-to-end', decrypted === secret, decrypted);

    // ---- fromPk probe: a legacy/hostile client sends a sender marker; the
    // relay must ignore it — never echo it, never log it, never route by it. ----
    const PROBE = 'SENDER_IDENTITY_MARKER_7f3a';
    const probeInbound = bobClient.once('message');
    aliceClient.send({
      type: 'send', toPk: bobAddr,
      envelope: aliceSession.encrypt(Buffer.from('probe with fromPk', 'utf8')),
      fromPk: PROBE,
    });
    const probeRecv = await withTimeout('bob probe message', probeInbound);
    assert('relay ignores a fromPk probe (delivery has no fromPk)', probeRecv.fromPk === undefined);
    const probePlain = bobSession.decrypt(probeRecv.envelope);
    assert('delivery still works when a legacy client sends fromPk', probePlain === 'probe with fromPk');

    // The instrumented relay: its own verbose log must never contain the
    // sender marker, nor the sender address in the context of a send.
    assert('relay log never records the fromPk probe marker', !relayLog.includes(PROBE));
    // Registration logs each address on its OWN line; no line may pair the two
    // addresses (that would be a who->whom record).
    const noPair = relayLog.split('\n')
      .every((line) => !(line.includes(aliceAddr.slice(0, 16)) && line.includes(bobAddr.slice(0, 16))));
    assert('relay log has no line pairing sender + recipient (no who->whom)', noPair);

    // ---- Abuse guard: an UNREGISTERED client floods an offline recipient. The
    // relay rate-limits by queue cap without ever learning the sender. ----
    const flooder = await connectTcp(RELAY_PORT);
    clients.push(flooder);
    const victim = b64(sodium.randombytes_buf(32)); // offline, never registered
    const groupEnv = (i) => ({ v: 6, mode: 'group', ciphertext: Buffer.from(`flood-${i}`).toString('base64') });
    let queueFullAt = -1;
    for (let i = 0; i < 105; i++) {
      // Each send gets an immediate {type:'sent'} (queued) or {type:'error'}
      // ('recipient queue full' once past the cap). Register the reply race
      // BEFORE sending so a fast ack cannot slip past the listener.
      const replyP = Promise.race([
        flooder.once('sent'),
        flooder.once('error'),
      ]);
      flooder.send({ type: 'send', toPk: victim, envelope: groupEnv(i) });
      const reply = await withTimeout(`flood reply ${i}`, replyP);
      if (reply.type === 'error' && reply.error === 'recipient queue full') { queueFullAt = i; break; }
      if (reply.type !== 'sent') throw new Error(`unexpected flood reply: ${JSON.stringify(reply)}`);
    }
    assert('flood of an offline recipient is rate-limited by the queue cap',
      queueFullAt > 0, `full at message #${queueFullAt}`);
    // The flooder never registered, so the relay holds no address for it; the
    // victim (an offline group target) is never logged either — nothing pairs them.
    assert('rate-limit recorded no sender identity for the unregistered flooder',
      !relayLog.split('\n').some((l) => l.includes(victim.slice(0, 16))));

    console.log(`\n${failures === 0 ? 'SEALED SENDER TESTS PASSED' : `${failures} SEALED SENDER TEST(S) FAILED`}`);
  } catch (err) {
    console.error('[sealed] ERROR:', err.message);
    if (relayLog.trim()) console.error('[sealed] relay log tail:', relayLog.trim().split('\n').slice(-12).join(' | '));
    failures++;
  } finally {
    for (const c of clients) c.socket.destroy();
    relay.kill('SIGTERM');
  }

  process.exit(failures === 0 ? 0 : 1);
}

main();
