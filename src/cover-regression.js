/**
 * Cover-traffic regression (ANONYMITY.md Phase 2 — first increment).
 *
 * Proves the RELAY side of cover traffic: a `mode:'cover'` envelope is
 * acknowledged as received and then DISCARDED — never delivered to an online
 * recipient, never queued for an offline one, never allowed to affect real
 * delivery, and never able to crash the relay. It also asserts the client-side
 * property that a cover frame and a real (group) frame carrying the same
 * payload serialize to the same length, so a size-only observer cannot tell
 * them apart.
 *
 * HONEST LIMIT (also in src/cover.js): `mode:'cover'` is visible on the
 * plaintext client→relay link, so full indistinguishability from an observer
 * who reads the application layer requires TLS on that link — the next step.
 * This test proves the machinery, not that TLS gap.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, loadPQ } from './crypto.js';
import { makeCoverEnvelope } from './cover.js';
import { connectRelay } from './test-tls.js';

const RELAY_PORT = Number(process.env.COVER_RELAY_PORT || 7994);
const WS_PORT = Number(process.env.COVER_WS_PORT || 8084);

let failures = 0;
function check(label, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

/** TLS client pinned to the dev cert. */
const connectTcp = (port) => connectRelay(port);

async function main() {
  const sodium = await init();
  await loadPQ();
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);

  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayErr = '';
  relay.stderr.on('data', (d) => { relayErr += d; });

  const sockets = [];
  try {
    await waitForTcp(RELAY_PORT);

    // A real identity so we can exercise the "offline then online" queue path.
    const recipient = new Identity();
    const recipientAddr = b64(Identity.deriveAddress(recipient.signPk, recipient.pk));

    const sink = await connectTcp(RELAY_PORT);      // unregistered cover sender
    const recipientClient = await connectTcp(RELAY_PORT);
    sockets.push(sink, recipientClient);

    // ---- 1. Cover to an OFFLINE recipient is acknowledged but never queued. ----
    const ack1 = sink.once('sent');
    sink.send({ type: 'send', toPk: recipientAddr, envelope: makeCoverEnvelope(sodium) });
    await ack1;
    check('cover frame acknowledged as received', true);

    const published = recipientClient.once('published');
    recipientClient.send({
      type: 'publish', address: recipientAddr,
      bundle: recipient.makeBundle(), oneTimePrekeys: [],
    });
    await published;
    await sleep(200);
    check('cover sent while offline was NOT queued (nothing flushed on publish)',
      recipientClient.messages.length === 0, `${recipientClient.messages.length} message(s)`);

    // ---- 2. Cover to an ONLINE recipient is never delivered. ----
    const ack2 = sink.once('sent');
    sink.send({ type: 'send', toPk: recipientAddr, envelope: makeCoverEnvelope(sodium) });
    await ack2;
    await sleep(200);
    check('cover sent while online is NOT delivered', recipientClient.messages.length === 0,
      `${recipientClient.messages.length} message(s)`);

    // ---- 3. Real delivery is unaffected while cover flows. ----
    const groupId = `cover-group-${Date.now()}`;
    const sub = recipientClient.once('subscribed');
    recipientClient.send({ type: 'subscribe', group: groupId });
    await sub;
    const ack3 = sink.once('sent');
    sink.send({ type: 'send', toPk: groupId, envelope: { v: 6, mode: 'group', ciphertext: b64(sodium.randombytes_buf(64)) } });
    await ack3;
    await sleep(200);
    check('real group message still delivers alongside cover', recipientClient.messages.length === 1,
      `${recipientClient.messages.length} message(s)`);

    // ---- 4. Cover and real frames of equal payload serialize to equal length. ----
    const payload = sodium.randombytes_buf(1024);
    const cover = { v: 6, mode: 'cover', ciphertext: b64(payload) };
    const real = { v: 6, mode: 'group', ciphertext: b64(payload) };
    check('cover and real frames of equal payload are equal-size on the wire',
      JSON.stringify(cover).length === JSON.stringify(real).length,
      `${JSON.stringify(cover).length} vs ${JSON.stringify(real).length}`);

    // ---- 5. Malformed cover is rejected without crashing the relay. ----
    const junk = await connectTcp(RELAY_PORT);
    sockets.push(junk);
    const errP = junk.once('error');
    junk.send({ type: 'send', toPk: recipientAddr, envelope: { v: 6, mode: 'cover', ciphertext: '' } });
    const err = await errP;
    check('malformed cover rejected, no crash', /malformed envelope rejected/.test(err.error));

    // 150 KB raw -> ~205 KB base64: above the 128 KB cover cap but below the
    // 256 KB line cap, so it reaches the envelope-size guard (not the line guard).
    const errP2 = junk.once('error');
    junk.send({ type: 'send', toPk: recipientAddr, envelope: { v: 6, mode: 'cover', ciphertext: b64(sodium.randombytes_buf(150 * 1024)) } });
    const err2 = await errP2;
    check('oversized cover rejected, no crash', /malformed envelope rejected/.test(err2.error));
  } catch (e) {
    console.error('[cover-regression] ERROR:', e.message);
    if (relayErr.trim()) console.error('[cover-regression] relay stderr:', relayErr.trim().slice(0, 400));
    failures++;
  } finally {
    for (const c of sockets) { try { c.socket.destroy(); } catch { /* ignore */ } }
    relay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nCOVER REGRESSION PASSED' : `\n${failures} COVER REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
