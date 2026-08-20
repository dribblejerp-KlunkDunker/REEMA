/**
 * Batching regression for relay-side message mixing (ROADMAP §8 / Phase 5).
 *
 * Spawns the REAL relay twice — once with mixing ON (a short MIX_WINDOW_MS) and
 * once with MIX_OFF=1 — and drives the relay's group fan-out (which needs no
 * crypto: group envelopes are opaque { v:6, mode:'group', ciphertext }) to prove
 * the scheduling behaviour, not the cipher:
 *
 *   ON:  `sent` acknowledges relay receipt immediately; delivery is DELAYED until
 *        the window closes, and everything accepted in one window flushes as a
 *        single tick — two messages to two members land as four near-simultaneous
 *        deliveries, so an observer cannot attribute a sender from timing.
 *   OFF: delivery is immediate, preserving the deterministic test suites' timing.
 *
 * Self-contained (spawns its own relays on loopback ports) and uses the same
 * newline-delimited TCP client as src/test.js.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { connectRelay } from './test-tls.js';

const MIX_RELAY_PORT = Number(process.env.MIX_RELAY_PORT || 7996);
const MIX_WS_PORT = Number(process.env.MIX_WS_PORT || 8086);
const OFF_RELAY_PORT = Number(process.env.MIX_OFF_RELAY_PORT || 7995);
const OFF_WS_PORT = Number(process.env.MIX_OFF_WS_PORT || 8085);

// Short enough for the test to be fast, long enough to give every assertion a
// wide, flake-free margin (see the thresholds below).
const WINDOW_MS = 300;

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

/** TLS client pinned to the dev cert; collects message arrivals with timestamps. */
const connectTcp = (port) => connectRelay(port);

const groupEnv = (n) => ({ v: 6, mode: 'group', ciphertext: Buffer.from(`mix-msg-${n}`).toString('base64') });

async function waitForCount(client, n, ms = 5000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (client.messages.length >= n) return;
    await sleep(20);
  }
  throw new Error(`timed out waiting for ${n} message(s) (got ${client.messages.length})`);
}

async function main() {
  const mixRelay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(MIX_RELAY_PORT), WS_PORT: String(MIX_WS_PORT), HOST: '127.0.0.1', MIX_WINDOW_MS: String(WINDOW_MS) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const offRelay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(OFF_RELAY_PORT), WS_PORT: String(OFF_WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let mixOut = '', mixErr = '', offOut = '', offErr = '';
  mixRelay.stdout.on('data', (d) => { mixOut += d; });
  mixRelay.stderr.on('data', (d) => { mixErr += d; });
  offRelay.stdout.on('data', (d) => { offOut += d; });
  offRelay.stderr.on('data', (d) => { offErr += d; });

  const sockets = [];
  try {
    await waitForTcp(MIX_RELAY_PORT);
    await waitForTcp(OFF_RELAY_PORT);
    check('mixing relay reports mixing ON', /message mixing ON/.test(mixOut), '');
    check('MIX_OFF relay does not report mixing ON', !/message mixing ON/.test(offOut), '');
    // TLS is default-on: neither relay was passed TLS_CERT/TLS_KEY or TLS_OFF,
    // yet both report TLS and the pinned clients above connected successfully.
    check('relay defaults to TLS ON (no TLS_CERT/TLS_KEY env)', /TLS ON/.test(mixOut) && /TLS ON/.test(offOut), '');

    // ---- Mixing ON: batching + uniform group delivery ----
    const groupId = `mix-group-${Date.now()}`;
    const sender = await connectTcp(MIX_RELAY_PORT);
    const memberA = await connectTcp(MIX_RELAY_PORT);
    const memberB = await connectTcp(MIX_RELAY_PORT);
    sockets.push(sender, memberA, memberB);

    const subA = memberA.once('subscribed');
    const subB = memberB.once('subscribed');
    memberA.send({ type: 'subscribe', group: groupId });
    memberB.send({ type: 'subscribe', group: groupId });
    await Promise.all([subA, subB]);
    check('two members subscribed on the mixing relay', true);

    const t0 = Date.now();
    const ack1 = sender.once('sent');
    sender.send({ type: 'send', toPk: groupId, envelope: groupEnv(1), fromPk: 'sender' });
    const sent1 = await ack1;
    check('sent ack is immediate (relay receipt, not batch release)', Date.now() - t0 < 200, `${Date.now() - t0}ms`);
    check('sent ack carries the routed group id', sent1.toPk === groupId);

    await sleep(150);
    check('message NOT delivered before the window closes',
      memberA.messages.length === 0 && memberB.messages.length === 0,
      `A=${memberA.messages.length} B=${memberB.messages.length}`);

    const ack2 = sender.once('sent');
    sender.send({ type: 'send', toPk: groupId, envelope: groupEnv(2), fromPk: 'sender' });
    await ack2;

    await waitForCount(memberA, 2);
    await waitForCount(memberB, 2);
    const arrivals = [...memberA.messages, ...memberB.messages].map((m) => m.ts);
    const first = Math.min(...arrivals);
    const spread = Math.max(...arrivals) - first;
    check('both messages delivered only after the window closed', first - t0 >= 150, `+${first - t0}ms`);
    check('all four deliveries land in the same tick (one batch)', spread < 100, `spread ${spread}ms`);
    check('both members received both messages (uniform delivery)',
      memberA.messages.length === 2 && memberB.messages.length === 2);

    // ---- MIX_OFF: immediate delivery (no window) ----
    const offGroupId = `mix-off-group-${Date.now()}`;
    const offSender = await connectTcp(OFF_RELAY_PORT);
    const offMember = await connectTcp(OFF_RELAY_PORT);
    sockets.push(offSender, offMember);

    const offSub = offMember.once('subscribed');
    offMember.send({ type: 'subscribe', group: offGroupId });
    await offSub;

    const tOff = Date.now();
    const offAck = offSender.once('sent');
    offSender.send({ type: 'send', toPk: offGroupId, envelope: groupEnv(1), fromPk: 'sender' });
    await offAck;
    await waitForCount(offMember, 1, 2000);
    check('MIX_OFF delivers immediately (no window delay)', offMember.messages[0].ts - tOff < 150, `${offMember.messages[0].ts - tOff}ms`);
  } catch (err) {
    console.error('[mix-regression] ERROR:', err.message);
    failures++;
    if (mixErr.trim()) console.error('[mix-regression] mix relay stderr:', mixErr.trim().slice(0, 400));
    if (offErr.trim()) console.error('[mix-regression] off relay stderr:', offErr.trim().slice(0, 400));
  } finally {
    for (const c of sockets) { try { c.socket.destroy(); } catch { /* ignore */ } }
    mixRelay.kill('SIGTERM');
    offRelay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nMIX REGRESSION PASSED' : `\n${failures} MIX REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
