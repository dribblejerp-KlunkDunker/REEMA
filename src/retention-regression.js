/**
 * Metadata retention + self-destruct regression (ANONYMITY.md §3.6).
 *
 * Proves the two halves of "metadata with a timer":
 *   1. By DEFAULT the relay writes no per-identity metadata to its operator log
 *      — a subscribed group id and a routed recipient address never appear,
 *      even though both are real traffic. (RELAY_VERBOSE=1 re-enables them for
 *      debugging; src/test.js runs verbose so those lines stay sanitized.)
 *   2. Undelivered metadata self-destructs: with a short QUEUE_TTL_MS, a queued
 *      message expires and is NOT delivered when the recipient later connects.
 *
 * Honest note (ANONYMITY.md §3.6): this controls the relay's OWN storage. It
 * does nothing about a passive observer's recording or a relay that lies about
 * its retention — which is why never-emit (sealed sender) and never-concentrate
 * (no single relay) remain the real defences.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { connectRelay } from './test-tls.js';

const RELAY_PORT = Number(process.env.RET_RELAY_PORT || 7992);
const WS_PORT = Number(process.env.RET_WS_PORT || 8082);
const TTL_RELAY_PORT = Number(process.env.RET_TTL_RELAY_PORT || 7991);
const TTL_WS_PORT = Number(process.env.RET_TTL_WS_PORT || 8081);

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

const groupEnv = (n) => ({ v: 6, mode: 'group', ciphertext: Buffer.from(`ret-${n}`).toString('base64') });

async function main() {
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const ttlRelay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(TTL_RELAY_PORT), WS_PORT: String(TTL_WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1', QUEUE_TTL_MS: '200' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '', ttlOut = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  ttlRelay.stdout.on('data', (d) => { ttlOut += d; });

  const sockets = [];
  try {
    await waitForTcp(RELAY_PORT);
    await waitForTcp(TTL_RELAY_PORT);

    // ---- 1. Default relay log holds no per-identity metadata. ----
    const groupMarker = `RETENTION_MARKER_GROUP_${Date.now()}`;
    const addrMarker = `RETENTION_MARKER_ADDR_${Date.now()}`;
    const client = await connectTcp(RELAY_PORT);
    sockets.push(client);
    const sub = client.once('subscribed');
    client.send({ type: 'subscribe', group: groupMarker });
    await sub;
    const ack = client.once('sent');
    client.send({ type: 'send', toPk: groupMarker, envelope: groupEnv(1), fromPk: addrMarker });
    await ack;
    const ack2 = client.once('sent');
    client.send({ type: 'send', toPk: addrMarker, envelope: groupEnv(2), fromPk: addrMarker });
    await ack2;
    await sleep(100);
    check('default relay log contains no group id', !relayOut.includes(groupMarker), '');
    check('default relay log contains no recipient address', !relayOut.includes(addrMarker), '');
    check('relay reports per-identity logs OFF', /per-identity logs OFF/.test(relayOut), '');

    // ---- 2. Undelivered metadata self-destructs after TTL. ----
    check('short-TTL relay reports its retention', /retention: 200ms TTL/.test(ttlOut), '');
    const deadGroup = `dead-group-${Date.now()}`;
    const sender = await connectTcp(TTL_RELAY_PORT);
    const member = await connectTcp(TTL_RELAY_PORT);
    sockets.push(sender, member);
    const deadAck = sender.once('sent');
    sender.send({ type: 'send', toPk: deadGroup, envelope: groupEnv(9), fromPk: 'sender' });
    await deadAck;
    await sleep(400); // past the 200ms TTL

    const subLate = member.once('subscribed');
    member.send({ type: 'subscribe', group: deadGroup });
    await subLate;
    await sleep(200);
    check('expired queued message self-destructed (not delivered after TTL)',
      member.messages.length === 0, `${member.messages.length} message(s)`);
  } catch (e) {
    console.error('[retention-regression] ERROR:', e.message);
    failures++;
  } finally {
    for (const c of sockets) { try { c.socket.destroy(); } catch { /* ignore */ } }
    relay.kill('SIGTERM');
    ttlRelay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nRETENTION REGRESSION PASSED' : `\n${failures} RETENTION REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
