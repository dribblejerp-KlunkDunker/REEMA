import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { connectRelay } from './test-tls.js';

/**
 * Zero-retention regression (ANONYMITY.md §3.6): RELAY_EPHEMERAL=1.
 *
 * The relay's default is store-and-forward (an undelivered message sits in
 * memory for QUEUE_TTL_MS). In ephemeral mode that queue is disabled entirely:
 * a message to an offline recipient is DROPPED at acceptance, never stored, so
 * there is no copy an adversary could later seize — once delivered (or dropped)
 * nothing survives. This proves the behaviour through the real relay:
 *
 *   1. the relay reports ephemeral retention;
 *   2. a send to an offline recipient is rejected as "ephemeral stores nothing"
 *      (not silently queued);
 *   3. a late subscriber receives NOTHING — no copy survived the delivery gap;
 *   4. live delivery to an online subscriber still works immediately.
 *
 * Uses opaque group envelopes (no crypto needed) so it exercises the exact
 * `queueMessage` choke point both pair and group traffic funnel through.
 */

const RELAY_PORT = Number(process.env.EPH_RELAY_PORT || 7990);
const WS_PORT = Number(process.env.EPH_WS_PORT || 8080);

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

const groupEnv = (n) => ({ v: 6, mode: 'group', ciphertext: Buffer.from(`eph-${n}`).toString('base64') });

async function main() {
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: {
      ...process.env,
      PORT: String(RELAY_PORT),
      WS_PORT: String(WS_PORT),
      HOST: '127.0.0.1',
      MIX_OFF: '1',
      RELAY_EPHEMERAL: '1',
      RELAY_VERBOSE: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayOut += d; });

  const clients = [];
  try {
    await waitForTcp(RELAY_PORT);
    check('relay reports ephemeral retention (nothing ever queued)',
      /ephemeral — nothing is ever queued/.test(relayOut), '');

    const sender = await connectRelay(RELAY_PORT);
    const member = await connectRelay(RELAY_PORT);
    clients.push(sender, member);

    // ---- 1. Offline send is dropped at acceptance, never queued. ----
    const groupId = `eph-group-${Date.now()}`;
    const errP = sender.once('error');
    sender.send({ type: 'send', toPk: groupId, envelope: groupEnv(1) });
    const err = await errP;
    check('offline send is dropped, not queued (ephemeral)',
      /ephemeral relay stores nothing/.test(err.error || ''), err.error);

    // ---- 2. No copy survives: a late subscriber receives nothing. ----
    const sub = member.once('subscribed');
    member.send({ type: 'subscribe', group: groupId });
    await sub;
    await sleep(200);
    check('no copy survives delivery — late subscriber receives nothing',
      member.messages.length === 0, `${member.messages.length} message(s)`);
    check('relay flushed 0 queued on subscribe (inbox held nothing)',
      /delivered 0 queued/.test(relayOut), '');

    // ---- 3. Live delivery to an online subscriber still works. ----
    const ack = sender.once('sent');
    sender.send({ type: 'send', toPk: groupId, envelope: groupEnv(2) });
    await ack;
    const deadline = Date.now() + 3000;
    while (member.messages.length < 1 && Date.now() < deadline) await sleep(20);
    check('live delivery still works (online subscriber receives immediately)',
      member.messages.length === 1, `${member.messages.length} message(s)`);

    // ---- 4. A second offline send to a fresh id is also not retained. ----
    const freshGroup = `eph-fresh-${Date.now()}`;
    const errP2 = sender.once('error');
    sender.send({ type: 'send', toPk: freshGroup, envelope: groupEnv(3) });
    const err2 = await errP2;
    check('second offline send also dropped (no accumulation)',
      /ephemeral relay stores nothing/.test(err2.error || ''), err2.error);
  } catch (e) {
    console.error('[ephemeral-regression] ERROR:', e.message);
    failures++;
  } finally {
    for (const c of clients) { try { c.socket.destroy(); } catch { /* ignore */ } }
    relay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nEPHEMERAL REGRESSION PASSED' : `\n${failures} EPHEMERAL REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
