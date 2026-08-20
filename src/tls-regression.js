/**
 * TLS regression for the client↔relay link (ANONYMITY.md §2).
 *
 * Spawns the relay with the committed loopback dev cert (tools/certs/dev-cert.pem),
 * then:
 *   1. places a byte-pipe observer between a client and the relay and proves the
 *      routing fields are NOT readable on the wire — a passive network observer
 *      sees only TLS ciphertext, so `toPk` / `fromPk` markers never appear;
 *   2. proves the full protocol (send ack + group delivery) still works over TLS;
 *   3. proves a wrong certificate fingerprint FAILS CLOSED.
 *
 * The expected fingerprint is derived from the committed cert at test time, so
 * regenerating tools/certs/dev-cert.pem updates the pin automatically.
 */
import { spawn } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { readFileSync } from 'node:fs';
import { init } from './crypto.js';
import { makeCoverEnvelope } from './cover.js';
import { createTlsSocket, sha256Fingerprint } from './tls.js';

const RELAY_PORT = Number(process.env.TLS_RELAY_PORT || 7993);
const WS_PORT = Number(process.env.TLS_WS_PORT || 8083);
const CERT = 'tools/certs/dev-cert.pem';
const KEY = 'tools/certs/dev-key.pem';

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

/** Expected pin: SHA-256 of the committed cert's DER bytes. */
function committedFingerprint() {
  const pem = readFileSync(CERT, 'utf8');
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/\s+/g, '');
  return sha256Fingerprint(Buffer.from(b64, 'base64'));
}

/** A byte-pipe observer: records everything flowing client↔relay, unmodified. */
function startObserver(relayPort) {
  const recorded = [];
  return new Promise((resolve) => {
    const server = createServer((clientSock) => {
      const relaySock = connect(relayPort, '127.0.0.1');
      clientSock.on('data', (d) => { recorded.push(d); relaySock.write(d); });
      relaySock.on('data', (d) => { recorded.push(d); clientSock.write(d); });
      clientSock.on('close', () => relaySock.destroy());
      relaySock.on('close', () => clientSock.destroy());
      clientSock.on('error', () => {});
      relaySock.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, recorded }));
  });
}

/** A newline-framed TLS client (same line protocol as src/test.js's TCP client). */
function tlsClient(port, pin) {
  return createTlsSocket('localhost', port, { pin }).then((sock) => {
    sock.setEncoding('utf8');
    let buffer = '';
    const handlers = {};
    const messages = [];
    sock.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.type === 'message') messages.push(msg.envelope);
        const h = handlers[msg.type];
        if (h) { delete handlers[msg.type]; h(msg); }
      }
    });
    return {
      sock,
      send: (obj) => sock.write(JSON.stringify(obj) + '\n'),
      once: (t) => new Promise((res) => { handlers[t] = (m) => { delete handlers[t]; res(m); }; }),
      messages,
    };
  });
}

async function main() {
  const sodium = await init();
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const pin = committedFingerprint();

  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', TLS_CERT: CERT, TLS_KEY: KEY, MIX_OFF: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '', relayErr = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayErr += d; });

  const clients = [];
  try {
    await waitForTcp(RELAY_PORT);
    check('relay reports TLS on the TCP listener', /\(TLS\)/.test(relayOut), '');
    check('relay reports WSS on the WS listener', /WSS relay listening/.test(relayOut), '');

    const { server: observer, recorded } = await startObserver(RELAY_PORT);
    const observerPort = observer.address().port;

    // ---- 1. Routing fields are encrypted on the wire. ----
    const sender = await tlsClient(observerPort, pin);
    clients.push(sender);
    const ack = sender.once('sent');
    // Distinctive markers that WOULD be plaintext-visible without TLS.
    sender.send({ type: 'send', toPk: 'OBSERVER_MARKER_TO', fromPk: 'OBSERVER_MARKER_FROM', envelope: makeCoverEnvelope(sodium) });
    await ack;
    check('send acknowledged over TLS', true);
    const wire = Buffer.concat(recorded);
    check('wire is encrypted — routing markers not visible to a passive observer',
      !wire.toString('latin1').includes('OBSERVER_MARKER_TO') &&
      !wire.toString('latin1').includes('OBSERVER_MARKER_FROM'),
      `${wire.length} bytes observed`);

    // ---- 2. Real group delivery still works end-to-end over TLS. ----
    const groupId = `tls-group-${Date.now()}`;
    const member = await tlsClient(observerPort, pin);
    clients.push(member);
    const sub = member.once('subscribed');
    member.send({ type: 'subscribe', group: groupId });
    await sub;
    const ackG = sender.once('sent');
    sender.send({ type: 'send', toPk: groupId, envelope: { v: 6, mode: 'group', ciphertext: b64(sodium.randombytes_buf(64)) } });
    await ackG;
    await sleep(200);
    check('group message delivers end-to-end over TLS', member.messages.length === 1,
      `${member.messages.length} message(s)`);

    // ---- 3. Wrong fingerprint fails closed. ----
    let wrongPinRejected = false;
    try {
      await createTlsSocket('localhost', RELAY_PORT, { pin: 'deadbeef'.repeat(8) });
    } catch {
      wrongPinRejected = true;
    }
    check('wrong certificate fingerprint fails closed', wrongPinRejected);

    observer.close();
  } catch (e) {
    console.error('[tls-regression] ERROR:', e.message);
    if (relayErr.trim()) console.error('[tls-regression] relay stderr:', relayErr.trim().slice(0, 400));
    failures++;
  } finally {
    for (const c of clients) { try { c.sock.destroy(); } catch { /* ignore */ } }
    relay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nTLS REGRESSION PASSED' : `\n${failures} TLS REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
