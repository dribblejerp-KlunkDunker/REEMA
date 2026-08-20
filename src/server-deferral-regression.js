import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { connectRelay } from './test-tls.js';
import { init, Identity, loadPQ } from './crypto.js';

/**
 * Server-side post-quantum deferral regression.
 *
 * The relay is ciphertext-only, so it must not load the @noble/post-quantum
 * graph (ML-KEM-768 / ML-DSA-65) at startup — only on the FIRST publish, when
 * it needs ML-DSA to verify a prekey bundle's self-signature. This proves the
 * deferral through the real relay process:
 *
 *   1. the relay boots and listens with zero @noble modules loaded;
 *   2. the moment the first publish arrives, the relay reports the loaded
 *      count BEFORE loading the PQ graph — it must be 0;
 *   3. the first publish then loads the graph and verifies, so a subsequent
 *      invalid bundle is rejected (the deferral did not skip verification).
 *
 * The count is reported by the relay itself via pqLoaded() (the crypto-core
 * probe), because Node does not expose a public registry of loaded ESM
 * modules for a parent process to inspect across a process boundary.
 */

const RELAY_PORT = Number(process.env.SD_RELAY_PORT || 7991);
const WS_PORT = Number(process.env.SD_WS_PORT || 8091);

let failures = 0;
function check(label, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
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

async function main() {
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: {
      ...process.env,
      PORT: String(RELAY_PORT),
      WS_PORT: String(WS_PORT),
      HOST: '127.0.0.1',
      MIX_OFF: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayOut += d; });

  const clients = [];
  try {
    await waitForTcp(RELAY_PORT);

    // The test process needs the PQ graph to mint a real identity/bundle (the
    // relay under test must NOT need it until the first publish arrives).
    const sodium = await init();
    await loadPQ();
    const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);

    const id = new Identity();
    id.newOneTimePrekeys(20);
    const address = b64(Identity.deriveAddress(id.signPk, id.pk));
    const otks = [...id.oneTimePrekeys.values()].map((kp) => ({
      id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
    }));

    // The relay must NOT have loaded @noble just from booting. This is
    // observable only after the first publish triggers the one-shot report,
    // but it proves the graph was still unloaded at that instant.
    const c = await connectRelay(RELAY_PORT);
    clients.push(c);
    const pubP = c.once('published');
    c.send({ type: 'publish', address, bundle: id.makeBundle(), oneTimePrekeys: otks });
    await pubP;

    check('relay reported zero @noble modules loaded before the first publish (server-side deferral)',
      /@noble modules loaded before first publish: 0/.test(relayOut),
      'the one-shot report must say 0');

    // The deferral must not have skipped verification: now that the graph is
    // loaded, an invalid bundle is rejected with the ML-DSA verify path live.
    const c2 = await connectRelay(RELAY_PORT);
    clients.push(c2);
    const errP = c2.once('error');
    c2.send({ type: 'publish', address: 'A'.repeat(44), bundle: { v: 6 }, oneTimePrekeys: [] });
    const err = await errP;
    check('first publish loaded the PQ graph and verification is live (invalid bundle rejected)',
      /invalid prekey bundle/.test(err.error || ''), err.error);
  } catch (e) {
    console.error('[server-deferral-regression] ERROR:', e.message);
    failures++;
  } finally {
    for (const c of clients) { try { c.socket.destroy(); } catch { /* ignore */ } }
    relay.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nSERVER DEFERRAL REGRESSION PASSED' : `\n${failures} SERVER DEFERRAL REGRESSION CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
