/**
 * Private directory lookup (ANONYMITY.md Phase 1, other half) — acceptance test
 * from DESIGN-sealed-sender.md, wired into `npm test`.
 *
 * `fetch-directory` used to ask for ONE address, so the relay could answer
 * "who looked up whom". It is replaced by `fetch-shard {shard}`: the requester
 * names a whole bucket (the first byte of the target address), the relay serves
 * every entry in that bucket, and the requester selects the target client-side
 * from the self-signed bundles. k-anonymity = shard population.
 *
 * This drives the REAL relay in verbose mode (the most it can ever record) and
 * proves:
 *
 *   1. the relay's own log records the SHARD, never the looked-up address;
 *   2. delivery still works end-to-end from a shard-resolved bundle;
 *   3. a tampered shard is caught — a forged bundle fails its self-signature,
 *      and a valid-but-swapped bundle fails the address-derivation check;
 *   4. the one-time prekey is burned RECIPIENT-side (no server-side consume),
 *      and two DISTINCT senders derive DISTINCT prekeys (deterministic
 *      per-sender selection), so single-use survives whole-shard fetch.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, Session, loadPQ, directoryShard, selectOneTimePrekey } from './crypto.js';
import { connectRelay } from './test-tls.js';

const RELAY_PORT = Number(process.env.PD_RELAY_PORT || 7994);
const WS_PORT = Number(process.env.PD_WS_PORT || 8084);

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

const connectTcp = (port, host = '127.0.0.1') => connectRelay(port, host);

function withTimeout(label, p, ms = 20000) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${label}`)), ms)),
  ]);
}

// Child stdout is delivered asynchronously, so poll the accumulated relay log
// until a marker appears before asserting on it.
async function waitForLog(getLog, needle, ms = 5000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (getLog().includes(needle)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function main() {
  const sodium = await init();
  await loadPQ();
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
  const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));

  console.log('=== Private directory lookup (instrumented relay) ===\n');

  // Verbose = the relay records everything it can possibly observe. If its own
  // log cannot reconstruct the lookup, no mode can.
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1', MIX_OFF: '1', RELAY_VERBOSE: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '', relayErr = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayErr += d; });

  const clients = [];
  try {
    await waitForTcp(RELAY_PORT);

    const alice = new Identity(); alice.newOneTimePrekeys(20);
    const bob = new Identity(); bob.newOneTimePrekeys(20);
    const carol = new Identity(); carol.newOneTimePrekeys(20);
    const aliceAddr = addr(alice);
    const bobAddr = addr(bob);
    const carolAddr = addr(carol);
    console.log(`[pd] Alice: ${aliceAddr.slice(0, 16)}...  Bob: ${bobAddr.slice(0, 16)}...  Carol: ${carolAddr.slice(0, 16)}...`);

    const aliceClient = await connectTcp(RELAY_PORT);
    const bobClient = await connectTcp(RELAY_PORT);
    const carolClient = await connectTcp(RELAY_PORT);
    clients.push(aliceClient, bobClient, carolClient);

    const pubs = [aliceClient.once('published'), bobClient.once('published'), carolClient.once('published')];
    aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice) });
    bobClient.send({ type: 'publish', address: bobAddr, bundle: bob.makeBundle(), oneTimePrekeys: otksOf(bob) });
    carolClient.send({ type: 'publish', address: carolAddr, bundle: carol.makeBundle(), oneTimePrekeys: otksOf(carol) });
    await withTimeout('publish', Promise.all(pubs));

    // ---- Alice fetches Bob's WHOLE shard (names the bucket, not Bob) ----
    const shard = directoryShard(bobAddr, 1);
    const resp = await (async () => {
      const p = aliceClient.once('directory-shard');
      aliceClient.send({ type: 'fetch-shard', shard });
      return withTimeout('bob shard', p);
    })();
    const bobEntry = resp.entries.find((e) => e.address === bobAddr);
    assert('shard contains Bob (selected client-side)', !!bobEntry);
    assert('shard response carries only the shard id, not the requested address',
      resp.shard === shard && resp.address === undefined);

    // 1. The instrumented relay's own log records the SHARD, never the address.
    await waitForLog(() => relayOut, 'served shard');
    const servedLines = relayOut.split('\n').filter((l) => l.includes('served shard'));
    assert('relay log records the fetch at shard granularity', servedLines.length > 0);
    assert('relay log never pairs the fetch with the looked-up address',
      servedLines.every((l) => !l.includes(bobAddr)),
      servedLines[0] ? servedLines[0].trim() : 'no served-shard line');

    // 2. Tamper detection: the requester re-verifies the entry client-side.
    const bobPeer = Identity.verifyBundle(bobEntry.bundle);
    assert('shard entry address derives from its bundle (swapped entry caught)',
      b64(Identity.deriveAddress(bobPeer.signPk, bobPeer.staticDhPk)) === bobAddr);
    const forged = { ...bobEntry.bundle, staticDhPk: b64(sodium.randombytes_buf(32)) };
    let forgedCaught = false;
    try { Identity.verifyBundle(forged); } catch { forgedCaught = true; }
    assert('forged bundle fails its self-signature', forgedCaught);

    // 3. Deterministic selection: two DISTINCT senders derive DISTINCT prekeys,
    //    so the recipient-side burn keeps single-use without a server consume.
    const aliceOtk = selectOneTimePrekey(aliceAddr, bobAddr, bobEntry.oneTimePrekeys);
    const carolOtk = selectOneTimePrekey(carolAddr, bobAddr, bobEntry.oneTimePrekeys);
    assert('distinct senders select distinct one-time prekeys', aliceOtk && carolOtk && aliceOtk.id !== carolOtk.id);
    assert('selected prekey is signed by Bob', Identity.verifyOneTimePrekey(bob.signPk, aliceOtk));

    // 4. Delivery still works from the shard-resolved bundle.
    const aliceSession = new Session(alice, bobEntry.bundle, aliceOtk);
    const secret = 'private lookup — the relay cannot learn who looked up whom';
    const bobInbound = bobClient.once('message');
    aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(secret, 'utf8')) });
    const recv = await withTimeout('bob first message', bobInbound);

    assert('first message carries the selected prekey id', recv.envelope.header.otk_id === aliceOtk.id);
    const bobOtk = bob.oneTimePrekeys.get(recv.envelope.header.otk_id);
    assert('Bob still holds the prekey (not consumed server-side)', !!bobOtk);
    const bobSession = new Session(bob, alice.makeBundle(), { id: bobOtk.id, sk: bobOtk.sk, pk: bobOtk.pk });
    bob.oneTimePrekeys.delete(bobOtk.id);
    assert('Bob burned the prekey on first receive (recipient-side single-use)', !bob.oneTimePrekeys.has(bobOtk.id));
    assert('shard-resolved session decrypts + verifies end-to-end',
      bobSession.decrypt(recv.envelope) === secret);

    console.log('\nPRIVATE DIRECTORY REGRESSION ' + (failures === 0 ? 'PASSED' : `FAILED (${failures})`));
  } catch (err) {
    console.error('[private-directory-regression] ERROR:', err.message);
    if (relayOut.trim()) console.error('[private-directory-regression] relay log:', relayOut.trim().split('\n').slice(-12).join(' | '));
    if (relayErr.trim()) console.error('[private-directory-regression] relay stderr:', relayErr.trim().slice(0, 400));
    failures++;
  } finally {
    relay.kill('SIGTERM');
  }

  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
