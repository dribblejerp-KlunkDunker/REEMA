import { init, Identity, Session, signingPayload } from './crypto.js';

/**
 * Mutation fuzzer for the Double Ratchet state machine.
 *
 * Every bug found in this project's review was a state-machine invariant
 * violation. This fuzzer generalises the demo's hardcoded freeze test:
 * thousands of randomized envelopes (bit flips, counter bumps, replays,
 * attacker re-signatures) are fed to a live session, asserting:
 *
 *   1. no acceptance unless the plaintext is one of the known corpus messages;
 *   2. byte-identical session state after every rejection;
 *   3. the session still delivers real messages throughout and afterwards.
 *
 * A separate bootstrap pass feeds mutations to a fresh session, asserting it
 * accepts nothing except the genuine first message — the class of bug behind
 * the v4 pre-reply forgery.
 *
 * Seeded PRNG so failures are reproducible. Run via `npm test` (or directly:
 * `node src/fuzz.js`).
 */

let failures = 0;
function assert(label, condition) {
  if (!condition) { console.log(`FAIL  ${label}`); failures++; }
}

// Deterministic PRNG (mulberry32) so a failing seed is reproducible.
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const utf8 = (s) => new TextEncoder().encode(s);

/** Full snapshot of every mutable field _snapshot() can restore. */
function freeze(s) {
  return JSON.stringify({
    RK: [...s.RK], DHsSk: [...s.DHs.sk], DHsPk: [...s.DHs.pk], DHr: s.DHr ? [...s.DHr] : null,
    PQsSk: [...s.PQs.secretKey], PQsPk: [...s.PQs.publicKey], PQr: s.PQr_pk ? [...s.PQr_pk] : null,
    nextPqCt: [...s.nextPqCt],
    CKs: s.CKs ? [...s.CKs] : null, CKr: s.CKr ? [...s.CKr] : null,
    Ns: s.Ns, Nr: s.Nr, PN: s.PN,
    MKSKIP: [...s.MKSKIP.entries()].map(([k, v]) => [k, [...v]]),
    epochs: [...s.epochs.entries()].map(([k, v]) => [k, { pk: [...v.pk], ct: [...v.ct] }]).sort(),
    pin: s.peerSignPk ? [...s.peerSignPk] : null,
    firstSent: s._isFirstMessage,
  });
}

const clone = (env) => JSON.parse(JSON.stringify(env));

async function main() {
  const sodium = await init();
  const rnd = mulberry32(0xC0FFEE);
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  const randBytes = (n) => sodium.randombytes_buf(n);
  const randB64 = () => b64(randBytes(1 + Math.floor(rnd() * 48)));

  console.log('=== Fuzz: Double Ratchet state integrity (protocol v6) ===\n');

  // ---- Live conversation in a non-trivial state (epochs + skipped keys) ----
  const alice = new Identity();
  const bob = new Identity();
  const mallory = new Identity();
  const A = new Session(alice, bob.makeBundle());
  const B = new Session(bob, alice.makeBundle());

  const corpus = [];
  const known = new Map();
  const push = (env, plaintext) => { corpus.push(env); known.set(JSON.stringify(env), plaintext); };

  const m0 = A.encrypt(utf8('epoch0-a'));
  B.decrypt(m0); push(m0, 'epoch0-a');
  const m1 = A.encrypt(utf8('epoch0-b'));
  push(m1, 'epoch0-b');                    // skipped, consumed after the ratchet
  const r1 = B.encrypt(utf8('reply1'));
  A.decrypt(r1); push(r1, 'reply1');       // ratchet -> epoch 1
  const m2 = A.encrypt(utf8('epoch1-a'));
  B.decrypt(m2); push(m2, 'epoch1-a');
  const m3 = A.encrypt(utf8('epoch1-b'));
  push(m3, 'epoch1-b');                    // skipped
  const r2 = B.encrypt(utf8('reply2'));
  A.decrypt(r2); push(r2, 'reply2');       // ratchet -> epoch 2
  const m4 = A.encrypt(utf8('epoch2-a'));
  B.decrypt(m4); push(m4, 'epoch2-a');
  B.decrypt(m1); B.decrypt(m3);

  const live = () => {
    try { return B.decrypt(A.encrypt(utf8('liveness'))) === 'liveness'; }
    catch { return false; }
  };

  // ---- Mutations ----
  function mutate(env) {
    const e = clone(env);
    const flip = (s) => {
      const bytes = unb64(s);
      bytes[Math.floor(rnd() * bytes.length)] ^= (1 + Math.floor(rnd() * 255));
      return b64(bytes);
    };
    switch (Math.floor(rnd() * 13)) {
      case 0: e.ciphertext = flip(e.ciphertext); break;
      case 1: e.nonce = flip(e.nonce); break;
      case 2: e.header.n += 1 + Math.floor(rnd() * 20); break;
      case 3: e.header.n = 100000 + Math.floor(rnd() * 1000000); break;
      case 4: e.header.pn += 1 + Math.floor(rnd() * 20); break;
      case 5: e.header.dh = b64(randBytes(32)); break;
      case 6: e.header.pq_pk = b64(randBytes(1184)); break;
      case 7: e.v = 3 + Math.floor(rnd() * 3); break;
      case 8: e.ciphertext = randB64(); break;
      case 9: e.header.n = -1; break;
      case 10: e.senderSignPk = b64(mallory.signPk); break;
      case 11: e.senderDhPk = b64(randBytes(32)); break;
      case 12: e.header.first = e.header.first === true ? 'yes' : true; break;
    }
    return e;
  }

  // Re-sign a mutated envelope with an attacker key (signed-but-wrong paths),
  // addressed to a specific recipient so the signature check passes there.
  function resign(env, recipientDhPk) {
    const e = clone(env);
    // Omitted KEM material is replaced with a placeholder: the envelope is
    // re-signed with the attacker's key, so the victim rejects it at the peer
    // check (or signature mismatch) regardless of the exact bytes.
    const payload = signingPayload({
      v: e.v, senderDhPk: unb64(e.senderDhPk), senderSignPk: mallory.signPk,
      recipientDhPk, dh: unb64(e.header.dh),
      pqPk: e.header.pq_pk ? unb64(e.header.pq_pk) : new Uint8Array(1184),
      pqCt: e.header.pq_ct ? unb64(e.header.pq_ct) : new Uint8Array(1088),
      pn: e.header.pn, n: e.header.n, nonce: unb64(e.nonce), ciphertext: unb64(e.ciphertext),
      first: e.header.first === true,
    });
    return { ...e, senderSignPk: b64(mallory.signPk), signature: b64(mallory.sign(payload)) };
  }

  const ITER = 1500;
  let accepted = 0, rejected = 0;

  for (let i = 0; i < ITER; i++) {
    const base = corpus[Math.floor(rnd() * corpus.length)];
    let env;
    if (i % 5 === 0) env = resign(mutate(base), bob.pk);
    else if (i % 7 === 0) env = clone(base);   // exact replay
    else env = mutate(base);

    const before = freeze(B);
    let plaintext = null;
    let threw = null;
    try { plaintext = B.decrypt(env); } catch (e) { threw = e.message; }

    if (threw) {
      rejected++;
      if (freeze(B) !== before) { assert(`state unchanged after fuzz #${i}`, false); break; }
    } else {
      accepted++;
      assert(`fuzz #${i} accepted only a known plaintext`, plaintext === known.get(JSON.stringify(env)));
    }

    if (i % 100 === 0 && !live()) { assert(`session live after ${i} fuzz iterations`, false); break; }
  }
  assert(`session live after all ${ITER} fuzz iterations`, live());
  console.log(`fuzz iterations: ${ITER} (${accepted} accepted, ${rejected} rejected)`);

  // ---- Bootstrap: a fresh session must accept nothing but the real first message ----
  console.log('\n=== Bootstrap: fresh session ===');
  const A2 = new Session(alice, bob.makeBundle());   // awaits Bob's first message
  const realB = new Session(bob, alice.makeBundle());
  realB.decrypt(A2.encrypt(utf8('hi bob')));         // Bob receives Alice's first message
  const realFirst = realB.encrypt(utf8('real first reply'));

  let acceptedJunk = false;
  for (let i = 0; i < 300; i++) {
    const base = corpus[Math.floor(rnd() * corpus.length)];
    const env = i % 3 === 0 ? resign(mutate(base), alice.pk) : mutate(base);
    const before = freeze(A2);
    let plaintext = null;
    try { plaintext = A2.decrypt(env); } catch { /* rejected */ }
    if (plaintext !== null) { acceptedJunk = true; break; }
    if (freeze(A2) !== before) { assert(`bootstrap state unchanged after fuzz #${i}`, false); break; }
  }
  assert('fresh session rejects all fuzzed envelopes', !acceptedJunk);

  // The v6 bootstrap forgery: an attacker's own first message, re-claimed as
  // Bob (signed by Mallory, addressed to Alice). The peer signing key is
  // pinned from the verified bundle, so this must be rejected.
  const forged = new Session(mallory, alice.makeBundle()).encrypt(utf8('forged'));
  forged.senderDhPk = b64(bob.pk);
  forged.senderSignPk = b64(mallory.signPk);
  forged.signature = b64(mallory.sign(signingPayload({
    v: forged.v, senderDhPk: bob.pk, senderSignPk: mallory.signPk, recipientDhPk: alice.pk,
    dh: unb64(forged.header.dh), pqPk: unb64(forged.header.pq_pk),
    pqCt: forged.header.pq_ct ? unb64(forged.header.pq_ct) : new Uint8Array(0),
    pn: forged.header.pn, n: forged.header.n,
    first: forged.header.first === true,
    nonce: unb64(forged.nonce), ciphertext: unb64(forged.ciphertext),
  })));
  let forgedRejected = false, forgedState = true;
  const beforeForged = freeze(A2);
  try { A2.decrypt(forged); } catch { forgedRejected = true; }
  if (freeze(A2) !== beforeForged) forgedState = false;
  assert('bootstrap forgery (foreign signing key) rejected', forgedRejected);
  assert('bootstrap forgery left the session unchanged', forgedState);

  // Non-first envelope signed by the genuine peer, arriving before any first
  // message: refused at the null-chain guard (no key derived from KDF_CK(null)).
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const evil = utf8('forged');
  const padded = new Uint8Array(256);
  padded[0] = (evil.length >>> 24) & 0xff; padded[1] = (evil.length >>> 16) & 0xff;
  padded[2] = (evil.length >>> 8) & 0xff;  padded[3] = evil.length & 0xff;
  padded.set(evil, 4);
  const ct = sodium.crypto_secretbox_easy(padded, nonce, sodium.crypto_generichash(32, new Uint8Array([2]), null));
  const nonFirst = {
    v: 6, senderDhPk: b64(bob.pk), senderSignPk: b64(bob.signPk),
    header: { dh: b64(bob.pk), pq_pk: b64(randBytes(1184)), pn: 0, n: 0 },
    nonce: b64(nonce), ciphertext: b64(ct), signature: '',
  };
  nonFirst.signature = b64(bob.sign(signingPayload({
    v: 6, senderDhPk: bob.pk, senderSignPk: bob.signPk, recipientDhPk: alice.pk,
    dh: bob.pk, pqPk: unb64(nonFirst.header.pq_pk), pqCt: new Uint8Array(0),
    pn: 0, n: 0, nonce, ciphertext: ct,
  })));
  let nullRejected = false, nullState = true;
  const beforeNull = freeze(A2);
  try { A2.decrypt(nonFirst); } catch { nullRejected = true; }
  if (freeze(A2) !== beforeNull) nullState = false;
  assert('non-first envelope to a fresh session rejected (null-chain guard)', nullRejected);
  assert('null-chain rejection left the session unchanged', nullState);

  let genuineOk = false;
  try { genuineOk = A2.decrypt(realFirst) === 'real first reply'; } catch { genuineOk = false; }
  assert('genuine first reply still accepted after bootstrap fuzz', genuineOk);
  assert('pin established from the verified bundle', A2.peerSignPk !== null);

  console.log(`\n${failures === 0 ? 'ALL FUZZ ASSERTIONS PASSED' : `${failures} FUZZ ASSERTION(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
