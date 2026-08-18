import { init, Identity, Session, signingPayload, encodeBundle, RECEIPT, isReceipt } from './crypto.js';

const _utf8 = (s) => new TextEncoder().encode(s);

let failures = 0;
function assert(label, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}`);
  if (!condition) failures++;
}

async function main() {
  const sodium = await init();

  console.log('=== Protocol v6: Post-Quantum Hybrid Double Ratchet ===\n');
  console.log('  Confidentiality : X25519 + ML-KEM-768 (FIPS 203)');
  console.log('  Authentication  : ML-DSA-65 (FIPS 204)');
  console.log('  Symmetric AEAD  : XSalsa20-Poly1305');
  console.log('  Bootstrap       : signed prekey bundles — no initiator role\n');

  const alice = new Identity();
  const bob = new Identity();
  const attacker = new Identity();

  const pk = (id) => '...' + sodium.to_base64(id.pk, sodium.base64_variants.ORIGINAL).slice(8, 32);
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  console.log('Alice X25519 public key :', pk(alice));
  console.log('Bob   X25519 public key :', pk(bob));
  console.log('Alice ML-DSA public key :', alice.signPk.length, 'bytes');
  console.log('Alice shareable bundle  :', encodeBundle(alice.makeBundle()).length, 'b64 chars');

  // Sessions are established from the peer's verified prekey bundle. Either
  // side may send the first message — there is no initiator/responder role.
  const aliceSession = new Session(alice, bob.makeBundle());
  const bobSession = new Session(bob, alice.makeBundle());

  // ---- Alice -> Bob (first message, post-quantum bootstrap) ----
  const secret1 = 'Hello Bob! This is message 1.';
  console.log('\n[Alice -> server] plaintext 1:', secret1);

  const envelope1 = aliceSession.encrypt(_utf8(secret1));

  console.log('[server sees]    header dh    :', envelope1.header.dh.slice(0, 16) + '...');
  console.log('[server sees]    header pq_pk :', envelope1.header.pq_pk.slice(0, 16) + `... (${envelope1.header.pq_pk.length} b64 chars)`);
  console.log('[server sees]    header pq_ct :', envelope1.header.pq_ct ? envelope1.header.pq_ct.slice(0, 16) + '...' : 'NONE');
  console.log('[server sees]    first msg    :', envelope1.header.first ? 'YES (carries Alice prekey bundle)' : 'no');
  console.log('[server sees]    ciphertext   :', envelope1.ciphertext.slice(0, 40) + '...');
  console.log('[server sees]    plaintext?   :', envelope1.plaintext ?? 'NONE (server cannot read it)');
  console.log('[server sees]    envelope size:', JSON.stringify(envelope1).length, 'bytes');

  const recovered1 = bobSession.decrypt(envelope1);
  console.log('\n[Bob decrypts]   plaintext 1:', recovered1);

  // ---- Symmetric ratchet ----
  console.log('\n=== Symmetric Ratchet (Forward Secrecy) ===');
  const secret2 = 'This is message 2. It uses a new message key!';
  console.log('[Alice -> server] plaintext 2:', secret2);
  const envelope2 = aliceSession.encrypt(_utf8(secret2));
  const recovered2 = bobSession.decrypt(envelope2);
  console.log('[Bob decrypts]   plaintext 2:', recovered2);

  // ---- Asymmetric ratchet ----
  console.log('\n=== Asymmetric Ratchet (Post-Compromise Security) ===');
  const secret3 = 'Hi Alice! My reply triggers a DH + ML-KEM ratchet step.';
  console.log('[Bob -> server]   plaintext 3:', secret3);
  const envelope3 = bobSession.encrypt(_utf8(secret3));
  console.log('[server sees]     header pq_ct :', envelope3.header.pq_ct ? 'PRESENT (ML-KEM active)' : 'NONE');
  const recovered3 = aliceSession.decrypt(envelope3);
  console.log('[Alice decrypts]  plaintext 3:', recovered3);

  // ---- Out-of-order delivery ----
  // The first message of the epoch establishes it (and always carries pq_pk);
  // the rest of the burst omits it. Delivering third-then-second exercises the
  // skipped-key path (MKSKIP) within the epoch.
  console.log('\n=== Out-of-order delivery ===');
  bobSession.decrypt(aliceSession.encrypt(_utf8('out-of-order base')));
  const ooo1 = aliceSession.encrypt(_utf8('out-of-order A'));
  const ooo2 = aliceSession.encrypt(_utf8('out-of-order B'));
  const gotB = bobSession.decrypt(ooo2);
  const gotA = bobSession.decrypt(ooo1);
  console.log(`[Bob decrypts]   third-then-second: "${gotB}" / "${gotA}"`);

  // ---- Security assertions ----
  console.log('\n=== Security assertions ===');

  assert('message 1 round-trips', recovered1 === secret1);
  assert('message 2 round-trips', recovered2 === secret2);
  assert('reply round-trips after ratchet', recovered3 === secret3);
  assert('out-of-order messages recovered', gotA === 'out-of-order A' && gotB === 'out-of-order B');

  // A third party who establishes a session from the public bundle still
  // cannot decrypt messages addressed to the real peer.
  let attackerBlocked = false;
  try {
    const attackerSession = new Session(attacker, alice.makeBundle());
    attackerSession.decrypt(envelope1);
  } catch { attackerBlocked = true; }
  assert('attacker cannot decrypt', attackerBlocked);

  // Ciphertext tampering.
  const tampered = JSON.parse(JSON.stringify(envelope1));
  tampered.ciphertext = tampered.ciphertext.endsWith('AA')
    ? tampered.ciphertext.slice(0, -2) + 'BB'
    : tampered.ciphertext.slice(0, -1) + 'A';
  let tamperBlocked = false;
  try { bobSession.decrypt(tampered); } catch { tamperBlocked = true; }
  assert('tampered ciphertext rejected', tamperBlocked);

  // Header tampering — the header is inside the signed payload, so mutating a
  // counter on a validly-signed envelope must fail signature verification
  // rather than driving the receiver into unbounded key derivation.
  const headerTampered = JSON.parse(JSON.stringify(envelope2));
  headerTampered.header.n = 200000;
  let headerBlocked = false;
  let headerErr = '';
  try { bobSession.decrypt(headerTampered); } catch (e) { headerBlocked = true; headerErr = e.message; }
  assert('tampered header rejected (signature covers header)', headerBlocked);
  console.log('       ->', headerErr);

  // MAX_SKIP — a peer that legitimately signs an absurd counter is still bounded.
  // Re-sign the mutated header so the signature check passes and we exercise
  // the MAX_SKIP guard specifically, against an ESTABLISHED victim (a fresh
  // session rejects a non-first envelope before any key skipping can happen).
  {
    const a3 = new Identity(), b3 = new Identity();
    const A3 = new Session(a3, b3.makeBundle());
    const B3 = new Session(b3, a3.makeBundle());
    B3.decrypt(A3.encrypt(_utf8('hello')));       // establish the victim
    const gap = A3.encrypt(_utf8('huge gap'));
    gap.header.n = 500000;
    let skipBounded = false;
    let skipErr = '';
    const t0 = Date.now();
    try {
      B3.decrypt(resignEnvelope(A3, gap, b3.pk, sodium));
    } catch (e) { skipBounded = true; skipErr = e.message; }
    assert('MAX_SKIP bounds skipped-key derivation', skipBounded);
    console.log(`       -> ${skipErr} (rejected in ${Date.now() - t0}ms)`);
  }

  // ---- State-integrity regressions ----
  // A failed decryption must leave the session exactly as it was. Without that,
  // any envelope that reaches a receiver is a permanent kill switch.
  console.log('\n=== State integrity under replay and forgery ===');

  {
    // Replay of an envelope from an epoch we already ratcheted past.
    const a2 = new Identity(), b2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());
    const old = A.encrypt(_utf8('epoch 0'));
    B.decrypt(old);
    A.decrypt(B.encrypt(_utf8('reply -> new epoch')));
    B.decrypt(A.encrypt(_utf8('epoch 1')));

    let rejected = false;
    try { B.decrypt(old); } catch { rejected = true; }
    let survives = false;
    try { survives = B.decrypt(A.encrypt(_utf8('still alive'))) === 'still alive'; } catch { survives = false; }
    assert('stale-epoch replay rejected without destroying the session', rejected && survives);
  }

  {
    // Redelivery of a message already consumed in the current chain.
    const a2 = new Identity(), b2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());
    const m0 = A.encrypt(_utf8('m0'));
    const m1 = A.encrypt(_utf8('m1'));
    B.decrypt(m0);
    let rejected = false;
    try { B.decrypt(m0); } catch { rejected = true; }
    let nextOk = false;
    try { nextOk = B.decrypt(m1) === 'm1'; } catch { nextOk = false; }
    assert('duplicate delivery does not desync the receive chain', rejected && nextOk);
  }

  {
    // An envelope signed by a key that holds no session secrets must not
    // advance the ratchet or change the pinned peer key.
    const a2 = new Identity(), b2 = new Identity(), m2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());

    const inner = new Session(m2, b2.makeBundle()).encrypt(_utf8('unopenable'));
    const forged = { ...inner, senderDhPk: sodium.to_base64(a2.pk, sodium.base64_variants.ORIGINAL), senderSignPk: sodium.to_base64(m2.signPk, sodium.base64_variants.ORIGINAL) };
    forged.signature = sodium.to_base64(m2.sign(signingPayload({
      v: forged.v,
      senderDhPk: a2.pk,
      senderSignPk: m2.signPk,
      recipientDhPk: b2.pk,
      dh: sodium.from_base64(forged.header.dh, sodium.base64_variants.ORIGINAL),
      pqPk: sodium.from_base64(forged.header.pq_pk, sodium.base64_variants.ORIGINAL),
      pqCt: forged.header.pq_ct ? sodium.from_base64(forged.header.pq_ct, sodium.base64_variants.ORIGINAL) : new Uint8Array(0),
      pn: forged.header.pn,
      n: forged.header.n,
      first: forged.header.first === true,
      nonce: sodium.from_base64(forged.nonce, sodium.base64_variants.ORIGINAL),
      ciphertext: sodium.from_base64(forged.ciphertext, sodium.base64_variants.ORIGINAL),
    })), sodium.base64_variants.ORIGINAL);

    let rejected = false;
    try { B.decrypt(forged); } catch { rejected = true; }
    let genuineOk = false;
    try { genuineOk = B.decrypt(A.encrypt(_utf8('really Alice'))) === 'really Alice'; } catch { genuineOk = false; }
    assert('forged-signer envelope cannot poison the ratchet', rejected && genuineOk);
  }

  {
    // Property test for the invariant the rollback rests on: after ANY failed
    // decryption, session state must be byte-identical. This catches an
    // incomplete _snapshot() — including a field added later and forgotten —
    // in a way that eyeballing the field list does not.
    const a2 = new Identity(), b2 = new Identity(), m2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());

    // Put the session into a non-trivial state first. The epoch's first
    // message is delivered before the burst so the burst's omitted pq_pk
    // reconstructs from the epoch cache.
    B.decrypt(A.encrypt(_utf8('one')));
    A.decrypt(B.encrypt(_utf8('two')));
    B.decrypt(A.encrypt(_utf8('epoch start')));
    const skipped = A.encrypt(_utf8('will arrive late'));
    const good = A.encrypt(_utf8('valid'));
    const corrupt = (env, mutate) => { const c = JSON.parse(JSON.stringify(env)); mutate(c); return c; };

    const attacks = [
      ['truncated ciphertext', corrupt(good, (e) => { e.ciphertext = e.ciphertext.slice(0, -4) + 'AAAA'; })],
      ['bumped counter', corrupt(good, (e) => { e.header.n += 5; })],
      ['huge counter', corrupt(good, (e) => { e.header.n = 999999; })],
      ['swapped ratchet key', corrupt(good, (e) => { e.header.dh = sodium.to_base64(m2.pk, sodium.base64_variants.ORIGINAL); })],
      ['foreign signer', corrupt(good, (e) => { e.senderSignPk = sodium.to_base64(m2.signPk, sodium.base64_variants.ORIGINAL); })],
      ['wrong version', corrupt(good, (e) => { e.v = 3; })],
      ['missing header', corrupt(good, (e) => { delete e.header; })],
      ['negative counter', corrupt(good, (e) => { e.header.n = -1; })],
      ['garbage nonce', corrupt(good, (e) => { e.nonce = 'AAAA'; })],
      ['envelope from another session', new Session(m2, b2.makeBundle()).encrypt(_utf8('not yours'))],
    ];

    const freeze = (s) => JSON.stringify({
      RK: [...s.RK], DHs: [...s.DHs.pk], DHr: s.DHr ? [...s.DHr] : null,
      PQs: [...s.PQs.publicKey], PQr: s.PQr_pk ? [...s.PQr_pk] : null,
      nextPqCt: [...s.nextPqCt],
      CKs: s.CKs ? [...s.CKs] : null, CKr: s.CKr ? [...s.CKr] : null,
      Ns: s.Ns, Nr: s.Nr, PN: s.PN,
      MKSKIP: [...s.MKSKIP.entries()].map(([k, v]) => [k, [...v]]),
      epochs: [...s.epochs.entries()].map(([k, v]) => [k, { pk: [...v.pk], ct: [...v.ct] }]).sort(),
      pin: s.peerSignPk ? [...s.peerSignPk] : null,
      firstSent: s._isFirstMessage,
    });

    let allStable = true;
    const drifted = [];
    for (const [name, env] of attacks) {
      const before = freeze(B);
      let threw = false;
      try { B.decrypt(env); } catch { threw = true; }
      const after = freeze(B);
      if (!threw || before !== after) { allStable = false; drifted.push(name); }
    }
    assert(`state unchanged after ${attacks.length} distinct failed decryptions`, allStable);
    if (drifted.length) console.log('       -> drifted on:', drifted.join(', '));

    // And the session must still work afterwards, including the delayed message.
    let stillLive = false;
    try {
      stillLive = B.decrypt(good) === 'valid' && B.decrypt(skipped) === 'will arrive late';
    } catch (e) { stillLive = false; }
    assert('session still delivers real messages after all that', stillLive);
  }

  {
    // Bootstrap forgery (v5). The peer signing key is pinned from the VERIFIED
    // prekey bundle at session creation, so there is no pre-reply window to
    // poison: an attacker who knows only public values cannot pass the peer
    // check, and no message key is ever derived from a null receiving chain.
    const a2 = new Identity(), b2 = new Identity(), m2 = new Identity();
    const A = new Session(a2, b2.makeBundle());      // awaiting Bob's first message
    const realB = new Session(b2, a2.makeBundle());

    // Mallory forges "from Bob" using only public values: her own bundle and
    // ephemeral, an ML-KEM encapsulation to Alice's public prekey — signed by
    // her own key, claiming to be Bob.
    const forged = new Session(m2, a2.makeBundle()).encrypt(_utf8('MALLORY: wire the money to account 12345'));
    forged.senderDhPk = b64(b2.pk);
    forged.senderSignPk = b64(m2.signPk);
    forged.signature = b64(m2.sign(signingPayload({
      v: forged.v,
      senderDhPk: b2.pk,
      senderSignPk: m2.signPk,
      recipientDhPk: a2.pk,
      dh: sodium.from_base64(forged.header.dh, sodium.base64_variants.ORIGINAL),
      pqPk: sodium.from_base64(forged.header.pq_pk, sodium.base64_variants.ORIGINAL),
      pqCt: forged.header.pq_ct ? sodium.from_base64(forged.header.pq_ct, sodium.base64_variants.ORIGINAL) : new Uint8Array(0),
      pn: forged.header.pn,
      n: forged.header.n,
      first: forged.header.first === true,
      nonce: sodium.from_base64(forged.nonce, sodium.base64_variants.ORIGINAL),
      ciphertext: sodium.from_base64(forged.ciphertext, sodium.base64_variants.ORIGINAL),
    })));

    let forgedRejected = false;
    try { A.decrypt(forged); } catch { forgedRejected = true; }
    assert('bootstrap forgery rejected (peer signing key pinned from bundle)', forgedRejected);

    // A non-first envelope to a fresh session is refused outright: no key is
    // ever derived from a null receiving chain (KDF_CK(null) is a public
    // constant — the v4 pre-reply forgery). Signed by the genuine Bob so it
    // passes the peer checks and reaches the guard.
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const evil = _utf8('no chain here');
    const nullMk = sodium.crypto_generichash(32, new Uint8Array([2]), null);
    const ct = sodium.crypto_secretbox_easy(padForTest(evil), nonce, nullMk);
    const nonFirst = {
      v: 6, senderDhPk: b64(b2.pk), senderSignPk: b64(b2.signPk),
      header: { dh: b64(b2.pk), pq_pk: b64(sodium.randombytes_buf(1184)), pn: 0, n: 0 },
      nonce: b64(nonce), ciphertext: b64(ct), signature: '',
    };
    nonFirst.signature = b64(b2.sign(signingPayload({
      v: 6, senderDhPk: b2.pk, senderSignPk: b2.signPk, recipientDhPk: a2.pk,
      dh: b2.pk, pqPk: sodium.from_base64(nonFirst.header.pq_pk, sodium.base64_variants.ORIGINAL),
      pqCt: new Uint8Array(0), pn: 0, n: 0, nonce, ciphertext: ct,
    })));
    let nullChainRejected = false;
    try { A.decrypt(nonFirst); } catch { nullChainRejected = true; }
    assert('non-first envelope to a fresh session rejected (null-chain guard)', nullChainRejected);

    let realOk = false;
    try { realOk = A.decrypt(realB.encrypt(_utf8('really Bob'))) === 'really Bob'; } catch { realOk = false; }
    assert('genuine Bob first message still accepted after the forgery', realOk);
  }

  {
    // Session persistence round-trip: serialize -> restore -> serialize must be
    // identical, and the restored session must keep working with the peer.
    const a2 = new Identity(), b2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());
    B.decrypt(A.encrypt(_utf8('one')));
    A.decrypt(B.encrypt(_utf8('two')));
    B.decrypt(A.encrypt(_utf8('epoch start'))); // establishes the new epoch
    const late = A.encrypt(_utf8('late'));      // will be skipped, then consumed
    const three = A.encrypt(_utf8('three'));
    B.decrypt(three);
    B.decrypt(late);

    const ser = A.serialize();
    const snapshotA = JSON.stringify(ser);
    const A2 = Session.restore(a2, ser);
    assert('serialize -> restore -> serialize is identical', JSON.stringify(A2.serialize()) === snapshotA);

    let restoredOk = false;
    try {
      restoredOk = B.decrypt(A2.encrypt(_utf8('after restore'))) === 'after restore'
        && A2.decrypt(B.encrypt(_utf8('back'))) === 'back';
    } catch { restoredOk = false; }
    assert('restored session still encrypts/decrypts with the peer', restoredOk);
  }

  {
    // Bootstrap crash recovery (README Limitation 6, now closed): a sender
    // that crashes after its first message was persisted must NOT re-flag the
    // next message as `first` — an established receiver rejects duplicate
    // firsts and the conversation would stall. The one-shot `firstBuilt` flag
    // (persisted in serialize(), restored in restore()) closes this edge.
    const a2 = new Identity(), b2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());
    B.decrypt(A.encrypt(_utf8('first before crash')));   // B establishes the session
    const persisted = A.serialize();                      // A persists after the send
    const A2 = Session.restore(a2, JSON.parse(JSON.stringify(persisted)));

    const next = A2.encrypt(_utf8('after crash'));
    const notRefirst = next.header.first !== true && next.header.bundle === undefined;
    let continues = false;
    try { continues = B.decrypt(next) === 'after crash'; } catch { continues = false; }
    assert('restored sender does not re-flag its next message as first', notRefirst);
    assert('conversation continues after the sender crash (no re-flag stall)', continues);
  }

  {
    // Delivery receipt: the receiver auto-acks the first message it
    // establishes from, so the sender's receiving chain is established even
    // without a hand-typed reply. This is what lets a crashed sender recover:
    // the receipt is queued at the relay and decrypts on reconnect.
    const a2 = new Identity(), b2 = new Identity();
    const A = new Session(a2, b2.makeBundle()), B = new Session(b2, a2.makeBundle());
    B.decrypt(A.encrypt(_utf8('first message')));        // B establishes
    const receipt = B.encrypt(_utf8(RECEIPT));            // B's automatic receipt
    let receiptDecrypts = false, chainEstablished = false;
    try {
      const plaintext = A.decrypt(receipt);
      receiptDecrypts = isReceipt(plaintext);
      chainEstablished = A.CKr !== null;
    } catch { /* leave false */ }
    assert('delivery receipt round-trips encrypted', receiptDecrypts);
    assert('delivery receipt establishes the sender receiving chain', chainEstablished);
  }

  console.log(`\n${failures === 0 ? 'All assertions passed.' : `${failures} ASSERTION(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

/** Pad a plaintext exactly like crypto-core's padMessage, for forged envelopes. */
function padForTest(buf, blockSize = 256) {
  const totalLen = 4 + buf.length;
  const paddedLen = Math.ceil(totalLen / blockSize) * blockSize;
  const padded = new Uint8Array(paddedLen);
  padded[0] = (buf.length >>> 24) & 0xff;
  padded[1] = (buf.length >>> 16) & 0xff;
  padded[2] = (buf.length >>> 8) & 0xff;
  padded[3] = buf.length & 0xff;
  padded.set(buf, 4);
  return padded;
}

/**
 * Re-sign an envelope whose header was modified, so signature checks pass.
 * Omitted fields are reconstructed exactly as the receiver will: the signing
 * key from the session's identity, the KEM key and ciphertext from the
 * sender's current epoch (the envelope is same-epoch).
 */
function resignEnvelope(session, env, recipientDhPk, sodium) {
  const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const payload = signingPayload({
    v: env.v,
    senderDhPk: unb64(env.senderDhPk),
    senderSignPk: env.senderSignPk ? unb64(env.senderSignPk) : session.identity.signPk,
    recipientDhPk,
    dh: unb64(env.header.dh),
    pqPk: env.header.pq_pk ? unb64(env.header.pq_pk) : session.PQs.publicKey,
    pqCt: env.header.pq_ct ? unb64(env.header.pq_ct) : session.nextPqCt,
    pn: env.header.pn,
    n: env.header.n,
    first: env.header.first === true,
    nonce: unb64(env.nonce),
    ciphertext: unb64(env.ciphertext),
  });
  return { ...env, signature: b64(session.identity.sign(payload)) };
}

main().catch((e) => { console.error(e); process.exit(1); });
