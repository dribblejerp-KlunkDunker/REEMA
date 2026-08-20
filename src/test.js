import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, Session, loadPQ } from './crypto.js';
import { GroupSession, useSodium } from '../public/group-core.js';
import { generateVaultIdentity, exportVault, importVault } from './vault.js';
import { stripControls, shortKey, normalizeConfusables, sanitizedLogger } from './sanitize.js';

/**
 * Integration test: full E2EE messaging through the REAL relay (protocol v6).
 *
 * Spawns `src/server.js` as a child process — the same relay the dashboard,
 * messenger, and CLI talk to — so the test can never drift from production.
 * Connects Alice and Bob over the relay's TCP line protocol, and verifies:
 *   - the relay only ever sees ciphertext (its own logs never emit plaintext)
 *   - the key directory serves a bundle + one one-time prekey, consumed
 *     server-side on fetch and burned client-side on first receive
 *   - messages round-trip in both directions across a ratchet step
 *   - a third party cannot decrypt a relayed envelope
 *   - queued (offline) delivery works by derived routing address
 *   - the relay survives malformed envelope field types (single-packet crash
 *     regression: non-string senderSignPk/pq_pk/pq_ct must reject, not kill)
 *   - the relay sanitizes control characters in logged keys/addresses, so a
 *     crafted toPk cannot inject terminal escape sequences into its console
 *   - the relay also NORMALIZES homoglyph confusables (Cyrillic/Greek
 *     lookalikes) in logged keys/addresses, so a crafted routing key cannot
 *     spoof a known address in the operator console
 *   - the shared stripControls() strips control bytes from peer message
 *     plaintext in the CLI client, so decrypted text cannot inject escapes
 */

const RELAY_PORT = Number(process.env.TEST_RELAY_PORT || 7999);
const WS_PORT = Number(process.env.TEST_WS_PORT || 8089);

let failures = 0;
function assert(label, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}`);
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

/** Minimal newline-delimited TCP client (the relay's line protocol). */
function connectTcp(port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const socket = connect(port, host);
    socket.setEncoding('utf8');
    let buffer = '';
    const handlers = {};
    socket.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line) {
          const msg = JSON.parse(line);
          if (handlers[msg.type]) handlers[msg.type](msg);
        }
      }
    });
    socket.once('connect', () => resolve({
      socket,
      send: (obj) => socket.write(JSON.stringify(obj) + '\n'),
      once: (t) => new Promise((res) => { handlers[t] = (m) => { delete handlers[t]; res(m); }; }),
    }));
    socket.once('error', reject);
  });
}

function withTimeout(label, p, ms = 30000) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${label}`)), ms)),
  ]);
}

async function main() {
  const sodium = await init();
  await loadPQ(); // the whole suite does keygen + session work immediately
  useSodium(sodium);
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const addr = (id) => b64(Identity.deriveAddress(id.signPk, id.pk));
  const otksOf = (id) => [...id.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));

  console.log('=== Integration Test: E2EE messaging through relay (protocol v6) ===\n');

  // ---- Terminal sanitization (VULN-005/006): stripControls() must remove
  // every C0/DEL/C1 byte so attacker-controlled plaintext (or a crafted toPk)
  // cannot fire ANSI/OSC terminal escape sequences. Deterministic unit
  // regression; the relay sink is additionally covered end-to-end below.
  {
    console.log('=== Terminal sanitization (VULN-005/006) ===');
    const malicious =
      '\x1b[2J' +                             // ANSI clear-screen
      '\x1b]8;;https://evil.example\x1b\\' +   // OSC-8 hyperlink
      '\x1b]0;pwned\x07' +                     // OSC title + BEL
      'Hello\x1b[31m' + 'red' + '\x1b[0m' + ' world' + '\x7f';
    const clean = stripControls(malicious);
    assert('strips every C0/C1/DEL control byte', !/[\u0000-\u001f\u007f-\u009f]/.test(clean));
    assert('removes the ESC introducer so no ANSI/OSC sequence can fire', !clean.includes('\x1b'));
    assert('keeps printable payload text intact', clean.includes('Hello') && clean.includes('red') && clean.includes('world'));
    assert('passes clean text through unchanged', stripControls('plain text') === 'plain text');
    assert('leaves non-strings alone', stripControls(undefined) === undefined && stripControls(123) === 123);
    // The relay echoes `unknown type: ${msg.type}` back over the wire and the
    // client prints msg.error raw, so the echo must also be control-free.
    assert('sanitizes the relay unknown-type echo shape',
      !/[\u0000-\u001f\u007f-\u009f]/.test(stripControls(`unknown type: ${malicious}`)));
    console.log(`[test] sanitized: ${JSON.stringify(clean)}`);
  }

  // ---- Trojan-Source bidi/format controls: stripControls() must also remove
  // Unicode format characters (\p{Cf}) — bidi overrides/isolates and
  // directional marks — so a crafted string cannot reorder or hide the text
  // the operator actually sees (a log line that renders backwards, or a URL
  // whose visible text points elsewhere than its real target).
  {
    console.log('=== Trojan-Source bidi/format sanitization ===');
    const bidiControls =
      '\u202a\u202b\u202c\u202d\u202e' +      // LRE/RLE/PDF/LRO/RLO
      '\u2066\u2067\u2068\u2069' +            // LRI/RLI/FSI/PDI isolates
      '\u061c' +                               // Arabic letter mark
      '\u200e\u200f' +                         // LRM/RLM directional marks
      '\u200b\u200c\u200d\ufeff' +           // ZWSP/ZWNJ/ZWJ/ZWNBSP
      '\u2060\u00ad';                          // word joiner, soft hyphen
    // Classic Trojan-Source shape: the log line's bytes read "file is safe",
    // but with an RLO the trailing text renders FIRST and in reverse.
    const spoofed = `file \u202e is safe \u2066 \u202e rm -rf / \u2069`;
    const clean = stripControls(spoofed);
    assert('strips every Unicode format control (\p{Cf})', !/[\p{Cf}]/u.test(clean));
    assert('strips the RLO override (U+202E)', !clean.includes('\u202e'));
    assert('strips the bidi isolates (U+2066-2069)', !/[\u2066-\u2069]/.test(clean));
    assert('strips every bidi/format control byte from the payload', ![...bidiControls].some((c) => clean.includes(c)));
    assert('keeps the surrounding printable text', clean.includes('file') && clean.includes('safe') && clean.includes('rm -rf /'));
    assert('passes clean text through unchanged', stripControls('plain text') === 'plain text');
    assert('leaves non-strings alone', stripControls(null) === null && stripControls(42) === 42);
    console.log(`[test] bidi-sanitized: ${JSON.stringify(clean)}`);
  }

  // ---- shortKey(): the CLI client displays wire-controlled values (an
  // envelope's senderDhPk, which the relay only validates as a non-empty
  // string) via `from ${shortKey(...)}`. Sanitization must happen BEFORE the
  // 16-char slice, or a raw escape prefix would survive the truncation.
  {
    const evilPrefix = '\x1b[2J' + '\x1b]8;;evil\x1b\\' + 'A'.repeat(20);
    const rendered = shortKey(evilPrefix);
    assert('shortKey strips controls BEFORE slicing (raw escape prefix cannot survive)',
      !/[\u0000-\u001f\u007f-\u009f\p{Cf}]/u.test(rendered));
    assert('shortKey strips bidi controls', !shortKey('\u202e' + 'B'.repeat(20)).includes('\u202e'));
    assert('shortKey caps at 16 chars with ellipsis', shortKey('C'.repeat(30)) === 'C'.repeat(16) + '...');
    assert('shortKey returns <invalid> for non-strings',
      shortKey(null) === '<invalid>' && shortKey(42) === '<invalid>' && shortKey(undefined) === '<invalid>');
    assert('shortKey keeps printable payload text', rendered.includes('A'));
  }

  // ---- Homoglyph confusable normalization (VULN-005 extension): a routing
  // key written with Cyrillic/Greek lookalikes (U+0430 'а' for 'a', U+03BF
  // 'ο' for 'o') renders identically to the genuine ASCII address in the
  // operator console, so an attacker could spoof "message from <known
  // address>" or a group id. normalizeConfusables() maps lookalikes to their
  // ASCII bases from the full Unicode confusables dataset; shortKey() applies
  // it BEFORE slicing. (The end-to-end relay sink is covered below.)
  {
    console.log('=== Homoglyph confusable normalization ===');
    // а->a р->p е->e с->c  (Cyrillic lookalikes)
    assert('maps Cyrillic lookalikes to ASCII bases', normalizeConfusables('арес') === 'apec');
    // ν->v ο->o  (Greek lookalikes)
    assert('maps Greek lookalikes to ASCII bases', normalizeConfusables('νο') === 'vo');
    // U+212A KELVIN SIGN -> K, U+212B ANGSTROM SIGN -> A (letterlike forms)
    assert('maps letterlike forms to ASCII bases', normalizeConfusables('K') === 'K' && normalizeConfusables('Å') === 'A');
    // U+24FE NEGATIVE CIRCLED NUMBER TEN -> '10' (multi-char base)
    assert('expands multi-char bases', normalizeConfusables('⓾') === '10');
    // The dataset's ASCII keys ('|' -> 'l', '1' -> '1', ' ' -> ' ') are
    // filtered: a pipe is not a homoglyph attack and must never be rewritten.
    assert('leaves ASCII untouched (pipe is not a homoglyph)',
      normalizeConfusables('plain | text 123') === 'plain | text 123');
    assert('leaves non-strings alone', normalizeConfusables(undefined) === undefined && normalizeConfusables(42) === 42);
    const spoof = 'а'.repeat(30);
    assert('shortKey normalizes a Cyrillic-lookalike key to ASCII',
      shortKey(spoof) === 'a'.repeat(16) + '...');
    assert('shortKey output is pure ASCII for lookalike input', !/[^\x00-\x7f]/.test(shortKey(spoof)));
    assert('shortKey keeps genuine ASCII keys byte-for-byte',
      shortKey('A'.repeat(20)) === 'A'.repeat(16) + '...');
    console.log(`[test] normalized: ${JSON.stringify(normalizeConfusables('арес νο'))}`);
  }

  // ---- Sink-level sanitized logger (--sanitize-log / RELAY_SANITIZE_LOG):
  // the relay can route EVERY line it writes through stripControls() —
  // defense-in-depth so a future call site that forgets the per-field
  // short()/stripControls() discipline still cannot emit a control
  // character. The main relay spawn below runs with the mode on, so the
  // suite's end-to-end "relay log is control-free" assertions double as the
  // integration proof.
  {
    console.log('=== Sink-level sanitized logger (--sanitize-log) ===');
    const captured = [];
    const fake = {
      log: (...a) => captured.push(['log', ...a]),
      error: (...a) => captured.push(['error', ...a]),
      warn: (...a) => captured.push(['warn', ...a]),
    };
    const safe = sanitizedLogger(fake);
    safe.log('[server] raw ' + '\x1b[2J' + ' value');
    safe.error('bad arg:', '\x1b]8;;https://evil.example\x1b\\' + 'payload');
    safe.warn('\u202e' + 'spoofed');
    safe.log('count:', 42, null);
    assert('strips controls from every logger line',
      !captured.flat().some((v) => typeof v === 'string' && /[\u0000-\u001f\u007f-\u009f\p{Cf}]/u.test(v)));
    assert('keeps the printable log text', captured[0][1].includes('raw') && captured[0][1].includes('value'));
    assert('covers log, error, and warn sinks',
      captured[0][0] === 'log' && captured[1][0] === 'error' && captured[2][0] === 'warn');
    assert('leaves non-string args untouched', captured[3][1] === 'count:' && captured[3][2] === 42 && captured[3][3] === null);
    console.log('[test] sanitized logger: ' + captured.map((c) => c.join(' ')).join(' | '));
  }

  // ---- Vault-at-rest (age format) round-trips ----
  {
    const { identity, recipient } = await generateVaultIdentity();
    const secret = 'BLACKVAULT vault payload — age format';
    const armored = await exportVault(secret, { recipient });
    assert('vault export is PEM-armored age', armored.startsWith('-----BEGIN AGE ENCRYPTED FILE-----'));
    assert('vault export/import round-trips through the age format',
      await importVault(armored, { identities: [identity], asText: true }) === secret);
    const pwArmored = await exportVault(secret, { passphrase: 'vault-passphrase-test' });
    assert('vault passphrase export/import round-trips',
      await importVault(pwArmored, { passphrase: 'vault-passphrase-test', asText: true }) === secret);
    let wrongPwRejected = false;
    try { await importVault(pwArmored, { passphrase: 'wrong', asText: true }); } catch { wrongPwRejected = true; }
    assert('vault rejects a wrong passphrase', wrongPwRejected);
    assert('vault raw-binary decrypt accepts a Buffer',
      Buffer.from(await importVault(await exportVault(secret, { recipient, armor: false }), { identities: [identity] })).toString('utf8') === secret);

    // Post-quantum hybrid recipient (X25519 + ML-KEM-768 at rest): the file
    // must be wrapped in an mlkem768x25519 stanza and decrypt with the PQ
    // identity — the classical path above is unaffected.
    const hy = await generateVaultIdentity({ hybrid: true });
    assert('hybrid identity uses the PQ prefix', hy.identity.startsWith('AGE-SECRET-KEY-PQ-1'));
    assert('hybrid recipient uses the age1pq prefix', hy.recipient.startsWith('age1pq1'));
    const hyArmored = await exportVault(secret, { recipient: hy.recipient });
    // The stanza tag is an ASCII string in the RAW age format; the armored form
    // re-encodes it as base64, so assert on the raw bytes.
    const hyRaw = await exportVault(secret, { recipient: hy.recipient, armor: false });
    assert('hybrid export wraps the file key in an mlkem768x25519 stanza',
      Buffer.from(hyRaw).includes(Buffer.from('mlkem768x25519')));
    assert('hybrid vault round-trips (PQ at rest)',
      await importVault(hyArmored, { identities: [hy.identity], asText: true }) === secret);
    let pqRejected = false;
    try { await importVault(hyArmored, { identities: [identity], asText: true }); } catch { pqRejected = true; }
    assert('a classical identity cannot open a hybrid vault', pqRejected);
  }


  // Spawn the real relay; capture its output so we can prove it never leaks
  // plaintext (it only logs addresses and ciphertext-forwarding events).
  const relay = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(RELAY_PORT), WS_PORT: String(WS_PORT), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let relayOut = '';
  let relayErr = '';
  relay.stdout.on('data', (d) => { relayOut += d; });
  relay.stderr.on('data', (d) => { relayErr += d; });

  const clients = [];

  try {
    await waitForTcp(RELAY_PORT);
    console.log(`[test] real relay started on 127.0.0.1:${RELAY_PORT} (WS ${WS_PORT})`);

    const alice = new Identity();
    alice.newOneTimePrekeys(5);
    const bob = new Identity();
    bob.newOneTimePrekeys(5);
    const mallory = new Identity();
    const carol = new Identity();
    carol.newOneTimePrekeys(5);

    const aliceAddr = addr(alice);
    const bobAddr = addr(bob);
    const carolAddr = addr(carol);
    console.log(`[test] Alice address: ${aliceAddr.slice(0, 16)}...`);
    console.log(`[test] Bob   address: ${bobAddr.slice(0, 16)}...`);

    console.log('[test] connecting clients...');
    const aliceClient = await connectTcp(RELAY_PORT);
    const bobClient = await connectTcp(RELAY_PORT);
    clients.push(aliceClient, bobClient);
    console.log('[test] clients connected');

    const bobPublished = bobClient.once('published');
    // ---- Malformed-envelope crash regression (relay must survive) ----
    // A crafted `send` whose OPTIONAL envelope fields (senderSignPk / header.pq_pk /
    // header.pq_ct) are non-strings used to throw ERR_INVALID_ARG_TYPE inside
    // isPlausibleEnvelope, escape handleLine uncaught, and kill the whole relay
    // process — a single-packet remote DoS over TCP or WebSocket. Feed every
    // variant, then prove the relay still answers and still works below.
    const junkClient = await connectTcp(RELAY_PORT);
    clients.push(junkClient);
    const junkBase = {
      v: 6,
      senderDhPk: 'A'.repeat(43) + '=',
      header: { dh: 'A'.repeat(43) + '=', pn: 0, n: 0 },
      nonce: 'A'.repeat(32),
      ciphertext: 'QUJD',
      signature: 'R0lG',
    };
    const junkVariants = [
      ['senderSignPk:number', { ...junkBase, senderSignPk: 123 }],
      ['senderSignPk:null', { ...junkBase, senderSignPk: null }],
      ['senderSignPk:object', { ...junkBase, senderSignPk: {} }],
      ['senderSignPk:boolean', { ...junkBase, senderSignPk: true }],
      ['pq_pk:number', { ...junkBase, header: { ...junkBase.header, pq_pk: 123 } }],
      ['pq_ct:number', { ...junkBase, header: { ...junkBase.header, pq_ct: 123 } }],
      ['pq_ct:object', { ...junkBase, header: { ...junkBase.header, pq_ct: {} } }],
    ];
    for (const [label, envelope] of junkVariants) {
      junkClient.send({ type: 'send', toPk: 'A'.repeat(43) + '=', envelope });
    }
    const alivePong = junkClient.once('pong');
    junkClient.send({ type: 'ping' });
    await withTimeout('relay pong after malformed envelopes', alivePong, 15000);
    assert('relay survives malformed envelope field types (no crash)', true);
    console.log('[test] relay alive after ' + junkVariants.length + ' malformed envelopes');

    const alicePublished = aliceClient.once('published');
    console.log('[test] publishing (authenticated, proof-of-possession)...');
    aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice) });
    bobClient.send({ type: 'publish', address: bobAddr, bundle: bob.makeBundle(), oneTimePrekeys: otksOf(bob) });
    await withTimeout('publish', Promise.all([alicePublished, bobPublished]));
    console.log('[test] published');

    // ---- Alice resolves Bob from the key directory (bundle + one-time prekey) ----
    const bobDir = await (async () => {
      const p = aliceClient.once('directory');
      aliceClient.send({ type: 'fetch-directory', address: bobAddr });
      return withTimeout('bob directory', p);
    })();
    assert('directory returned Bob bundle + one one-time prekey', !!bobDir.bundle && !!bobDir.oneTimePrekey);
    const bobBundle = bobDir.bundle;
    const bobOtk = bobDir.oneTimePrekey;
    const bobPoolBefore = bob.oneTimePrekeys.size;
    assert('directory one-time prekey is signed by Bob', Identity.verifyOneTimePrekey(bob.signPk, bobOtk));

    // A second fetch must return a DIFFERENT prekey (consumed server-side).
    const bobDir2 = await (async () => {
      const p = aliceClient.once('directory');
      aliceClient.send({ type: 'fetch-directory', address: bobAddr });
      return withTimeout('bob directory (2nd fetch)', p);
    })();
    assert('directory never serves the same one-time prekey twice',
      !!bobDir2.oneTimePrekey && bobDir2.oneTimePrekey.id !== bobOtk.id);

    // ---- Alice -> Bob (first message, post-quantum + OTK bootstrap) ----
    const aliceSession = new Session(alice, bobBundle, bobOtk);
    const secret = 'Hello Bob — this traveled through the relay as ciphertext only.';
    console.log(`\n[test] Alice plaintext: "${secret}"`);

    const bobInbound = bobClient.once('message');
    aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(secret, 'utf8')), fromPk: aliceAddr });

    const received = await withTimeout('bob first message', bobInbound);
    const envelope = received.envelope;
    console.log(`[test] Bob received ciphertext: ${envelope.ciphertext.slice(0, 40)}...`);
    assert('first message carries the consumed one-time prekey id', envelope.header.otk_id === bobOtk.id);

    // Bob establishes from the first message's own bundle + his consumed OTK.
    const otk = bob.oneTimePrekeys.get(envelope.header.otk_id);
    assert('Bob still holds the OTK the sender used', !!otk);
    const bobSession = new Session(bob, alice.makeBundle(), { id: otk.id, sk: otk.sk, pk: otk.pk });
    bob.oneTimePrekeys.delete(otk.id);
    const decrypted = bobSession.decrypt(envelope);
    console.log(`[test] Bob decrypted: "${decrypted}"`);
    assert('Bob consumed the one-time prekey after first receive', bob.oneTimePrekeys.size === bobPoolBefore - 1);

    // ---- Bob -> Alice (exercises a full ratchet step over the wire) ----
    const reply = 'Got it Alice — replying through the same relay.';
    const aliceInbound = aliceClient.once('message');
    bobClient.send({ type: 'send', toPk: aliceAddr, envelope: bobSession.encrypt(Buffer.from(reply, 'utf8')), fromPk: bobAddr });

    const replyMsg = await withTimeout('alice reply', aliceInbound);
    const decryptedReply = aliceSession.decrypt(replyMsg.envelope);
    console.log(`[test] Alice decrypted reply: "${decryptedReply}"`);

    // ---- Mallory ----
    let malloryBlocked = false;
    try {
      new Session(mallory, alice.makeBundle()).decrypt(envelope);
    } catch { malloryBlocked = true; }

    // ---- Offline queueing (by derived address) ----
    const aliceToCarol = new Session(alice, carol.makeBundle());
    aliceClient.send({ type: 'send', toPk: carolAddr, envelope: aliceToCarol.encrypt(Buffer.from('queued while offline', 'utf8')), fromPk: aliceAddr });
    await new Promise((r) => setTimeout(r, 50));

    const carolClient = await connectTcp(RELAY_PORT);
    clients.push(carolClient);
    const carolInbound = carolClient.once('message');
    carolClient.send({ type: 'publish', address: carolAddr, bundle: carol.makeBundle(), oneTimePrekeys: otksOf(carol) });
    const carolMsg = await withTimeout('carol queued message', carolInbound);
    const carolPlain = new Session(carol, alice.makeBundle()).decrypt(carolMsg.envelope);
    console.log(`[test] Carol received queued message: "${carolPlain}"`);

    // ---- Group-mode (MLS) envelopes (prototype — ROADMAP §7) ----
    // The relay must carry OPAQUE group envelopes ({ v: 6, mode: 'group',
    // ciphertext }) to opaque group_ids: accept well-formed ones, fan them out
    // to online subscribers, queue them for late joiners, and keep rejecting
    // junk — all without touching the pair flow exercised above.
    {
      const groupId = b64(sodium.randombytes_buf(32)); // opaque 44-char group_id
      const groupMsg = (ciphertext, extra = {}) => ({ v: 6, mode: 'group', ciphertext, ...extra });

      // Junk group envelopes are rejected (relay replies 'malformed envelope
      // rejected' and does not deliver — and certainly must not crash).
      const gJunk = await connectTcp(RELAY_PORT);
      clients.push(gJunk);
      const junkGroupVariants = [
        ['missing ciphertext', groupMsg('')],
        ['non-base64 ciphertext', groupMsg('!!!')],
        ['wrong protocol version', { ...groupMsg('QUJD'), v: 5 }],
        ['oversized ciphertext', groupMsg('A'.repeat(180 * 1024))],
        ['senderSignPk wrong size', groupMsg('QUJD', { senderSignPk: 'AA==' })],
        ['negative epoch', groupMsg('QUJD', { epoch: -1 })],
        ['non-integer epoch', groupMsg('QUJD', { epoch: 1.5 })],
        ['sender not a string', groupMsg('QUJD', { sender: 5 })],
        ['negative n', groupMsg('QUJD', { n: -1 })],
      ];
      let groupJunkAllRejected = true;
      for (const [label, envelope] of junkGroupVariants) {
        const errP = gJunk.once('error');
        gJunk.send({ type: 'send', toPk: groupId, envelope });
        const err = await withTimeout(`group junk rejection (${label})`, errP);
        if (!err || !/malformed envelope rejected/.test(err.error)) groupJunkAllRejected = false;
      }
      assert('relay rejects malformed group-mode envelopes (no crash)', groupJunkAllRejected);

      // Online fan-out: two members subscribed to the group both receive the
      // same opaque envelope, byte-for-byte as sent.
      const gSender = await connectTcp(RELAY_PORT);
      const gMemberA = await connectTcp(RELAY_PORT);
      const gMemberB = await connectTcp(RELAY_PORT);
      clients.push(gSender, gMemberA, gMemberB);
      const subA = gMemberA.once('subscribed');
      const subB = gMemberB.once('subscribed');
      gMemberA.send({ type: 'subscribe', group: groupId });
      gMemberB.send({ type: 'subscribe', group: groupId });
      await withTimeout('group subscribe A', subA);
      await withTimeout('group subscribe B', subB);

      const gPayload = sodium.randombytes_buf(96); // opaque MLS-message stand-in
      const gEnv = groupMsg(b64(gPayload), { epoch: 3 });
      const msgA = gMemberA.once('message');
      const msgB = gMemberB.once('message');
      gSender.send({ type: 'send', toPk: groupId, envelope: gEnv, fromPk: aliceAddr });
      const [recvA, recvB] = await withTimeout('group fan-out', Promise.all([msgA, msgB]));
      assert('group envelope fanned out to every online subscriber',
        recvA.envelope.mode === 'group' && recvB.envelope.mode === 'group' &&
        recvA.envelope.ciphertext === gEnv.ciphertext && recvB.envelope.ciphertext === gEnv.ciphertext &&
        recvA.envelope.epoch === 3 && recvB.envelope.epoch === 3);
      assert('group envelope stays opaque to the relay (no pair fields added)',
        recvA.envelope.header === undefined && recvA.envelope.nonce === undefined &&
        recvA.envelope.signature === undefined);

      // Offline queueing: sent to a group with no online subscriber, then
      // flushed when a member subscribes. Uses a FRESH group id — members A/B
      // are still subscribed to groupId above, so a send there would (correctly)
      // fan out instead of queueing.
      const groupId2 = b64(sodium.randombytes_buf(32));
      const gEnv2 = groupMsg(b64(sodium.randombytes_buf(64)));
      gSender.send({ type: 'send', toPk: groupId2, envelope: gEnv2, fromPk: aliceAddr });
      await new Promise((r) => setTimeout(r, 50));
      const gLate = await connectTcp(RELAY_PORT);
      clients.push(gLate);
      const lateSub = gLate.once('subscribed');
      const lateMsg = gLate.once('message');
      gLate.send({ type: 'subscribe', group: groupId2 });
      await withTimeout('late group subscribe', lateSub);
      const recvLate = await withTimeout('group queued delivery', lateMsg);
      assert('queued group envelope flushed to a late subscriber',
        recvLate.envelope.mode === 'group' && recvLate.envelope.ciphertext === gEnv2.ciphertext);
    }

    // ---- GroupSession prototype (ROADMAP §7): a client-side group over the
    // real relay, reusing group_id as the routing address. Alice creates the
    // group and welcomes Bob through their EXISTING pair session; group
    // messages are opaque mode:'group' envelopes the relay fans out to
    // subscribers. Bob joins at epoch 0; Alice then ratchets to epoch 1 to add
    // Carol (Commit broadcast to the group, Welcome over a fresh pair
    // first-message), and epoch-1 traffic flows to both members. ----
    {
      const aliceGroup = GroupSession.create({
        creatorAddress: aliceAddr, label: 'ops-room', nonce: sodium.randombytes_buf(32),
        members: [bobAddr], myAddress: aliceAddr,
      });
      const groupId = aliceGroup.groupId;
      assert('group_id is a 44-char routing address (same shape as a pair address)',
        /^[A-Za-z0-9+/]{43}=$/.test(groupId));

      // Bob joins via the Welcome, delivered through the established pair
      // session (the design's "Welcome is a normal send to *their* address").
      const welcomePlain = await (async () => {
        const p = bobClient.once('message');
        aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(aliceGroup.makeWelcome(), 'utf8')), fromPk: aliceAddr });
        const m = await withTimeout('bob welcome', p);
        return bobSession.decrypt(m.envelope);
      })();
      const bobGroup = GroupSession.fromWelcome(welcomePlain, bobAddr);
      assert('bob derives the same group_id from the welcome', bobGroup.groupId === groupId);
      assert('welcome carries the epoch-0 member roster',
        bobGroup.members.includes(bobAddr) && bobGroup.members.includes(aliceAddr));

      // Both members subscribe (group delivery is fan-out to subscribers; a
      // member receives its OWN sends back too — one-shot listeners discard
      // those echoes). Alice sends the first group message at epoch 0.
      const bobSub = bobClient.once('subscribed');
      bobClient.send({ type: 'subscribe', group: groupId });
      await withTimeout('bob group subscribe', bobSub);
      const aliceSub = aliceClient.once('subscribed');
      aliceClient.send({ type: 'subscribe', group: groupId });
      await withTimeout('alice group subscribe', aliceSub);

      const aEnv = aliceGroup.encrypt('hello group — first message');
      const bobGotA1 = bobClient.once('message');
      const sentA1 = aliceClient.once('sent');
      aliceClient.send({ type: 'send', toPk: groupId, envelope: aEnv, fromPk: aliceAddr });
      const [sentAck, a1Recv] = await withTimeout('A1 ack+delivery', Promise.all([sentA1, bobGotA1]));
      assert('relay accepted the GroupSession envelope (sent ack)', sentAck.toPk === groupId);
      const a1 = bobGroup.handleIncoming(a1Recv.envelope);
      assert('bob decrypts the epoch-0 group message', a1.text === 'hello group — first message');

      // Bob replies; Alice (also subscribed) receives it; Bob's own echo is
      // discarded (no pending listener).
      const bEnv = bobGroup.encrypt('reply from bob');
      const aliceGotB1 = aliceClient.once('message');
      const sentB1 = bobClient.once('sent');
      bobClient.send({ type: 'send', toPk: groupId, envelope: bEnv, fromPk: bobAddr });
      await withTimeout('B1 ack', sentB1);
      const b1Recv = await withTimeout('B1 to alice', aliceGotB1);
      const b1 = aliceGroup.handleIncoming(b1Recv.envelope);
      assert('alice decrypts bob\'s group reply', b1.text === 'reply from bob');

      // Replay + non-member rejection.
      let replayRejected = false;
      try { bobGroup.decrypt(aEnv); } catch { replayRejected = true; }
      assert('bob rejects a replayed group message', replayRejected);
      const malloryGroup = new GroupSession({
        groupId, epoch: 0, epochKey: sodium.randombytes_buf(32),
        members: [addr(mallory)], creator: aliceAddr, myAddress: addr(mallory),
      });
      let nonMemberRejected = false;
      try { malloryGroup.decrypt(aEnv); } catch { nonMemberRejected = true; }
      assert('a non-member (wrong epoch key) cannot decrypt', nonMemberRejected);

      // Alice ratchets to epoch 1 to add Carol: Commit broadcast to the group
      // (encrypted under the epoch-0 key), Welcome to Carol carrying the
      // epoch-1 key over a fresh pair first-message.
      const commitSecret = sodium.randombytes_buf(32);
      const { commit, envelope: commitEnv } = aliceGroup.makeCommit({
        secret: commitSecret, toMembers: [...aliceGroup.members, carolAddr],
      });
      aliceGroup.applyCommit(commit);
      assert('alice advanced to epoch 1', aliceGroup.epoch === 1);

      const bobGotCommit = bobClient.once('message');
      const sentCommit = aliceClient.once('sent');
      aliceClient.send({ type: 'send', toPk: groupId, envelope: commitEnv, fromPk: aliceAddr });
      await withTimeout('commit ack', sentCommit);
      const commitRecv = await withTimeout('bob commit', bobGotCommit);
      const bobCommitRes = bobGroup.handleIncoming(commitRecv.envelope);
      assert('bob applies the commit and ratchets to epoch 1',
        !!bobCommitRes.commit && bobGroup.epoch === 1);
      assert('epoch-1 membership includes carol', bobGroup.members.includes(carolAddr));

      const carolWelcome = await (async () => {
        const p = carolClient.once('message');
        const s = new Session(alice, carol.makeBundle());
        aliceClient.send({ type: 'send', toPk: carolAddr, envelope: s.encrypt(Buffer.from(aliceGroup.makeWelcome(), 'utf8')), fromPk: aliceAddr });
        const m = await withTimeout('carol welcome', p);
        return new Session(carol, alice.makeBundle()).decrypt(m.envelope);
      })();
      const carolGroup = GroupSession.fromWelcome(carolWelcome, carolAddr);
      assert('carol joins at epoch 1 with the same group_id',
        carolGroup.epoch === 1 && carolGroup.groupId === groupId);

      const carolSub = carolClient.once('subscribed');
      carolClient.send({ type: 'subscribe', group: groupId });
      await withTimeout('carol group subscribe', carolSub);

      // Epoch-1 traffic fans out to both members.
      const cEnv = aliceGroup.encrypt('epoch 1 — carol can read this');
      const carolGotC1 = carolClient.once('message');
      const bobGotC1 = bobClient.once('message');
      const sentC1 = aliceClient.once('sent');
      aliceClient.send({ type: 'send', toPk: groupId, envelope: cEnv, fromPk: aliceAddr });
      await withTimeout('C1 ack', sentC1);
      const [c1Carol, c1Bob] = await withTimeout('C1 fan-out', Promise.all([carolGotC1, bobGotC1]));
      const c1c = carolGroup.handleIncoming(c1Carol.envelope);
      const c1b = bobGroup.handleIncoming(c1Bob.envelope);
      assert('carol decrypts the epoch-1 message from alice', c1c.text === 'epoch 1 — carol can read this');
      assert('bob still decrypts after the ratchet', c1b.text === 'epoch 1 — carol can read this');

      const carolReply = carolGroup.encrypt('carol can send too');
      const aliceGotC2 = aliceClient.once('message');
      carolClient.send({ type: 'send', toPk: groupId, envelope: carolReply, fromPk: carolAddr });
      const c2Recv = await withTimeout('C2 to alice', aliceGotC2);
      const c2 = aliceGroup.handleIncoming(c2Recv.envelope);
      assert('alice decrypts carol\'s epoch-1 reply', c2.text === 'carol can send too');
    }

    // ---- MLS KeyPackage plumbing (ROADMAP §7): the relay directory now also
    // accepts an MLS-style KeyPackage per address, and the whole Add → Commit
    // → Welcome flow rides the EXISTING four verbs — publish (carry the
    // KeyPackage), fetch-directory (discover the joinable peer), send (Commit
    // to the group, Welcome to the member's address), subscribe (bind to the
    // group) — with no further relay changes. ----
    {
      // A fresh group; Bob joins at epoch 0 via Welcome over the pair session.
      const group2 = GroupSession.create({
        creatorAddress: aliceAddr, label: 'kp-room', nonce: sodium.randombytes_buf(32),
        members: [bobAddr], myAddress: aliceAddr,
      });
      const groupId2 = group2.groupId;
      const bobWelcome2 = await (async () => {
        const p = bobClient.once('message');
        aliceClient.send({ type: 'send', toPk: bobAddr, envelope: aliceSession.encrypt(Buffer.from(group2.makeWelcome(), 'utf8')), fromPk: aliceAddr });
        const m = await withTimeout('bob welcome2', p);
        return bobSession.decrypt(m.envelope);
      })();
      const bobGroup2 = GroupSession.fromWelcome(bobWelcome2, bobAddr);
      assert('group2: bob joins at epoch 0', bobGroup2.groupId === groupId2 && bobGroup2.epoch === 0);
      const bobSub2 = bobClient.once('subscribed');
      bobClient.send({ type: 'subscribe', group: groupId2 });
      await withTimeout('group2 bob subscribe', bobSub2);

      // Malformed KeyPackages are rejected before touching the directory.
      const kpJunk = [
        ['not an object', 5],
        ['missing init_key', { version: 1, cipher_suite: 2, credential: { identity: 'x' }, capabilities: {}, extensions: [] }],
        ['init_key wrong size', { version: 1, cipher_suite: 2, init_key: b64(sodium.randombytes_buf(16)), credential: { identity: 'x' }, capabilities: {}, extensions: [] }],
        ['extensions not an array', { version: 1, cipher_suite: 2, init_key: b64(sodium.randombytes_buf(32)), credential: { identity: 'x' }, capabilities: {}, extensions: 'nope' }],
        ['bad extension shape', { version: 1, cipher_suite: 2, init_key: b64(sodium.randombytes_buf(32)), credential: { identity: 'x' }, capabilities: {}, extensions: [{ type: 5, data: 'x' }] }],
      ];
      let kpJunkAllRejected = true;
      for (const [label, badKp] of kpJunk) {
        const errP = aliceClient.once('error');
        aliceClient.send({ type: 'publish', address: aliceAddr, bundle: alice.makeBundle(), oneTimePrekeys: otksOf(alice), keyPackage: badKp });
        const err = await withTimeout(`keyPackage junk rejection (${label})`, errP);
        if (!err || !/invalid key package/.test(err.error)) kpJunkAllRejected = false;
      }
      assert('relay rejects malformed MLS KeyPackages (no directory mutation)', kpJunkAllRejected);

      // Carol publishes her KeyPackage bound to this group (Add discovery).
      const carolKp = GroupSession.makeKeyPackage(carolAddr, { groupId: groupId2 });
      const pubC = carolClient.once('published');
      carolClient.send({ type: 'publish', address: carolAddr, bundle: carol.makeBundle(), oneTimePrekeys: otksOf(carol), keyPackage: carolKp });
      await withTimeout('carol keyPackage publish', pubC);

      // Add: Alice fetches Carol's KeyPackage via fetch-directory and verifies
      // it is bound to this group — the discovery half of the flow.
      const dirP = aliceClient.once('directory');
      aliceClient.send({ type: 'fetch-directory', address: carolAddr });
      const dirReply = await withTimeout('fetch carol keyPackage', dirP);
      assert('directory serves carol\'s KeyPackage', !!dirReply.keyPackage && dirReply.keyPackage.credential.identity === carolAddr);
      assert('KeyPackage round-trips byte-identical (opaque to the relay)',
        JSON.stringify(dirReply.keyPackage) === JSON.stringify(carolKp));
      assert('KeyPackage is bound to this group (group_id extension) and well-formed',
        GroupSession.checkKeyPackage(dirReply.keyPackage, { groupId: groupId2 }).credential.identity === carolAddr);
      let wrongGroupRejected = false;
      try { GroupSession.checkKeyPackage(dirReply.keyPackage, { groupId: b64(sodium.randombytes_buf(32)) }); } catch { wrongGroupRejected = true; }
      assert('a KeyPackage fetched for one group cannot Add into another', wrongGroupRejected);

      // Commit: Alice ratchets group2 to epoch 1 adding Carol; the Commit
      // envelope rides the group send verb to every online subscriber.
      const commitSecret2 = sodium.randombytes_buf(32);
      const { commit: commit2, envelope: commitEnv2 } = group2.makeCommit({
        secret: commitSecret2, toMembers: [...group2.members, carolAddr],
      });
      group2.applyCommit(commit2);
      const bobGotCommit2 = bobClient.once('message');
      const sentCommit2 = aliceClient.once('sent');
      aliceClient.send({ type: 'send', toPk: groupId2, envelope: commitEnv2, fromPk: aliceAddr });
      await withTimeout('group2 commit ack', sentCommit2);
      const commitRecv2 = await withTimeout('bob group2 commit', bobGotCommit2);
      const bobCommit2 = bobGroup2.handleIncoming(commitRecv2.envelope);
      assert('group2: bob applies the commit and ratchets to epoch 1',
        !!bobCommit2.commit && bobGroup2.epoch === 1 && bobGroup2.members.includes(carolAddr));

      // Welcome: Carol joins at epoch 1 via a fresh pair first-message — the
      // KeyPackage only got her DISCOVERED; the key still rides the existing
      // pair send verb to her own address.
      const carolWelcome2 = await (async () => {
        const p = carolClient.once('message');
        const s = new Session(alice, carol.makeBundle());
        aliceClient.send({ type: 'send', toPk: carolAddr, envelope: s.encrypt(Buffer.from(group2.makeWelcome(), 'utf8')), fromPk: aliceAddr });
        const m = await withTimeout('carol welcome2', p);
        return new Session(carol, alice.makeBundle()).decrypt(m.envelope);
      })();
      const carolGroup2 = GroupSession.fromWelcome(carolWelcome2, carolAddr);
      assert('carol joins group2 at epoch 1 (KeyPackage-backed Add → Welcome)',
        carolGroup2.groupId === groupId2 && carolGroup2.epoch === 1 && carolGroup2.members.includes(carolAddr));

      // Carol subscribes and epoch-1 traffic flows to both members.
      const carolSub2 = carolClient.once('subscribed');
      carolClient.send({ type: 'subscribe', group: groupId2 });
      await withTimeout('group2 carol subscribe', carolSub2);
      const aliceSub2 = aliceClient.once('subscribed');
      aliceClient.send({ type: 'subscribe', group: groupId2 });
      await withTimeout('group2 alice subscribe', aliceSub2);
      const cEnv2 = carolGroup2.encrypt('hello from carol via KeyPackage add');
      const aliceGotC2b = aliceClient.once('message');
      const sentC2 = carolClient.once('sent');
      carolClient.send({ type: 'send', toPk: groupId2, envelope: cEnv2, fromPk: carolAddr });
      await withTimeout('group2 carol send ack', sentC2);
      const cRecv2 = await withTimeout('alice gets carol group2 msg', aliceGotC2b);
      assert('alice decrypts carol\'s epoch-1 message (KeyPackage add worked end-to-end)',
        group2.handleIncoming(cRecv2.envelope).text === 'hello from carol via KeyPackage add');
    }

    // ---- Log-injection regression (VULN-005): a crafted `toPk` must not emit
    // terminal escape sequences into the relay's operator console. The send
    // path treats `toPk` as an opaque routing key (any non-empty string), so a
    // hostile client could otherwise clear the screen or plant OSC-8 hyperlinks
    // in the log. Send a plausible envelope with a control-laden toPk and
    // assert the relay's own output stays clean — ANSI/OSC escapes AND
    // Trojan-Source bidi/format controls (RLO, isolates, directional marks).
    const injectedPk = '\x1b[2J' + '\x1b]8;;https://evil.example\x1b\\'
      + '\u202e' + '\u2066' + '\u2067' + '\u2068' + '\u2069' + '\u061c' + '\u200e' + '\u200f'
      + 'Z'.repeat(44);
    aliceClient.send({ type: 'send', toPk: injectedPk, envelope: aliceSession.encrypt(Buffer.from('log injection probe', 'utf8')), fromPk: aliceAddr });
    await new Promise((r) => setTimeout(r, 100));

    // ---- VULN-006-equivalent (client display): the relay validates
    // senderDhPk only as a non-empty string, so a hostile envelope can carry
    // control bytes in it — the CLI client's message-display path prints
    // `from ${shortKey(senderPkB64)}` for exactly this value. Prove the
    // crafted senderDhPk travels the REAL relay to the recipient (the sink is
    // wire-reachable) and that shortKey() renders it control-free for the
    // console.
    const spoofEnv = new Session(mallory, bob.makeBundle()).encrypt(Buffer.from('spoofed sender', 'utf8'));
    spoofEnv.senderDhPk = '\x1b[2J' + '\u202e' + 'E'.repeat(40);
    const bobGotSpoof = bobClient.once('message');
    aliceClient.send({ type: 'send', toPk: bobAddr, envelope: spoofEnv, fromPk: aliceAddr });
    const spoofRecv = await withTimeout('bob spoofed sender', bobGotSpoof);
    assert('relay forwards a control-laden senderDhPk (display sink is wire-reachable)',
      spoofRecv.envelope.senderDhPk === spoofEnv.senderDhPk);
    assert('shortKey renders the spoofed senderDhPk control-free for the client console',
      !/[\u0000-\u001f\u007f-\u009f\p{Cf}]/u.test(shortKey(spoofRecv.envelope.senderDhPk))
      && shortKey(spoofRecv.envelope.senderDhPk).endsWith('...'));

    // ---- REAL CLI client regression (VULN-006 end-to-end): spawn the actual
    // src/client.js process against a TEMP identity/session dir (BLACKVAULT_
    // STATE_DIR), deliver a control-laden senderDhPk envelope through the real
    // relay, and assert the client's own stdout is escape-free. This closes the
    // gap the earlier in-process check left: the unit assertion proved shortKey
    // renders the payload control-free, but never exercised the real client's
    // display path in a live process.
    {
      const { mkdtempSync, existsSync, statSync, rmSync } = await import('node:fs');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const { fileURLToPath } = await import('node:url');
      const tmpDir = mkdtempSync(join(tmpdir(), 'bv-client-e2e-'));
      const projRoot = join(fileURLToPath(new URL('..', import.meta.url)), '.');
      const projIdentity = join(projRoot, '.identity.json');
      const projSessions = join(projRoot, '.sessions.json');
      const projIdentityMtime = existsSync(projIdentity) ? statSync(projIdentity).mtimeMs : null;
      const projSessionsMtime = existsSync(projSessions) ? statSync(projSessions).mtimeMs : null;

      const clientProc = spawn(process.execPath, ['src/client.js', bobAddr, '--no-tor'], {
        env: {
          ...process.env,
          RELAY_HOST: '127.0.0.1',
          RELAY_PORT: String(RELAY_PORT),
          BLACKVAULT_STATE_DIR: tmpDir,
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let clientOut = '';
      clientProc.stdout.on('data', (d) => { clientOut += d; });
      clientProc.stderr.on('data', (d) => { clientOut += d; });

      const tClient = Date.now();
      while (!clientOut.includes('published + registered') && Date.now() - tClient < 45000) {
        await new Promise((r) => setTimeout(r, 150));
      }
      assert('real client registered against the temp identity', clientOut.includes('published + registered'));
      const addrLine = clientOut.match(/my address\s*: (\S+)/);
      assert('real client printed its (temp) address', !!addrLine);
      const realClientAddr = addrLine[1];

      // Env-override proof: the identity landed in the temp dir and the
      // project-root identity file (if any) was not touched. (.sessions.json is
      // written on persist — receive/close — so it is asserted after the
      // graceful exit below.)
      assert('identity persisted in BLACKVAULT_STATE_DIR', existsSync(join(tmpDir, '.identity.json')));
      assert('project-root identity file untouched by the isolated client',
        projIdentityMtime === null || statSync(projIdentity).mtimeMs === projIdentityMtime);

      // The attack: a plausible first-contact envelope whose senderDhPk carries
      // ESC + OSC-8 + Trojan-Source bidi. The relay forwards it (senderDhPk is
      // validated only as a non-empty string); the real client's receive path
      // hits the drop-and-display sink with shortKey().
      const attackEnv = new Session(mallory, bob.makeBundle()).encrypt(Buffer.from('client sink probe', 'utf8'));
      attackEnv.senderDhPk = '\x1b[2J' + '\x1b]8;;https://evil.example\x1b\\'
        + '\u202e' + '\u2066' + '\u2067' + '\u2068' + '\u2069' + '\u061c' + '\u200e' + '\u200f'
        + 'F'.repeat(36);
      aliceClient.send({ type: 'send', toPk: realClientAddr, envelope: attackEnv, fromPk: aliceAddr });
      const tHit = Date.now();
      while (!clientOut.includes('dropped self-inconsistent envelope') && Date.now() - tHit < 15000) {
        await new Promise((r) => setTimeout(r, 150));
      }
      assert('real client hit the display sink for the crafted senderDhPk',
        clientOut.includes('dropped self-inconsistent envelope'));

      // The escape-free end-to-end assertion: the REAL process's stdout has no
      // ESC, no other C0 controls (beyond the legitimate \n/\r/\t), and no
      // bidi/format controls — across the whole session, not just the one line.
      const dangerous = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
      assert('real client stdout is escape-free end-to-end (no ESC/OSC)', !clientOut.includes('\x1b'));
      assert('real client stdout has no C0 controls', !dangerous.test(clientOut));
      assert('real client stdout resists Trojan-Source bidi/format controls', !/[\p{Cf}]/u.test(clientOut));

      // Graceful exit: the client's close handler persists sessions, which
      // writes .sessions.json into the temp dir — the second half of the
      // env-override proof (the attack envelope was dropped pre-persist).
      clientProc.stdin.write('exit\n');
      const tExit = Date.now();
      while (!existsSync(join(tmpDir, '.sessions.json')) && Date.now() - tExit < 10000) {
        await new Promise((r) => setTimeout(r, 150));
      }
      assert('sessions persisted in BLACKVAULT_STATE_DIR on exit',
        existsSync(join(tmpDir, '.sessions.json')));
      assert('project-root sessions file untouched by the isolated client',
        projSessionsMtime === null || statSync(projSessions).mtimeMs === projSessionsMtime);

      clientProc.kill();
      rmSync(tmpDir, { recursive: true, force: true });
    }

    console.log('\n=== Results ===');
    assert('relay never saw plaintext', !relayOut.includes(secret) && !relayErr.includes(secret)
      && !relayOut.includes(reply) && !relayErr.includes(reply));
    assert('relay log sanitizes toPk (no ESC/OSC terminal escape sequences)', !relayOut.includes('\x1b'));
    assert('relay log resists Trojan-Source bidi/format spoofing (no \p{Cf} in relay output)',
      !/[\p{Cf}]/u.test(relayOut) && !/[\p{Cf}]/u.test(relayErr));
    assert('Bob decrypted Alice message correctly', decrypted === secret);
    assert('Alice decrypted Bob reply correctly', decryptedReply === reply);
    assert('Mallory cannot decrypt relayed message', malloryBlocked);
    assert('queued offline message delivered and decrypted', carolPlain === 'queued while offline');

    console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`}`);
  } catch (err) {
    console.error('[test] ERROR:', err.message);
    if (relayOut.trim()) console.error('[test] relay log:', relayOut.trim().split('\n').slice(-12).join(' | '));
    if (relayErr.trim()) console.error('[test] relay stderr:', relayErr.trim().slice(0, 600));
    failures++;
  } finally {
    for (const c of clients) c.socket.destroy();
    relay.kill('SIGTERM');
  }

  process.exit(failures === 0 ? 0 : 1);
}

main();
