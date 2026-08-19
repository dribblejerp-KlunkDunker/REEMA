import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { init, Identity, Session } from './crypto.js';
import { generateVaultIdentity, exportVault, importVault } from './vault.js';
import { stripControls, shortKey } from './sanitize.js';

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
 *   - the relay sanitizes control characters in logged keys/addresses, so a
 *     crafted toPk cannot inject terminal escape sequences into its console
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
