import { init, Session, Identity, signingPayload, decodeBundle, loadPQ, RECEIPT, isReceipt, directoryShard, selectOneTimePrekey } from './crypto.js';
import { createTorSocket } from './tor.js';
import { createTlsSocket } from './tls.js';
import { loadOrCreateIdentity, saveIdentity } from './identity.js';
import { loadSessions, saveSessions } from './sessions.js';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { stripControls, shortKey } from './sanitize.js';
import { createMemory } from './memory.js';
import { startCoverCadence, makeCoverSinkAddress } from './cover.js';

/**
 * E2EE messaging client (protocol v6).
 *
 * Connects to the ciphertext-only relay + key directory and exchanges
 * end-to-end encrypted messages. Registration is authenticated: the client
 * publishes its identity-bound routing address together with a self-signed
 * prekey bundle (proof-of-possession), so no one can claim its address.
 *
 * The recipient argument is either:
 *   - the peer's SHAREABLE PREKEY BUNDLE (base64, out-of-band), or
 *   - the peer's 44-char base64 ROUTING ADDRESS (fetched from the key
 *     directory, which also supplies a one-time prekey for first-message
 *     forward secrecy).
 *
 * Usage:
 *   node src/client.js <peerPrekeyBundleBase64 | peerAddress> [options]
 *
 * Options:
 *   --no-tor                 Direct connection (NOT anonymous)
 *   --allow-direct-fallback  Try Tor, accept a direct connection if unavailable
 *   --cover[=ms]             Emit relay-discarded cover traffic on a cadence
 *                            (default every 5000ms) — ANONYMITY.md Phase 2
 *
 * Optional client-side memory (Hindsight daemon; off unless configured):
 *   HINDSIGHT_URL   e.g. http://127.0.0.1:8877 — enables retain on send +
 *                   retain/recall on receive (best-effort, never blocking)
 *   HINDSIGHT_BANK  override the per-address bank id (default bv-<addr-hash>)
 */

const HOST = process.env.RELAY_HOST || '127.0.0.1';
const PORT = Number(process.env.RELAY_PORT || 7980);
// Must match the relay's DIR_SHARD_BYTES (default 1 byte → 256 shards) so the
// client names the same bucket the relay indexes on.
const DIR_SHARD_BYTES = Math.max(1, Number(process.env.DIR_SHARD_BYTES) || 1);

async function main() {
  const sodium = await init();
  // Deferred post-quantum bootstrap: ML-KEM/ML-DSA are NOT loaded here. The
  // REPL opens first (below) so first interactivity is never blocked on the
  // ~67 KB @noble/post-quantum graph; keygen, bundle/OTK signing, and session
  // work all await loadPQ() inside the deferred bootstrap that follows.
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);

  const args = process.argv.slice(2);
  const useTor = !args.includes('--no-tor');
  const allowDirectFallback = args.includes('--allow-direct-fallback');
  const recipientArg = args.find((a) => !a.startsWith('--'));

  if (!recipientArg) {
    console.error('Usage: node src/client.js <peerPrekeyBundleBase64 | peerAddress> [--no-tor] [--allow-direct-fallback]');
    console.error('Bundle (out-of-band):  node src/index.js bundle');
    console.error('Address (key directory): the 44-char base64 address your peer printed');
    process.exit(1);
  }

  // A routing address is the base64 of 32 bytes; a bundle is much longer.
  const isAddress = recipientArg.length === 44;

  // ---- Mutable bootstrap state, declared up front so the REPL (opened next)
  // can reference it; the deferred bootstrap below populates it. ----
  let ourId = null;
  let myAddress = null;
  let socket = null;
  const sessions = new Map();
  let recipientBundle = null;
  let recipientPkB64 = null;
  let recipientAddress = null;
  let recipientOtk = null;
  let pendingDirectory = null;
  let memory = null;
  let ready = false;
  let quitRequested = false;

  const persist = () => {
    try { saveSessions(sodium, ourId, sessions); }
    catch (err) { console.warn('[client] failed to persist sessions:', err.message); }
  };

  /** One ratchet session per peer, keyed by their base64 X25519 public key. */
  function sessionFor(peerPkB64, peerBundle, peerOtk = null) {
    if (!sessions.has(peerPkB64)) {
      sessions.set(peerPkB64, new Session(ourId, peerBundle, peerOtk));
    }
    return sessions.get(peerPkB64);
  }

  /**
   * Sealed sender: find a session by its opaque per-session delivery token
   * (derived identically on both sides from the bootstrap secrets). Returns
   * null when the token is absent or unknown, so the caller falls back to
   * senderDhPk for pre-sealed sessions and the simultaneous-first race.
   */
  function sessionByToken(tokenB64) {
    if (!tokenB64) return null;
    for (const s of sessions.values()) {
      if (b64(s.deliveryToken) === tokenB64) return s;
    }
    return null;
  }

  /**
   * Cheap gate before allocating an expensive Session: the envelope must at
   * least be self-consistent (signed by its own senderSignPk).
   */
  function selfConsistent(env) {
    try {
      const payload = signingPayload({
        v: env.v,
        senderDhPk: unb64(env.senderDhPk),
        senderSignPk: unb64(env.senderSignPk),
        recipientDhPk: ourId.pk,
        dh: unb64(env.header.dh),
        pqPk: unb64(env.header.pq_pk),
        pqCt: env.header.pq_ct ? unb64(env.header.pq_ct) : new Uint8Array(0),
        pn: env.header.pn,
        n: env.header.n,
        first: env.header.first === true,
        otkId: env.header.otk_id ?? -1,
        nonce: unb64(env.nonce),
        ciphertext: unb64(env.ciphertext),
      });
      return Identity.verify(unb64(env.senderSignPk), payload, unb64(env.signature));
    } catch {
      return false;
    }
  }

  // Resolve an address from a shard response (private directory lookup): pick
  // the target entry, re-verify its bundle self-signature and that the address
  // derives from it (a tampering relay is caught here), then select one
  // one-time prekey deterministically per (sender, recipient).
  function resolveFromShard(msg, targetAddress) {
    const entry = (msg.entries || []).find((e) => e.address === targetAddress);
    if (!entry) throw new Error('address not in shard (peer not registered)');
    const peer = Identity.verifyBundle(entry.bundle);
    if (b64(Identity.deriveAddress(peer.signPk, peer.staticDhPk)) !== targetAddress) {
      throw new Error('shard entry does not match its bundle (tampered relay)');
    }
    const otk = selectOneTimePrekey(myAddress, targetAddress, entry.oneTimePrekeys || []);
    if (otk && !Identity.verifyOneTimePrekey(peer.signPk, otk)) {
      throw new Error('shard served a one-time prekey not signed by the peer');
    }
    return { bundle: entry.bundle, pkB64: b64(peer.staticDhPk), otk };
  }

  // ---- Open the REPL FIRST (the CLI's "first paint"). The prompt is printed
  // before the deferred post-quantum bootstrap finishes, and the send/open
  // paths gate on `ready` below — so a slow ML-KEM/ML-DSA load or keygen never
  // blocks first interactivity. ----
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  console.log('\n[client] Type a message and press Enter to send. Type "exit" to quit.\n');

  rl.on('line', async (input) => {
    const text = input.trim();

    if (text.toLowerCase() === 'exit') {
      quitRequested = true;
      if (socket) socket.end();
      else rl.close();
      return;
    }

    if (!ready) {
      console.error('[client] still starting up — crypto bootstrap in progress, try again in a moment');
      return;
    }

    // Runtime re-targeting: `/to <44-char address>` switches the peer without
    // restarting — needed when the peer registers after this client started.
    if (text.startsWith('/to ')) {
      const target = text.slice(4).trim();
      if (target.length !== 44) {
        console.error('[client] /to requires a 44-char routing address');
        return;
      }
      if (pendingDirectory) {
        console.error('[client] /to already in progress');
        return;
      }
      try {
        const msg = await new Promise((resolve, reject) => {
          pendingDirectory = { resolve, reject };
          socket.write(JSON.stringify({ type: 'fetch-shard', shard: directoryShard(target, DIR_SHARD_BYTES) }) + '\n');
        });
        if (msg.error) throw new Error(msg.error);
        const resolved = resolveFromShard(msg, target);
        recipientAddress = target;
        recipientBundle = resolved.bundle;
        recipientPkB64 = resolved.pkB64;
        recipientOtk = resolved.otk;
        console.log(`[client] now talking to ${shortKey(target)}`);
      } catch (err) {
        console.error(`[client] /to failed: ${err.message}`);
      }
      return;
    }

    if (!text) return;

    if (!recipientPkB64) {
      console.error('[client] no peer resolved yet — target one with /to <address>');
      return;
    }

    try {
      const session = sessionFor(recipientPkB64, recipientBundle, recipientOtk);
      const envelope = session.encrypt(Buffer.from(text, 'utf8'));
      // Persist the ratchet state BEFORE the send is observable: a crash after
      // the send must not leave a session that re-flags as `first` on restore
      // (the receiver would reject the duplicate and stall).
      persist();
      // Sealed sender: NO sender identity on the wire — the relay routes by
      // toPk alone and the recipient keys the session by the envelope's opaque
      // per-session delivery token.
      socket.write(JSON.stringify({
        type: 'send',
        toPk: recipientAddress,
        envelope,
      }) + '\n');
      console.log('[client] sent (encrypted)');
      // Fire-and-forget: memory must never block or break the send path.
      // No document_id: a shared id would upsert (replace) earlier messages
      // in the bank — each retained message stands on its own.
      if (memory) memory.retain(text, { context: 'sent' });
    } catch (err) {
      console.error('[client] send error:', err.message);
    }
  });

  function handleServer(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }

    switch (msg.type) {
      case 'published':
        console.log('[client] published + registered with relay');
        break;

      case 'directory-shard': {
        if (pendingDirectory) {
          const r = pendingDirectory;
          pendingDirectory = null;
          r.resolve(msg);
        }
        break;
      }

      case 'message': {
        let senderPkB64 = null;
        let created = false;
        let senderAddress = null;
        try {
          const env = typeof msg.envelope === 'string' ? JSON.parse(msg.envelope) : msg.envelope;
          senderPkB64 = env.senderDhPk;
          if (!senderPkB64) throw new Error('envelope has no senderDhPk');

          // Sealed sender (ANONYMITY.md Phase 1): dispatch by the opaque
          // per-session delivery token first, then fall back to senderDhPk for
          // pre-sealed sessions and the rare simultaneous-first race.
          let session = sessionByToken(env.deliveryToken);
          if (session && b64(session.peerDhPk) !== senderPkB64) session = null;
          if (!session) session = sessions.get(senderPkB64);

          if (!session) {
            if (!selfConsistent(env)) {
              console.error(`[client] dropped self-inconsistent envelope from ${shortKey(senderPkB64)}`);
              return;
            }
            if (env.header.first !== true || !env.header.bundle) {
              console.error(`[client] dropped first contact without a prekey bundle from ${shortKey(senderPkB64)}`);
              return;
            }
            let peer;
            try {
              peer = Identity.verifyBundle(env.header.bundle);
            } catch {
              console.error(`[client] dropped envelope with invalid prekey bundle from ${shortKey(senderPkB64)}`);
              return;
            }
            if (b64(peer.staticDhPk) !== senderPkB64 || b64(peer.signPk) !== env.senderSignPk) {
              console.error(`[client] dropped envelope whose bundle does not match its signature from ${shortKey(senderPkB64)}`);
              return;
            }
            created = true;
            senderAddress = b64(Identity.deriveAddress(peer.signPk, peer.staticDhPk));
            // v6: if the sender consumed one of our one-time prekeys, derive
            // the same root from it, then burn it locally (first-message
            // forward secrecy). An unknown id means we cannot establish.
            let peerOtk = null;
            if (env.header.otk_id !== undefined) {
              const otk = ourId.oneTimePrekeys.get(env.header.otk_id);
              if (!otk) throw new Error('unknown one-time prekey id');
              peerOtk = { id: otk.id, sk: otk.sk, pk: otk.pk };
              ourId.oneTimePrekeys.delete(otk.id);
              saveIdentity(sodium, ourId);
            }
            sessions.set(senderPkB64, new Session(ourId, env.header.bundle, peerOtk));
            session = sessions.get(senderPkB64);
          }
          const plaintext = session.decrypt(env);

          // Delivery receipt: acknowledge a newly-established session so the
          // sender's receiving chain is established even if it never replies
          // by hand (closes the bootstrap crash-recovery edge).
          if (created && senderAddress) {
            const receiptEnv = session.encrypt(Buffer.from(RECEIPT, 'utf8'));
            socket.write(JSON.stringify({ type: 'send', toPk: senderAddress, envelope: receiptEnv }) + '\n');
          }

          if (isReceipt(plaintext)) {
            console.log(`[client] receipt from ${shortKey(senderPkB64)} (session established)`);
          } else {
            console.log(`\n[client] <<< from ${shortKey(senderPkB64)}`);
            console.log(`[client] <<< ${stripControls(plaintext)}`);
            // Fire-and-forget: retain what we received, and surface related
            // memory as a one-line hint. Never awaited, never throws.
            if (memory) {
              memory.retain(plaintext, { context: 'received' });
              memory.recall(plaintext).then((r) => {
                if (r.ok && r.results.length) {
                  const top = r.results[0];
                  const score = top.score != null ? ` (score ${top.score.toFixed(2)})` : '';
                  console.log(`[memory] related: ${top.text.slice(0, 140)}${score}`);
                }
              });
            }
          }
          persist();
        } catch (err) {
          if (created && senderPkB64) sessions.delete(senderPkB64);
          persist();
          console.error('[client] failed to decrypt incoming message:', err.message);
        }
        break;
      }

      case 'sent':
        console.log('[client] relay acknowledged delivery');
        break;

      case 'error':
        if (pendingDirectory) {
          const r = pendingDirectory;
          pendingDirectory = null;
          r.reject(new Error(msg.error));
        }
        console.error('[client] server error:', stripControls(msg.error));
        break;
    }
  }

  // ---- Deferred post-quantum bootstrap (runs AFTER the REPL is already
  // open). Everything here needs ML-KEM-768 / ML-DSA-65: keygen, bundle and
  // one-time-prekey signing, bundle verification, and session establishment. ----
  await loadPQ();
  console.log('[client] post-quantum core ready (ML-KEM-768 + ML-DSA-65)');

  // Bundle mode: verify up front so a malformed bundle cannot allocate a
  // session. Address mode defers resolution to the directory fetch.
  if (!isAddress) {
    try {
      recipientBundle = decodeBundle(recipientArg);
      const peer = Identity.verifyBundle(recipientBundle);
      recipientPkB64 = b64(peer.staticDhPk);
      recipientAddress = b64(Identity.deriveAddress(peer.signPk, peer.staticDhPk));
    } catch (err) {
      console.error(`[client] invalid peer prekey bundle: ${err.message}`);
      process.exit(1);
    }
  } else {
    recipientAddress = recipientArg;
  }

  ourId = loadOrCreateIdentity(sodium);
  myAddress = b64(Identity.deriveAddress(ourId.signPk, ourId.pk));

  // Client-side memory layer: speaks the Hindsight REST API directly and is
  // strictly best-effort — a dead daemon must never break the messaging path.
  // Note this operates on *decrypted plaintext at the client* (the user's own
  // daemon on 127.0.0.1), so E2EE is untouched: the relay never sees it.
  const HINDSIGHT_URL = process.env.HINDSIGHT_URL;
  memory = HINDSIGHT_URL
    ? createMemory({
        baseUrl: HINDSIGHT_URL,
        bankId: process.env.HINDSIGHT_BANK || `bv-${createHash('sha256').update(myAddress).digest('hex').slice(0, 16)}`,
        logger: { warn: (...a) => console.warn(...a) },
      })
    : null;
  if (memory) {
    console.log(`[client] memory       : bank '${memory.bankId}' @ ${HINDSIGHT_URL} (retain+recall)`);
  }

  console.log(`[client] my address    : ${myAddress}`);
  console.log(`[client] peer address  : ${recipientAddress}`);
  console.log(`[client] routing       : ${useTor ? (allowDirectFallback ? 'Tor (direct fallback allowed)' : 'Tor (strict)') : 'DIRECT — not anonymous'}`);
  if (process.env.RELAY_TLS === '1') console.log(`[client] transport     : TLS (pinned fingerprint ${process.env.RELAY_PIN ? process.env.RELAY_PIN.slice(0, 16) + '…' : 'MISSING'})`);
  console.log(`[client] connecting to relay at ${HOST}:${PORT}...`);

  try {
    const useTls = process.env.RELAY_TLS === '1';
    const tlsPin = process.env.RELAY_PIN || null;
    if (useTls) {
      if (!tlsPin) {
        throw new Error('RELAY_TLS=1 requires RELAY_PIN=<sha256 fingerprint of the relay certificate> — refusing to connect unverified (fail closed)');
      }
      // When both are requested, TLS runs INSIDE the Tor tunnel: SOCKS first,
      // then the TLS handshake with the relay over that anonymous stream.
      if (useTor) {
        const raw = await createTorSocket(HOST, PORT, { useTor, allowDirectFallback });
        socket = await createTlsSocket(HOST, PORT, { pin: tlsPin, socket: raw });
      } else {
        socket = await createTlsSocket(HOST, PORT, { pin: tlsPin });
      }
    } else {
      socket = await createTorSocket(HOST, PORT, { useTor, allowDirectFallback });
    }
  } catch (err) {
    console.error(`[client] ${err.message}`);
    process.exit(1);
  }

  // Optional cover traffic (ANONYMITY.md Phase 2): a fixed-cadence stream of
  // dummy frames the relay discards, so the link never goes quiet in a way an
  // observer could correlate with real sends. OFF by default.
  const coverArg = args.find((a) => a.startsWith('--cover'));
  let coverStop = null;
  if (coverArg) {
    const intervalMs = Number(coverArg.split('=')[1]) || 5000;
    const sendCover = (envelope) => {
      if (socket && !socket.destroyed) {
        socket.write(JSON.stringify({
          type: 'send', toPk: makeCoverSinkAddress(sodium), envelope,
        }) + '\n');
      }
    };
    coverStop = startCoverCadence(sodium, sendCover, { intervalMs });
    console.log(`[client] cover traffic : ON (every ${intervalMs}ms, relay-discarded)`);
  }

  // Restore persisted sessions so a restart does not desync the ratchet.
  for (const [peerPkB64, state] of loadSessions(sodium, ourId)) {
    try {
      const session = Session.restore(ourId, state);
      if (b64(session.peerDhPk) !== peerPkB64) throw new Error('session key mismatch');
      sessions.set(peerPkB64, session);
    } catch (err) {
      console.warn(`[client] dropping unreadable session for ${peerPkB64.slice(0, 16)}...: ${err.message}`);
    }
  }

  socket.setEncoding('utf8');
  let buffer = '';
  socket.on('data', (chunk) => {
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) handleServer(line);
    }
  });
  socket.on('error', (err) => {
    console.error('[client] connection error:', err.message);
    process.exit(1);
  });
  socket.on('close', () => {
    persist();
    console.log('[client] disconnected');
    process.exit(0);
  });

  // Address mode: resolve the peer's bundle + one-time prekey from the key
  // directory before the REPL can send.
  if (isAddress) {
    try {
      const msg = await new Promise((resolve, reject) => {
        pendingDirectory = { resolve, reject };
        // Private directory lookup: fetch the WHOLE shard, never the address.
        socket.write(JSON.stringify({ type: 'fetch-shard', shard: directoryShard(recipientAddress, DIR_SHARD_BYTES) }) + '\n');
      });
      if (msg.error) throw new Error(msg.error);
      const resolved = resolveFromShard(msg, recipientAddress);
      recipientBundle = resolved.bundle;
      recipientPkB64 = resolved.pkB64;
      recipientOtk = resolved.otk;
      console.log('[client] resolved peer from key directory shard' + (recipientOtk ? ' (with one-time prekey)' : ' (no one-time prekeys left)'));
    } catch (err) {
      // Non-fatal: the peer may simply not be registered yet. Keep running and
      // let the user re-target with `/to <address>` once they come online.
      console.error(`[client] directory lookup failed: ${err.message} (use /to <address> to re-target)`);
    }
  }

  // Authenticated registration: publish the identity-bound address, the
  // self-signed bundle (proof-of-possession) and the one-time prekey pool.
  const otks = [...ourId.oneTimePrekeys.values()].map((kp) => ({
    id: kp.id, dhPk: b64(kp.pk), signature: b64(kp.signature),
  }));
  socket.write(JSON.stringify({
    type: 'publish',
    address: myAddress,
    bundle: ourId.makeBundle(),
    oneTimePrekeys: otks,
  }) + '\n');

  // The REPL is now fully usable.
  ready = true;

  // A user who typed "exit" while the bootstrap was still running should still
  // tear the connection down cleanly now that it exists.
  if (quitRequested && socket) socket.end();
}

main().catch((err) => {
  console.error('[client] fatal:', err);
  process.exit(1);
});
