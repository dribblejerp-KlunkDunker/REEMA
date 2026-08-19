import { init, Session, Identity, signingPayload, decodeBundle, RECEIPT, isReceipt } from './crypto.js';
import { createTorSocket } from './tor.js';
import { loadOrCreateIdentity, saveIdentity } from './identity.js';
import { loadSessions, saveSessions } from './sessions.js';
import { createInterface } from 'node:readline';
import { stripControls } from './sanitize.js';

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
 */

const HOST = process.env.RELAY_HOST || '127.0.0.1';
const PORT = Number(process.env.RELAY_PORT || 7980);

async function main() {
  const sodium = await init();
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

  // Bundle mode: verify up front so a malformed bundle cannot allocate a
  // session. Address mode defers resolution to the directory fetch.
  let recipientBundle = null;
  let recipientPkB64 = null;
  let recipientAddress = null;
  let recipientOtk = null;
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

  const ourId = loadOrCreateIdentity(sodium);
  const myAddress = b64(Identity.deriveAddress(ourId.signPk, ourId.pk));

  console.log(`[client] my address    : ${myAddress}`);
  console.log(`[client] peer address  : ${recipientAddress}`);
  console.log(`[client] routing       : ${useTor ? (allowDirectFallback ? 'Tor (direct fallback allowed)' : 'Tor (strict)') : 'DIRECT — not anonymous'}`);
  console.log(`[client] connecting to relay at ${HOST}:${PORT}...`);

  let socket;
  try {
    socket = await createTorSocket(HOST, PORT, { useTor, allowDirectFallback });
  } catch (err) {
    console.error(`[client] ${err.message}`);
    process.exit(1);
  }

  // One ratchet session per peer, keyed by their base64 X25519 public key.
  const sessions = new Map();

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
  const persist = () => {
    try { saveSessions(sodium, ourId, sessions); }
    catch (err) { console.warn('[client] failed to persist sessions:', err.message); }
  };

  function sessionFor(peerPkB64, peerBundle, peerOtk = null) {
    if (!sessions.has(peerPkB64)) {
      sessions.set(peerPkB64, new Session(ourId, peerBundle, peerOtk));
    }
    return sessions.get(peerPkB64);
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

  // Resolver for a pending fetch-directory response (address mode).
  let pendingDirectory = null;

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
  // directory before starting the REPL.
  if (isAddress) {
    try {
      const msg = await new Promise((resolve, reject) => {
        pendingDirectory = { resolve, reject };
        socket.write(JSON.stringify({ type: 'fetch-directory', address: recipientAddress }) + '\n');
      });
      if (msg.error) throw new Error(msg.error);
      recipientBundle = msg.bundle;
      recipientOtk = msg.oneTimePrekey;
      const peer = Identity.verifyBundle(recipientBundle);
      recipientPkB64 = b64(peer.staticDhPk);
      if (recipientOtk && !Identity.verifyOneTimePrekey(peer.signPk, recipientOtk)) {
        throw new Error('directory served a one-time prekey not signed by the peer');
      }
      console.log('[client] resolved peer from key directory' + (recipientOtk ? ' (with one-time prekey)' : ' (no one-time prekeys left)'));
    } catch (err) {
      console.error(`[client] directory lookup failed: ${err.message}`);
      process.exit(1);
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

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  console.log('\n[client] Type a message and press Enter to send. Type "exit" to quit.\n');

  rl.on('line', (input) => {
    const text = input.trim();
    if (text.toLowerCase() === 'exit') {
      socket.end();
      rl.close();
      return;
    }
    if (!text) return;

    try {
      const session = sessionFor(recipientPkB64, recipientBundle, recipientOtk);
      const envelope = session.encrypt(Buffer.from(text, 'utf8'));
      // Persist the ratchet state BEFORE the send is observable: a crash after
      // the send must not leave a session that re-flags as `first` on restore
      // (the receiver would reject the duplicate and stall).
      persist();
      socket.write(JSON.stringify({
        type: 'send',
        toPk: recipientAddress,
        envelope,
        fromPk: myAddress,
      }) + '\n');
      console.log('[client] sent (encrypted)');
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

      case 'directory': {
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

          if (!sessions.has(senderPkB64)) {
            if (!selfConsistent(env)) {
              console.error(`[client] dropped self-inconsistent envelope from ${senderPkB64.slice(0, 16)}...`);
              return;
            }
            if (env.header.first !== true || !env.header.bundle) {
              console.error(`[client] dropped first contact without a prekey bundle from ${senderPkB64.slice(0, 16)}...`);
              return;
            }
            let peer;
            try {
              peer = Identity.verifyBundle(env.header.bundle);
            } catch {
              console.error(`[client] dropped envelope with invalid prekey bundle from ${senderPkB64.slice(0, 16)}...`);
              return;
            }
            if (b64(peer.staticDhPk) !== senderPkB64 || b64(peer.signPk) !== env.senderSignPk) {
              console.error(`[client] dropped envelope whose bundle does not match its signature from ${senderPkB64.slice(0, 16)}...`);
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
          }
          const session = sessions.get(senderPkB64);
          const plaintext = session.decrypt(env);

          // Delivery receipt: acknowledge a newly-established session so the
          // sender's receiving chain is established even if it never replies
          // by hand (closes the bootstrap crash-recovery edge).
          if (created && senderAddress) {
            const receiptEnv = session.encrypt(Buffer.from(RECEIPT, 'utf8'));
            socket.write(JSON.stringify({ type: 'send', toPk: senderAddress, envelope: receiptEnv, fromPk: myAddress }) + '\n');
          }

          if (isReceipt(plaintext)) {
            console.log(`[client] receipt from ${senderPkB64.slice(0, 16)}... (session established)`);
          } else {
            console.log(`\n[client] <<< from ${senderPkB64.slice(0, 16)}...`);
            console.log(`[client] <<< ${stripControls(plaintext)}`);
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
        console.error('[client] server error:', stripControls(msg.error));
        break;
    }
  }
}

main().catch((err) => {
  console.error('[client] fatal:', err);
  process.exit(1);
});
