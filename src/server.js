import { createServer } from 'node:net';
import { WebSocketServer } from 'ws';
import { init, Identity, loadPQ } from './crypto.js';
import { stripControls } from './sanitize.js';

/**
 * Ciphertext-only relay + key directory (protocol v6).
 *
 * The relay NEVER sees plaintext or private keys. It only:
 *   - accepts encrypted envelopes from clients
 *   - queues them by routing address
 *   - delivers them when the recipient connects
 *   - publishes/fetches prekey-bundle directory entries
 *
 * This is the Threema/Signal server model: an untrusted relay that shuffles
 * ciphertext and nothing else.
 *
 * Trust model (v6): registration is AUTHENTICATED. A client publishes its
 * routing address together with a self-signed prekey bundle; the address must
 * equal BLAKE2b(32, signPk || staticDhPk) and the bundle must verify under
 * its own signPk. The bundle signature is the proof-of-possession, so a
 * hostile client cannot claim an offline user's address (it would need their
 * signing key). The relay verifies public key material only — never private
 * keys or plaintext.
 *
 * The directory also holds one-time prekeys, handed out one per fetch and
 * consumed server-side, so each new session bootstrap gets its own forward
 * secrecy. An exhausted pool degrades to a prekey-less bootstrap.
 *
 * Group mode (prototype — ROADMAP §7): the relay also carries OPAQUE
 * group-mode envelopes ({ v: 6, mode: 'group', ciphertext }) to opaque
 * group_ids, exactly as it carries pair-mode envelopes to routing addresses.
 * The MLS message inside `ciphertext` is never parsed; a `subscribe` verb
 * binds a connection to a group_id for fan-out. Members keep their own
 * registered address and simply also listen on group ids, so authenticated
 * registration is untouched.
 */

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 7980);
const WS_PORT = Number(process.env.WS_PORT || 8080);

// A v6 envelope is ~9 KB (ML-KEM public key + ML-DSA signature); the first
// message additionally carries the sender's prekey bundle (~6 KB). Allow room
// for large padded messages but refuse anything that is clearly not an envelope.
const MAX_LINE_BYTES = 256 * 1024;
const MAX_QUEUE_PER_RECIPIENT = 100;
const MAX_QUEUED_RECIPIENTS = 10_000;
const QUEUE_TTL_MS = 24 * 60 * 60 * 1000;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;

// Deliveries are padded to a fixed bucket so a network observer cannot read
// the plaintext length off the ciphertext size. Plaintext padding (256-byte
// blocks) already hides exact length; this hides the residual size variation.
// Pad the relay->client direction only — the relay cannot pad what it receives.
const DELIVERY_PAD_BUCKET = 12 * 1024;

// Group-mode (MLS) envelopes carry an opaque message in `ciphertext`. Cap it
// at 128 KB decoded — generous for a PrivateMessage/Commit and a small-group
// Welcome (which embeds the ratchet tree) — while staying well inside
// MAX_LINE_BYTES after base64 inflation (128 KB * 4/3 ≈ 171 KB).
const MAX_GROUP_ENVELOPE_BYTES = 128 * 1024;

// recipientPk -> array of { envelope, fromPk, ts }
const inbox = new Map();
// recipientPk -> { type: 'tcp'|'ws', raw: socket }
const online = new Map();
// Key directory: address -> { bundle, oneTimePrekeys: Map(id -> { dhPk, signature }), keyPackage }.
// `keyPackage` is an MLS-style KeyPackage (ROADMAP §7): shape/size-capped but
// opaque — the relay stores and serves it so members can discover joinable
// peers (the Add half of Add/Commit/Welcome), never parsing its contents.
const directory = new Map();
// Group delivery (prototype — ROADMAP §7): group_id -> Set<client> subscribed
// to that id. Members register their own address as usual AND subscribe to
// group ids, so group fan-out never touches the address/directory machinery.
const groups = new Map();
let sodium = null; // bound by init() before the servers listen

// Sanitize control characters before echoing a key/address into the operator's
// console. The `send` path accepts an arbitrary non-empty string as `toPk`
// (the relay treats it as an opaque routing key), so a crafted value could
// otherwise inject ANSI/OSC terminal escape sequences into the log (VULN-005)
// or reorder/hide text via Unicode bidi/format controls (Trojan-Source).
// stripControls() strips both; the slice keeps the log line short.
const short = (pk) => {
  if (typeof pk !== 'string') return '<invalid>';
  return stripControls(pk).slice(0, 16) + '...';
};

function isAlive(client) {
  if (!client) return false;
  return client.type === 'ws' ? client.raw.readyState === 1 : !client.raw.destroyed;
}

function sendLine(client, obj) {
  const line = JSON.stringify(obj) + '\n';
  if (!isAlive(client)) return;
  if (client.type === 'ws') client.raw.send(line);
  else client.raw.write(line);
}

/**
 * Deliver a message padded to a fixed bucket size. The recipient ignores the
 * extra `pad` field; the point is that every delivery looks the same size on
 * the wire. Messages larger than one bucket are padded to the next multiple.
 */
function sendPadded(client, obj) {
  if (!isAlive(client)) return;
  const base = JSON.stringify(obj);
  const target = Math.ceil((base.length + 2) / DELIVERY_PAD_BUCKET) * DELIVERY_PAD_BUCKET;
  const pad = target - base.length - 10; // 10 = overhead of ',"pad":"..."'
  const line = pad > 0 ? JSON.stringify({ ...obj, pad: ' '.repeat(pad) }) + '\n' : base + '\n';
  if (client.type === 'ws') client.raw.send(line);
  else client.raw.write(line);
}

function queueMessage(toPk, envelope, fromPk) {
  const list = inbox.get(toPk) || [];
  if (list.length >= MAX_QUEUE_PER_RECIPIENT) {
    return { ok: false, error: 'recipient queue full' };
  }
  if (!inbox.has(toPk) && inbox.size >= MAX_QUEUED_RECIPIENTS) {
    return { ok: false, error: 'relay queue capacity reached' };
  }
  list.push({ envelope, fromPk, ts: Date.now() });
  inbox.set(toPk, list);
  return { ok: true };
}

/**
 * Structural validation for envelopes, so the relay does not accept (and
 * forward) arbitrary junk that would make every recipient allocate a Session
 * and burn ML-KEM keygen per unknown sender. The relay stays ciphertext-only:
 * it checks shape and encodability — never decrypts, never inspects key
 * material beyond its length.
 *
 * Sizes are the protocol v6 constants: X25519 pk 32, ML-DSA-65 pk 1952 /
 * signature 3309, XSalsa20 nonce 24, ML-KEM-768 pk 1184 / ciphertext 1088.
 * First messages additionally carry the sender's prekey bundle, which is
 * checked structurally (version + field sizes) but never verified here — the
 * relay stays ciphertext-only.
 *
 * senderSignPk and header.pq_pk are OMITTED on steady-state non-first
 * messages (the receiver reconstructs them from cached values), so they are
 * required only on first messages and validated for size when present.
 *
 * Group mode ({ v: 6, mode: 'group', ciphertext }) is OPAQUE: the relay
 * validates shape and encodability only — the MLS message inside ciphertext
 * is never parsed, and the pair-mode header/bundle/OTK fields are
 * intentionally absent (group members decrypt against their epoch key without
 * the per-session ML-KEM allocation pair mode's strictness protects against).
 * Optional senderSignPk (1952 B) and epoch (non-negative int) are still
 * type/size-checked when present.
 */
// MLS KeyPackage (ROADMAP §7): shape/size-capped but opaque — the relay
// stores what the member publishes and serves it back unchanged. Checks cover
// the MLS-ish envelope (version, cipher suite, 32-byte init_key, credential,
// capabilities, extension list) and a hard size cap so junk cannot fill the
// directory; the CONTENT is never parsed.
const MAX_KEYPACKAGE_BYTES = 8 * 1024;
function isPlausibleKeyPackage(kp) {
  if (!kp || typeof kp !== 'object' || Array.isArray(kp)) return false;
  if (!Number.isInteger(kp.version) || kp.version < 1) return false;
  if (!Number.isInteger(kp.cipher_suite) || kp.cipher_suite < 0) return false;
  if (typeof kp.init_key !== 'string' || !kp.init_key || Buffer.from(kp.init_key, 'base64').length !== 32) return false;
  if (!kp.credential || typeof kp.credential !== 'object' || Array.isArray(kp.credential)
      || typeof kp.credential.identity !== 'string' || !kp.credential.identity) return false;
  if (!kp.capabilities || typeof kp.capabilities !== 'object' || Array.isArray(kp.capabilities)) return false;
  if (!Array.isArray(kp.extensions)) return false;
  for (const ext of kp.extensions) {
    if (!ext || typeof ext !== 'object' || Array.isArray(ext)
        || typeof ext.type !== 'string' || typeof ext.data !== 'string') return false;
  }
  if (Buffer.from(JSON.stringify(kp), 'utf8').length > MAX_KEYPACKAGE_BYTES) return false;
  return true;
}

function isPlausibleEnvelope(env) {
  if (!env || typeof env !== 'object') return false;
  if (env.v !== 6) return false;

  // Group mode (prototype — ROADMAP §7): accept an opaque MLS envelope. No
  // header, bundle, nonce, or signature fields are required — the ciphertext
  // IS the message. Shape/size checks keep the flood gate (junk must not
  // reach every group member) without the relay parsing MLS.
  if (env.mode === 'group') {
    if (typeof env.ciphertext !== 'string' || !env.ciphertext) return false;
    const gct = Buffer.from(env.ciphertext, 'base64');
    if (gct.length === 0 || gct.length > MAX_GROUP_ENVELOPE_BYTES) return false;
    if (env.senderSignPk !== undefined && (typeof env.senderSignPk !== 'string' ||
        Buffer.from(env.senderSignPk, 'base64').length !== 1952)) return false;
    if (env.epoch !== undefined && (!Number.isInteger(env.epoch) || env.epoch < 0)) return false;
    // GroupSession envelopes (prototype — public/group-core.js) carry the
    // sender's b64 address and a per-sender message counter so recipients can
    // rebuild the AEAD nonce; validate them when present.
    if (env.sender !== undefined && (typeof env.sender !== 'string' || !env.sender || env.sender.length > 128)) return false;
    if (env.n !== undefined && (!Number.isInteger(env.n) || env.n < 0)) return false;
    return true;
  }

  const h = env.header;
  if (!h || typeof h !== 'object') return false;
  if (typeof h.dh !== 'string' || !h.dh) return false;
  if (!Number.isInteger(h.n) || h.n < 0 || !Number.isInteger(h.pn) || h.pn < 0) return false;
  if (h.first !== undefined && h.first !== true) return false;
  if (h.otk_id !== undefined && (!Number.isInteger(h.otk_id) || h.otk_id < 0)) return false;

  for (const f of ['senderDhPk', 'nonce', 'ciphertext', 'signature']) {
    if (typeof env[f] !== 'string' || env[f].length === 0) return false;
  }

  // Fixed-size fields must decode to exactly the right number of bytes when
  // present; senderSignPk and pq_pk are mandatory on the first message.
  if (h.first === true && (typeof env.senderSignPk !== 'string' ||
      Buffer.from(env.senderSignPk, 'base64').length !== 1952)) return false;
  if (env.senderSignPk !== undefined && (typeof env.senderSignPk !== 'string' ||
      Buffer.from(env.senderSignPk, 'base64').length !== 1952)) return false;
  if (Buffer.from(h.dh, 'base64').length !== 32) return false;
  if (h.first === true && (typeof h.pq_pk !== 'string' ||
      Buffer.from(h.pq_pk, 'base64').length !== 1184)) return false;
  if (h.pq_pk !== undefined && (typeof h.pq_pk !== 'string' ||
      Buffer.from(h.pq_pk, 'base64').length !== 1184)) return false;
  if (h.first === true && (typeof h.pq_ct !== 'string' ||
      Buffer.from(h.pq_ct, 'base64').length !== 1088)) return false;
  if (h.pq_ct && (typeof h.pq_ct !== 'string' ||
      Buffer.from(h.pq_ct, 'base64').length !== 1088)) return false;

  // First messages must carry a structurally-plausible prekey bundle.
  if (h.first === true) {
    const b = h.bundle;
    if (!b || typeof b !== 'object' || b.v !== 6) return false;
    const bundleFixed = { staticDhPk: 32, signPk: 1952, signedDhPk: 32, kemPk: 1184, signature: 3309 };
    for (const [f, len] of Object.entries(bundleFixed)) {
      if (typeof b[f] !== 'string' || Buffer.from(b[f], 'base64').length !== len) return false;
    }
  }

  return Buffer.from(env.ciphertext, 'base64').length > 0;
}

function handleLine(client, line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    sendLine(client, { type: 'error', error: 'invalid JSON' });
    return;
  }

  if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') {
    sendLine(client, { type: 'error', error: 'malformed message' });
    return;
  }

  // Defense-in-depth: a validation bug in any handler must degrade to a
  // per-connection error, never an uncaught exception that kills the relay
  // (the malformed-envelope crash regression in src/test.js).
  try {
    switch (msg.type) {
    case 'publish': {
      const { address, bundle, oneTimePrekeys, keyPackage } = msg;
      if (typeof address !== 'string' || !address || address.length > 128) {
        sendLine(client, { type: 'error', error: 'valid address required' });
        return;
      }
      if (keyPackage !== undefined && !isPlausibleKeyPackage(keyPackage)) {
        sendLine(client, { type: 'error', error: 'invalid key package' });
        return;
      }

      // Authenticated registration: the bundle must be self-signed (proving
      // the announcer holds the signing key) and the address must be the
      // identity-bound routing address derived from it. A hostile client
      // cannot claim someone else's address — that requires their signing key.
      let peer;
      try {
        peer = Identity.verifyBundle(bundle);
      } catch {
        sendLine(client, { type: 'error', error: 'invalid prekey bundle' });
        return;
      }
      const derived = Identity.deriveAddress(peer.signPk, peer.staticDhPk);
      const addrBytes = Buffer.from(address, 'base64');
      if (addrBytes.length !== 32 || !addrBytes.equals(Buffer.from(derived))) {
        sendLine(client, { type: 'error', error: 'address does not match identity' });
        return;
      }

      // Verify every one-time prekey is signed by the bundle's signing key.
      const otkMap = new Map();
      if (Array.isArray(oneTimePrekeys)) {
        for (const otk of oneTimePrekeys) {
          if (!Identity.verifyOneTimePrekey(peer.signPk, otk)) {
            sendLine(client, { type: 'error', error: 'invalid one-time prekey' });
            return;
          }
          otkMap.set(otk.id, { id: otk.id, dhPk: otk.dhPk, signature: otk.signature });
        }
      }
      directory.set(address, { bundle, oneTimePrekeys: otkMap, keyPackage: keyPackage || null });

      // Refuse to move an address currently held by a live connection.
      const existing = online.get(address);
      if (existing && existing !== client && isAlive(existing)) {
        sendLine(client, { type: 'error', error: 'address already registered by an active connection' });
        console.log(`[server] rejected duplicate registration for ${short(address)}`);
        return;
      }

      // Release the address this connection previously held before taking the
      // new one, so stale entries never accumulate and the genuine owner is
      // never locked out by a stale mapping.
      if (client.pk && client.pk !== address && online.get(client.pk) === client) {
        online.delete(client.pk);
        console.log(`[server] released previous address ${short(client.pk)}`);
      }

      client.pk = address;
      online.set(address, client);

      const queued = inbox.get(address) || [];
      inbox.delete(address);
      for (const item of queued) {
        sendPadded(client, { type: 'message', envelope: item.envelope, fromPk: item.fromPk });
      }
      sendLine(client, { type: 'published', address });
      console.log(`[server] published+registered ${short(address)} (delivered ${queued.length} queued)`);
      break;
    }

    case 'fetch-directory': {
      const { address } = msg;
      if (typeof address !== 'string' || !address || address.length > 128) {
        sendLine(client, { type: 'error', error: 'valid address required' });
        return;
      }
      const entry = directory.get(address);
      if (!entry) {
        sendLine(client, { type: 'error', error: 'unknown address' });
        return;
      }
      // Hand out one one-time prekey per fetch and consume it server-side, so
      // a prekey is never reused across two sessions. An exhausted pool
      // degrades to a prekey-less bootstrap.
      let oneTimePrekey = null;
      if (entry.oneTimePrekeys.size > 0) {
        const firstId = entry.oneTimePrekeys.keys().next().value;
        const otk = entry.oneTimePrekeys.get(firstId);
        entry.oneTimePrekeys.delete(firstId);
        oneTimePrekey = { id: otk.id, dhPk: otk.dhPk, signature: otk.signature };
      }
      sendLine(client, { type: 'directory', address, bundle: entry.bundle, oneTimePrekey, keyPackage: entry.keyPackage || null });
      break;
    }

    case 'subscribe': {
      // Group delivery (prototype — ROADMAP §7): bind this connection to a
      // group_id so group-mode envelopes routed to that id are fanned out
      // here. Deliberately does NOT touch the address/directory machinery —
      // a member keeps its own bound address and simply also listens on
      // group ids, so authenticated registration is unaffected. Queued group
      // messages (sent while no member was online) are flushed on subscribe.
      const { group } = msg;
      if (typeof group !== 'string' || !group || group.length > 128) {
        sendLine(client, { type: 'error', error: 'valid group id required' });
        return;
      }
      let subs = groups.get(group);
      if (!subs) { subs = new Set(); groups.set(group, subs); }
      subs.add(client);
      const queued = inbox.get(group) || [];
      inbox.delete(group);
      for (const item of queued) {
        sendPadded(client, { type: 'message', envelope: item.envelope, fromPk: item.fromPk });
      }
      sendLine(client, { type: 'subscribed', group });
      console.log(`[server] client subscribed to group ${short(group)} (delivered ${queued.length} queued)`);
      break;
    }

    case 'send': {
      const { toPk, envelope } = msg;
      if (typeof toPk !== 'string' || !toPk || !envelope || typeof envelope !== 'object') {
        sendLine(client, { type: 'error', error: 'toPk and envelope object required' });
        return;
      }
      if (!isPlausibleEnvelope(envelope)) {
        sendLine(client, { type: 'error', error: 'malformed envelope rejected' });
        return;
      }

      console.log(`[server] relaying ciphertext to ${short(toPk)} (opaque to relay)`);

      // Group-mode envelope (prototype — ROADMAP §7): fan out to every online
      // subscriber of the group_id, or queue for the group if none are online.
      if (envelope.mode === 'group') {
        const subs = groups.get(toPk);
        const members = subs ? [...subs].filter(isAlive) : [];
        if (members.length) {
          for (const m of members) {
            sendPadded(m, { type: 'message', envelope, fromPk: msg.fromPk || null });
          }
        } else {
          const result = queueMessage(toPk, envelope, msg.fromPk || null);
          if (!result.ok) {
            sendLine(client, { type: 'error', error: result.error });
            return;
          }
        }
        sendLine(client, { type: 'sent', toPk });
        break;
      }

      // Pair flow (unchanged): route by registered address.
      const target = online.get(toPk);
      if (isAlive(target)) {
        sendPadded(target, { type: 'message', envelope, fromPk: msg.fromPk || null });
      } else {
        const result = queueMessage(toPk, envelope, msg.fromPk || null);
        if (!result.ok) {
          sendLine(client, { type: 'error', error: result.error });
          return;
        }
      }
      sendLine(client, { type: 'sent', toPk });
      break;
    }

    case 'ping':
      sendLine(client, { type: 'pong' });
      break;

    default:
      sendLine(client, { type: 'error', error: `unknown type: ${stripControls(msg.type)}` });
    }
  } catch (err) {
    sendLine(client, { type: 'error', error: 'internal error' });
    console.error(`[server] unhandled error in handleLine: ${err.message}`);
  }
}

/**
 * TCP is a byte stream, so messages are newline-delimited and a partial line
 * must be buffered. The buffer is capped so an endless unterminated line
 * cannot exhaust memory.
 */
function makeStreamReader(client, onOverflow) {
  let buffer = '';
  return (chunk) => {
    buffer += chunk;
    if (buffer.length > MAX_LINE_BYTES) {
      buffer = '';
      onOverflow();
      return;
    }
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) handleLine(client, line);
    }
  };
}

/**
 * WebSocket is already message-framed, so each frame is a complete payload —
 * it must NOT require a trailing newline. Frames may still carry several
 * newline-separated messages, which keeps it compatible with the TCP protocol.
 */
function makeFrameReader(client, onOverflow) {
  return (payload) => {
    if (payload.length > MAX_LINE_BYTES) {
      onOverflow();
      return;
    }
    for (const line of payload.split('\n')) {
      const trimmed = line.trim();
      if (trimmed) handleLine(client, trimmed);
    }
  };
}

function dropClient(client) {
  if (client.pk && online.get(client.pk) === client) online.delete(client.pk);
  // Group subscriptions are connection-scoped: drop this client from every
  // group's fan-out set so stale entries never accumulate (VULN-004 pattern).
  for (const subs of groups.values()) subs.delete(client);
}

const server = createServer((socket) => {
  console.log('[server] TCP client connected');
  const client = { type: 'tcp', raw: socket, pk: null };
  socket.setEncoding('utf8');

  const read = makeStreamReader(client, () => {
    sendLine(client, { type: 'error', error: 'message too large' });
    socket.destroy();
  });

  socket.on('data', read);
  socket.on('close', () => {
    dropClient(client);
    console.log('[server] TCP client disconnected');
  });
  socket.on('error', () => { /* ignore */ });
});

// Bind the crypto core before any client can publish (registration verifies
// the bundle signature), then start the WebSocket listener. The relay needs
// ML-DSA verification the moment the first client registers, so it loads the
// PQ graph at startup — unlike clients, whose init() defers it.
sodium = await init();
await loadPQ();

const wss = new WebSocketServer({ host: HOST, port: WS_PORT, maxPayload: MAX_LINE_BYTES }, () => {
  console.log(`[server] WebSocket relay listening on ${HOST}:${WS_PORT}`);
});

wss.on('connection', (ws) => {
  console.log('[server] WebSocket client connected');
  const client = { type: 'ws', raw: ws, pk: null };

  const read = makeFrameReader(client, () => {
    sendLine(client, { type: 'error', error: 'message too large' });
    ws.close();
  });

  ws.on('message', (message) => read(message.toString()));
  ws.on('close', () => {
    dropClient(client);
    console.log('[server] WebSocket client disconnected');
  });
  ws.on('error', () => { /* ignore */ });
});

// Evict queued messages nobody collected.
const sweep = setInterval(() => {
  const cutoff = Date.now() - QUEUE_TTL_MS;
  let dropped = 0;
  for (const [pk, list] of inbox) {
    const kept = list.filter((item) => item.ts >= cutoff);
    dropped += list.length - kept.length;
    if (kept.length === 0) inbox.delete(pk);
    else inbox.set(pk, kept);
  }
  if (dropped > 0) console.log(`[server] swept ${dropped} expired queued message(s)`);
}, SWEEP_INTERVAL_MS);
sweep.unref();

server.listen(PORT, HOST, () => {
  console.log(`[server] ciphertext-only relay listening on ${HOST}:${PORT}`);
  console.log('[server] The relay never sees plaintext or keys — only ciphertext envelopes.');
  if (HOST !== '127.0.0.1' && HOST !== '::1') {
    console.warn(`[server] WARNING: bound to ${HOST}, not loopback. See the trust model in src/server.js.`);
  }
});
