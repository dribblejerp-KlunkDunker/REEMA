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

// recipientPk -> array of { envelope, fromPk, ts }
const inbox = new Map();
// recipientPk -> { type: 'tcp'|'ws', raw: socket }
const online = new Map();
// Key directory: address -> { bundle, oneTimePrekeys: Map(id -> { dhPk, signature }) }.
const directory = new Map();
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
 */
function isPlausibleEnvelope(env) {
  if (!env || typeof env !== 'object') return false;
  if (env.v !== 6) return false;

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
  if (env.senderSignPk !== undefined && Buffer.from(env.senderSignPk, 'base64').length !== 1952) return false;
  if (Buffer.from(h.dh, 'base64').length !== 32) return false;
  if (h.first === true && (typeof h.pq_pk !== 'string' ||
      Buffer.from(h.pq_pk, 'base64').length !== 1184)) return false;
  if (h.pq_pk !== undefined && Buffer.from(h.pq_pk, 'base64').length !== 1184) return false;
  if (h.first === true && (typeof h.pq_ct !== 'string' ||
      Buffer.from(h.pq_ct, 'base64').length !== 1088)) return false;
  if (h.pq_ct && Buffer.from(h.pq_ct, 'base64').length !== 1088) return false;

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

  switch (msg.type) {
    case 'publish': {
      const { address, bundle, oneTimePrekeys } = msg;
      if (typeof address !== 'string' || !address || address.length > 128) {
        sendLine(client, { type: 'error', error: 'valid address required' });
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
      directory.set(address, { bundle, oneTimePrekeys: otkMap });

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
      sendLine(client, { type: 'directory', address, bundle: entry.bundle, oneTimePrekey });
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
