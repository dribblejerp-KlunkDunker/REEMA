import { createServer } from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { init, Identity, loadPQ, pqLoaded, directoryShard } from './crypto.js';
import { stripControls, shortKey, sanitizedLogger } from './sanitize.js';

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
 * The directory also holds one-time prekeys, served INSIDE a whole shard and
 * burned by the recipient on first receive — single-use is enforced client-side,
 * because the relay cannot know which entry a shard requester actually wanted.
 * An exhausted pool degrades to a prekey-less bootstrap.
 *
 * Group mode (prototype — ROADMAP §7): the relay also carries OPAQUE
 * group-mode envelopes ({ v: 6, mode: 'group', ciphertext }) to opaque
 * group_ids, exactly as it carries pair-mode envelopes to routing addresses.
 * The MLS message inside `ciphertext` is never parsed; a `subscribe` verb
 * binds a connection to a group_id for fan-out. Members keep their own
 * registered address and simply also listen on group ids, so authenticated
 * registration is untouched.
 */

// --sanitize-log mode (or RELAY_SANITIZE_LOG=1): sink-level last line of
// defense. Every field the relay echoes is already routed through short()/
// stripControls() at the call site, but this additionally wraps console.log/
// console.error/console.warn so EVERY line the relay writes passes through
// stripControls() — a future code path that forgets the per-field discipline
// still cannot emit a control character. Installed before anything can log.
const SANITIZE_LOG =
  process.argv.includes('--sanitize-log')
  || process.env.RELAY_SANITIZE_LOG === '1'
  || process.env.RELAY_SANITIZE_LOG === 'true';
if (SANITIZE_LOG) {
  const safe = sanitizedLogger();
  console.log = safe.log;
  console.error = safe.error;
  console.warn = safe.warn;
}

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 7980);
const WS_PORT = Number(process.env.WS_PORT || 8080);

// A v6 envelope is ~9 KB (ML-KEM public key + ML-DSA signature); the first
// message additionally carries the sender's prekey bundle (~6 KB). Allow room
// for large padded messages but refuse anything that is clearly not an envelope.
const MAX_LINE_BYTES = 256 * 1024;
const MAX_QUEUE_PER_RECIPIENT = 100;
const MAX_QUEUED_RECIPIENTS = 10_000;
// How long an undelivered message is retained before it self-destructs
// (ANONYMITY.md §3.6: metadata lives in YOUR storage only as long as needed).
// Configurable so an operator can run an ephemeral relay; 24h default is
// store-and-forward.
const QUEUE_TTL_MS = Number(process.env.QUEUE_TTL_MS) > 0
  ? Number(process.env.QUEUE_TTL_MS)
  : 24 * 60 * 60 * 1000;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
// Zero-retention mode (ANONYMITY.md §3.6): RELAY_EPHEMERAL=1 disables
// store-and-forward entirely — the relay NEVER queues. A message to an offline
// recipient is dropped at acceptance, so no copy exists for an adversary to
// seize later: once delivered (or dropped), nothing survives the moment.
const EPHEMERAL = process.env.RELAY_EPHEMERAL === '1' || process.env.RELAY_EPHEMERAL === 'true';
// Identity-bearing log lines are OFF by default: the relay must not accumulate
// a who→whom record in its operator logs. RELAY_VERBOSE=1 re-enables them for
// debugging; src/test.js runs verbose so those lines stay proven control-free.
const VERBOSE = process.env.RELAY_VERBOSE === '1';

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
// Private directory lookup (ANONYMITY.md Phase 1): the directory is sharded by
// a fixed prefix of the routing address. A requester fetches a WHOLE shard, so
// the relay learns "fetched shard #k" — never "looked up address X".
// k-anonymity = shard population; raise this to shrink shards (more buckets,
// less anonymity per fetch), lower it (1 byte = 256 buckets) for bigger shards.
const DIR_SHARD_BYTES = Math.max(1, Number(process.env.DIR_SHARD_BYTES) || 1);

// ---- Relay-side message mixing (ROADMAP §8) ----
// A fixed-cadence mix window. Every message accepted for relay enters a pool,
// and a ticker closes the window once per MIX_WINDOW_MS, delivering the whole
// window's traffic as ONE batch (crypto-shuffled order). Batching breaks the
// send-time -> deliver-time correlation a passive observer could otherwise read
// off the relay; the existing fixed-size padding already hid *size*. This is
// NOT a mixnet — at low traffic the anonymity set is one message — but it is
// the cheap, relay-only win ROADMAP §8 describes.
//
// Opt out with MIX_OFF=1 (or MIX_WINDOW_MS=0): the deterministic test suites
// and latency-sensitive flows run with it off, so delivery stays immediate.
const MIX_OFF = process.env.MIX_OFF === '1' || process.env.MIX_OFF === 'true'
  || process.env.MIX_WINDOW_MS === '0';
const MIX_WINDOW_MS = MIX_OFF ? 0 : Math.max(1, Number(process.env.MIX_WINDOW_MS) || 1000);
// Optional intra-batch jitter (ms): randomise each PAIR delivery's moment within
// the batch (0..MIX_JITTER_MS) so per-recipient arrival order does not leak.
// Group fan-out stays identical-time regardless (maximises sender hiding within
// the batch). Default 0 keeps the batching regression deterministic.
const MIX_JITTER_MS = MIX_OFF ? 0 : Math.max(0, Number(process.env.MIX_JITTER_MS) || 0);

// recipientPk -> array of { envelope, ts }. Sealed sender (ANONYMITY.md Phase 1):
// there is deliberately NO sender field here — the relay never learns who sent
// a message, only where it is going and an opaque envelope.
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
// The mix pool: everything accepted for relay since the last window close.
// Each item keeps its original receipt ts so the TTL sweep can still expire it
// (mixing must never resurrect a message past its TTL) and an optional directTo
// client used by the subscribe-backlog flush.
const mixPool = []; // { recipient, envelope, ts, directTo|null }
// Timer for the current mix window (see scheduleMixFlush). null when idle.
let mixTimer = null;
// Aggregate count of discarded cover frames (never queued, never delivered).
let coverDiscarded = 0;
// Aggregate count of relayed messages. Kept instead of a per-recipient log line:
// the relay must not accumulate a who→whom record in its own operator logs.
let relayedCount = 0;
let sodium = null; // bound by init() before the servers listen
let pqLoadedReported = false; // one-shot deferral report, emitted at the first publish

// Sanitize control characters and homoglyph lookalikes before echoing a
// key/address into the operator's console. The `send` path accepts an
// arbitrary non-empty string as `toPk` (the relay treats it as an opaque
// routing key), so a crafted value could otherwise inject ANSI/OSC terminal
// escape sequences into the log (VULN-005), reorder/hide text via Unicode
// bidi/format controls (Trojan-Source), or spoof a known address with
// Cyrillic/Greek lookalikes. shortKey() strips the controls, normalizes the
// confusables to ASCII, and slices to a short display form — one shared
// implementation, so the relay log path can never drift from the client's.
const short = shortKey;

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

function queueMessage(toPk, envelope, ts = Date.now()) {
  // Single queueing choke point. In ephemeral mode nothing is ever stored, so
  // every "would queue" path (offline pair, offline group, backlog flush)
  // degrades to a drop. Guarding here — not at each call site — means no code
  // path can accidentally retain a copy.
  if (EPHEMERAL) {
    return { ok: false, error: 'recipient offline — ephemeral relay stores nothing' };
  }
  const list = inbox.get(toPk) || [];
  if (list.length >= MAX_QUEUE_PER_RECIPIENT) {
    return { ok: false, error: 'recipient queue full' };
  }
  if (!inbox.has(toPk) && inbox.size >= MAX_QUEUED_RECIPIENTS) {
    return { ok: false, error: 'relay queue capacity reached' };
  }
  list.push({ envelope, ts });
  inbox.set(toPk, list);
  return { ok: true };
}

// Uniform-random shuffle source: prefer libsodium's RNG (bound at startup) so
// the batch order is not predictable from Math.random(), and fall back only if
// sodium is somehow unavailable.
function randomBelow(n) {
  if (sodium && typeof sodium.randombytes_uniform === 'function') {
    try { return sodium.randombytes_uniform(n); } catch { /* fall through */ }
  }
  return Math.floor(Math.random() * n);
}

/**
 * Resolve one accepted message to its live destination(s) and deliver. The
 * relay re-resolves online/offline at FLUSH time (not send time), so a
 * recipient who connected during the window still receives directly and one who
 * went away falls back to the inbox queue. This mirrors the pre-mix `send`
 * fan-out byte-for-byte.
 *
 * @returns {{ok: boolean, error?: string}}
 */
function deliverMixed(item) {
  const { recipient, envelope, ts, directTo } = item;
  if (Date.now() - ts > QUEUE_TTL_MS) return { ok: false, error: 'expired' };
  // No sender field on the delivery (sealed sender): the recipient derives the
  // sender from inside the authenticated envelope, keyed by the opaque
  // per-session deliveryToken the envelope carries.
  const run = (member) => sendPadded(member, { type: 'message', envelope });

  // Subscribe-backlog flush: deliver to the joining client only, never re-broadcast
  // to members who were already online when the message was queued.
  if (directTo) {
    if (!isAlive(directTo)) return queueMessage(recipient, envelope, ts);
    run(directTo);
    return { ok: true };
  }

  if (envelope.mode === 'group') {
    const subs = groups.get(recipient);
    const members = subs ? [...subs].filter(isAlive) : [];
    if (members.length) { members.forEach(run); return { ok: true }; }
    return queueMessage(recipient, envelope, ts);
  }

  const target = online.get(recipient);
  if (isAlive(target)) { run(target); return { ok: true }; }
  return queueMessage(recipient, envelope, ts);
}

/**
 * Accept a message for relay. With mixing ON it enters the mix pool and is
 * delivered at the next window close as part of one batch; with mixing OFF it
 * is resolved and delivered immediately (the pre-mix behaviour, used by the
 * deterministic suites). The `sent` ack is emitted by the caller at acceptance
 * time — relay receipt, never batch release.
 */
function enqueueRelay(recipient, envelope, { directTo = null, ts = Date.now() } = {}) {
  const item = { recipient, envelope, ts, directTo };
  if (MIX_OFF) return deliverMixed(item);
  mixPool.push(item);
  scheduleMixFlush();
  return { ok: true };
}

/**
 * Open the window on the first message and close it MIX_WINDOW_MS later: a
 * self-rescheduling timer, so a batch is a rolling window measured from the
 * first arrival rather than from an arbitrary boot-aligned tick. That makes the
 * delay bound exact (the first message waits the full window, later messages
 * less) and the batching regression deterministic.
 */
function scheduleMixFlush() {
  if (mixTimer !== null || mixPool.length === 0 || MIX_OFF) return;
  mixTimer = setTimeout(() => {
    mixTimer = null;
    flushMixBatch();
    scheduleMixFlush(); // more arrived during/after the flush -> next window
  }, MIX_WINDOW_MS);
  mixTimer.unref?.();
}

/**
 * Close the current mix window: deliver everything in the pool as one batch.
 * Delivery order is crypto-shuffled so per-recipient arrival order within the
 * batch does not fingerprint the sender; optional jitter spreads pair deliveries
 * while group fan-out stays identical-time.
 */
function flushMixBatch() {
  if (mixPool.length === 0) return;
  const batch = mixPool.splice(0, mixPool.length);

  for (let i = batch.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [batch[i], batch[j]] = [batch[j], batch[i]];
  }

  let dropped = 0;
  for (const item of batch) {
    const deliver = () => {
      const r = deliverMixed(item);
      if (!r.ok) {
        dropped++;
        if (VERBOSE) console.log(`[server] mix: dropped message to ${short(item.recipient)} (${r.error})`);
      }
    };
    if (MIX_JITTER_MS > 0 && item.envelope.mode !== 'group') {
      setTimeout(deliver, randomBelow(MIX_JITTER_MS));
    } else {
      deliver();
    }
  }

  console.log(`[server] mix: flushed ${batch.length} message(s) in one batch`);
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

  // Sealed-sender delivery token (ANONYMITY.md Phase 1): opaque to the relay,
  // but shape-checked so a hostile client cannot smuggle a non-token through
  // the same field. It is a base64 32-byte id when present.
  if (env.deliveryToken !== undefined &&
      (typeof env.deliveryToken !== 'string' ||
       Buffer.from(env.deliveryToken, 'base64').length !== 32)) return false;

  // Cover traffic (ANONYMITY.md Phase 2): an opaque dummy the relay DISCARDS,
  // never queues or delivers. Shape/size-validated so a hostile client cannot
  // use the cover channel to flood inboxes. See the send handler for discard.
  if (env.mode === 'cover') {
    if (typeof env.ciphertext !== 'string' || !env.ciphertext) return false;
    const cct = Buffer.from(env.ciphertext, 'base64');
    if (cct.length === 0 || cct.length > MAX_GROUP_ENVELOPE_BYTES) return false;
    return true;
  }

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

async function handleLine(client, line) {
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

      // Server-side deferral: the ML-KEM/ML-DSA graph is loaded HERE, on the
      // first publish, not at startup. Report the loaded state first so the
      // regression in src/server-deferral-regression.js can prove zero
      // @noble modules were loaded before the first publish arrived.
      if (!pqLoadedReported) {
        pqLoadedReported = true;
        console.log(`[server] @noble modules loaded before first publish: ${pqLoaded() ? 1 : 0}`);
      }
      await loadPQ();

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
        if (VERBOSE) console.log(`[server] rejected duplicate registration for ${short(address)}`);
        return;
      }

      // Release the address this connection previously held before taking the
      // new one, so stale entries never accumulate and the genuine owner is
      // never locked out by a stale mapping.
      if (client.pk && client.pk !== address && online.get(client.pk) === client) {
        online.delete(client.pk);
        if (VERBOSE) console.log(`[server] released previous address ${short(client.pk)}`);
      }

      client.pk = address;
      online.set(address, client);

      const queued = inbox.get(address) || [];
      inbox.delete(address);
      // Catch-up delivery is mixed too (ROADMAP §8): a late registrant's burst
      // of queued messages enters the window instead of bursting out instantly,
      // which would leak exactly when and how much they missed. Preserve each
      // item's original ts so the TTL sweep still expires it.
      for (const item of queued) {
        enqueueRelay(address, item.envelope, { ts: item.ts });
      }
      sendLine(client, { type: 'published', address });
      if (VERBOSE) console.log(`[server] published+registered ${short(address)} (delivered ${queued.length} queued)`);
      break;
    }

    case 'fetch-shard': {
      // Private directory lookup (ANONYMITY.md Phase 1): the requester names a
      // SHARD, never an address. The relay returns every entry whose address
      // has that prefix, so its logs can only record "served shard #k" — it
      // cannot answer "who looked up whom". The requester selects the target
      // client-side from the self-signed bundles in the shard.
      const { shard } = msg;
      if (typeof shard !== 'string' || !shard || shard.length > 32) {
        sendLine(client, { type: 'error', error: 'valid shard id required' });
        return;
      }
      const entries = [];
      for (const [address, entry] of directory) {
        if (directoryShard(address, DIR_SHARD_BYTES) !== shard) continue;
        entries.push({
          address,
          bundle: entry.bundle,
          keyPackage: entry.keyPackage || null,
          oneTimePrekeys: [...entry.oneTimePrekeys.values()]
            .sort((a, b) => a.id - b.id)
            .map((o) => ({ id: o.id, dhPk: o.dhPk, signature: o.signature })),
        });
      }
      // No prekey is consumed server-side: the relay cannot know WHICH entry
      // the requester wanted, so single-use is enforced by the RECIPIENT
      // burning the prekey on first use (and republishing its smaller pool).
      // Deterministic per-sender selection (selectOneTimePrekey) keeps two
      // distinct senders from colliding on the same prekey.
      const payload = JSON.stringify({ type: 'directory-shard', shard, entries });
      if (payload.length > MAX_LINE_BYTES) {
        sendLine(client, { type: 'error', error: 'shard too large — raise DIR_SHARD_BYTES' });
        return;
      }
      sendLine(client, { type: 'directory-shard', shard, entries });
      if (VERBOSE) console.log(`[server] served shard ${short(shard)} (${entries.length} entries)`);
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
      // Same rule as publish: a late joiner's backlog goes through the mix window
      // (delivered to THIS client only, never re-broadcast to members who were
      // already online) with its original ts preserved for TTL.
      for (const item of queued) {
        enqueueRelay(group, item.envelope, { ts: item.ts, directTo: client });
      }
      sendLine(client, { type: 'subscribed', group });
      if (VERBOSE) console.log(`[server] client subscribed to group ${short(group)} (delivered ${queued.length} queued)`);
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

      // Cover traffic is DISCARDED at acceptance: never mixed, never queued,
      // never delivered, and never logged per-recipient (only this aggregate
      // counter). `sent` still acknowledges receipt so the sender's cadence
      // loop completes like any other frame.
      if (envelope.mode === 'cover') {
        coverDiscarded++;
        if (coverDiscarded % 1000 === 0) {
          console.log(`[server] discarded ${coverDiscarded} cover frame(s) (never queued)`);
        }
        sendLine(client, { type: 'sent', toPk });
        return;
      }

      // No per-recipient log line here (ANONYMITY.md §4): the relay must not
      // build a who→whom record in its own operator logs. Only an aggregate
      // counter is kept, so there is nothing to destroy, seize, or subpoena.
      relayedCount++;
      if (relayedCount % 1000 === 0) console.log(`[server] relayed ${relayedCount} message(s) (no per-recipient log kept)`);

      // Pair and group traffic enter the SAME mix window (ROADMAP §8): one batch
      // per window, so an observer cannot tell group-mode from pair-mode by
      // timing, let alone which member sent what. `sent` acknowledges relay
      // receipt immediately; delivery/queueing happens at window close (or
      // immediately when mixing is off).
      const result = enqueueRelay(toPk, envelope);
      if (!result.ok) {
        // With mixing ON the pool always accepts (capacity is enforced at flush
        // and a full queue drops + logs); with MIX_OFF a queue-full is reported
        // to the sender exactly as before mixing.
        sendLine(client, { type: 'error', error: result.error });
        return;
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
      if (line) handleLine(client, line).catch(() => {});
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
      if (trimmed) handleLine(client, trimmed).catch(() => {});
    }
  };
}

function dropClient(client) {
  if (client.pk && online.get(client.pk) === client) online.delete(client.pk);
  // Group subscriptions are connection-scoped: drop this client from every
  // group's fan-out set so stale entries never accumulate (VULN-004 pattern).
  for (const subs of groups.values()) subs.delete(client);
}

function handleTcpSocket(socket) {
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
}

// TLS on the client↔relay link (ANONYMITY.md §2) is ON by default: without it
// a passive network observer reads every routing field in the clear. The relay
// serves the committed loopback dev cert unless TLS_CERT/TLS_KEY point at the
// operator's own pair; TLS_OFF=1 is the explicit opt-out (plaintext) for
// debugging. If TLS is on and no keypair is found, the relay refuses to start —
// running plaintext must be a conscious decision, never an accident.
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const DEFAULT_TLS_CERT = path.join(__dirname, '..', 'tools', 'certs', 'dev-cert.pem');
const DEFAULT_TLS_KEY = path.join(__dirname, '..', 'tools', 'certs', 'dev-key.pem');
const TLS_OFF = process.env.TLS_OFF === '1' || process.env.TLS_OFF === 'true';
const TLS_CERT = process.env.TLS_CERT || DEFAULT_TLS_CERT;
const TLS_KEY = process.env.TLS_KEY || DEFAULT_TLS_KEY;
const useTls = !TLS_OFF;
let tlsOptions = null;
if (useTls) {
  if (!existsSync(TLS_CERT) || !existsSync(TLS_KEY)) {
    console.error(`[server] TLS is ON by default but no keypair found at:\n  cert: ${TLS_CERT}\n  key : ${TLS_KEY}\nProvide TLS_CERT/TLS_KEY, or set TLS_OFF=1 to run plaintext.`);
    process.exit(1);
  }
  tlsOptions = { cert: readFileSync(TLS_CERT), key: readFileSync(TLS_KEY) };
}

const server = useTls
  ? tls.createServer(tlsOptions, handleTcpSocket)
  : createServer(handleTcpSocket);

// Bind the crypto core (sodium only) before any client can publish. The
// ML-KEM/ML-DSA graph is deferred to the FIRST publish (registration verifies
// the bundle signature), so a relay that only ever routes ciphertext never
// loads @noble/post-quantum — see the pqLoaded() report in the publish case.
sodium = await init();

// The WebSocket side shares the same TLS decision: WSS when TLS_CERT/TLS_KEY are
// set, plain WS otherwise.
const wsHttp = useTls ? https.createServer(tlsOptions) : http.createServer();
const wss = new WebSocketServer({ server: wsHttp, maxPayload: MAX_LINE_BYTES });
wsHttp.listen(WS_PORT, HOST, () => {
  console.log(`[server] ${useTls ? 'WSS' : 'WebSocket'} relay listening on ${HOST}:${WS_PORT}`);
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

// Mixing is scheduled on-demand by scheduleMixFlush() (the window opens on the
// first message). Announce the mode here so the operator knows it is active.
if (!MIX_OFF) {
  console.log(`[server] message mixing ON (window ${MIX_WINDOW_MS}ms, jitter ${MIX_JITTER_MS}ms) — set MIX_OFF=1 or MIX_WINDOW_MS=0 to disable`);
}
if (SANITIZE_LOG) {
  console.log('[server] log sanitization ON (--sanitize-log) — every log line passes through stripControls()');
}

server.listen(PORT, HOST, () => {
  console.log(`[server] ciphertext-only relay listening on ${HOST}:${PORT}${useTls ? ' (TLS)' : ' (plaintext)'}`);
  console.log('[server] The relay never sees plaintext or keys — only ciphertext envelopes.');
  console.log(`[server] retention: ${EPHEMERAL ? 'ephemeral — nothing is ever queued' : `${QUEUE_TTL_MS}ms TTL, memory-only`}, per-identity logs ${VERBOSE ? 'ON (verbose)' : 'OFF'}`);
  if (useTls) {
    console.log(`[server] TLS ON — ${TLS_CERT}; set TLS_OFF=1 to run plaintext.`);
  } else {
    console.log('[server] TLS OFF (opt-out) — routing fields are readable on the wire (see ANONYMITY.md §2).');
  }
  if (HOST !== '127.0.0.1' && HOST !== '::1') {
    console.warn(`[server] WARNING: bound to ${HOST}, not loopback. See the trust model in src/server.js.`);
  }
});
