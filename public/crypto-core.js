/**
 * Shared post-quantum hybrid Double Ratchet — protocol v6.
 *
 *   Key exchange      : X25519 ECDH (static + signed prekey + per-epoch ephemerals)
 *   Key encapsulation : ML-KEM-768 (FIPS 203) — mixed into the root and every epoch
 *   Signatures        : ML-DSA-65 (FIPS 204) over the full envelope + prekey bundle
 *   Symmetric AEAD    : XSalsa20-Poly1305 (crypto_secretbox)
 *   Ratchet           : Signal-style Double Ratchet, symmetric bootstrap
 *
 * v6 prekey bundles + one-time prekeys. Every peer publishes a self-signed bundle
 * { staticDhPk, signPk, signedDhPk, kemPk, signature }. A session is
 * established from the peer's bundle, so:
 *
 *   - the root key is post-quantum: BLAKE2b(64, DH(signedDhSk, peer.signedDhPk),
 *     DH(staticSk, peer.staticPk)) — symmetric, computable by both sides;
 *   - the first message is post-quantum too: its chain is derived from
 *     DH(eph, peer.signedDhPk) mixed with an ML-KEM encapsulation to the
 *     peer's kemPk, and it carries the sender's bundle so the receiver can
 *     establish the session without a key directory;
 *   - there is no initiator/responder role. Either side may send the first
 *     message; two peers who both send their first message before receiving
 *     still converge (each receives the other's first chain directly).
 *
 * This module is environment-agnostic: it talks to libsodium through the
 * instance injected by useSodium(), and it lazily imports the ML-KEM-768 /
 * ML-DSA-65 implementations (loadPQ) only when crypto is first needed, so the
 * @noble/post-quantum graph (~67 KB brotli, incl. @noble/hashes + @noble/curves)
 * stays out of the page's initial module graph. Both the Node CLI (src/crypto.js)
 * and the browser client (public/browser-crypto.js) are thin adapters over this
 * one core. init() binds sodium only; loadPQ() is deferred to the first
 * operation that actually needs ML-KEM/ML-DSA (identity keygen, bundle/OTK
 * signing, bundle verification, or a session encrypt/decrypt), so a client
 * that restores a persisted identity and sessions never parses the PQ graph
 * until a session is first established. Every PQ-touching method guards with
 * requirePQ(), so forgetting to await loadPQ() fails loudly instead of
 * dereferencing null.
 */
let sodium = null;
let ml_kem768 = null; // bound by loadPQ() — see the init() contract below
let ml_dsa65 = null;
let pqPromise = null;

/**
 * Dynamically import the ML-KEM-768 / ML-DSA-65 implementations on first use
 * (idempotent — later calls reuse the same promise). They are the only reason
 * @noble/post-quantum and its @noble/hashes/@noble/curves dependencies are in
 * the module graph, so deferring them keeps them out of the initial page load:
 * they are fetched when identity keygen runs (fresh identity), when a bundle
 * or one-time prekey is signed/verified, or when a session is first
 * established — never at init(). Adapters re-export this; consumers await it
 * before the first operation that touches ML-KEM/ML-DSA, and every such
 * operation guards with requirePQ() so a missed await fails loudly.
 */
export function loadPQ() {
  if (!pqPromise) {
    pqPromise = Promise.all([
      import('@noble/post-quantum/ml-kem.js'),
      import('@noble/post-quantum/ml-dsa.js'),
    ]).then(([kem, dsa]) => {
      ml_kem768 = kem.ml_kem768;
      ml_dsa65 = dsa.ml_dsa65;
    });
  }
  return pqPromise;
}

/**
 * Whether the post-quantum graph (ML-KEM-768 / ML-DSA-65) has finished
 * loading via loadPQ(). The relay uses this to prove server-side deferral:
 * before the first publish arrives this must be false — i.e. zero
 * @noble/post-quantum modules have been loaded.
 */
export function pqLoaded() {
  return ml_kem768 !== null && ml_dsa65 !== null;
}

/**
 * Fail loudly if the PQ graph is not loaded yet. Every method that touches
 * ml_kem768 / ml_dsa65 calls this first, so a consumer that skipped
 * `await loadPQ()` gets a descriptive error instead of a null dereference.
 */
function requirePQ() {
  if (!ml_dsa65 || !ml_kem768) {
    throw new Error(
      'Post-quantum core (ML-KEM-768 / ML-DSA-65) is not loaded. ' +
      'Await loadPQ() (via the crypto adapter) before the first keygen, ' +
      'bundle sign/verify, or session encrypt/decrypt.'
    );
  }
}

/**
 * Bind a libsodium instance (libsodium-wrappers in Node, window.sodium in the
 * browser). Must be called — via an adapter's init() — before any Identity or
 * Session is constructed.
 */
export function useSodium(s) {
  sodium = s;
}

/** Refuse to derive more than this many skipped message keys for one message. */
const MAX_SKIP = 1000;
/** Cap on retained out-of-order message keys per session. */
const MAX_MKSKIP = 2000;
/** Cap on remembered ratchet epochs (each ~1.2 KB: dh + ML-KEM public key). */
const MAX_EPOCHS = 256;

/** Protocol v6 constant sizes (bytes). */
const SIZE = {
  dhPk: 32,        // X25519 public key
  signPk: 1952,    // ML-DSA-65 public key
  signature: 3309, // ML-DSA-65 signature
  kemPk: 1184,     // ML-KEM-768 public key
  kemCt: 1088,     // ML-KEM-768 ciphertext
  nonce: 24,       // XSalsa20-Poly1305 nonce
};

/**
 * Reserved plaintext a receiver sends back the moment it establishes a session
 * from a first message (a delivery receipt). It is an ordinary encrypted
 * message — no wire-format change — so only the intended peer can read it. The
 * receipt advances the receiver's sending chain and establishes the sender's
 * receiving chain, which is what lets a crashed sender self-heal: the receipt
 * is queued at the relay and decrypts on reconnect.
 */
export const RECEIPT = '\u0000receipt\u0000';
export const isReceipt = (plaintext) => plaintext === RECEIPT;

export class Identity {
  /**
   * @param {object} [keys] — all eight keypairs; omit to generate fresh.
   *   { signSk, signPk, sk, pk, signedDhSk, signedDhPk, kemSk, kemPk }
   */
  constructor(keys = {}) {
    if (keys.signSk && keys.signPk && keys.sk && keys.pk &&
        keys.signedDhSk && keys.signedDhPk && keys.kemSk && keys.kemPk) {
      this.signSk = keys.signSk;      // ML-DSA-65 secret key
      this.signPk = keys.signPk;      // ML-DSA-65 public key
      this.sk = keys.sk;              // X25519 static secret key (routing address)
      this.pk = keys.pk;              // X25519 static public key
      this.signedDhSk = keys.signedDhSk;   // X25519 signed-prekey secret key
      this.signedDhPk = keys.signedDhPk;   // X25519 signed-prekey public key
      this.kemSk = keys.kemSk;             // ML-KEM-768 secret key
      this.kemPk = keys.kemPk;             // ML-KEM-768 public key
    } else {
      requirePQ(); // fresh keygen needs ML-DSA-65 + ML-KEM-768
      const sigKp = ml_dsa65.keygen();
      this.signSk = sigKp.secretKey;
      this.signPk = sigKp.publicKey;

      const dhKp = sodium.crypto_box_keypair();
      this.sk = dhKp.privateKey;
      this.pk = dhKp.publicKey;

      const signedKp = sodium.crypto_box_keypair();
      this.signedDhSk = signedKp.privateKey;
      this.signedDhPk = signedKp.publicKey;

      const kemKp = ml_kem768.keygen();
      this.kemSk = kemKp.secretKey;
      this.kemPk = kemKp.publicKey;
    }
    // v6 one-time prekey pool (id -> { sk, pk }). Consumed per session for
    // first-message forward secrecy; persisted with the keyfile.
    this.oneTimePrekeys = keys.oneTimePrekeys instanceof Map ? keys.oneTimePrekeys : new Map();
  }

  /**
   * Generate a fresh one-time prekey, signed by signSk so the relay and any
   * peer fetching the directory can verify it belongs to this identity.
   */
  makeOneTimePrekey() {
    const kp = sodium.crypto_box_keypair();
    const id = sodium.randombytes_uniform(0x7fffffff);
    return { id, sk: kp.privateKey, pk: kp.publicKey, signature: this.sign(otkPayload(id, kp.publicKey)) };
  }

  /** Top up the one-time prekey pool to at least `n` unused prekeys. */
  newOneTimePrekeys(n) {
    while (this.oneTimePrekeys.size < n) {
      const otk = this.makeOneTimePrekey();
      this.oneTimePrekeys.set(otk.id, { id: otk.id, sk: otk.sk, pk: otk.pk, signature: otk.signature });
    }
  }

  /** Verify a one-time prekey is signed by the given signPk. */
  static verifyOneTimePrekey(signPk, otk) {
    if (!otk || typeof otk !== 'object' || !Number.isInteger(otk.id) || otk.id < 0) return false;
    let dhPk, sig;
    try {
      dhPk = fromB64(otk.dhPk);
      sig = fromB64(otk.signature);
    } catch { return false; }
    if (dhPk.length !== SIZE.dhPk || sig.length !== SIZE.signature) return false;
    return Identity.verify(signPk, otkPayload(otk.id, dhPk), sig);
  }

  /** Routing address bound to this identity: BLAKE2b(32, signPk || staticDhPk). */
  static deriveAddress(signPk, staticDhPk) {
    // The signing key is 1952 bytes — far beyond generichash's 64-byte key
    // limit, so hash the concatenation rather than using it as a key.
    return sodium.crypto_generichash(32, concatBytes([signPk, staticDhPk]));
  }

  sharedSecret(peerDhPk) {
    return sodium.crypto_box_beforenm(peerDhPk, this.sk);
  }

  signedSharedSecret(peerSignedDhPk) {
    return sodium.crypto_box_beforenm(peerSignedDhPk, this.signedDhSk);
  }

  sign(buf) {
    requirePQ();
    return ml_dsa65.sign(buf, this.signSk);
  }

  static verify(signPk, buf, sig) {
    requirePQ();
    try {
      return ml_dsa65.verify(sig, buf, signPk);
    } catch {
      // Malformed key or signature length — treat as a failed verification
      // rather than letting the exception escape as a different error class.
      return false;
    }
  }

  /**
   * Rebuild a v5 identity from the four v4 keypairs (sign + static DH),
   * generating fresh v5-only keypairs (signed prekey + ML-KEM-768). Used for
   * the in-place v4 -> v5 keyfile migration; the existing keys are preserved
   * so the routing address and signature identity are unchanged.
   */
  static fromLegacy(legacy) {
    const signedKp = sodium.crypto_box_keypair();
    const kemKp = ml_kem768.keygen();
    return new Identity({
      signSk: legacy.signSk, signPk: legacy.signPk,
      sk: legacy.sk, pk: legacy.pk,
      signedDhSk: signedKp.privateKey, signedDhPk: signedKp.publicKey,
      kemSk: kemKp.secretKey, kemPk: kemKp.publicKey,
    });
  }

  /** The peer's shareable identity: a self-signed prekey bundle. */
  makeBundle() {
    const payload = bundlePayload(this.pk, this.signPk, this.signedDhPk, this.kemPk);
    return {
      v: 6,
      staticDhPk: toB64(this.pk),
      signPk: toB64(this.signPk),
      signedDhPk: toB64(this.signedDhPk),
      kemPk: toB64(this.kemPk),
      signature: toB64(this.sign(payload)),
    };
  }

  /**
   * Verify a bundle is self-consistent (signed by its own signPk) and return
   * the decoded keys. Throws on any malformed or unsigned bundle.
   */
  static verifyBundle(bundle) {
    if (!bundle || typeof bundle !== 'object' || bundle.v !== 6) {
      throw new Error('Invalid prekey bundle version');
    }
    const staticDhPk = fromB64(bundle.staticDhPk);
    const signPk = fromB64(bundle.signPk);
    const signedDhPk = fromB64(bundle.signedDhPk);
    const kemPk = fromB64(bundle.kemPk);
    const sig = fromB64(bundle.signature);
    if (staticDhPk.length !== SIZE.dhPk || signPk.length !== SIZE.signPk ||
        signedDhPk.length !== SIZE.dhPk || kemPk.length !== SIZE.kemPk ||
        sig.length !== SIZE.signature) {
      throw new Error('Malformed prekey bundle field sizes');
    }
    if (!Identity.verify(signPk, bundlePayload(staticDhPk, signPk, signedDhPk, kemPk), sig)) {
      throw new Error('Prekey bundle signature verification failed');
    }
    return { staticDhPk, signPk, signedDhPk, kemPk };
  }
}

function toB64(u) { return sodium.to_base64(u, sodium.base64_variants.ORIGINAL); }
function fromB64(s) { return sodium.from_base64(s, sodium.base64_variants.ORIGINAL); }

/**
 * The directory-shard id for a routing address (ANONYMITY.md Phase 1, private
 * directory lookup): the first `shardBytes` bytes of the 32-byte address,
 * re-encoded. Both the relay and the client compute this identically, so a
 * `fetch-shard {shard}` request names a whole bucket — never one address — and
 * k-anonymity equals the shard's population.
 * @param {string} addressB64 — 44-char base64 routing address
 * @param {number} shardBytes — prefix length in bytes (default 1 → 256 shards)
 * @returns {string} base64 shard id
 */
export function directoryShard(addressB64, shardBytes = 1) {
  const raw = fromB64(addressB64);
  if (!Number.isInteger(shardBytes) || shardBytes < 1 || shardBytes > raw.length) {
    throw new Error('invalid directory shard size');
  }
  return toB64(raw.slice(0, shardBytes));
}

/**
 * Pick a one-time prekey from a shard-served pool, deterministically per
 * (sender, recipient). With whole-shard fetch the relay no longer consumes the
 * prekey server-side (it cannot know WHICH entry was wanted), so two distinct
 * senders could otherwise both pick the same prekey and the second's first
 * message would be dropped after the recipient burns the prekey. Deriving the
 * index from the sender's own address makes distinct senders pick distinct
 * prekeys (barring pool exhaustion or a hash collision), so single-use is
 * enforced recipient-side without a server-side consume.
 * @returns {object|null} the selected `{ id, dhPk, signature }`, or null if empty
 */
export function selectOneTimePrekey(senderAddressB64, recipientAddressB64, pool) {
  if (!Array.isArray(pool) || pool.length === 0) return null;
  const sorted = [...pool].sort((a, b) => a.id - b.id);
  const msg = new TextEncoder().encode(
    'reema-otk-select-v1\u0000' + senderAddressB64 + '\u0000' + recipientAddressB64
  );
  const h = sodium.crypto_generichash(32, msg);
  const idx = (h[0] * 256 + h[1]) % sorted.length;
  return sorted[idx];
}

/**
 * Encode a prekey bundle as a compact shareable string (base64 of the JSON).
 * This is the v5 replacement for the raw 32-byte X25519 key that v4
 * distributed: it carries the static DH key, signing key, signed prekey and
 * ML-KEM key plus the self-signature, so a peer can establish a session
 * without any key directory.
 */
export function encodeBundle(bundle) {
  return toB64(new TextEncoder().encode(JSON.stringify(bundle)));
}

/** Decode a shareable bundle string back into a bundle object. */
export function decodeBundle(str) {
  return JSON.parse(sodium.to_string(fromB64(str)));
}

function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return sodium.memcmp(a, b);
}

function u32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function concatBytes(parts) {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** Domain separator for one-time-prekey signatures (distinct from the bundle). */
const OTK_DOMAIN = new TextEncoder().encode('aegis-otk-v6');

/** Domain separator for the per-session delivery token (sealed sender). */
const TOKEN_DOMAIN = new TextEncoder().encode('aegis-session-token-v1');

/** Canonical encoding of a one-time prekey the signature covers. */
function otkPayload(id, dhPk) {
  return concatBytes([OTK_DOMAIN, u32be(id), u32be(dhPk.length), dhPk]);
}

/** Canonical, length-prefixed encoding of the prekey bundle the signature covers. */
function bundlePayload(staticDhPk, signPk, signedDhPk, kemPk) {
  return concatBytes([
    u32be(6),
    u32be(staticDhPk.length), staticDhPk,
    u32be(signPk.length), signPk,
    u32be(signedDhPk.length), signedDhPk,
    u32be(kemPk.length), kemPk,
  ]);
}

/**
 * Per-session delivery token (ANONYMITY.md Phase 1, sealed sender): a 32-byte
 * opaque id derived from the bootstrap DH secrets that ONLY the two peers can
 * compute. It is identical on both sides (replies need no negotiation round
 * trip), is never an address, and — because it mixes in the one-time prekey
 * when one is used — rotates per session. When the OTK pool is exhausted it
 * degrades to a per-identity-pair constant (the honest limit stated in
 * DESIGN-sealed-sender.md). The token is carried on the envelope so a recipient
 * can dispatch to the right session BEFORE decrypting; it is deliberately NOT
 * covered by the envelope signature (a relay could swap it to force a drop,
 * never a wrong-session decrypt).
 */
function deriveDeliveryToken(static_ss, signed_ss, otk_ss = new Uint8Array(0)) {
  return sodium.crypto_generichash(32, concatBytes([TOKEN_DOMAIN, static_ss, signed_ss, otk_ss]));
}

// ---- Double Ratchet KDFs ----
function KDF_RK(rk, dh_out) {
  const h = sodium.crypto_generichash(64, dh_out, rk);
  return [h.slice(0, 32), h.slice(32, 64)];
}

function KDF_CK(ck) {
  const next_ck = sodium.crypto_generichash(32, new Uint8Array([1]), ck);
  const mk = sodium.crypto_generichash(32, new Uint8Array([2]), ck);
  return [next_ck, mk];
}

function generateDH() {
  const keypair = sodium.crypto_box_keypair();
  return { sk: keypair.privateKey, pk: keypair.publicKey };
}

function DH(dh_pair, dh_pub) {
  return sodium.crypto_box_beforenm(dh_pub, dh_pair.sk);
}

/**
 * Canonical byte encoding of everything the envelope signature must cover.
 * The ratchet header (including the `first` flag) is signed, not just the
 * ciphertext, so no field can be mutated on a validly-signed envelope.
 * `recipientDhPk` is signed but NOT transmitted — the sender uses the peer's
 * key and the receiver substitutes its own, so an envelope minted for one
 * conversation cannot be replayed into another.
 */
export function signingPayload({ v, senderDhPk, senderSignPk, recipientDhPk, dh, pqPk, pqCt, pn, n, nonce, ciphertext, first = false, otkId = -1 }) {
  return concatBytes([
    u32be(v),
    u32be(senderDhPk.length), senderDhPk,
    u32be(senderSignPk.length), senderSignPk,
    u32be(recipientDhPk.length), recipientDhPk,
    u32be(dh.length), dh,
    u32be(pqPk.length), pqPk,
    u32be(pqCt.length), pqCt,
    u32be(pn),
    u32be(n),
    u32be(first ? 1 : 0),
    // -1 (0xFFFFFFFF) means "no one-time prekey used"; a real id is >= 0.
    u32be(otkId),
    u32be(nonce.length), nonce,
    u32be(ciphertext.length), ciphertext,
  ]);
}

export class Session {
  /**
   * Establish a session from the peer's verified prekey bundle. There is no
   * initiator/responder role: either side may send the first message.
   * @param {Identity} identity
   * @param {object} peerBundle — output of Identity#makeBundle()
   */
  constructor(identity, peerBundle, peerOneTimePrekey = null) {
    const peer = Identity.verifyBundle(peerBundle);
    this.identity = identity;
    this.peerDhPk = peer.staticDhPk;     // routing address
    this.peerSignPk = peer.signPk;       // pinned from the verified bundle
    this.peerSignedDhPk = peer.signedDhPk;
    this.peerKemPk = peer.kemPk;

    // Post-quantum root: hybrid over the static DH and the signed-prekey DH.
    const static_ss = identity.sharedSecret(this.peerDhPk);
    const signed_ss = identity.signedSharedSecret(this.peerSignedDhPk);
    let root = sodium.crypto_generichash(64, signed_ss, static_ss);

    // v6 one-time prekey (X3DH DH3) gives the bootstrap its own forward
    // secrecy. Two roles:
    //   - sender: peerOneTimePrekey = { id, dhPk, signature } from the key
    //     directory; verify it is signed by the bundle's signPk, then
    //     DH3 = DH(staticSk, peer.otkPk);
    //   - receiver: peerOneTimePrekey = { id, sk, pk } — our own OTK chosen
    //     by the sender (header.otk_id); DH3 = DH(otkSk, peer.staticPk).
    // Either way the same shared secret is mixed into the root.
    this.peerOneTimePrekeyId = null;
    let otk_ss = new Uint8Array(0);
    if (peerOneTimePrekey) {
      if (peerOneTimePrekey.sk) {
        otk_ss = sodium.crypto_box_beforenm(peer.staticDhPk, peerOneTimePrekey.sk);
      } else {
        if (!Identity.verifyOneTimePrekey(peer.signPk, peerOneTimePrekey)) {
          throw new Error('Invalid one-time prekey for session');
        }
        otk_ss = sodium.crypto_box_beforenm(fromB64(peerOneTimePrekey.dhPk), identity.sk);
      }
      root = sodium.crypto_generichash(64, otk_ss, root);
      this.peerOneTimePrekeyId = peerOneTimePrekey.id;
    }
    this.RK = root;
    // Sealed-sender delivery token: derived from the bootstrap secrets, so it
    // is identical on both sides and opaque to the relay (which never sees
    // these secrets). See deriveDeliveryToken().
    this.deliveryToken = deriveDeliveryToken(static_ss, signed_ss, otk_ss);

    this._firstBuilt = false; // true once a first message has been built (crash recovery)

    this.DHs = null;          // current ephemeral sending keypair (created lazily)
    this.DHr = null;          // peer's current ephemeral ratchet key
    this.PQs = null;          // current ML-KEM keypair (created lazily)
    this.PQr_pk = null;
    this.nextPqCt = new Uint8Array(0);

    this.CKs = null;
    this.CKr = null;
    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
    this.MKSKIP = new Map();

    // Per-epoch cache: ratchet key (b64 dh) -> the sender's ML-KEM material
    // { pk, ct } for that epoch. Used both to reject replayed old-epoch
    // envelopes (a dh we have already ratcheted past) and to reconstruct the
    // omitted `pq_pk` / `pq_ct` on same-epoch messages (the v6 envelope
    // shrink). Bounded so a very long conversation cannot grow it without
    // limit.
    this.epochs = new Map();
    this._lastSentDh = null; // b64 dh of the last sent message (envelope shrink)

    this._isFirstMessage = false; // transient: true only while building the first envelope
  }

  /**
   * Remember a ratchet epoch's KEM material, evicting the oldest epochs.
   * Entries are plain objects created here and never mutated, so a shallow
   * Map copy is enough for atomic snapshots.
   */
  _rememberEpoch(dhB64, epoch) {
    this.epochs.set(dhB64, epoch);
    while (this.epochs.size > MAX_EPOCHS) {
      this.epochs.delete(this.epochs.keys().next().value);
    }
  }

  /**
   * First send: derive the first sending chain from the peer's signed prekey
   * and an ML-KEM encapsulation, so the very first message is post-quantum.
   *
   * Deliberately does NOT advance the root key. The receiver derives the
   * matching chain from the same initial root, and the root only advances on
   * the first DH ratchet. If the sender's root advanced here, two peers who
   * both send first would each be one KDF step ahead in a different direction
   * and never converge — the simultaneous-first-message race.
   */
  _firstSend() {
    this._firstBuilt = true;
    this.DHs = generateDH();
    this.PQs = ml_kem768.keygen();
    const x = DH(this.DHs, this.peerSignedDhPk);         // eph0 × peer signed prekey
    const enc = ml_kem768.encapsulate(this.peerKemPk);   // to peer's KEM prekey
    const combined = sodium.crypto_generichash(64, enc.sharedSecret, x);
    const [, cks] = KDF_RK(this.RK, combined);
    this.CKs = cks;
    this.nextPqCt = enc.cipherText;
    this._isFirstMessage = true;
  }

  encrypt(plaintext) {
    requirePQ(); // first send or ratchet step needs ML-KEM-768
    if (this.CKs === null) this._firstSend();
    const isFirst = this._isFirstMessage;
    this._isFirstMessage = false;

    const [cks, mk] = KDF_CK(this.CKs);
    this.CKs = cks;

    const dh = this.DHs.pk;
    const pqPk = this.PQs.publicKey;
    const pqCt = this.nextPqCt;
    const pn = this.PN;
    const n = this.Ns;
    this.Ns += 1;

    const nonce = sodium.randombytes_buf(SIZE.nonce);
    const padded = padMessage(plaintext, 256);
    const ciphertext = sodium.crypto_secretbox_easy(padded, nonce, mk);

    // The signature always covers the FULL values; only the wire fields are
    // omitted, and the receiver substitutes the same values back, so the
    // signed payload reconstructs byte-for-byte.
    const signature = this.identity.sign(signingPayload({
      v: 6,
      senderDhPk: this.identity.pk,
      senderSignPk: this.identity.signPk,
      recipientDhPk: this.peerDhPk,
      dh, pqPk, pqCt, pn, n, nonce, ciphertext, first: isFirst,
      // otk_id lives in the header of the FIRST message only; steady-state
      // messages always sign -1 so the receiver reconstructs the payload
      // from the (absent) header field.
      otkId: isFirst && this.peerOneTimePrekeyId !== null ? this.peerOneTimePrekeyId : -1,
    }));

    // v6 envelope shrink. On non-first messages:
    //   - senderSignPk is omitted (the receiver reconstructs it from the peer
    //     key pinned at session creation — always known, so loss-safe);
    //   - pq_pk and pq_ct are omitted when this `dh` was sent before (same
    //     epoch). They are constant within an epoch, so the receiver
    //     reconstructs them from its per-epoch cache. The first message of an
    //     epoch is the one the receiver cannot recover without, so it is never
    //     omitted there.
    const header = { dh: toB64(dh), pn, n };
    if (isFirst || this._lastSentDh !== toB64(dh)) {
      header.pq_pk = toB64(pqPk);
      if (pqCt.length > 0) header.pq_ct = toB64(pqCt);
    }
    if (isFirst) {
      header.first = true;
      header.bundle = this.identity.makeBundle();
      if (this.peerOneTimePrekeyId !== null) header.otk_id = this.peerOneTimePrekeyId;
    }

    const envelope = {
      v: 6,
      senderDhPk: toB64(this.identity.pk),
      deliveryToken: toB64(this.deliveryToken),
      header,
      nonce: toB64(nonce),
      ciphertext: toB64(ciphertext),
      signature: toB64(signature),
    };
    if (isFirst) envelope.senderSignPk = toB64(this.identity.signPk);

    this._lastSentDh = toB64(dh);
    return envelope;
  }

  /**
   * Shallow copy of all mutable ratchet state. Key material is always replaced
   * wholesale (KDFs return fresh arrays, never mutate in place), so copying the
   * references is enough; only the collections need real copies.
   */
  _snapshot() {
    return {
      RK: this.RK, DHs: this.DHs, DHr: this.DHr,
      PQs: this.PQs, PQr_pk: this.PQr_pk, nextPqCt: this.nextPqCt,
      CKs: this.CKs, CKr: this.CKr,
      Ns: this.Ns, Nr: this.Nr, PN: this.PN,
      MKSKIP: new Map(this.MKSKIP),
      epochs: new Map(this.epochs),
      peerSignPk: this.peerSignPk,
      _isFirstMessage: this._isFirstMessage,
    };
  }

  /**
   * Decrypt atomically. A failed decryption leaves session state byte-for-byte
   * unchanged, so no envelope that reaches us — replay or forgery — can rewind
   * or burn the ratchet before its Poly1305 tag verifies.
   */
  decrypt(envelope) {
    requirePQ(); // first receive / ratchet step needs ML-KEM-768 + ML-DSA-65 verify
    const snapshot = this._snapshot();
    try {
      return this._decryptChecked(envelope);
    } catch (err) {
      Object.assign(this, snapshot);
      throw err;
    }
  }

  _decryptChecked(envelope) {
    const env = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;

    if (env.v !== 6) throw new Error(`Unsupported protocol version: ${env.v}`);
    if (!env.header) throw new Error('Envelope missing header');

    // senderSignPk is omitted on non-first messages; reconstruct it from the
    // peer key pinned at session creation. It is always known by the time a
    // non-first message can be processed (a fresh session rejects those), and
    // first messages always carry it.
    const senderSignPk = env.senderSignPk ? fromB64(env.senderSignPk) : this.peerSignPk;
    const senderDhPk = fromB64(env.senderDhPk);
    const nonce = fromB64(env.nonce);
    const ciphertext = fromB64(env.ciphertext);
    const signature = fromB64(env.signature);

    const header = env.header;
    const headerDh = fromB64(header.dh);
    // `first` is only present on the very first envelope; absence means false.
    // Anything else (string, number, object) is a malformed header.
    if (header.first !== undefined && typeof header.first !== 'boolean') {
      throw new Error('Invalid first flag');
    }
    const isFirst = header.first === true;
    if (!Number.isInteger(header.n) || header.n < 0 ||
        !Number.isInteger(header.pn) || header.pn < 0) {
      throw new Error('Invalid header counters');
    }
    // otk_id is optional (absent when no one-time prekey was used) and, when
    // present, must be a non-negative integer.
    if (header.otk_id !== undefined && (!Number.isInteger(header.otk_id) || header.otk_id < 0)) {
      throw new Error('Invalid one-time prekey id');
    }

    // pq_pk and pq_ct are omitted on same-epoch non-first messages; reconstruct
    // both from the per-epoch cache (populated when the epoch's first message,
    // which always carries them, was processed). A first message always carries
    // them; a message with a new ratchet key (new epoch) carries them too — the
    // receiver cannot reconstruct an epoch it has never seen. The wire value
    // wins when present, because that is exactly what the sender signed.
    let headerPqPk;
    let headerPqCt;
    if (header.pq_pk) {
      headerPqPk = fromB64(header.pq_pk);
      headerPqCt = header.pq_ct ? fromB64(header.pq_ct) : new Uint8Array(0);
    } else if (isFirst) {
      throw new Error('First message must carry its ML-KEM public key');
    } else {
      const epoch = this.epochs.get(header.dh);
      if (!epoch) {
        throw new Error('Omitted ML-KEM material for an unknown epoch — cannot authenticate');
      }
      headerPqPk = epoch.pk;
      headerPqCt = header.pq_ct ? fromB64(header.pq_ct) : epoch.ct;
    }
    if (isFirst && headerPqCt.length === 0) {
      throw new Error('First message must carry an ML-KEM ciphertext');
    }

    // The signature covers the header (including `first`), so this must run
    // before anything reads header fields to make decisions.
    const payload = signingPayload({
      v: env.v,
      senderDhPk, senderSignPk,
      recipientDhPk: this.identity.pk,
      dh: headerDh,
      pqPk: headerPqPk,
      pqCt: headerPqCt,
      pn: header.pn,
      n: header.n,
      nonce, ciphertext, first: isFirst,
      otkId: header.otk_id ?? -1,
    });
    if (!Identity.verify(senderSignPk, payload, signature)) {
      throw new Error('ML-DSA-65 signature verification failed — forged, tampered, or not addressed to us');
    }

    if (!equalBytes(senderDhPk, this.peerDhPk)) {
      throw new Error('Sender public key mismatch — envelope is not from this session peer');
    }
    if (this.peerSignPk !== null && !equalBytes(senderSignPk, this.peerSignPk)) {
      throw new Error('Peer signing key changed mid-session — refusing message');
    }

    if (isFirst) {
      // A first message establishes the receiving chain from our signed prekey
      // and KEM secret. It may only happen once per session: re-running it on
      // an established session would re-derive the root key from the already-
      // advanced RK and permanently corrupt the ratchet. The genuine peer
      // sends exactly one first message (the flag is one-shot), so any repeat
      // is a replay and must be refused.
      if (this.CKr !== null) {
        throw new Error('Duplicate first message — session already established');
      }
      this._establishFirst(headerDh, headerPqPk, headerPqCt);
    } else {
      const skipKey = `${header.dh}:${header.n}`;
      if (this.MKSKIP.has(skipKey)) {
        const mk = this.MKSKIP.get(skipKey);
        this.MKSKIP.delete(skipKey);
        return this._doDecrypt(mk, ciphertext, nonce);
      }

      if (this.DHr === null || !equalBytes(headerDh, this.DHr)) {
        // Reject envelopes from an epoch we already ratcheted past. The epochs
        // cache holds every dh we have seen, so a dh that is present but not
        // the current DHr is a past epoch.
        if (this.epochs.has(header.dh)) {
          throw new Error('Stale ratchet epoch — replayed envelope from a past epoch');
        }
        if (this.DHs === null) {
          throw new Error('No session established — expected a first message');
        }
        this.skipMessageKeys(header.pn);
        this.DHRatchet(headerDh, headerPqPk, headerPqCt);
      }

      // A message that did not trigger a ratchet must belong to a chain we
      // already have. Refuse to derive a key from a null chain (KDF on a null
      // chain key is a public constant — the pre-reply forgery).
      if (this.CKr === null) {
        throw new Error('No receiving chain — envelope is not from a known ratchet epoch');
      }
    }

    this.skipMessageKeys(header.n);

    const [ckr, mk] = KDF_CK(this.CKr);
    this.CKr = ckr;
    this.Nr += 1;

    const plaintext = this._doDecrypt(mk, ciphertext, nonce);

    if (this.peerSignPk === null) this.peerSignPk = senderSignPk;
    return plaintext;
  }

  /**
   * First receive: derive the receiving chain from the sender's first
   * ephemeral against our signed prekey, mixed with the ML-KEM decapsulation.
   *
   * Like _firstSend, this does NOT advance the root: the chain derives from
   * the initial root (this.RK is still initial here — neither side advanced it
   * during bootstrap), so both first directions converge regardless of who
   * sent first.
   *
   * The sending chain is advanced in exactly one case per exchange, so the
   * peer can still derive the receiving chain from the bootstrap keys it
   * knows:
   *   - responder (we have not sent first): always ratchet, so we can reply;
   *   - simultaneous firsts: only the side with the larger static key
   *     ratchets. Both sides compute this deterministically, so exactly one
   *     of them generates a fresh ephemeral; the other still holds its
   *     bootstrap key, which is the very value the ratcheting side derived
   *     from. This keeps forward secrecy advancing in the simultaneous flow
   *     instead of pinning the conversation to the bootstrap ephemerals.
   */
  _establishFirst(headerDh, headerPqPk, headerPqCt) {
    const x = sodium.crypto_box_beforenm(headerDh, this.identity.signedDhSk);
    const kem = ml_kem768.decapsulate(headerPqCt, this.identity.kemSk);
    const combined = sodium.crypto_generichash(64, kem, x);
    const [, ckr] = KDF_RK(this.RK, combined);
    this.CKr = ckr;
    this.DHr = headerDh;
    this.PQr_pk = headerPqPk;
    this._rememberEpoch(toB64(headerDh), { pk: headerPqPk, ct: headerPqCt });

    if (this.CKs === null) {
      this._ratchetSendStep();
    } else if (sodium.compare(this.identity.pk, this.peerDhPk) > 0) {
      // Mirror DHRatchet's counter handling: the new sending chain starts at
      // n=0 and the old chain's length is published as PN, so the peer skips
      // exactly the right number of message keys when this new epoch arrives.
      this.PN = this.Ns;
      this.Ns = 0;
      this._ratchetSendStep();
    }
  }

  _doDecrypt(mk, ciphertext, nonce) {
    const paddedPlaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, mk);
    if (!paddedPlaintext) throw new Error('Decryption failed');
    return sodium.to_string(unpadMessage(paddedPlaintext));
  }

  skipMessageKeys(until) {
    if (this.CKr === null) return;
    if (until - this.Nr > MAX_SKIP) {
      throw new Error(`Refusing to skip ${until - this.Nr} message keys (MAX_SKIP=${MAX_SKIP})`);
    }
    while (this.Nr < until) {
      const [ckr, mk] = KDF_CK(this.CKr);
      this.CKr = ckr;
      this.MKSKIP.set(`${toB64(this.DHr)}:${this.Nr}`, mk);
      this.Nr += 1;
    }
    // Evict oldest entries first — Map preserves insertion order.
    while (this.MKSKIP.size > MAX_MKSKIP) {
      this.MKSKIP.delete(this.MKSKIP.keys().next().value);
    }
  }

  /** Sending step of a DH ratchet: fresh ephemeral + KEM keypair, new sending chain. */
  _ratchetSendStep() {
    this.DHs = generateDH();
    this.PQs = ml_kem768.keygen();

    const x25519_shared_tx = DH(this.DHs, this.DHr);

    let pq_shared_tx = new Uint8Array(32);
    this.nextPqCt = new Uint8Array(0);

    if (this.PQr_pk && this.PQr_pk.length > 0) {
      const enc = ml_kem768.encapsulate(this.PQr_pk);
      pq_shared_tx = enc.sharedSecret;
      this.nextPqCt = enc.cipherText;
    }

    const combined_tx = sodium.crypto_generichash(64, pq_shared_tx, x25519_shared_tx);
    const [rk2, cks] = KDF_RK(this.RK, combined_tx);
    this.RK = rk2;
    this.CKs = cks;
  }

  /** Normal DH ratchet on receiving a message with a new ratchet key. */
  DHRatchet(headerDh, headerPqPk, headerPqCt) {
    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;
    this.DHr = headerDh;
    this.PQr_pk = headerPqPk;
    this._rememberEpoch(toB64(headerDh), { pk: headerPqPk, ct: headerPqCt });

    // ---- Receiving step: my current sending key × the peer's new key ----
    const x25519_shared_rx = DH(this.DHs, this.DHr);

    let pq_shared_rx = new Uint8Array(32);
    if (headerPqCt.length > 0) {
      pq_shared_rx = ml_kem768.decapsulate(headerPqCt, this.PQs.secretKey);
    }

    const combined_rx = sodium.crypto_generichash(64, pq_shared_rx, x25519_shared_rx);
    const [rk, ckr] = KDF_RK(this.RK, combined_rx);
    this.RK = rk;
    this.CKr = ckr;

    // ---- Sending step ----
    this._ratchetSendStep();
  }

  /**
   * Serialize the full ratchet state to a JSON-safe plain object, so a session
   * can survive a restart. Keep this in lockstep with restore() — the demo's
   * round-trip assertion (serialize -> restore -> serialize) catches drift.
   */
  serialize() {
    const b64 = (u) => toB64(u);
    const b64or = (u) => (u ? b64(u) : null);
    return {
      v: 6,
      peerDhPk: b64(this.peerDhPk),
      peerSignPk: b64(this.peerSignPk),
      peerSignedDhPk: b64(this.peerSignedDhPk),
      peerKemPk: b64(this.peerKemPk),
      deliveryToken: b64(this.deliveryToken),
      RK: b64(this.RK),
      DHs: this.DHs ? { sk: b64(this.DHs.sk), pk: b64(this.DHs.pk) } : null,
      DHr: b64or(this.DHr),
      PQs: this.PQs ? { secretKey: b64(this.PQs.secretKey), publicKey: b64(this.PQs.publicKey) } : null,
      PQr_pk: b64or(this.PQr_pk),
      nextPqCt: b64(this.nextPqCt),
      CKs: b64or(this.CKs),
      CKr: b64or(this.CKr),
      Ns: this.Ns, Nr: this.Nr, PN: this.PN,
      MKSKIP: [...this.MKSKIP.entries()].map(([k, v]) => [k, b64(v)]),
      epochs: [...this.epochs.entries()].map(([k, v]) => [k, { pk: b64(v.pk), ct: b64(v.ct) }]),
      // _lastSentDh is deliberately NOT persisted: after a restore the next
      // send includes the KEM material, which is always safe (the receiver
      // either has the epoch cached or ratchets on it).
      // Crash recovery: `firstBuilt` is an absolute one-shot — true once a
      // first message has been BUILT, and it is only ever persisted after the
      // envelope was handed to the transport (clients persist post-send). So a
      // restored session never re-flags as `first`: re-flagging would make an
      // established receiver reject the re-send as a duplicate first and stall
      // the conversation until the peer's reply. If the process crashed before
      // the first encrypt was persisted, no state exists at all and the
      // session starts fresh, re-sending a genuine first message.
      firstBuilt: this._firstBuilt === true,
    };
  }

  /** Reconstruct a session from serialize() output. */
  static restore(identity, data) {
    const unb64 = (s) => fromB64(s);
    const unb64or = (s) => (s ? unb64(s) : null);
    const s = Object.create(Session.prototype);
    s.identity = identity;
    s.peerDhPk = unb64(data.peerDhPk);
    s.peerSignPk = unb64(data.peerSignPk);
    s.peerSignedDhPk = unb64(data.peerSignedDhPk);
    s.peerKemPk = unb64(data.peerKemPk);
    // Sessions persisted before sealed sender have no token; re-derive it from
    // the static + signed DH secrets (the one-time prekey secret is gone, so
    // this token may differ from the peer's — dispatch falls back to
    // senderDhPk in that rare migration case).
    s.deliveryToken = data.deliveryToken
      ? unb64(data.deliveryToken)
      : deriveDeliveryToken(
          identity.sharedSecret(s.peerDhPk),
          identity.signedSharedSecret(s.peerSignedDhPk),
        );
    s.RK = unb64(data.RK);
    s.DHs = data.DHs ? { sk: unb64(data.DHs.sk), pk: unb64(data.DHs.pk) } : null;
    s.DHr = unb64or(data.DHr);
    s.PQs = data.PQs ? { secretKey: unb64(data.PQs.secretKey), publicKey: unb64(data.PQs.publicKey) } : null;
    s.PQr_pk = unb64or(data.PQr_pk);
    s.nextPqCt = unb64(data.nextPqCt);
    s.CKs = unb64or(data.CKs);
    s.CKr = unb64or(data.CKr);
    s.Ns = data.Ns; s.Nr = data.Nr; s.PN = data.PN;
    s.MKSKIP = new Map(data.MKSKIP.map(([k, v]) => [k, unb64(v)]));
    s.epochs = new Map((data.epochs || []).map(([k, v]) => [k, { pk: unb64(v.pk), ct: unb64(v.ct) }]));
    s._lastSentDh = null; // not persisted — next send includes the KEM material (safe)
    // Sessions persisted before the shrink have no epoch cache. Seed the
    // current epoch's public key (the ciphertext is not retained, so an
    // omitted-ct message is rejected until the next ratchet repairs it).
    if (s.DHr && s.PQr_pk && !s.epochs.has(toB64(s.DHr))) {
      s.epochs.set(toB64(s.DHr), { pk: s.PQr_pk, ct: new Uint8Array(0) });
    }
    s._firstBuilt = data.firstBuilt === true || data.firstSent === true;
    // Re-flag as first ONLY when no first message was ever built (crash before
    // the first encrypt was persisted). Once built and persisted, the first
    // message reached the transport — re-sending it as `first` would be
    // rejected by an established receiver (duplicate-first guard). A session
    // with a receiving chain is established regardless.
    s._isFirstMessage = !s._firstBuilt && s.CKr === null;
    return s;
  }
}

// ---- Metadata padding helper ----
function padMessage(buf, blockSize = 256) {
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

function unpadMessage(padded) {
  if (padded.length < 4) throw new Error('Invalid padded message');
  const len = ((padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3]) >>> 0;
  if (len > padded.length - 4) throw new Error('Invalid padding length');
  return padded.slice(4, 4 + len);
}

export { SIZE };
