/**
 * GroupSession — prototype of ROADMAP §7 "MLS group messaging" over the v6
 * relay, reusing `group_id` as a routing address.
 *
 * The relay already carries OPAQUE group-mode envelopes
 * ({ v: 6, mode: 'group', ciphertext }) to opaque group_ids and fans them out
 * to subscribers (the `subscribe` verb). This module is the client-side piece:
 *
 *   - `groupId = BLAKE2b-32(creatorAddress || label || nonce)` — a 32-byte
 *     value in the same 44-char base64 shape the relay already treats as a
 *     routing address, so a group is "just another address" to the relay;
 *   - every member holds a per-epoch symmetric group key (the epoch ratchets
 *     forward on a Commit, exactly when membership changes);
 *   - joining happens through a WELCOME delivered over an existing v6 pair
 *     session (the design's "Welcome to the new member is a normal send to
 *     *their* address"), so no new wire verb is needed to join;
 *   - messages are XSalsa20-Poly1305 (crypto_secretbox) under the epoch key,
 *     with a per-sender message counter so nonces never repeat, padded to
 *     256-byte blocks like the pair flow.
 *
 * Honest simplifications vs RFC 9420 (the reason this is a PROTOTYPE, not
 * production MLS):
 *   - the epoch secret is a SHARED symmetric key, not a ratchet tree — so
 *     REMOVAL is out of scope (a removed member would keep the key until a
 *     Commit rotates it; there is no per-member leaf to kick);
 *   - sender authenticity is the epoch key (any member can forge), not
 *     per-leaf ML-DSA signatures — real MLS needs the tree for this;
 *   - replacement crypto is the open decision in ROADMAP §7 (openmls /
 *     mls-rs as WASM), keeping this exact relay wire shape.
 *
 * The module is environment-agnostic: libsodium is injected with useSodium()
 * (same contract as crypto-core.js).
 */
let sodium = null;

/** Bind a libsodium instance before constructing any GroupSession. */
export function useSodium(s) {
  sodium = s;
}

function needSodium() {
  if (!sodium) throw new Error('useSodium(sodium) must be called before constructing a GroupSession');
  return sodium;
}

const te = new TextEncoder();
const td = new TextDecoder();

function u32be(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; }
function u32le(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; }

function concatBytes(arrs) {
  const total = arrs.reduce((acc, b) => acc + b.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Pad to 256-byte blocks with a 4-byte big-endian length prefix (the pair
// flow pads plaintext the same way so ciphertext sizes hide message lengths).
function padBlock(bytes) {
  const len = bytes.length + 4;
  const padded = new Uint8Array(Math.ceil(len / 256) * 256);
  padded.set(u32be(bytes.length), 0);
  padded.set(bytes, 4);
  return padded;
}

function unpadBlock(padded) {
  const len = new DataView(padded.buffer, padded.byteOffset, 4).getUint32(0, false);
  return padded.slice(4, 4 + len);
}

export class GroupSession {
  /**
   * @param {object} init
   * @param {string} init.groupId    44-char b64 — the relay's routing address
   * @param {number} init.epoch      current MLS-style epoch (>= 0)
   * @param {Uint8Array} init.epochKey  32-byte shared group key for the epoch
   * @param {string[]} init.members  sorted b64 member addresses
   * @param {string|null} init.creator   b64 creator address
   * @param {string} init.myAddress  THIS member's b64 address
   */
  constructor({ groupId, epoch, epochKey, members, creator, myAddress }) {
    this.groupId = groupId;
    this.epoch = epoch;
    this.epochKey = epochKey;
    this.prevEpochKey = null; // one-epoch lookback so self-delivered Commits apply
    this.members = [...members];
    this.creator = creator;
    this.myAddress = myAddress;
    this.sent = 0;                 // per-epoch send counter (nonce uniqueness)
    this.seen = new Set();         // `${sender}:${epoch}:${n}` replay guard
  }

  /**
   * Create a new group: derive groupId from the creator + label + nonce.
   * `members` is the initial invitee roster (the creator is always included),
   * so the first Welcome carries the full epoch-0 membership.
   */
  static create({ creatorAddress, label, nonce, members = [], myAddress }) {
    const s = needSodium();
    const groupId = s.to_base64(
      s.crypto_generichash(32, concatBytes([te.encode(creatorAddress), te.encode(label), nonce])),
      s.base64_variants.ORIGINAL
    );
    return new GroupSession({
      groupId,
      epoch: 0,
      epochKey: s.randombytes_buf(32),
      members: [...new Set([...members, myAddress])],
      creator: creatorAddress,
      myAddress,
    });
  }

  /** Serialize the current epoch state into a Welcome (sent via a pair session). */
  makeWelcome() {
    const s = needSodium();
    return JSON.stringify({
      v: 1,
      type: 'group-welcome',
      groupId: this.groupId,
      epoch: this.epoch,
      epochKey: s.to_base64(this.epochKey, s.base64_variants.ORIGINAL),
      members: [...this.members].sort(),
      creator: this.creator,
    });
  }

  /** Reconstruct a GroupSession from a Welcome (validates shape + membership). */
  static fromWelcome(welcomeJson, myAddress) {
    const s = needSodium();
    let w;
    try { w = JSON.parse(welcomeJson); } catch { throw new Error('invalid group welcome'); }
    if (!w || w.v !== 1 || w.type !== 'group-welcome' || typeof w.groupId !== 'string' || !w.groupId ||
        !Number.isInteger(w.epoch) || w.epoch < 0 || typeof w.epochKey !== 'string' || !Array.isArray(w.members)) {
      throw new Error('malformed group welcome');
    }
    if (!w.members.includes(myAddress)) throw new Error('welcome does not include this member');
    return new GroupSession({
      groupId: w.groupId,
      epoch: w.epoch,
      epochKey: s.from_base64(w.epochKey, s.base64_variants.ORIGINAL),
      members: w.members,
      creator: w.creator || null,
      myAddress,
    });
  }

  /**
   * Build an MLS-style KeyPackage for this member (ROADMAP §7): published via
   * the relay's `publish` verb and served back by `fetch-shard`, it is how
   * an existing member DISCOVERS a joinable peer (the Add half of
   * Add/Commit/Welcome). The relay stores it opaquely. `groupId`, when given,
   * is recorded as a `group_id` extension so the Add flow can verify the
   * KeyPackage is bound to the group being joined.
   */
  static makeKeyPackage(myAddress, { groupId = null } = {}) {
    const s = needSodium();
    const initKey = s.crypto_box_keypair(); // X25519 init key (MLS init_key)
    const extensions = [];
    if (groupId) extensions.push({ type: 'group_id', data: groupId });
    return {
      version: 1,
      cipher_suite: 0x0002, // X25519-based suite marker; opaque to the relay
      init_key: s.to_base64(initKey.publicKey, s.base64_variants.ORIGINAL),
      credential: { identity: myAddress },
      capabilities: { versions: [1], cipher_suites: [0x0002], extensions: ['group_id'] },
      extensions,
    };
  }

  /**
   * Validate a KeyPackage retrieved from the directory. With `groupId` set,
   * requires the `group_id` extension to match — a KeyPackage fetched for one
   * group cannot be used to Add into another.
   */
  static checkKeyPackage(kp, { groupId = null } = {}) {
    if (!kp || typeof kp !== 'object' || Array.isArray(kp)
        || !Number.isInteger(kp.version) || kp.version < 1
        || !Number.isInteger(kp.cipher_suite) || kp.cipher_suite < 0
        || typeof kp.init_key !== 'string' || !kp.init_key
        || !kp.credential || typeof kp.credential.identity !== 'string' || !kp.credential.identity
        || !kp.capabilities || typeof kp.capabilities !== 'object'
        || !Array.isArray(kp.extensions)) {
      throw new Error('malformed MLS key package');
    }
    if (groupId) {
      const ext = kp.extensions.find((e) => e && e.type === 'group_id');
      if (!ext || ext.data !== groupId) throw new Error('key package not bound to this group');
    }
    return kp;
  }

  /** Nonce for (sender, counter): BLAKE2b-24 keyed by the epoch key. */
  _nonce(key, sender, n) {
    const s = needSodium();
    return s.crypto_generichash(
      s.crypto_secretbox_NONCEBYTES,
      concatBytes([te.encode(sender), u32le(n)]),
      key
    );
  }

  /**
   * Encrypt `text` for the whole group as an opaque group-mode envelope —
   * the exact shape the relay's `isPlausibleEnvelope` accepts and routes by
   * group_id. `sender` + `n` let every member rebuild the nonce.
   */
  encrypt(text) {
    const s = needSodium();
    const n = ++this.sent;
    const ciphertext = s.crypto_secretbox_easy(padBlock(te.encode(String(text))), this._nonce(this.epochKey, this.myAddress, n), this.epochKey);
    return {
      v: 6,
      mode: 'group',
      epoch: this.epoch,
      sender: this.myAddress,
      n,
      ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    };
  }

  /**
   * Decrypt a group envelope. Accepts the current epoch (and the previous one
   * so self-delivered or one-epoch-stale Commits still apply). Rejects replays
   * and messages from members of a FUTURE epoch (they are not members here).
   */
  decrypt(env) {
    const s = needSodium();
    if (!env || env.mode !== 'group' || typeof env.sender !== 'string' || !env.sender ||
        !Number.isInteger(env.n) || env.n < 0 || typeof env.ciphertext !== 'string') {
      throw new Error('malformed group envelope');
    }
    const key = env.epoch === this.epoch
      ? this.epochKey
      : (env.epoch === this.epoch - 1 && this.prevEpochKey ? this.prevEpochKey : null);
    if (!key) throw new Error(`unknown group epoch ${env.epoch} (local epoch ${this.epoch})`);
    const seenKey = `${env.sender}:${env.epoch}:${env.n}`;
    if (this.seen.has(seenKey)) throw new Error('replayed group message');
    const padded = s.crypto_secretbox_open_easy(
      s.from_base64(env.ciphertext, s.base64_variants.ORIGINAL),
      this._nonce(key, env.sender, env.n),
      key
    );
    this.seen.add(seenKey);
    return td.decode(unpadBlock(padded));
  }

  /**
   * Build a Commit that ratchets the group to the next epoch (e.g. when a
   * member is added). Encrypted under the CURRENT epoch key, so every current
   * member can apply it; the new member gets the post-commit key via Welcome.
   */
  makeCommit({ secret, toMembers }) {
    const s = needSodium();
    const commit = {
      type: 'commit',
      toEpoch: this.epoch + 1,
      commitSecret: s.to_base64(secret, s.base64_variants.ORIGINAL),
      members: [...toMembers].sort(),
    };
    return { commit, envelope: this.encrypt(JSON.stringify(commit)) };
  }

  /** Advance the local epoch using a verified Commit (idempotent when already applied). */
  applyCommit(commitObj) {
    const s = needSodium();
    if (!commitObj || commitObj.type !== 'commit' || !Number.isInteger(commitObj.toEpoch) ||
        typeof commitObj.commitSecret !== 'string' || !Array.isArray(commitObj.members)) {
      throw new Error('malformed group commit');
    }
    if (commitObj.toEpoch < this.epoch) throw new Error('stale group commit');
    if (commitObj.toEpoch === this.epoch) return; // already applied (e.g. own Commit echoed back)
    const secret = s.from_base64(commitObj.commitSecret, s.base64_variants.ORIGINAL);
    if (secret.length !== 32) throw new Error('malformed commit secret');
    const nextKey = s.crypto_generichash(
      32,
      concatBytes([secret, u32le(commitObj.toEpoch), te.encode(JSON.stringify(commitObj.members))]),
      this.epochKey
    );
    this.prevEpochKey = this.epochKey;
    this.epochKey = nextKey;
    this.epoch = commitObj.toEpoch;
    this.members = [...commitObj.members];
    this.sent = 0;
    this.seen = new Set();
  }

  /**
   * Decrypt an incoming envelope and fold in a Commit if that is what it is.
   * Returns { commit } for a Commit, { text } for an application message.
   */
  handleIncoming(env) {
    const plain = this.decrypt(env);
    let obj = null;
    try { obj = JSON.parse(plain); } catch { /* not a commit */ }
    if (obj && obj.type === 'commit') {
      this.applyCommit(obj);
      return { commit: obj };
    }
    return { text: plain };
  }
}
