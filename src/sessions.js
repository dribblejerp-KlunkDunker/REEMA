import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/**
 * Encrypted-at-rest session persistence for the CLI client.
 *
 * Double Ratchet state is held in memory only, so a restart leaves the peer
 * ahead in the ratchet and the conversation can never recover. This store
 * serializes every live session and encrypts it (crypto_secretbox) with a key
 * derived from this identity's own static DH secret, so only the holder of
 * .identity.json can read it back — the same trust boundary as the private
 * keys themselves. Rotating the identity changes the key, so stale sessions
 * simply fail to decrypt and are dropped.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SESSIONS_FILE = path.join(ROOT, '.sessions.json');

/** Deterministic encryption key bound to this identity. */
export function sessionStoreKey(sodium, identity) {
  return sodium.crypto_generichash(32, new Uint8Array(0), identity.sk);
}

/**
 * Load persisted sessions as a Map<peerPkB64, serializedState>. Returns an
 * empty Map when the file is absent, unreadable, or fails to decrypt (e.g.
 * after an identity rotation).
 */
export function loadSessions(sodium, identity) {
  if (!existsSync(SESSIONS_FILE)) return new Map();
  try {
    const raw = JSON.parse(readFileSync(SESSIONS_FILE, 'utf8'));
    const key = sessionStoreKey(sodium, identity);
    const box = sodium.from_base64(raw.box, sodium.base64_variants.ORIGINAL);
    const nonce = sodium.from_base64(raw.nonce, sodium.base64_variants.ORIGINAL);
    const plaintext = sodium.crypto_secretbox_open_easy(box, nonce, key);
    if (!plaintext) return new Map();
    const data = JSON.parse(sodium.to_string(plaintext));
    return new Map(Object.entries(data));
  } catch {
    return new Map();
  }
}

/** Persist a Map<peerPkB64, Session> encrypted at rest. */
export function saveSessions(sodium, identity, sessions) {
  const data = {};
  for (const [pk, session] of sessions) data[pk] = session.serialize();
  const key = sessionStoreKey(sodium, identity);
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const box = sodium.crypto_secretbox_easy(new TextEncoder().encode(JSON.stringify(data)), nonce, key);
  writeFileSync(
    SESSIONS_FILE,
    JSON.stringify({
      v: 1,
      nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
      box: sodium.to_base64(box, sodium.base64_variants.ORIGINAL),
    }),
    { encoding: 'utf8', mode: 0o600 }
  );
}
