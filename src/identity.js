import { Identity } from './crypto.js';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/**
 * Persistent identity management.
 *
 * Stores all eight keypairs in `.identity.json` at the project root:
 *   - ML-DSA-65 signing keys          (signSk / signPk)
 *   - X25519 static DH keys           (dhSk / dhPk)  — the routing address
 *   - X25519 signed-prekey DH keys    (signedDhSk / signedDhPk)
 *   - ML-KEM-768 keys                 (kemSk / kemPk)
 *
 * A v4 keyfile (sign + static DH only) is migrated in place on first load:
 * the existing keys are preserved and fresh signed-prekey + ML-KEM keypairs
 * are generated, so the routing address and signature identity are unchanged.
 *
 * IMPORTANT: `.identity.json` contains private keys. It is covered by
 * .gitignore. For a real app, store it in an OS keychain or secure enclave.
 */

// new URL('..', import.meta.url) already resolves to the project root directory.
// Do not wrap this in path.dirname() — that walks one level too far up and
// drops the keyfile outside the project (it used to land on the Desktop).
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const KEYFILE = path.join(ROOT, '.identity.json');

// Where the path bug used to write keys, so we can tell the user to clean up.
const LEGACY_KEYFILE = path.join(path.dirname(ROOT), '.identity.json');

function warnAboutLegacyKeyfile() {
  if (LEGACY_KEYFILE !== KEYFILE && existsSync(LEGACY_KEYFILE)) {
    console.warn(
      `[identity] WARNING: a stray private key from an older build exists at\n` +
      `           ${LEGACY_KEYFILE}\n` +
      `           It is no longer used. Delete it — it is outside the project and not gitignored.`
    );
  }
}

// One-time prekeys are kept topped up to this many, so a burst of new
// conversations never exhausts the pool before the client can refill it.
const OTK_POOL_SIZE = 20;

function writeKeyfile(sodium, id) {
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
  const otks = {};
  for (const [otkId, kp] of id.oneTimePrekeys || []) {
    otks[otkId] = { dhSk: b64(kp.sk), dhPk: b64(kp.pk) };
  }
  writeFileSync(
    KEYFILE,
    JSON.stringify({
      v: 6,
      signSk: b64(id.signSk),
      signPk: b64(id.signPk),
      dhSk: b64(id.sk),
      dhPk: b64(id.pk),
      signedDhSk: b64(id.signedDhSk),
      signedDhPk: b64(id.signedDhPk),
      kemSk: b64(id.kemSk),
      kemPk: b64(id.kemPk),
      oneTimePrekeys: otks,
    }),
    { encoding: 'utf8', mode: 0o600 }
  );
}

/** Persist the current keyfile (used after a one-time prekey is consumed). */
export function saveIdentity(sodium, id) {
  writeKeyfile(sodium, id);
}

export function loadOrCreateIdentity(sodium) {
  warnAboutLegacyKeyfile();

  const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);

  let id;
  let data = null;
  if (existsSync(KEYFILE)) {
    data = JSON.parse(readFileSync(KEYFILE, 'utf8'));
    if (data.signSk && data.signPk && data.dhSk && data.dhPk) {
      const legacy = {
        signSk: unb64(data.signSk),
        signPk: unb64(data.signPk),
        sk: unb64(data.dhSk),
        pk: unb64(data.dhPk),
      };
      if (data.signedDhSk && data.signedDhPk && data.kemSk && data.kemPk) {
        id = new Identity({
          ...legacy,
          signedDhSk: unb64(data.signedDhSk), signedDhPk: unb64(data.signedDhPk),
          kemSk: unb64(data.kemSk), kemPk: unb64(data.kemPk),
        });
      } else {
        // v4 -> v5 in-place migration: keep the routing address and signing
        // identity, generate the signed prekey + ML-KEM keypairs.
        console.log('[identity] migrated v4 keyfile to v5 (added signed prekey + ML-KEM-768 keypair)');
        id = Identity.fromLegacy(legacy);
      }
    } else {
      // A v3 (Ed25519) keyfile cannot be upgraded in place — the signing
      // algorithm changed. Fail loudly rather than silently replacing keys.
      throw new Error(
        `${KEYFILE} is not a v4/v5 identity (missing dhSk/dhPk).\n` +
        `It was created by an older Ed25519 build. Move it aside and re-run to generate v5 keys.`
      );
    }
  } else {
    id = new Identity();
  }

  // v6 one-time prekey pool: load persisted prekeys, then top up. A v5
  // keyfile has no pool field, so it silently gains one here (v5 -> v6).
  if (data && data.oneTimePrekeys && typeof data.oneTimePrekeys === 'object') {
    const otks = new Map();
    for (const [otkId, kp] of Object.entries(data.oneTimePrekeys)) {
      otks.set(Number(otkId), { sk: unb64(kp.dhSk), pk: unb64(kp.dhPk) });
    }
    id.oneTimePrekeys = otks;
  }
  if (id.oneTimePrekeys.size < OTK_POOL_SIZE) {
    id.newOneTimePrekeys(OTK_POOL_SIZE);
    writeKeyfile(sodium, id);
  }
  return id;
}

export { KEYFILE };
