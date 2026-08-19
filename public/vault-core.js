import * as age from 'age-encryption';

/**
 * Vault-at-rest layer using the age file-encryption format
 * (age-encryption.org/v1).
 *
 * Exported vaults are standard age files: they decrypt with the `age` and
 * `rage` CLIs and with any age implementation, so a BlackVault backup is never
 * locked into this codebase. Two recipient kinds are supported:
 *   - an X25519 recipient (`age1...`) — universal interop, the default;
 *   - a passphrase (scrypt) — no keyfile to manage.
 * ASCII armor (PEM) is the default export format so a vault survives
 * text-based transport (email, chat, paste).
 *
 * This is the ONE implementation, shared by the Node CLI (`src/vault.js`
 * re-exports this module) and the browser dashboard (`public/index.html`
 * lazy-imports it through the import map). It imports only the
 * `age-encryption` package (FiloSottile/typage — the age author's official
 * TypeScript implementation of the format), which depends solely on @noble
 * crypto and Web-standard APIs and is vendored into `public/vendor/` by
 * `tools/vendor.mjs` — matching this project's dependency posture (libsodium +
 * @noble/post-quantum, no CDN at runtime).
 */

/**
 * Generate a fresh age identity + its recipient string.
 *
 * With `hybrid: true` the identity is POST-QUANTUM HYBRID (X25519 + ML-KEM-768,
 * the same construction the messenger uses in-band): the identity string is
 * `AGE-SECRET-KEY-PQ-1...` and the recipient `age1pq1...`. A hybrid file wraps
 * the file key in an `mlkem768x25519` stanza, so a quantum attacker cannot
 * break the X25519 layer alone — matching the app's threat model of
 * harvest-now/decrypt-later resistance at rest. Note: hybrid recipients
 * require age v1.2.0+ tooling; classical `age1...` stays the universal default.
 */
export async function generateVaultIdentity({ hybrid = false } = {}) {
  const identity = hybrid ? await age.generateHybridIdentity() : await age.generateIdentity();
  const recipient = await age.identityToRecipient(identity);
  return { identity, recipient };
}

/**
 * Encrypt `plaintext` (string or Uint8Array) to an age recipient and/or a
 * passphrase. Returns an armored (PEM) string by default, or the raw binary
 * age file with `armor: false`.
 *
 * @param {string|Uint8Array} plaintext
 * @param {object} [opts]
 * @param {string} [opts.recipient]  an `age1...` recipient
 * @param {string} [opts.passphrase] scrypt passphrase
 * @param {boolean} [opts.armor=true]
 * @returns {Promise<string|Uint8Array>}
 */
export async function exportVault(plaintext, { recipient, passphrase, armor = true } = {}) {
  if (!recipient && !passphrase) {
    throw new Error('exportVault: provide a recipient and/or a passphrase');
  }
  const enc = new age.Encrypter();
  if (recipient) enc.addRecipient(recipient);
  if (passphrase) enc.setPassphrase(passphrase);
  const bytes = await enc.encrypt(plaintext);
  return armor ? age.armor.encode(bytes) : bytes;
}

/**
 * Decrypt an age-encrypted vault (armored PEM string or raw bytes) with one or
 * more identities and/or a passphrase. Returns raw bytes by default, or a
 * UTF-8 string with `asText: true`.
 *
 * @param {string|Uint8Array} ciphertext
 * @param {object} [opts]
 * @param {string[]} [opts.identities]  `AGE-SECRET-KEY-1...` strings
 * @param {string} [opts.passphrase]    scrypt passphrase
 * @param {boolean} [opts.armored] auto-detected when omitted: PEM-armored text
 *                                 is decoded, a Uint8Array is treated as raw
 * @param {boolean} [opts.asText=false] decode the result as UTF-8 text
 * @returns {Promise<Uint8Array|string>}
 */
export async function importVault(ciphertext, { identities = [], passphrase, armored, asText = false } = {}) {
  if (!identities.length && !passphrase) {
    throw new Error('importVault: provide at least one identity or a passphrase');
  }
  const dec = new age.Decrypter();
  for (const id of identities) dec.addIdentity(id);
  if (passphrase) dec.addPassphrase(passphrase);
  const isArmored = armored ?? (typeof ciphertext === 'string' &&
    ciphertext.trimStart().startsWith('-----BEGIN AGE ENCRYPTED FILE-----'));
  let bytes;
  if (isArmored) {
    bytes = age.armor.decode(ciphertext);
  } else if (typeof ciphertext === 'string') {
    // The age body is raw binary (not base64), so a decoded string would have
    // already lost bytes — reject it rather than silently fail decryption.
    throw new Error('importVault: raw age is binary — pass a Buffer/Uint8Array, not a decoded string');
  } else {
    bytes = ciphertext;
  }
  return asText ? dec.decrypt(bytes, 'text') : dec.decrypt(bytes);
}
