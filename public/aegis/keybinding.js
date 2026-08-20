/**
 * SOVEREIGN // AEGIS — DID ↔ Reema key-binding credential
 *
 * The messenger runs on TWO identities (see DESIGN-aegis-reema-seam.md):
 *   - AEGIS DID (WebCrypto ECDSA P-256, did:key) — signs attestations/credentials.
 *   - Reema routing address (X25519 + ML-DSA-65 + ML-KEM-768) — encrypts + routes.
 *
 * This module binds them with one signed statement: the operator asserts, under their
 * DID signature, that their DID is the attestation identity behind a given Reema
 * routing address and ML-DSA signing key. A peer verifies the DID signature, then knows
 * that credentials/prebunk cards signed by the DID belong to the same party as the
 * encrypted session — without either project changing its core.
 *
 * The load-bearing check is in verifyKeyBinding(): the embedded public key must hash to
 * the credential's issuer DID, or an attacker could sign with their own key and swap in
 * their own JWK. Rejecting that is asserted in tests.
 *
 * Pure module: imports only AegisCrypto, touches no DOM and no storage.
 *
 * @module keybinding
 */

import { AegisCrypto } from './crypto.js';

export const KEYBINDING_TYPE = 'KeyBindingCredential';
const SUBJECT_TYPE = 'KeyBinding';

/** @returns {{ok: false, reason: string}} */
function fail(reason) {
  return { ok: false, reason };
}

/**
 * The exact subject signed under the DID. Field names are load-bearing: verification
 * re-canonicalises this object, so a mismatch between what was signed and what is
 * verified fails closed.
 *
 * @param {{did: string, routingAddress: string, signPk: string, boundAt?: string}} args
 * @returns {{id: string, type: string, routingAddress: string, signPk: string, boundAt: string}}
 */
export function buildBindingSubject({ did, routingAddress, signPk, boundAt = new Date().toISOString() }) {
  if (typeof did !== 'string' || !did.startsWith('did:key:')) {
    throw new Error('[keybinding] issuer must be a did:key');
  }
  if (typeof routingAddress !== 'string' || routingAddress.length < 32) {
    throw new Error('[keybinding] routingAddress must be the 44-char Reema address');
  }
  if (typeof signPk !== 'string' || !signPk) {
    throw new Error('[keybinding] signPk must be the base64 Reema ML-DSA public key');
  }
  return { id: did, type: SUBJECT_TYPE, routingAddress, signPk, boundAt };
}

/**
 * Sign a binding credential.
 *
 * @param {CryptoKey|JsonWebKey} privateKey - AEGIS signing key (non-extractable CryptoKey or JWK)
 * @param {{did: string, routingAddress: string, signPk: string, publicKeyJwk: JsonWebKey, boundAt?: string}} args
 * @returns {Promise<object>} a W3C-style Verifiable Credential carrying the binding
 */
export async function signKeyBinding(privateKey, { did, routingAddress, signPk, publicKeyJwk, boundAt }) {
  if (!publicKeyJwk || typeof publicKeyJwk !== 'object') {
    throw new Error('[keybinding] publicKeyJwk is required so a verifier can check it matches the DID');
  }
  if (AegisCrypto.jwkToDidKey(publicKeyJwk) !== did) {
    throw new Error('[keybinding] publicKeyJwk does not match the issuer DID');
  }

  const subject = buildBindingSubject({ did, routingAddress, signPk, boundAt });
  const signature = await AegisCrypto.signStatement(privateKey, subject);

  const credential = AegisCrypto.exportVerifiableCredential(did, publicKeyJwk, subject, signature);
  credential.type = ['VerifiableCredential', KEYBINDING_TYPE];
  // Self-contained: a verifier who holds only this credential can check the JWK against
  // the issuer DID without a side channel.
  credential.publicKeyJwk = publicKeyJwk;
  return credential;
}

/**
 * Verify a binding credential.
 *
 * @param {object} credential
 * @param {{publicKeyJwk?: JsonWebKey}} [opts] - an already-trusted JWK, when the verifier
 *   prefers not to trust the embedded one. Defaults to the credential's embedded JWK.
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
export async function verifyKeyBinding(credential, opts = {}) {
  try {
    if (!credential || typeof credential !== 'object') return fail('missing credential');

    const issuer = credential.issuer;
    if (typeof issuer !== 'string' || !issuer.startsWith('did:key:')) {
      return fail('issuer is not a did:key');
    }

    const jwk = opts.publicKeyJwk || credential.publicKeyJwk;
    if (!jwk || typeof jwk !== 'object') return fail('missing public key');

    // THE check: the key used to verify must actually be the issuer's key. Without this,
    // an attacker signs with their own key and embeds their own JWK under the victim's DID.
    if (AegisCrypto.jwkToDidKey(jwk) !== issuer) {
      return fail('public key does not match issuer DID');
    }

    const subject = credential.credentialSubject;
    if (!subject || typeof subject !== 'object') return fail('missing credentialSubject');
    if (subject.type !== SUBJECT_TYPE) return fail('not a KeyBinding credential');
    if (subject.id !== issuer) return fail('subject id does not match issuer');
    if (typeof subject.routingAddress !== 'string' || !subject.routingAddress) return fail('missing routingAddress');
    if (typeof subject.signPk !== 'string' || !subject.signPk) return fail('missing signPk');

    const signature = credential.proof && credential.proof.jws;
    if (typeof signature !== 'string' || !signature) return fail('missing proof signature');

    const ok = await AegisCrypto.verifyStatement(jwk, subject, signature);
    return ok ? { ok: true } : fail('signature mismatch');
  } catch (err) {
    return fail(err && err.message ? err.message : String(err));
  }
}

export default { signKeyBinding, verifyKeyBinding, buildBindingSubject, KEYBINDING_TYPE };
