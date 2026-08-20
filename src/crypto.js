import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const _sodium = require('libsodium-wrappers');

import { Identity, Session, signingPayload, encodeBundle, decodeBundle, useSodium, loadPQ, pqLoaded, RECEIPT, isReceipt, directoryShard, selectOneTimePrekey } from '../public/crypto-core.js';

/**
 * Node adapter for the shared post-quantum hybrid Double Ratchet core
 * (public/crypto-core.js). The browser client uses the same core through
 * public/browser-crypto.js, so a fix in the core is a fix in both clients and
 * they interoperate over the same wire format.
 */

let sodium = null;

/** Initialise libsodium and bind it to the shared core. Returns sodium. */
export async function init() {
  if (sodium) return sodium;
  await _sodium.ready;
  sodium = _sodium;
  useSodium(sodium);
  // Deliberately does NOT await loadPQ(): ML-KEM/ML-DSA are fetched on first
  // use (keygen, bundle sign/verify, or session establishment) so a process
  // that only restores a persisted identity/sessions never parses the PQ
  // graph. Consumers must await loadPQ() before their first PQ operation.
  return sodium;
}

export { Identity, Session, signingPayload, encodeBundle, decodeBundle, loadPQ, pqLoaded, RECEIPT, isReceipt, directoryShard, selectOneTimePrekey };
