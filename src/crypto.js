import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const _sodium = require('libsodium-wrappers');

import { Identity, Session, signingPayload, encodeBundle, decodeBundle, useSodium, RECEIPT, isReceipt } from '../public/crypto-core.js';

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
  return sodium;
}

export { Identity, Session, signingPayload, encodeBundle, decodeBundle, RECEIPT, isReceipt };
