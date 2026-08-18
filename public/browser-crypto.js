import { Identity, Session, signingPayload, encodeBundle, decodeBundle, useSodium, RECEIPT, isReceipt } from './crypto-core.js';

/**
 * Browser adapter for the shared post-quantum hybrid Double Ratchet core
 * (public/crypto-core.js). Wire-compatible with src/crypto.js: the Node CLI
 * and this client can talk to each other through the same relay.
 *
 * The bare @noble/post-quantum specifiers inside crypto-core.js resolve through
 * the import map in index.html to the vendored copies in public/vendor/ — no
 * third-party CDN is contacted at runtime.
 */

let sodium = null;

/** Initialise libsodium and bind it to the shared core. Returns sodium. */
export async function init() {
  if (sodium) return sodium;
  await window.sodium.ready;
  sodium = window.sodium;
  useSodium(sodium);
  return sodium;
}

export { Identity, Session, signingPayload, encodeBundle, decodeBundle, RECEIPT, isReceipt };
