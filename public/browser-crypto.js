import { Identity, Session, signingPayload, encodeBundle, decodeBundle, useSodium, loadPQ, RECEIPT, isReceipt } from './crypto-core.js';

/**
 * Browser adapter for the shared post-quantum hybrid Double Ratchet core
 * (public/crypto-core.js). Wire-compatible with src/crypto.js: the Node CLI
 * and this client can talk to each other through the same relay.
 *
 * The bare @noble/post-quantum specifiers inside crypto-core.js resolve through
 * the import map in index.html to the vendored copies in public/vendor/ — no
 * third-party CDN is contacted at runtime.
 *
 * libsodium is NOT loaded via <script defer> tags in the HTML anymore: the
 * vendored scripts are injected on first init() (the idle-time bootstrap), so
 * their ~192 KB brotli transfer (wrapper + inline WASM) stays out of the
 * initial parse — the same deferral as the @noble/post-quantum graph.
 */

let sodium = null;
let sodiumPromise = null;

/**
 * Inject the vendored libsodium scripts on first use (idempotent). They are
 * classic UMD scripts that set window.sodium, so dynamic import() cannot load
 * them — a <script> element injection is the module-graph equivalent. The src
 * is document-relative (both pages live at the public/ root). On failure the
 * cached promise resets, so a retried init() re-attempts the injection.
 */
function loadSodium() {
  if (!sodiumPromise) {
    sodiumPromise = (async () => {
      await injectScript('./vendor/libsodium/libsodium.js');
      await injectScript('./vendor/libsodium/libsodium-wrappers.js');
      await window.sodium.ready;
      sodium = window.sodium;
      useSodium(sodium);
      return sodium;
    })().catch((err) => { sodiumPromise = null; throw err; });
  }
  return sodiumPromise;
}

function injectScript(src) {
  return new Promise((resolve, reject) => {
    const el = document.createElement('script');
    el.src = src;
    el.onload = () => resolve();
    el.onerror = () => reject(new Error(`failed to load ${src}`));
    document.head.appendChild(el);
  });
}

/** Initialise libsodium and bind it to the shared core. Returns sodium. */
export async function init() {
  if (sodium) return sodium;
  await loadSodium();
  // Deliberately does NOT await loadPQ(): the ML-KEM-768/ML-DSA-65 graph is
  // fetched only when a session is first established (or fresh keygen runs),
  // keeping ~67 KB brotli of post-quantum code out of the page's bootstrap.
  return sodium;
}

export { Identity, Session, signingPayload, encodeBundle, decodeBundle, loadPQ, RECEIPT, isReceipt };
