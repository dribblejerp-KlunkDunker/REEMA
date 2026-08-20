/**
 * SOVEREIGN // AEGIS — zero-click claim ingestion
 *
 * Pure helpers for the two surfaces that hand a claim to VERDAD from outside:
 *
 *   1. the `?verify=` deep link — a URL that carries claim text into the app;
 *   2. the bookmarklet — a `javascript:` snippet the operator installs in their
 *      browser, which grabs the current page's selection and navigates here.
 *
 * This module deliberately does no DOM and no I/O. The parsing rules are the one
 * part of the feature an attacker can reach with a crafted URL (the `verify` query
 * parameter), so they are kept in a pure function and unit-tested rather than
 * buried in a boot handler where a regression would be invisible.
 *
 * @module ingest
 */

/** Ceiling on how much shared text the app will ingest. A shared claim is a claim,
 *  not a document; the cap also bounds what a hostile deep link can make us hold. */
export const VERIFY_MAX_CHARS = 8000;

/**
 * Decode a base64url-ish payload into text, in both browser and Node.
 *
 * `atob` exists in browsers and modern Node; `Buffer` covers older Node runtimes.
 * Returns a UTF-8 string.
 * @private
 */
function b64ToText(b64) {
  // The `b64:` form is base64url, not standard base64: `+` and `/` are URL-unsafe and
  // `+` is decoded to a space by URLSearchParams before this ever runs. So translate
  // the URL-safe alphabet back, restore padding, and decode.
  let standard = b64.replace(/-/g, '+').replace(/_/g, '/');
  const rem = standard.length % 4;
  if (rem === 1) throw new Error('invalid base64 length');
  if (rem === 2) standard += '==';
  else if (rem === 3) standard += '=';

  if (typeof atob === 'function') {
    const bin = atob(standard);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(standard, 'base64').toString('utf8');
  }
  throw new Error('No base64 decoder available');
}

/**
 * Turn a raw `verify` parameter value into claim text.
 *
 * Accepts plain URL-encoded text, and a `b64:`-prefixed **base64url** form for text
 * that is hostile to being left as a raw query value. Anything unparseable is `null`
 * rather than a guess: a malformed shared link must land nowhere, not somewhere
 * wrong.
 *
 * @param {string} raw
 * @returns {string|null}
 */
export function decodeVerifyText(raw) {
  if (typeof raw !== 'string') return null;
  let text = raw;
  if (raw.startsWith('b64:')) {
    try {
      text = b64ToText(raw.slice(4));
    } catch {
      return null;
    }
  }
  text = text.trim();
  if (!text) return null;
  return text.length > VERIFY_MAX_CHARS ? text.slice(0, VERIFY_MAX_CHARS) : text;
}

/**
 * Extract a claim from a query string, e.g. `"?verify=<text>"` or `"?verify=b64:<…>"`.
 *
 * @param {string} search - `window.location.search`
 * @returns {string|null}
 */
export function parseVerify(search) {
  if (typeof search !== 'string') return null;
  const params = new URLSearchParams(search);
  const raw = params.get('verify');
  if (raw === null) return null;
  return decodeVerifyText(raw);
}

/**
 * Build the bookmarklet snippet for a given app URL.
 *
 * The snippet runs in the SOURCE page's context (never this app's), so it is
 * unaffected by this app's Content-Security-Policy. It reads the page selection
 * and navigates to `<base>?verify=<selection>`.
 *
 * @param {string} baseUrl - e.g. `window.location.origin + window.location.pathname`
 * @returns {string} a `javascript:` bookmarklet URL
 */
export function buildBookmarklet(baseUrl) {
  const base = String(baseUrl || '').split('?')[0].split('#')[0];
  const src =
    "(function(){var s=(window.getSelection?window.getSelection().toString():'').trim();" +
    "if(!s){alert('Select the claim text first, then run this bookmarklet.');return;}" +
    "location.href='" + base + "?verify='+encodeURIComponent(s);})();";
  return 'javascript:' + src;
}

export default { parseVerify, decodeVerifyText, buildBookmarklet, VERIFY_MAX_CHARS };
