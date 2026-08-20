/**
 * SOVEREIGN // AEGIS — Output Encoding & Sanitisation Primitives
 *
 * This module exists because SOVEREIGN // AEGIS ingests, by design, text authored by
 * hostile parties: pasted disinformation, dropped files, community case packs handed
 * over by third parties, and LLM output summarising all of the above.
 *
 * Any such value that reaches `innerHTML` unencoded is remote code execution against
 * the operator — and the operator's localStorage holds their signing key, their API
 * credentials, and their debiasing journal.
 *
 * Rule for this codebase:
 *   Every value interpolated into an HTML template literal MUST be wrapped in esc(),
 *   unless it is a locally-constructed HTML fragment (in which case name it *Html or
 *   pass it through markSafe()).
 *
 * @module security
 */

const HTML_ENTITIES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
  '=': '&#61;'
};

const HTML_UNSAFE = /[&<>"'`=]/g;

/**
 * Marker for strings that are already trusted HTML and must not be re-encoded.
 * Kept deliberately minimal — a Symbol-tagged String wrapper, not a full VDOM.
 */
const SAFE = Symbol('aegis.safeHtml');

class SafeHtml {
  constructor(value) {
    this.value = String(value);
    this[SAFE] = true;
  }
  toString() {
    return this.value;
  }
}

/**
 * Mark a locally-constructed HTML fragment as trusted, exempting it from encoding.
 * Only ever call this on markup this codebase built itself — never on ingested data.
 *
 * @param {string} htmlFragment
 * @returns {SafeHtml}
 */
export function markSafe(htmlFragment) {
  return new SafeHtml(htmlFragment);
}

/**
 * Encode a value for safe interpolation into HTML text or a quoted attribute.
 *
 * Handles the shapes this codebase actually interpolates:
 *   - null / undefined  -> '' (matches prior template behaviour, which printed
 *                          "undefined"; empty string is the safer and saner render)
 *   - SafeHtml          -> passed through unencoded
 *   - Array             -> each element encoded, joined with '' (matches .map().join(''))
 *   - number / boolean  -> stringified, no encoding needed
 *   - everything else   -> String() then entity-encoded
 *
 * @param {*} value
 * @returns {string} HTML-safe string
 */
export function esc(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof SafeHtml || (value && value[SAFE])) return String(value);
  if (Array.isArray(value)) return value.map(esc).join('');
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return String(value).replace(HTML_UNSAFE, (ch) => HTML_ENTITIES[ch]);
}

/** Long-form alias. Identical to esc(). */
export const escapeHtml = esc;

/**
 * Encode a value for interpolation into a URL context (href/src or query string).
 * Rejects javascript:, data: and vbscript: schemes outright rather than encoding them,
 * since encoding does not neutralise a hostile scheme.
 *
 * @param {*} value
 * @returns {string}
 */
export function escUrl(value) {
  if (value === null || value === undefined) return '';
  const raw = String(value).trim();
  if (/^(javascript|data|vbscript):/i.test(raw.replace(/[\s\u0000-\u001F]/g, ''))) {
    return '#blocked';
  }
  return esc(raw);
}

/**
 * Recursively strip HTML-significant characters from every string in a parsed
 * third-party payload (imported case packs, restored backups).
 *
 * This is belt-and-braces alongside esc() at render time: it means a hostile pack is
 * declawed the moment it is parsed, so it cannot reach a render path this module has
 * not yet been applied to, and cannot lie dormant in localStorage waiting for one.
 *
 * Angle brackets are replaced rather than entity-encoded so the value stays correct
 * when read back into textContent, exported, or diffed.
 *
 * @param {*} node - parsed JSON value
 * @param {number} [depth=0]
 * @returns {*} structurally identical value with strings neutralised
 */
export function sanitizeDeep(node, depth = 0) {
  if (depth > 32) return null; // cheap cycle / zip-bomb guard
  if (node === null || node === undefined) return node;
  if (typeof node === 'string') {
    return node.replace(/[<>]/g, (ch) => (ch === '<' ? '‹' : '›'));
  }
  if (typeof node === 'number' || typeof node === 'boolean') return node;
  if (Array.isArray(node)) return node.map((v) => sanitizeDeep(v, depth + 1));
  if (typeof node === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(node)) {
      // Block prototype-pollution keys while we are already walking the tree.
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      clean[sanitizeDeep(k, depth + 1)] = sanitizeDeep(v, depth + 1);
    }
    return clean;
  }
  return null;
}

export default { esc, escapeHtml, escUrl, markSafe, sanitizeDeep };
