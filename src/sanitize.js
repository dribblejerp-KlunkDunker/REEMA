/**
 * Terminal-output sanitization shared by the relay and the CLI client.
 *
 * Control characters (C0, DEL, C1) are stripped so attacker-controlled
 * strings — a peer's decrypted message plaintext, or a routing key such as
 * `toPk` — cannot inject ANSI/OSC terminal escape sequences (clear screen,
 * OSC-8 hyperlinks, title changes) into the operator's console. This is the
 * fix for VULN-005 (relay `toPk` log) and VULN-006 (CLI plaintext display):
 * every echoed value must pass through this before printing.
 *
 * Stripping the ESC introducer (0x1b) is what disables the sequences; the
 * remaining printable payload (e.g. the OSC-8 URL text) is left in place as
 * inert literal text. The C1 range (0x80-0x9f) is also stripped so 8-bit
 * encodings of the same controls cannot slip through.
 *
 * Unicode format controls (the \p{Cf} category) are stripped as well, so
 * logs resist Trojan-Source style spoofing:
 *   - bidi overrides and embedding: U+202A LRE, U+202B RLE, U+202C PDF,
 *     U+202D LRO, U+202E RLO;
 *   - bidi isolates: U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI;
 *   - directional marks: U+061C ALM, U+200E LRM, U+200F RLM;
 *   - zero-width / invisible format chars: U+200B-U+200D, U+FEFF, U+2060
 *     word joiner, U+00AD soft hyphen, and the rest of \p{Cf}.
 * Bidi controls make a crafted string RENDER in a different order than its
 * bytes (a log line that looks like a benign success while the hostile part
 * reads first, or a URL whose visible text points elsewhere than the actual
 * target); zero-width chars can hide text entirely.
 *
 * Homoglyph confusables are NORMALIZED (VULN-005 extension): lookalike
 * characters from the full Unicode confusables dataset — Cyrillic/Greek and
 * letterlike forms such as U+0430 'а' for 'a', U+03BF 'ο' for 'o', U+212A
 * 'K' for 'K' — are rewritten to their ASCII bases before a key/address is
 * logged. Without this, a routing key written with lookalikes renders
 * IDENTICALLY to the genuine ASCII address in the operator console, letting
 * an attacker spoof "message from <known address>" or a group id. The
 * normalization is applied only to key/address RENDERING (shortKey/short),
 * never to message plaintext, whose content must reach the user untouched.
 *
 * Sink-level defense (--sanitize-log / RELAY_SANITIZE_LOG): the relay can
 * additionally route EVERY line it writes through stripControls() via
 * sanitizedLogger() — so even a future call site that forgets the per-field
 * short()/stripControls() discipline cannot emit a control character.
 *
 * Non-strings are returned unchanged so callers can still print a fallback
 * such as "<invalid>".
 */
import * as confusables from 'confusables';

// char -> lookalike base, from the `confusables` package (generated from
// Unicode's confusables.txt data). ASCII keys are dropped: the dataset
// includes '|' -> 'l' (a pipe is not a homoglyph attack, and rewriting it
// would corrupt genuine addresses that contain one), plus '1' -> '1' and
// ' ' -> ' ' identity no-ops. Identity entries (k === v) are dropped the
// same way. Values may expand to multi-char bases ('⓾' -> '10'); keys are
// always single code points.
const CONFUSABLE_MAP = new Map(
  [...confusables.confusablesMap]
    .filter(([k, v]) => !(k.length === 1 && k.charCodeAt(0) < 128) && k !== v)
);

export function stripControls(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/[\u0000-\u001f\u007f-\u009f\p{Cf}]/gu, '');
}

/**
 * Normalize Unicode confusable homoglyphs to their ASCII lookalike bases
 * (U+0430 'а' -> 'a', U+03BF 'ο' -> 'o', U+212A 'K' -> 'K', U+24FE '⓾' ->
 * '10', ...), so a routing key written with Cyrillic/Greek lookalikes cannot
 * spoof a genuine ASCII address in the operator console. Iteration is per
 * code point (keys are single code points; a lone surrogate half can never
 * match, so astral characters pass through byte-exact). The original string
 * is returned unchanged when nothing needed rewriting; non-strings are
 * returned unchanged too.
 */
export function normalizeConfusables(s) {
  if (typeof s !== 'string') return s;
  let out = '';
  let changed = false;
  for (const c of s) {
    const base = CONFUSABLE_MAP.get(c);
    if (base !== undefined) { out += base; changed = true; }
    else out += c;
  }
  return changed ? out : s;
}

/**
 * Wrap a logger (default `console`) so every string argument passes through
 * stripControls() before it is written — a sink-level last line of defense
 * for the relay's --sanitize-log / RELAY_SANITIZE_LOG mode. Every line the
 * relay writes is thus control-free even if a future code path forgets to
 * route a wire-controlled value through short()/stripControls() at the
 * call site. Non-string arguments are passed through untouched.
 */
export function sanitizedLogger(logger = console) {
  const wrap = (fn) => (...args) => fn(...args.map((a) => (typeof a === 'string' ? stripControls(a) : a)));
  return {
    log: wrap(logger.log.bind(logger)),
    error: wrap(logger.error.bind(logger)),
    warn: wrap(logger.warn.bind(logger)),
  };
}

/**
 * Short, display-safe rendering of a key/address for a console log line,
 * mirroring the relay's `short()`. The value may be wire-controlled (e.g. an
 * envelope's `senderDhPk`, which the relay only validates as a non-empty
 * string), so it must pass through stripControls() and normalizeConfusables()
 * BEFORE the slice — slicing first would keep the first 16 raw bytes of an
 * escape sequence (or a lookalike prefix) intact. Non-strings render as
 * "<invalid>" so a malformed value never crashes the display path.
 */
export function shortKey(pk) {
  if (typeof pk !== 'string') return '<invalid>';
  return normalizeConfusables(stripControls(pk)).slice(0, 16) + '...';
}
