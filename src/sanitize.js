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
 * Non-strings are returned unchanged so callers can still print a fallback
 * such as "<invalid>".
 */
export function stripControls(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/[\u0000-\u001f\u007f-\u009f\p{Cf}]/gu, '');
}
