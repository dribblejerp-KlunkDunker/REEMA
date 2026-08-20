// public/sanitize.js
// Browser twin of src/sanitize.js — the control-character layer
// (stripControls) and the shortKey() short-rendering, dependency-free so the
// dashboard's console/toast display path gets the same VULN-005/006
// protection as the relay and the CLI client.
//
// DELIBERATE DIVERGENCE: the Node-side sanitizer additionally NORMALIZES
// homoglyph confusables (Cyrillic/Greek lookalikes rewritten to their ASCII
// bases, so a routing key cannot spoof a known address in the operator
// console) using the `confusables` npm dataset. That layer is not replicated
// here: this file must stay dependency-free, and the full dataset (~3.3k
// pairs) is too heavy to pull into the browser module graph. If the
// dashboard needs lookalike-resistant address rendering too, vendor a
// curated subset (Cyrillic/Greek/letterlike forms) into this file.
//
// Wire-controlled values (an envelope's senderDhPk is validated by the relay
// only as a non-empty string) must pass through stripControls()/shortKey()
// before being printed or rendered. Bidi/format controls (U+202E, U+2066-2069,
// …) make a string RENDER in a different order than its bytes (Trojan-Source);
// ESC/C0/C1 disable ANSI/OSC terminal sequences in consoles that interpret
// them. Keep both classes out of any sink that echoes attacker input.

export function stripControls(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/[\u0000-\u001f\u007f-\u009f\p{Cf}]/gu, '');
}

export function shortKey(pk) {
  if (typeof pk !== 'string') return '<invalid>';
  return stripControls(pk).slice(0, 16) + '...';
}
