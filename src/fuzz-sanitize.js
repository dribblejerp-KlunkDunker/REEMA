import { stripControls } from './sanitize.js';

/**
 * Property-based fuzzer for stripControls() — the control-character layer
 * behind the relay's per-field short() discipline AND its --sanitize-log
 * sink wrapper, so this directly verifies the function the hardened log mode
 * relies on.
 *
 * Random Unicode control/format sequences (C0, DEL, C1, and \p{Cf} bidi /
 * zero-width / tag / interlinear-annotation controls) are interleaved with
 * printable text at random positions and lengths, and every output is
 * asserted against the sanitizer's documented contract:
 *
 *   1. control-free: no C0 (U+0000-001F), DEL (U+007F), C1 (U+0080-009F),
 *      or Unicode format control (\p{Cf}) remains — "printable-safe";
 *   2. deletion-only: the output is exactly the input with control-class
 *      code points removed in order — nothing else may be altered, added,
 *      or reordered (independently recomputed in the harness, so the module
 *      cannot drift from its own spec);
 *   3. idempotent: stripping a stripped string is a no-op;
 *   4. printable input is byte-for-byte unchanged;
 *   5. output is never longer than input;
 *   6. non-strings pass through untouched.
 *
 * Deliberate boundaries are asserted too: U+2028/U+2029 (Zl/Zp line and
 * paragraph separators) are NOT in the strip set — they are whitespace
 * separators, not terminal escape machinery — and lone surrogates are
 * preserved byte-exact (the /u regex cannot match them, so they must pass
 * through).
 *
 * Seeded PRNG so a failure reproduces exactly (report the seed, rerun with
 * `node src/fuzz-sanitize.js <seed>` or SANITIZE_FUZZ_SEED=<seed>). Run via
 * `npm test` (or directly: `node src/fuzz-sanitize.js`).
 */

let failures = 0;
function assert(label, ok) {
  if (!ok) { console.log(`FAIL  ${label}`); failures++; }
}

// Deterministic PRNG (mulberry32) so a failing seed is reproducible.
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The spec classes, recomputed independently of stripControls itself.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\p{Cf}]/gu;      // for deletion check
const CONTROL_TEST = /[\u0000-\u001f\u007f-\u009f\p{Cf}]/u;     // non-global: stateless test
const isControl = (s) => CONTROL_TEST.test(s);

// ---- Hostile token pool: every code point stripControls targets ----
// C0 + DEL + C1 (enumerated), plus the \p{Cf} ranges known to the harness
// (bidi, zero-width, tags, interlinear annotations, ...). Any random
// candidate that tests as \p{Cf} in the running ICU is also admitted, so
// the corpus tracks the runtime's actual format-control set.
function buildHostilePool() {
  const cps = new Set();
  for (let cp = 0x0000; cp <= 0x001f; cp++) cps.add(cp);        // C0
  cps.add(0x007f);                                               // DEL
  for (let cp = 0x0080; cp <= 0x009f; cp++) cps.add(cp);        // C1
  const cfRanges = [
    [0x00AD, 0x00AD], [0x0600, 0x0605], [0x061C, 0x061C], [0x06DD, 0x06DD],
    [0x070F, 0x070F], [0x0890, 0x0891], [0x08E2, 0x08E2], [0x180E, 0x180E],
    [0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x206F],
    [0xFEFF, 0xFEFF], [0xFFF9, 0xFFFB], [0x110BD, 0x110BD], [0x110CD, 0x110CD],
    [0x13430, 0x13438], [0x1BCA0, 0x1BCA3], [0x1D173, 0x1D17A],
    [0xE0001, 0xE0001], [0xE0020, 0xE007F],
  ];
  for (const [lo, hi] of cfRanges) for (let cp = lo; cp <= hi; cp++) cps.add(cp);
  return [...cps].map((cp) => String.fromCodePoint(cp));
}

// Printable pool: ASCII, accented Latin, Cyrillic/Greek (confusables),
// CJK, astral (emoji/math), plus non-ASCII punctuation. U+2028/U+2029 and
// lone surrogates are deliberately here as boundary cases — they are NOT
// controls and must survive untouched.
const PRINTABLE = [
  'a', 'B', '0', '9', ' ', '_', '-', '.', '/', '|', '~', '!', '?',
  'é', 'ñ', 'а', 'г', 'ο', '汉', '𝔥', '😀', 'K', '⓾', '×', '\u2028', '\u2029',
  '\uD800', '\uDC00', '\uD83D\uDE00',
];

const hostilePool = buildHostilePool();

// ---- The four structural properties, checked per iteration ----
function checkProperties(input, out, iter) {
  // 1. control-free / printable-safe
  assert(`iter ${iter}: output is control-free (no C0/DEL/C1/Cf)`, !isControl(out));
  // 2. deletion-only: recompute the spec's deletion independently
  assert(`iter ${iter}: output is exactly input minus control-class chars, in order`,
    input.replace(CONTROL_RE, '') === out);
  // 3. idempotence
  assert(`iter ${iter}: stripControls is idempotent`, stripControls(out) === out);
  // 4. printable input unchanged (implied by 1+2, asserted for the claim)
  if (!isControl(input)) {
    assert(`iter ${iter}: printable-only input is byte-for-byte unchanged`, out === input);
  }
  // 5. length bound (implied by 2, asserted for the claim)
  assert(`iter ${iter}: output is never longer than input`, out.length <= input.length);
}

// One fuzz string: random hostile/printable interleaving with position bias
// (hostile runs forced to start/middle/end so boundary handling is hit).
function makeCase(rnd, maxLen) {
  const len = Math.floor(rnd() * rnd() * maxLen); // bias toward short strings
  let s = '';
  for (let i = 0; i < len; i++) {
    const hostile = rnd() < 0.45;
    if (hostile) {
      // Runs: repeat the same hostile token so runs of one char are covered.
      const t = hostilePool[Math.floor(rnd() * hostilePool.length)];
      const run = 1 + Math.floor(rnd() * 8);
      for (let k = 0; k < run && s.length < maxLen; k++) s += t;
    } else {
      s += PRINTABLE[Math.floor(rnd() * PRINTABLE.length)];
    }
  }
  // Sometimes graft a hostile run at a boundary.
  const r = rnd();
  if (r < 0.15 && s.length < maxLen) {
    const t = hostilePool[Math.floor(rnd() * hostilePool.length)];
    s = t.repeat(1 + Math.floor(rnd() * 5)) + s;
  } else if (r < 0.3 && s.length < maxLen) {
    const t = hostilePool[Math.floor(rnd() * hostilePool.length)];
    s = s + t.repeat(1 + Math.floor(rnd() * 5));
  }
  // Occasionally admit a random code point (dynamic \p{Cf} tracking).
  if (rnd() < 0.05) {
    const cp = Math.floor(rnd() * 0x110000);
    if (cp < 0xD800 || cp > 0xDFFF) s += String.fromCodePoint(cp);
  }
  return s.slice(0, maxLen);
}

function main() {
  const seed = Number(
    process.env.SANITIZE_FUZZ_SEED ?? process.argv[2] ?? 0x5A17A7E5
  ) >>> 0;
  const rnd = mulberry32(seed);

  // ---- Deliberate boundary probes (exact expectations) ----
  assert('Zl/Zp separators (U+2028/U+2029) are outside the strip set',
    stripControls('a\u2028b') === 'a\u2028b' && stripControls('a\u2029b') === 'a\u2029b');
  assert('lone surrogates are preserved byte-exact',
    stripControls('\uD800') === '\uD800' && stripControls('\uDC00') === '\uDC00');
  assert('empty string stays empty', stripControls('') === '');
  const obj = {}, arr = [];
  assert('non-strings pass through untouched',
    stripControls(undefined) === undefined && stripControls(42) === 42
    && stripControls(null) === null && stripControls(obj) === obj && stripControls(arr) === arr);

  // ---- Main fuzz loop ----
  let controlsRemoved = 0, maxInput = 0, maxOutput = 0;
  const NORMAL_ITERS = 50000;
  for (let i = 0; i < NORMAL_ITERS; i++) {
    const input = makeCase(rnd, 256);
    const out = stripControls(input);
    controlsRemoved += input.length - out.length;
    maxInput = Math.max(maxInput, input.length);
    maxOutput = Math.max(maxOutput, out.length);
    checkProperties(input, out, `normal#${i}`);
    if (failures > 0) {
      console.log(`      seed=0x${seed.toString(16)}, input=${JSON.stringify(input)}, out=${JSON.stringify(out)}`);
      break;
    }
  }

  // ---- Stress leg: large inputs (perf + regex sanity) ----
  const STRESS_ITERS = 250;
  for (let i = 0; i < STRESS_ITERS; i++) {
    const input = makeCase(rnd, 65536);
    const out = stripControls(input);
    controlsRemoved += input.length - out.length;
    maxInput = Math.max(maxInput, input.length);
    maxOutput = Math.max(maxOutput, out.length);
    checkProperties(input, out, `stress#${i}`);
    if (failures > 0) {
      console.log(`      seed=0x${seed.toString(16)}, stress input.length=${input.length}, out.length=${out.length}`);
      break;
    }
  }

  console.log(`[fuzz-sanitize] seed=0x${seed.toString(16)}, normal iters=${NORMAL_ITERS}, stress iters=${STRESS_ITERS}, controls removed=${controlsRemoved}, max input=${maxInput}cp, max output=${maxOutput}cp`);
  console.log(`\n${failures === 0 ? 'ALL FUZZ-SANITIZE ASSERTIONS PASSED' : `${failures} FUZZ-SANITIZE ASSERTION(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
