// Walk the ESM import graph from the noble entrypoints and copy only the
// reachable modules into public/vendor/, preserving package layout so the
// import map + relative specifiers resolve unchanged.
//
// Content is PINNED: every vendored file is recorded with its SHA-256 in
// tools/vendor-manifest.json, and `--check` verifies the on-disk files against
// those pins (offline, exit 0/1). public/vendor/ holds the entire runtime
// crypto stack — libsodium, @noble, age-encryption — so a tampered or
// substituted file would be a backdoored cipher; npm test runs the check as a
// stage, and tools/serve.mjs re-verifies at startup and refuses to serve
// vendor/ on mismatch. Re-pin deliberately: `npm run vendor` rewrites both
// public/vendor/ and the manifest.
//
// Run with:  node tools/vendor.mjs <root>            (vendor + write hash pins)
//            node tools/vendor.mjs --check           (verify public/vendor/ on disk, no network)
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const args = process.argv.slice(2);
const checkOnly = args.includes('--check');
const ROOT = args.find((a) => !a.startsWith('--')) || '.';
const NM = path.join(ROOT, 'node_modules');
const OUT = path.join(ROOT, 'public', 'vendor');

const VENDOR_MANIFEST = path.join(ROOT, 'tools', 'vendor-manifest.json');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// Throws-free offline verification: every pinned file must exist on disk with
// the exact pinned hash. Exits 1 on any MISSING/MISMATCH so CI fails loudly.
function checkVendor() {
  if (!existsSync(VENDOR_MANIFEST)) {
    console.error(`no hash manifest at ${VENDOR_MANIFEST} — run "npm run vendor" to create the baseline`);
    return 1;
  }
  const manifest = JSON.parse(readFileSync(VENDOR_MANIFEST, 'utf8'));
  const entries = Object.entries(manifest).sort();
  let bad = 0;
  for (const [file, expected] of entries) {
    const p = path.join(OUT, file);
    if (!existsSync(p)) { console.error(`MISSING   ${file}`); bad++; continue; }
    const actual = sha256(readFileSync(p));
    if (actual !== expected) {
      console.error(`MISMATCH  ${file}\n  expected ${expected}\n  actual   ${actual}`);
      bad++;
    } else {
      console.log(`ok        ${file}`);
    }
  }
  console.log(bad === 0
    ? `\nall ${entries.length} vendored crypto files verified against ${VENDOR_MANIFEST}`
    : `\n${bad} vendored file(s) failed verification`);
  return bad === 0 ? 0 : 1;
}

if (checkOnly) process.exit(checkVendor());

const ENTRIES = [
  '@noble/post-quantum/ml-kem.js',
  '@noble/post-quantum/ml-dsa.js',
  // age-encryption (vault-at-rest, ROADMAP/README "Vault at rest") — the
  // author's official TS implementation of age-encryption.org/v1; the walker
  // pulls @noble/ciphers, @noble/curves, @noble/hashes, @noble/post-quantum
  // and @scure/base along with it.
  'age-encryption/dist/index.js',
];

const IMPORT_RE = /(?:^|\s)(?:import|export)\s+(?:[\s\S]*?\sfrom\s+)?['"]([^'"]+)['"]/g;

/**
 * Resolve any specifier to a file path inside node_modules. Relative
 * specifiers are joined to the importing module; bare specifiers that are
 * already files (e.g. '@noble/hashes/utils.js') pass through; bare specifiers
 * that are package roots (e.g. '@scure/base') are resolved through the
 * package's exports/main entry point.
 */
function resolveSpec(spec, fromSpec) {
  if (spec.startsWith('.')) {
    return path.posix.normalize(path.posix.join(path.posix.dirname(fromSpec), spec));
  }
  try {
    if (statSync(path.join(NM, spec)).isFile()) return spec; // file path, keep as-is
  } catch { /* not a file — maybe a package root */ }
  // Package root: resolve its entry point (exports['.'] preferred, then main).
  const pkgJson = path.join(NM, spec, 'package.json');
  if (existsSync(pkgJson)) {
    const p = JSON.parse(readFileSync(pkgJson, 'utf8'));
    let entry = p.exports?.['.'] ?? p.main ?? 'index.js';
    if (typeof entry === 'object') entry = entry.import ?? entry.default ?? entry.require;
    if (typeof entry === 'string' && entry.startsWith('./')) entry = entry.slice(2);
    if (typeof entry === 'string') return `${spec}/${entry}`;
  }
  return spec; // give up; readFileSync below will report it missing
}

const seen = new Set();
const queue = [...ENTRIES];
const copied = [];

while (queue.length) {
  const spec = queue.shift();
  if (seen.has(spec)) continue;
  seen.add(spec);

  const src = path.join(NM, spec);
  const dest = path.join(OUT, spec);
  let code;
  try {
    code = readFileSync(src, 'utf8');
  } catch (e) {
    console.error(`MISSING: ${spec} (${e.code})`);
    process.exitCode = 1;
    continue;
  }

  mkdirSync(path.dirname(dest), { recursive: true });
  copyFileSync(src, dest);
  copied.push(spec);

  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(code)) !== null) {
    queue.push(resolveSpec(m[1], spec));
  }
}

// libsodium classic scripts
mkdirSync(path.join(OUT, 'libsodium'), { recursive: true });
for (const [from, to] of [
  ['libsodium/dist/modules/libsodium.js', 'libsodium/libsodium.js'],
  ['libsodium-wrappers/dist/modules/libsodium-wrappers.js', 'libsodium/libsodium-wrappers.js'],
]) {
  copyFileSync(path.join(NM, from), path.join(OUT, to));
  copied.push(to);
}

console.log(`vendored ${copied.length} files into public/vendor/`);
for (const c of copied.sort()) console.log('  ' + c);

const pkgs = [...new Set(copied.filter((c) => c.startsWith('@noble/')).map((c) => c.split('/').slice(0, 2).join('/')))];
console.log('\nimport map packages:', pkgs.join(', '));
writeFileSync(path.join(OUT, 'MANIFEST.txt'),
  `Vendored from node_modules at build time. Regenerate with: npm run vendor\n\n${copied.sort().join('\n')}\n`);

// Pin every vendored file: SHA-256 per relative path, mirroring the fonts
// manifest so --check / serve.mjs / CI can verify the served crypto bytes.
const vendorHashes = {};
for (const c of copied) vendorHashes[c] = sha256(readFileSync(path.join(OUT, c)));
writeFileSync(VENDOR_MANIFEST, JSON.stringify(vendorHashes, null, 2) + '\n');
console.log(`wrote ${VENDOR_MANIFEST} (${copied.length} pinned hashes)`);
