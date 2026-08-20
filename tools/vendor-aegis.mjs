// Vendor SOVEREIGN // AEGIS's pure "brain" modules into public/aegis/, so the
// messenger (public/messenger.html) can import the SAME verdict and identity
// logic the standalone AEGIS app uses — one logic, not two drifting copies.
//
// These ten modules are the only AEGIS files the messenger needs, and they are
// all DOM-free at import time (the verdict + identity modules import cleanly in
// Node; the attempt-log recorder needs IndexedDB only at write time, so the
// browser E2E is where its recording is asserted). The UI-bound remainder of
// AEGIS stays out of this tree.
//
// Content is PINNED exactly like tools/vendor.mjs: every vendored file is
// recorded with its SHA-256 in tools/vendor-aegis-manifest.json, and `--check`
// verifies the on-disk files against those pins (offline, exit 0/1). The
// verdict logic decides whether a message gets flagged before it leaves the
// device, so a tampered or substituted copy would be a backdoored gate.
//
// The manifest also records each file's source path and source hash so drift
// from the AEGIS tree is detectable: `--check-source <aegisRoot>` compares the
// live AEGIS sources against the hashes recorded at vendor time.
//
//   node tools/vendor-aegis.mjs <aegisRoot>          vendor + write pins
//   node tools/vendor-aegis.mjs --check              verify public/aegis/ on disk
//   node tools/vendor-aegis.mjs --check-source <aegisRoot>   detect source drift
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT = fileURLToPath(new URL('..', import.meta.url));
const OUT = path.join(PROJECT, 'public', 'aegis');
const MANIFEST = path.join(PROJECT, 'tools', 'vendor-aegis-manifest.json');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// Default AEGIS root on this machine; overridable with AEGIS_ROOT or a positional
// arg so the script still works when the two trees live elsewhere. Only the
// regenerate paths need it — `--check` is fully offline.
const DEFAULT_AEGIS_ROOT = 'C:/Users/dribb/AI PROJECT FOLDER/blackvault-app/BLACKVAULT DASHBOARD/perimeter-suite/sovereign-aegis';

// dest (relative to public/aegis) -> source (relative to <aegisRoot>/js).
const FILES = {
  'verdad-service.js': 'verdad-service.js',
  'keybinding.js': 'keybinding.js',
  'crypto.js': 'crypto.js',
  'factcheck.js': 'factcheck.js',
  'security.js': 'security.js',
  'ingest.js': 'ingest.js',
  'modules/verdad.js': 'modules/verdad.js',
  // The competency spine's recorder: a near-share of a flagged claim writes an
  // attempt (context 'messenger') into the SAME append-only log AEGIS uses.
  'attempts.js': 'attempts.js',
  'attemptlog.js': 'attemptlog.js',
  'confidence.js': 'confidence.js',
};

const args = process.argv.slice(2);
const checkOnly = args.includes('--check');
const checkSource = args.includes('--check-source');

function readManifest() {
  if (!existsSync(MANIFEST)) {
    console.error(`no manifest at ${MANIFEST} — run "npm run vendor:aegis" to create the baseline`);
    return null;
  }
  return JSON.parse(readFileSync(MANIFEST, 'utf8'));
}

// Verify the on-disk vendored files against the pinned hashes (offline).
function checkVendored() {
  const manifest = readManifest();
  if (!manifest) return 1;
  const entries = Object.entries(manifest).sort();
  let bad = 0;
  for (const [file, meta] of entries) {
    const p = path.join(OUT, file);
    if (!existsSync(p)) { console.error(`MISSING   ${file}`); bad++; continue; }
    const actual = sha256(readFileSync(p));
    if (actual !== meta.sha256) {
      console.error(`MISMATCH  ${file}\n  expected ${meta.sha256}\n  actual   ${actual}`);
      bad++;
    } else {
      console.log(`ok        ${file}`);
    }
  }
  console.log(bad === 0
    ? `\nall ${entries.length} vendored AEGIS files verified against ${path.basename(MANIFEST)}`
    : `\n${bad} vendored AEGIS file(s) failed verification`);
  return bad === 0 ? 0 : 1;
}

// Compare the live AEGIS sources against the source hashes recorded at vendor
// time. Exit 1 on drift so a change to the AEGIS brain cannot silently diverge
// from the messenger's copy.
function checkSourceDrift(aegisRoot) {
  const manifest = readManifest();
  if (!manifest) return 1;
  let bad = 0;
  for (const [file, meta] of Object.entries(manifest)) {
    const src = path.join(aegisRoot, 'js', meta.source);
    if (!existsSync(src)) { console.error(`SOURCE MISSING  ${meta.source}`); bad++; continue; }
    const actual = sha256(readFileSync(src));
    if (actual !== meta.sourceSha256) {
      console.error(`SOURCE DRIFT   ${meta.source}\n  vendored from ${meta.sourceSha256}\n  now            ${actual}\n  run "npm run vendor:aegis" to re-vendor.`);
      bad++;
    } else {
      console.log(`source-ok    ${meta.source}`);
    }
  }
  console.log(bad === 0
    ? `\nall ${Object.keys(manifest).length} AEGIS sources match the vendored copies`
    : `\n${bad} AEGIS source(s) drifted from public/aegis/ — re-vendor`);
  return bad === 0 ? 0 : 1;
}

if (checkOnly) process.exit(checkVendored());
if (checkSource) {
  const root = args.find((a) => !a.startsWith('--')) || process.env.AEGIS_ROOT || DEFAULT_AEGIS_ROOT;
  if (!root) { console.error('--check-source requires the AEGIS root (or AEGIS_ROOT)'); process.exit(2); }
  process.exit(checkSourceDrift(root));
}

const aegisRoot = args.find((a) => !a.startsWith('--')) || process.env.AEGIS_ROOT || DEFAULT_AEGIS_ROOT;
if (!aegisRoot) {
  console.error('Usage: node tools/vendor-aegis.mjs <aegisRoot>\n  or set AEGIS_ROOT to the sovereign-aegis directory.');
  process.exit(2);
}

const JS = path.join(aegisRoot, 'js');
const manifest = {};
for (const [dest, source] of Object.entries(FILES)) {
  const src = path.join(JS, source);
  if (!existsSync(src)) { console.error(`MISSING source: ${src}`); process.exitCode = 1; continue; }
  const buf = readFileSync(src);
  const destPath = path.join(OUT, dest);
  mkdirSync(path.dirname(destPath), { recursive: true });
  copyFileSync(src, destPath);
  manifest[dest] = { sha256: sha256(buf), source, sourceSha256: sha256(readFileSync(src)) };
  console.log(`vendored  ${dest}  <-  ${source}`);
}

writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n');
console.log(`\nwrote ${MANIFEST} (${Object.keys(manifest).length} pinned files)`);
