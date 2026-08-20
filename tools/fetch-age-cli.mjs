/**
 * Install the reference Go age CLI (filippo.io/age) into the repo, verified.
 *
 * The browser<->Go interop cross-checks in src/browser-e2e.js decrypt/encrypt
 * vaults with the real age binary. This script makes that install
 * reproducible and supply-chain-safe, matching the project's pinning posture
 * (fonts, vendored crypto):
 *
 *   - the VERSION and every supported platform artifact's SHA-256 are pinned
 *     here, computed from the official GitHub release (FiloSottile/age);
 *   - the archive is downloaded to a temp dir and its hash MUST match the pin
 *     before anything is written into the repo — a compromised release or
 *     MITM'd download is rejected, never installed;
 *   - the install is project-local (tools/.age-cli/, gitignored) — no global
 *     binary, no PATH pollution;
 *   - --check re-verifies the stored archive hash and that the binary runs and
 *     prints the pinned version (offline, no network).
 *
 * The pinned version (v1.3.1) is the minimum-age-v1.2.0+ needed for hybrid
 * (X25519 + ML-KEM-768) recipient interop, so the SAME binary drives both the
 * classical and the PQ-hybrid cross-checks.
 *
 * Run with:  node tools/fetch-age-cli.mjs            (install if missing/corrupt)
 *            node tools/fetch-age-cli.mjs --check    (verify the local install, no network)
 *            node tools/fetch-age-cli.mjs --print-path
 *            node tools/fetch-age-cli.mjs --force    (re-download even if verified)
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, renameSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CACHE = path.join(ROOT, 'tools', '.age-cli');

// Pinned release. SHA-256s were computed from the official GitHub release
// assets (https://github.com/FiloSottile/age/releases/tag/v1.3.1) at authoring
// time. Re-pin deliberately only after reviewing the release.
const VERSION = 'v1.3.1';
const ARTIFACTS = {
  'windows-amd64.zip': 'c56e8ce22f7e80cb85ad946cc82d198767b056366201d3e1a2b93d865be38154',
  'linux-amd64.tar.gz': 'bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377',
  'darwin-arm64.tar.gz': '01120ea2cbf0463d4c6bd767f99f3271bbed1cdc8a9aa718a76ba1fe4f01998b',
  'darwin-amd64.tar.gz': '2b233301ad21ab7b1eabd9ae1198a164005fa4928fcdd745d47c39f8593209d7',
};
const BASE_URL = `https://github.com/FiloSottile/age/releases/download/${VERSION}`;

// ---- platform resolution -----------------------------------------------------

function platformArtifact() {
  const os = process.platform; // win32 | linux | darwin | ...
  const arch = process.arch;   // x64 | arm64 | ...
  const archName = arch === 'x64' ? 'amd64' : arch === 'arm64' ? 'arm64' : null;
  if (!archName) throw new Error(`unsupported arch: ${process.platform}/${process.arch}`);
  const ext = os === 'win32' ? 'zip' : 'tar.gz';
  if (os === 'win32' && archName !== 'amd64') throw new Error(`no pinned age artifact for ${os}/${arch}`);
  if (os === 'linux' && archName !== 'amd64' && archName !== 'arm64') throw new Error(`no pinned age artifact for ${os}/${arch}`);
  if (os !== 'win32' && os !== 'linux' && os !== 'darwin') throw new Error(`no pinned age artifact for ${os}/${arch}`);
  const artifact = `${os === 'win32' ? 'windows' : os}-${archName}.${ext}`;
  if (!ARTIFACTS[artifact]) throw new Error(`no pinned hash for ${artifact}`);
  return artifact;
}

export function ageCliDir() { return CACHE; }
export function ageCliBin() {
  const artifact = platformArtifact();
  return path.join(CACHE, 'bin', osBinName());
}
function osBinName() { return process.platform === 'win32' ? 'age.exe' : 'age'; }

// ---- helpers -----------------------------------------------------------------

const sha256 = (file) => {
  const h = createHash('sha256');
  h.update(readFileSync(file));
  return h.digest('hex');
};

function download(url, dest) {
  // No fetch dependency: curl exists on every platform this project runs on
  // (and on Windows it ships with Git Bash). Fail loudly on any HTTP error.
  const r = spawnSync('curl', ['-fsSL', '-m', '180', '-o', dest, url], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`download failed (curl ${r.status}): ${(r.stderr || r.stdout || '').trim().slice(0, 300)}`);
}

function extract(archive, dest) {
  // tar.gz → GNU tar everywhere. zip → Windows-native Expand-Archive (GNU tar
  // from Git Bash cannot read zips; the system bsdtar could, but PowerShell is
  // guaranteed present on Windows).
  let r;
  if (archive.endsWith('.zip')) {
    const destAbs = path.resolve(dest);
    const arcAbs = path.resolve(archive);
    r = spawnSync('powershell', ['-NoProfile', '-Command', `Expand-Archive -Force -LiteralPath '${arcAbs}' -DestinationPath '${destAbs}'`], { encoding: 'utf8' });
  } else {
    r = spawnSync('tar', ['-xzf', archive, '-C', dest], { encoding: 'utf8' });
  }
  if (r.status !== 0) throw new Error(`extract failed (${r.status}): ${(r.stderr || '').trim().slice(0, 300)}`);
  const bin = path.join(dest, 'age', osBinName());
  if (!existsSync(bin)) throw new Error(`extracted archive has no age/${osBinName()}`);
  return bin;
}

function verifyBinary(bin) {
  const r = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 10000 });
  if (r.status !== 0) return { ok: false, detail: `age --version exited ${r.status}` };
  const out = String(r.stdout || '').trim();
  if (!out.includes(VERSION)) return { ok: false, detail: `age --version printed "${out}", expected ${VERSION}` };
  return { ok: true, detail: out };
}

/** Verify the installed cache: stored archive hash + binary presence + version. */
function check(verbose = true) {
  const artifact = platformArtifact();
  const archive = path.join(CACHE, artifact);
  const bin = ageCliBin();
  if (!existsSync(archive)) { if (verbose) console.log(`[age-cli] MISSING ${archive} — run "node tools/fetch-age-cli.mjs"`); return false; }
  const actual = sha256(archive);
  if (actual !== ARTIFACTS[artifact]) {
    if (verbose) console.log(`[age-cli] HASH MISMATCH ${artifact}\n  pinned ${ARTIFACTS[artifact]}\n  actual ${actual}`);
    return false;
  }
  if (!existsSync(bin)) { if (verbose) console.log(`[age-cli] MISSING binary ${bin}`); return false; }
  const v = verifyBinary(bin);
  if (!v.ok) { if (verbose) console.log(`[age-cli] BINARY BROKEN: ${v.detail}`); return false; }
  if (verbose) console.log(`[age-cli] OK ${bin} (${v.detail})`);
  return true;
}

function install(force = false) {
  if (!force && check()) return;
  const artifact = platformArtifact();
  const url = `${BASE_URL}/age-${VERSION}-${artifact}`;
  const stage = path.join(tmpdir(), `age-cli-${process.pid}-${Date.now()}`);
  mkdirSync(stage, { recursive: true });
  try {
    console.log(`[age-cli] downloading ${url}`);
    const archive = path.join(stage, artifact);
    download(url, archive);
    const actual = sha256(archive);
    if (actual !== ARTIFACTS[artifact]) {
      throw new Error(`HASH MISMATCH for ${artifact} — refusing to install\n  pinned ${ARTIFACTS[artifact]}\n  actual ${actual}`);
    }
    const extractDir = path.join(stage, 'x');
    mkdirSync(extractDir, { recursive: true });
    const bin = extract(archive, extractDir);
    const v = verifyBinary(bin);
    if (!v.ok) throw new Error(`installed binary broken: ${v.detail}`);

    // All-or-nothing swap into the cache: wipe the old cache only after the
    // new one is fully verified.
    const newCache = path.join(stage, 'cache');
    mkdirSync(newCache, { recursive: true });
    mkdirSync(path.join(newCache, 'bin'), { recursive: true });
    renameSync(bin, path.join(newCache, 'bin', osBinName()));
    renameSync(archive, path.join(newCache, artifact));
    const lic = path.join(extractDir, 'age', 'LICENSE');
    if (existsSync(lic)) renameSync(lic, path.join(newCache, 'LICENSE'));
    if (existsSync(CACHE)) rmSync(CACHE, { recursive: true, force: true });
    renameSync(newCache, CACHE);
    console.log(`[age-cli] installed ${VERSION} to ${ageCliBin()} (${v.detail}) — pinned ${ARTIFACTS[artifact].slice(0, 16)}…`);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

// ---- CLI ---------------------------------------------------------------------

const args = process.argv.slice(2);
const want = args.includes('--print-path');
const checkOnly = args.includes('--check');
const force = args.includes('--force');
if (want) {
  console.log(ageCliBin());
  process.exit(existsSync(ageCliBin()) ? 0 : 1);
}
if (checkOnly) process.exit(check() ? 0 : 1);
try {
  install(force);
} catch (e) {
  console.error(`[age-cli] ${e.message}`);
  process.exit(1);
}
