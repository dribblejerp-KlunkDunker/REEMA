/**
 * Self-host the Google Fonts used by public/index.html.
 *
 * The dashboard loads three families (EB Garamond, Cinzel, Cormorant Garamond)
 * from fonts.googleapis.com / fonts.gstatic.com — the page's only third-party
 * origin and its only render-blocking stylesheet. This fetches the css2
 * manifest with a browser UA, keeps the latin + latin-ext subset files
 * (English-only page; cyrillic/greek/vietnamese/devanagari subsets are dead
 * weight), downloads the woff2 into public/fonts/, and writes a local
 * fonts.css that serve.mjs compresses and caches.
 *
 * Google serves these families as VARIABLE fonts: every weight in a family
 * shares one woff2 file per (family, style, subset), so the local CSS emits
 * one @font-face per weight all pointing at the same file.
 *
 * Google Fonts are SIL OFL 1.1 licensed — self-hosting is permitted.
 *
 * Content is PINNED: every downloaded woff2 is verified against committed
 * SHA-256 hashes (tools/fonts-manifest.json) before it is written, so a
 * compromised CDN cannot silently substitute font bytes even from an
 * allowlisted host. Re-pin deliberately with --update-manifest after
 * reviewing the hash diff.
 *
 * Run with:  node tools/fetch-fonts.mjs                    (fetch + verify against pinned hashes)
 *            node tools/fetch-fonts.mjs --update-manifest  (re-pin after a reviewed font change)
 *            node tools/fetch-fonts.mjs --check            (verify public/fonts/ on disk, no network)
 */
import { mkdirSync, writeFileSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = path.join(ROOT, 'public', 'fonts');

const FONTS_URL = [
  'https://fonts.googleapis.com/css2?',
  'family=EB+Garamond:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500',
  '&family=Cinzel:wght@400;600;700;900',
  '&family=Cormorant+Garamond:ital,wght@0,300;0,400;1,300;1,400',
  '&display=swap',
].join('');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

// Keep only latin (U+0000-…) and latin-ext (U+0100-02BA, …) subset blocks.
// (Vietnamese also starts U+0102 — deliberately excluded.)
const KEEP_RANGE = /^U\+0000|^U\+0100-02BA/;

const slug = (s) => (s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'font');

// Pin font downloads to Google's static CDN over HTTPS. The manifest is
// fetched from fonts.googleapis.com and the woff2 files from fonts.gstatic.com;
// a compromised manifest must not be able to redirect the build to an
// attacker-chosen URL, so hosts are allowlisted and redirects are disabled.
const ALLOWED_FONT_HOSTS = new Set(['fonts.gstatic.com', 'fonts.googleapis.com']);

function assertSafeFontUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`refusing malformed font URL: ${url}`);
  }
  if (u.protocol !== 'https:') throw new Error(`refusing non-https font URL: ${url}`);
  if (!ALLOWED_FONT_HOSTS.has(u.hostname)) throw new Error(`refusing font URL from unallowlisted host "${u.hostname}": ${url}`);
  if (!u.pathname.endsWith('.woff2')) throw new Error(`refusing non-woff2 font URL: ${url}`);
}

// ---- Content pinning (anti-substitution) ----
// Beyond pinning the *URLs*, every downloaded woff2 is verified against
// committed SHA-256 hashes. A compromised CDN cannot silently substitute font
// bytes: the build refuses to write any file whose hash does not match. The
// manifest is re-pinned deliberately with --update-manifest.
const MANIFEST = path.join(ROOT, 'tools', 'fonts-manifest.json');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function loadManifest() {
  if (!existsSync(MANIFEST)) return null;
  return JSON.parse(readFileSync(MANIFEST, 'utf8'));
}

// Throws — failing the build — when `buf` does not match the pinned hash for
// `file` (or when there is no pin for it at all), so a silent content
// substitution can never land in public/fonts/. Returns the actual hash so the
// caller can build the next manifest. In --update-manifest mode it accepts any
// bytes (the new hashes become the new baseline).
function verifyFont(file, buf, manifest, updateManifest) {
  const actual = sha256(buf);
  const expected = manifest?.[file];
  if (updateManifest) return actual;
  if (!expected) {
    throw new Error(
      `font ${file} has no pinned hash in ${MANIFEST}; refusing to write unverified content.\n` +
      `If this is an intentional font change, review it and rerun with --update-manifest.`
    );
  }
  if (actual !== expected) {
    throw new Error(
      `font ${file} hash mismatch — possible silent CDN content substitution:\n` +
      `  expected ${expected}\n` +
      `  actual   ${actual}\n` +
      `Refusing to write. If intentional, review and rerun with --update-manifest.`
    );
  }
  return actual;
}

async function main() {
  const args = process.argv.slice(2);
  const updateManifest = args.includes('--update-manifest');
  const checkOnly = args.includes('--check');

  // --check: verify the committed files on disk against the committed hashes
  // (no network). Catches local corruption or an accidental edit to public/fonts/.
  if (checkOnly) {
    const manifest = loadManifest();
    if (!manifest) {
      console.error(`no hash manifest at ${MANIFEST} — run "node tools/fetch-fonts.mjs --update-manifest" to create the baseline`);
      process.exit(1);
    }
    let bad = 0;
    for (const file of Object.keys(manifest).sort()) {
      const p = path.join(OUT, file);
      if (!existsSync(p)) { console.error(`MISSING   ${file}`); bad++; continue; }
      const actual = sha256(readFileSync(p));
      if (actual !== manifest[file]) {
        console.error(`MISMATCH  ${file}\n  expected ${manifest[file]}\n  actual   ${actual}`);
        bad++;
      } else {
        console.log(`ok        ${file}`);
      }
    }
    console.log(bad === 0
      ? `\nall ${Object.keys(manifest).length} font files verified against ${MANIFEST}`
      : `\n${bad} font file(s) failed verification`);
    process.exit(bad === 0 ? 0 : 1);
  }

  const cssRes = await fetch(FONTS_URL, { headers: { 'User-Agent': UA }, redirect: 'error' });
  if (!cssRes.ok) throw new Error(`fonts.googleapis.com returned ${cssRes.status}`);
  const css = await cssRes.text();

  // Parse every @font-face block; keep latin + latin-ext woff2 blocks.
  // Group by (family, style, subset): the variable font file serves all weights.
  const groups = new Map(); // `${family}|${style}|${subset}` -> { file, url, weights: [{weight, range}] }
  for (const m of css.matchAll(/@font-face\s*\{([^}]*)\}/g)) {
    const prop = (name) => (m[1].match(new RegExp(`${name}:\\s*([^;]+);`)) || [])[1]?.trim();
    const family = prop('font-family')?.replace(/['"]/g, '');
    const weight = prop('font-weight');
    const style = prop('font-style') || 'normal';
    const range = prop('unicode-range');
    const src = (m[1].match(/url\(([^)]+)\)\s*format\('woff2'\)/) || [])[1]?.trim().replace(/^['"]|['"]$/g, '');
    if (!family || !src || !range || !KEEP_RANGE.test(range.trim())) continue;
    const subset = /^U\+0000/.test(range.trim()) ? 'latin' : 'latin-ext';
    const key = `${family}|${style}|${subset}`;
    if (!groups.has(key)) {
      groups.set(key, {
        file: `${slug(family)}-${subset}${style === 'italic' ? '-italic' : ''}.woff2`,
        url: src,
        weights: [],
      });
    }
    groups.get(key).weights.push({ weight, range: range.trim() });
  }

  // Download each unique variable-font file, verifying every byte against the
  // committed manifest before it is written.
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  const manifest = loadManifest();
  const nextManifest = {};
  let total = 0;
  for (const g of groups.values()) {
    assertSafeFontUrl(g.url);
    const res = await fetch(g.url, { headers: { 'User-Agent': UA }, redirect: 'error' });
    if (!res.ok) throw new Error(`font fetch failed (${res.status}): ${g.url}`);
    const buf = Buffer.from(await res.arrayBuffer());
    nextManifest[g.file] = verifyFont(g.file, buf, manifest, updateManifest);
    writeFileSync(path.join(OUT, g.file), buf);
    total += buf.length;
    console.log(`  ${g.file.padEnd(44)} ${buf.length} B  (${g.weights.map((w) => w.weight).join(', ')} ${g.weights[0].range.slice(0, 12)}…)`);
  }
  if (!updateManifest && manifest) {
    for (const f of Object.keys(manifest)) {
      if (!nextManifest[f]) console.warn(`warn: pinned font ${f} is no longer downloaded (upstream change?)`);
    }
  }

  // One @font-face per weight, all pointing at the shared variable file.
  const rules = [];
  for (const [key, g] of groups) {
    const [family, style] = key.split('|');
    for (const w of g.weights) {
      rules.push(
        `@font-face {\n` +
        `  font-family: '${family}';\n` +
        `  font-style: ${style};\n` +
        `  font-weight: ${w.weight};\n` +
        `  font-display: swap;\n` +
        `  src: url('./${g.file}') format('woff2');\n` +
        `  unicode-range: ${w.range};\n` +
        `}`
      );
    }
  }
  const header =
    `/* Self-hosted fonts for public/index.html — fetched from Google Fonts (SIL OFL 1.1).\n` +
    ` * Source: ${FONTS_URL}\n` +
    ` * Regenerate with: node tools/fetch-fonts.mjs\n` +
    ` */\n\n`;
  writeFileSync(path.join(OUT, 'fonts.css'), header + rules.join('\n\n') + '\n');
  console.log(`\nwrote ${groups.size} variable font files (${(total / 1024).toFixed(1)} KB) + ${rules.length} @font-face rules in public/fonts/fonts.css`);

  if (updateManifest) {
    const prev = loadManifest();
    for (const [file, hash] of Object.entries(nextManifest).sort()) {
      if (!prev || prev[file] === undefined) console.log(`new pin   ${file}  ${hash}`);
      else if (prev[file] !== hash) console.log(`changed   ${file}\n  ${prev[file]}\n  ${hash}`);
    }
    writeFileSync(MANIFEST, JSON.stringify(nextManifest, null, 2) + '\n');
    console.log(`wrote ${MANIFEST} (${Object.keys(nextManifest).length} pinned hashes)`);
  } else {
    console.log(`verified ${Object.keys(nextManifest).length} font files against ${MANIFEST}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
