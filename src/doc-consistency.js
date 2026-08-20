/**
 * Doc-vs-code consistency check (wired into `npm test`).
 *
 * README.md and ROADMAP.md quote runtime facts that drift when the code
 * changes: the shareable-bundle size, the files they cite, the stages that
 * make up `npm test`, and the default ports. This check measures/reads the
 * real values from the code and fails on any disagreement, so the docs stay
 * tied to the working tree:
 *
 *   1. bundle-size figures (base64 chars / raw KB) match a live measurement;
 *   2. every cited project file/directory exists (gitignored runtime artifacts
 *      are instead required to be listed in .gitignore);
 *   3. every stage of `npm test` (from package.json) is cited in both docs,
 *      and any explicit `node src/... && ...` chain quoted in a doc matches
 *      package.json exactly;
 *   4. every port-like number cited in a doc matches a current default read
 *      from the source files (server.js, serve.mjs, browser-e2e.js, tor.js).
 *
 * Extensible: add a regex + measurement to verify any other quoted figure.
 */
import { readFileSync, existsSync } from 'node:fs';
import { init, Identity, encodeBundle, loadPQ } from './crypto.js';

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

const DOCS = ['README.md', 'ROADMAP.md'];
const read = (f) => readFileSync(f, 'utf8');

async function main() {
  const sodium = await init();
  await loadPQ(); // bundle measurement does keygen + self-signature

  // ---- 1. Shareable-bundle size ----
  console.log('=== Doc consistency: shareable-bundle size ===');
  const b64Chars = encodeBundle(new Identity().makeBundle()).length;
  // Docs quote decimal KB (1 KB = 1000 bytes), not KiB — 11,684 b64 chars is
  // 8,763 raw bytes = 8.8 KB decimal (8.6 KiB). Keep the convention explicit
  // here so the docs and the check agree.
  const rawBytes = Math.round((b64Chars * 3) / 4);
  const rawKb = (rawBytes / 1000).toFixed(1);
  console.log(`measured: ${b64Chars} base64 chars ≈ ${rawKb} KB raw\n`);
  for (const file of DOCS) {
    const text = read(file);
    const charMatches = [...text.matchAll(/([\d,]+) base64 chars/g)];
    const kbMatches = [...text.matchAll(/≈\s*([0-9.]+)\s*KB\s*raw/g)];
    const figures = [
      ...charMatches.map((m) => ['base64 chars', m[1].replace(/,/g, '')]),
      ...kbMatches.map((m) => ['KB raw', m[1]]),
    ];
    const ok = figures.length > 0 &&
      figures.every(([kind, v]) => (kind === 'base64 chars' ? v === String(b64Chars) : v === rawKb));
    check(`${file}: bundle-size figures match the measured value`, ok,
      figures.map(([k, v]) => `${v} ${k}`).join(', ') || 'none quoted');
  }

  // ---- 2. Cited files exist ----
  console.log('\n=== Doc consistency: cited files ===');
  const PATH_RE = /^(src|public|tools|scratch)\/[\w./-]+\.(js|mjs|html|json|md)$/;
  const DIR_RE = /^(src|public|tools|scratch)\/[\w./-]+\/$/;
  const ROOT_FILES = new Set(['package.json', '.gitignore', 'README.md', 'ROADMAP.md']);
  // Runtime artifacts that exist only in a developer's working tree, never in
  // a fresh clone: known root files plus anything under a gitignored directory
  // (scratch/, node_modules/). For these, verify the .gitignore entry instead
  // of requiring the file on disk — otherwise the check fails in CI, where a
  // clean checkout has no scratch/ files.
  const RUNTIME_ARTIFACTS = new Set(['.identity.json', '.sessions.json']);
  const gitignore = read('.gitignore');
  const gitignoreLines = gitignore.split('\n').map((l) => l.trim()).filter(Boolean);
  const gitignoredDirs = new Set(gitignoreLines.filter((l) => l.endsWith('/')).map((l) => l.slice(0, -1)));
  const isGitignored = (p) => RUNTIME_ARTIFACTS.has(p) || gitignoredDirs.has(p.split('/')[0]);
  for (const file of DOCS) {
    const text = read(file);
    const cited = new Set();
    for (const m of text.matchAll(/`([^`\n]+)`/g)) {
      const tok = m[1].trim();
      if (PATH_RE.test(tok) || ROOT_FILES.has(tok)) cited.add(tok);
      else if (DIR_RE.test(tok)) cited.add(tok);
    }
    for (const p of cited) {
      if (isGitignored(p)) {
        const entry = RUNTIME_ARTIFACTS.has(p) ? p : `${p.split('/')[0]}/`;
        check(`${file}: ${p} is gitignored`, gitignoreLines.includes(entry), '');
      } else {
        const target = p.endsWith('/') ? p.slice(0, -1) : p;
        check(`${file}: ${p} exists`, existsSync(target), existsSync(target) ? '' : 'MISSING');
      }
    }
  }

  // ---- 3. npm-test stage composition ----
  console.log('\n=== Doc consistency: npm-test stages ===');
  const pkg = JSON.parse(read('package.json'));
  const stages = [...pkg.scripts.test.matchAll(/node (src\/[\w.-]+\.js)/g)].map((m) => m[1]);
  for (const file of DOCS) {
    const text = read(file);
    for (const s of stages) {
      // Docs cite stages by bare filename (layout tree) or full path — accept
      // either.
      const name = s.split('/')[1];
      check(`${file}: cites npm-test stage ${s}`, text.includes(s) || text.includes(name));
    }
    // Any explicit `node src/... && node src/...` chain quoted in a doc must
    // match package.json's stage set exactly (order-insensitive).
    for (const m of text.matchAll(/node src\/[\w.-]+\.js(?: && node src\/[\w.-]+\.js)+/g)) {
      const chain = [...m[0].matchAll(/src\/[\w.-]+\.js/g)].map((x) => x[0]).sort();
      const expect = [...stages].sort();
      check(`${file}: quoted npm-test chain matches package.json`,
        JSON.stringify(chain) === JSON.stringify(expect), m[0]);
    }
  }

  // ---- 4. Port defaults ----
  console.log('\n=== Doc consistency: ports ===');
  const portDefaults = [];
  const portsFrom = (file, patterns) => {
    const text = read(file);
    for (const re of patterns) {
      for (const m of text.matchAll(re)) portDefaults.push({ name: m[1], port: Number(m[2]) });
    }
  };
  portsFrom('src/server.js', [
    /process\.env\.(PORT)\s*\|\|\s*(\d+)/g,
    /process\.env\.(WS_PORT)\s*\|\|\s*(\d+)/g,
  ]);
  portsFrom('tools/serve.mjs', [/process\.env\.(UI_PORT)\s*\|\|\s*(\d+)/g]);
  portsFrom('src/browser-e2e.js', [
    /process\.env\.(E2E_RELAY_PORT|E2E_WS_PORT|E2E_UI_PORT)\s*\|\|\s*(\d+)/g,
  ]);
  portsFrom('src/messenger-smoke.js', [
    /process\.env\.(M_RELAY_PORT|M_WS_PORT|M_UI_PORT)\s*\|\|\s*(\d+)/g,
  ]);
  portsFrom('src/xss-regression.js', [/process\.env\.(XSS_UI_PORT)\s*\|\|\s*(\d+)/g]);
  portsFrom('src/tor.js', [/process\.env\.(TOR_PORT)\s*\|\|\s*(\d+)/g]);
  const known = new Set(portDefaults.map((p) => p.port));
  for (const file of DOCS) {
    const text = read(file);
    const found = new Set();
    for (const m of text.matchAll(/:(\d{2,5})\b|\bTCP (\d{2,5})\b|\bWS (\d{2,5})\b|\bport (\d{2,5})\b/gi)) {
      found.add(Number(m.slice(1).find(Boolean)));
    }
    for (const n of found) {
      const match = portDefaults.find((p) => p.port === n);
      check(`${file}: port ${n} matches a current default`, !!match,
        match ? `${match.name} (${match.port})` : 'no such default in the code');
    }
  }

  console.log(failures === 0 ? '\nDOC CONSISTENCY PASSED' : `\n${failures} DOC CONSISTENCY CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
