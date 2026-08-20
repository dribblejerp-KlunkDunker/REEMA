#!/usr/bin/env node
/**
 * patch-ags-cli.mjs — re-apply the local fix to the globally installed
 * @agentskill.sh/cli after a fresh `npm install` clobbers it.
 *
 * @agentskill.sh/cli <=2.0.2's `ags update` crashes with
 * `TypeError: remote.map is not a function`: the /agent/skills/version
 * endpoint returns `{ versions: { "<slug>": { contentSha } } }` — an OBJECT
 * keyed by slug — but the CLI assumed an array. The upstream fix is tracked in
 * upstream/ags-update-remote-map.patch; until a fixed version ships, this hook
 * re-applies the one-line parsing fix to the installed dist after every
 * `npm install` (wired as the package.json `postinstall` script).
 *
 * Idempotent and non-breaking:
 *   - CLI not installed        -> skip, exit 0 (fresh machines / CI)
 *   - fix already present      -> skip, exit 0 (already patched, or upstream-fixed)
 *   - bug present, fix applied -> exit 0
 *   - unexpected dist shape    -> FAIL LOUDLY, exit 1 — silently skipping would
 *     leave the next `ags update` broken again with no explanation
 *
 * The project `postinstall` runs BOTH this hook and the verification check
 * (tools/check-ags-update.mjs --warn), so a clobbered fix is re-applied AND
 * re-verified on every `npm install`. After a standalone
 * `npm i -g @agentskill.sh/cli`, run:
 *   npm run patch:ags     # re-apply the fix
 *   npm run verify:ags    # strict check against the live response fixture
 *   AGS_CLI_DIR=<dir> node tools/patch-ags-cli.mjs
 *   node tools/patch-ags-cli.mjs --self-test   # hermetic scenario coverage
 */
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { patch, FIXED, FIX_MARKER } from './ags-fix-lib.mjs';

function defaultUpdateJs() {
  if (process.env.AGS_CLI_DIR) return join(process.env.AGS_CLI_DIR, 'dist/commands/update.js');
  try {
    const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
    const p = join(root, '@agentskill.sh/cli/dist/commands/update.js');
    if (existsSync(p)) return p;
  } catch { /* fall through to the Windows default */ }
  return join(homedir(), 'AppData/Roaming/npm/node_modules/@agentskill.sh/cli/dist/commands/update.js');
}

if (process.argv.includes('--self-test')) {
  // ---- hermetic scenario coverage (no global CLI touched) ----
  const root = mkdtempSync(join(tmpdir(), 'ags-patch-'));
  const cliDir = join(root, 'cli');
  const dist = join(cliDir, 'dist', 'commands');
  mkdirSync(dist, { recursive: true });
  const updateJs = join(dist, 'update.js');
  const buggy = 'export async function updateCommand() {\n  const remoteMap = new Map(remote.map((r) => [r.slug, r.contentSha]));\n}\n';
  const fixed = `export async function updateCommand() {\n  const remoteMap = ${FIXED};\n}\n`;

  let failures = 0;
  const check = (label, cond, extra = '') => {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : extra ? '  <<< ' + extra : ''}`);
    if (!cond) failures++;
  };

  // 1. not installed -> skip, exit 0
  process.env.AGS_CLI_DIR = join(root, 'nope');
  check('not installed -> skip', patch(defaultUpdateJs()) === 'skip-not-installed');

  // 2. bug present -> patched
  writeFileSync(updateJs, buggy);
  process.env.AGS_CLI_DIR = cliDir;
  check('bug present -> patched', patch(defaultUpdateJs()) === 'patched');
  check('patched file carries the fix marker', readFileSync(updateJs, 'utf8').includes(FIX_MARKER));

  // 3. already fixed -> skip
  writeFileSync(updateJs, fixed);
  check('already fixed -> skip', patch(defaultUpdateJs()) === 'skip-already-fixed');

  // 4. unexpected shape -> fail loudly
  writeFileSync(updateJs, 'export const mystery = 42;\n');
  check('unexpected shape -> error', patch(defaultUpdateJs()) === 'error');

  rmSync(root, { recursive: true, force: true });
  console.log(`\n${failures === 0 ? 'AGS PATCH SELF-TEST OK' : failures + ' CHECK(S) FAILED'}`);
  process.exit(failures === 0 ? 0 : 1);
}

const target = process.argv[2] || defaultUpdateJs();
const result = patch(target);
if (result === 'skip-not-installed') {
  console.log(`[patch-ags-cli] @agentskill.sh/cli not installed (${target}) — nothing to patch.`);
  process.exit(0);
}
if (result === 'skip-already-fixed') {
  console.log('[patch-ags-cli] update.js already carries the versions-object fix — skipping.');
  process.exit(0);
}
if (result === 'patched') {
  console.log(`[patch-ags-cli] patched ${target} (remote.map -> Object.entries(remote.versions)).`);
  process.exit(0);
}
process.exit(1); // 'error' already printed loudly
