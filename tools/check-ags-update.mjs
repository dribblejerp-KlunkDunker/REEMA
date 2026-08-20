#!/usr/bin/env node
/**
 * check-ags-update.mjs — regression check for the ags CLI's `ags update`
 * version-endpoint contract, replayed against the REAL live response shape.
 *
 * The API endpoint `GET /api/agent/skills/version` returns
 * `{ versions: { "<slug>": { contentSha, updatedAt } } }` — an OBJECT keyed by
 * slug. The CLI's `updateCommand` must parse that object shape. A regression to
 * the old array assumption (`remote.map(...)`, shipped in @agentskill.sh/cli
 * <=2.0.2) throws `TypeError: remote.map is not a function` and breaks
 * `ags update` for every user — including after a plain `npm install -g`
 * clobbers the local fix.
 *
 * Instead of a hand-authored stub, this test REPLAYS the actual response body
 * captured from the live endpoint — committed at tools/fixtures/
 * ags-version-response.json (see `--refresh` below to re-capture it). If the
 * server ever changes the shape (e.g. back to an array), re-capturing with
 * --refresh makes the replay fail, so the drift can't go unnoticed.
 *
 * The check is also a SELF-HEALER: before replaying it calls the shared
 * tools/ags-fix-lib.mjs `patch()` — the same idempotent re-application used by
 * the postinstall hook — so a clobbered dist is repaired first, then the
 * replay proves the healed state. It only fails loudly (or warns, with --warn)
 * when the dist shape changed in a way that cannot be patched.
 *
 * Two scenarios are replayed against the REAL updateCommand:
 *   A) every tracked skill's lock sha matches the fixture -> all up to date;
 *   B) one lock sha is STALE -> the skill must be reported as outdated and the
 *      full update path (fetch install data, install to agents, finalize the
 *      lock) must run — hermetically, since non-global installs write under
 *      process.cwd()/<agent>.skillsDir, so a temp cwd absorbs the writes.
 *
 * The check is hermetic and offline:
 *   - a scratch lock is placed via XDG_STATE_HOME (honored by the CLI's
 *     readLock), so the real ~/.agents/.skill-lock.json is never touched; the
 *     lock's contentShas are derived FROM the fixture, so the replay is
 *     self-consistent (every tracked slug matches -> up to date);
 *   - globalThis.fetch is stubbed with the fixture body, so the real
 *     apiFetch + updateCommand logic runs without any network I/O.
 *
 * Usage:
 *   node tools/check-ags-update.mjs                       # replay fixture (offline)
 *   node tools/check-ags-update.mjs --refresh             # re-capture live shape, then replay
 *   node tools/check-ags-update.mjs --warn                # warn instead of failing (postinstall)
 *   node tools/check-ags-update.mjs <path-to-update.js>   # check any build
 *   AGS_CLI_DIR=<dir> node tools/check-ags-update.mjs     # explicit CLI dir
 *
 * Exit code: 0 = contract holds, 1 = regression detected (or check broken).
 * If the CLI is not installed the check SKIPS with exit 0 (npm test must not
 * fail on machines without the global CLI). --warn is the postinstall mode:
 * failures print a prominent WARNING but exit 0, so a broken fix never breaks
 * `npm install` — strict enforcement lives in `npm test` and `npm run verify:ags`.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync, mkdtempSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { patch } from './ags-fix-lib.mjs';

const FIXTURE = fileURLToPath(new URL('./fixtures/ags-version-response.json', import.meta.url));
const DEFAULT_SLUGS = ['agentskill-sh/learn', 'sametcelikbicak/coverage-guard'];
const warnMode = process.argv.includes('--warn');

let failures = 0;
function assert(label, cond, extra = '') {
  // Postinstall (--warn) mode stays quiet on success; failures always print.
  if (warnMode && cond) return;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : extra ? '  <<< ' + extra : ''}`);
  if (!cond) failures++;
}

function defaultUpdateJs() {
  if (process.env.AGS_CLI_DIR) {
    return join(process.env.AGS_CLI_DIR, 'dist/commands/update.js');
  }
  try {
    const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
    const p = join(root, '@agentskill.sh/cli/dist/commands/update.js');
    if (existsSync(p)) return p;
  } catch { /* fall through to the Windows default */ }
  return join(homedir(), 'AppData/Roaming/npm/node_modules/@agentskill.sh/cli/dist/commands/update.js');
}

// ---- fixture loading / shape guard ----
function loadFixture() {
  if (!existsSync(FIXTURE)) return null;
  const f = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  if (!f || typeof f !== 'object' || Array.isArray(f.versions) || typeof f.versions !== 'object') {
    console.error(`[check-ags-update] FATAL: fixture ${FIXTURE} is not the expected object shape — run --refresh to re-capture from the live endpoint.`);
    process.exit(1);
  }
  for (const [slug, entry] of Object.entries(f.versions)) {
    if (!entry || typeof entry.contentSha !== 'string') {
      console.error(`[check-ags-update] FATAL: fixture entry "${slug}" lacks a string contentSha — run --refresh.`);
      process.exit(1);
    }
  }
  return f;
}

// ---- --refresh: re-capture the live response shape into the fixture ----
if (process.argv.includes('--refresh')) {
  const existing = loadFixture(); // validates shape if present
  const slugs = existing ? Object.keys(existing.versions) : DEFAULT_SLUGS;
  const url = `https://agentskill.sh/api/agent/skills/version?slugs=${encodeURIComponent(slugs.join(','))}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!res.ok) {
    console.error(`[check-ags-update] refresh failed: HTTP ${res.status} ${res.statusText}`);
    process.exit(1);
  }
  const body = await res.json();
  if (!body || typeof body !== 'object' || Array.isArray(body.versions) || typeof body.versions !== 'object') {
    console.error(`[check-ags-update] refresh failed: live response is not the expected object shape — ${JSON.stringify(body).slice(0, 200)}`);
    process.exit(1);
  }
  mkdirSync(dirname(FIXTURE), { recursive: true });
  writeFileSync(FIXTURE, JSON.stringify(body, null, 2) + '\n');
  console.log(`[check-ags-update] fixture refreshed from ${url}`);
  console.log(`[check-ags-update] wrote ${FIXTURE} (${Object.keys(body.versions).length} tracked slugs)`);
  // fall through and replay the refreshed fixture below
}

const fixture = loadFixture();
if (!fixture) {
  console.error(`[check-ags-update] no fixture at ${FIXTURE} — run --refresh to capture the live /agent/skills/version shape.`);
  process.exit(1);
}

const target = process.argv.slice(2).find((a) => a !== '--refresh' && !a.startsWith('--')) || defaultUpdateJs();
if (!existsSync(target)) {
  console.log(`[check-ags-update] SKIP: update.js not found (${target}) — @agentskill.sh/cli is not installed on this machine.`);
  process.exit(0);
}

// ---- self-heal: if the fix was clobbered, re-apply it BEFORE the replay ----
const heal = patch(target);
if (heal === 'error') process.exit(1); // patch() already printed the loud FATAL
if (heal === 'patched') {
  console.log('[check-ags-update] self-healed: re-applied the remote.map -> Object.entries(remote.versions) fix before verifying.');
}

assert('no regression to the array assumption (no "remote.map" pattern)',
  !readFileSync(target, 'utf8').includes('remote.map('));

const tracked = Object.keys(fixture.versions);

// ---- hermetic lock derived FROM the fixture (never touches the real lock) ----
// Returns the per-scenario XDG temp dir so the caller can clean it up.
function writeHermeticLock(staleSha) {
  const stateHome = mkdtempSync(join(tmpdir(), 'ags-check-'));
  process.env.XDG_STATE_HOME = stateHome;
  const lock = {
    version: 1,
    skills: Object.fromEntries(tracked.map((slug) => [
      slug,
      {
        slug,
        contentSha: slug === staleSha ? `stale-${fixture.versions[slug].contentSha}` : fixture.versions[slug].contentSha,
        installedAt: '2026-08-18T00:00:00.000Z',
        agents: ['claude-code'],
      },
    ])),
  };
  const lockDir = join(stateHome, 'agentskill');
  mkdirSync(lockDir, { recursive: true });
  writeFileSync(join(lockDir, '.skill-lock.json'), JSON.stringify(lock, null, 2));
  return stateHome;
}

// ---- run the REAL installed updateCommand against a stubbed network ----
// The version endpoint returns the live-captured fixture; the per-skill install
// endpoint returns `installData` when provided (or throws when null).
async function runUpdateCommand(installData) {
  let calledUrl = null, installCalled = false;
  globalThis.fetch = async (url) => {
    const u = String(url);
    calledUrl = u;
    if (u.includes('/agent/skills/version')) {
      return { ok: true, status: 200, async json() { return fixture; } };
    }
    if (u.includes('/install')) {
      installCalled = true;
      return { ok: true, status: 200, async json() { return installData; } };
    }
    throw new Error(`unexpected API URL in check: ${u}`);
  };
  const logged = [];
  const originalLog = console.log;
  console.log = (...args) => logged.push(args.join(' '));
  let thrown = null;
  try {
    const mod = await import(pathToFileURL(target).href);
    if (typeof mod.updateCommand !== 'function') {
      throw new Error(`no updateCommand export in ${target}`);
    }
    await mod.updateCommand(['--json']);
  } catch (err) {
    thrown = err;
  } finally {
    console.log = originalLog;
  }
  const jsonLine = logged.find((l) => l.trim().startsWith('{'));
  let parsed = null;
  try { parsed = jsonLine ? JSON.parse(jsonLine) : null; } catch { parsed = null; }
  return { parsed, thrown, calledUrl, installCalled };
}

function hasSkillMark(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory() && hasSkillMark(p)) return true;
    if (entry.isFile() && entry.name === 'SKILL.md' && readFileSync(p, 'utf8').includes('updated skill')) return true;
  }
  return false;
}

// ---- Scenario A: every tracked skill matches the live fixture (up to date) ----
{
  const stateHome = writeHermeticLock(null);
  const a = await runUpdateCommand(null);
  assert('fixture is the live object shape (versions keyed by slug)',
    fixture.versions && !Array.isArray(fixture.versions) && tracked.length > 0,
    JSON.stringify(fixture).slice(0, 120));
  assert('A: updateCommand ran without throwing', a.thrown === null, a.thrown ? String((a.thrown && a.thrown.message) || a.thrown) : '');
  assert('A: the version endpoint was called',
    a.calledUrl !== null && a.calledUrl.includes('/agent/skills/version?slugs='), a.calledUrl || '(no call)');
  assert('A: all skills up to date (upToDate == tracked count)',
    a.parsed !== null && a.parsed.upToDate === tracked.length,
    (a.parsed && JSON.stringify(a.parsed)) || '(no JSON output)');
  assert('A: no update was reported as pending',
    a.parsed !== null && Array.isArray(a.parsed.updated) && a.parsed.updated.length === 0);
  rmSync(stateHome, { recursive: true, force: true });
}

// ---- Scenario B: a skill whose LOCK sha differs from the remote MUST be
// reported as outdated — and the full update path (fetch install data, install
// to agents, finalize the lock) must run. Install writes land under a hermetic
// cwd (non-global installs write to process.cwd()/<agent>.skillsDir), so no
// real agent directory is ever touched. ----
{
  const staleSlug = tracked[0];
  const workDir = mkdtempSync(join(tmpdir(), 'ags-update-'));
  const prevCwd = process.cwd();
  process.chdir(workDir);
  const stateHome = writeHermeticLock(staleSlug);
  const b = await runUpdateCommand({
    slug: staleSlug,
    name: staleSlug.split('/').pop(),
    owner: staleSlug.split('/')[0],
    skillMd: '# updated skill\n',
    contentSha: fixture.versions[staleSlug].contentSha,
    skillFiles: [],
  });
  process.chdir(prevCwd);

  assert('B: updateCommand ran without throwing (full update path)',
    b.thrown === null, b.thrown ? String((b.thrown && b.thrown.message) || b.thrown) : '');
  assert('B: the stale skill is reported as outdated (upToDate == tracked - 1)',
    b.parsed !== null && b.parsed.upToDate === tracked.length - 1,
    (b.parsed && JSON.stringify(b.parsed)) || '(no JSON output)');
  assert('B: the stale skill is listed in updated',
    b.parsed !== null && Array.isArray(b.parsed.updated) && b.parsed.updated.includes(staleSlug),
    (b.parsed && JSON.stringify(b.parsed.updated)) || '(no JSON output)');
  assert('B: the install endpoint was called for the stale skill', b.installCalled, '(no install call)');
  assert('B: updated skill written under the hermetic cwd', hasSkillMark(workDir), workDir);

  rmSync(stateHome, { recursive: true, force: true });
  rmSync(workDir, { recursive: true, force: true });
}

if (warnMode) {
  if (failures === 0) {
    console.log('[check-ags-update] ags update fix verified against the live fixture — OK.');
  } else {
    console.error('');
    console.error('[check-ags-update] WARNING: the ags update fix is broken or was clobbered (FAIL lines above).');
    console.error('[check-ags-update] Re-apply with `npm run patch:ags`, then verify with `npm run verify:ags`.');
    console.error('[check-ags-update] Patch reference: upstream/ags-update-remote-map.patch');
  }
  process.exit(0);
}

console.log(`\n${failures === 0 ? 'AGS UPDATE CONTRACT OK (replayed from live fixture)' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
