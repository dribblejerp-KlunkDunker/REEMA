#!/usr/bin/env node
/**
 * Install the committed pre-commit hook into .git/hooks.
 *
 * .git/hooks is not version-controlled, so a fresh clone (or a re-clone
 * that wipes .git) has no hooks until this runs. The hook itself lives at
 * tools/hooks/pre-commit (committed, reviewed like any other code) and this
 * script is the only thing that copies it into place.
 *
 * Run:  npm run hooks:install
 */
import { copyFileSync, chmodSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = path.join(ROOT, 'tools', 'hooks', 'pre-commit');
const DEST = path.join(ROOT, '.git', 'hooks', 'pre-commit');

const top = spawnSync('git', ['rev-parse', '--show-toplevel'], { cwd: ROOT, encoding: 'utf8' });
if (top.status !== 0 || !top.stdout.trim()) {
  console.error('[hooks] not a git work tree — nothing to install.');
  process.exit(1);
}

mkdirSync(path.dirname(DEST), { recursive: true });
copyFileSync(SRC, DEST);
// Windows ignores the exec bit; POSIX git invokes the hook via sh anyway,
// but keep the bit correct for good measure.
try { chmodSync(DEST, 0o755); } catch { /* non-POSIX */ }
console.log(`[hooks] installed pre-commit -> ${DEST}`);
