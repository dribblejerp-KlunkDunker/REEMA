#!/usr/bin/env node
/**
 * Staged-content verifier for surgical commits.
 *
 * The repo is advanced with deliberately small, selective commits (partial
 * hunks staged via `git apply --cached`, or whole files whose diffs mix
 * several features). That pattern has three failure modes this tool exists
 * to catch BEFORE the commit lands:
 *
 *   1. a hunk is mis-applied, so the STAGED blob is syntactically broken
 *      even though the working tree is fine (the staged version is what
 *      gets committed, not the file on disk);
 *   2. a staged file imports a dependency that is neither committed nor
 *      staged (the untracked-twin case: messenger.html -> ./sanitize.js
 *      would have silently broken the committed tree if the twin hadn't
 *      been staged in the same commit);
 *   3. a staged file imports a bare package that is not declared in the
 *      committed/staged package.json.
 *
 * The verifier reads content from the INDEX (`git cat-file :path`), never
 * from the working tree, so it proves the exact bytes that would be
 * committed. Checks:
 *
 *   - .js/.mjs/.cjs: `node --check` (parse-only) on the staged blob;
 *   - .json: JSON.parse;
 *   - .html: inline module import specifiers resolve (same rules as .js;
 *     the extraction is best-effort — see checkImportsInHtml);
 *   - every import/export specifier in a checked file: relative imports
 *     must resolve to a file present in the index; bare imports must be
 *     node: builtins or declared in the index's package.json
 *     dependencies/devDependencies.
 *
 * Deliberate scope notes: files under public/vendor/ are vendored
 * third-party code (pinned + hash-checked by tools/vendor.mjs) whose bare
 * self-imports resolve via the page's import map, not package.json — their
 * import checks are skipped. Inline <script> SYNTAX is not parsed: naive
 * block extraction mangles scripts that embed '</script>' inside strings
 * (a common pattern), producing false duplicate-declaration errors; the
 * headless suites (messenger-smoke, browser-e2e, xss-regression) exercise
 * committed HTML scripts instead.
 *
 * Modes:
 *   (default)              verify `git diff --cached` (the pre-commit hook)
 *   --all                  verify every tracked JS/JSON/HTML file
 *                          (CI backstop; catches committed content npm test
 *                          may never touch, e.g. tools/*.mjs)
 *   --commit <sha>         verify the files of one commit
 *
 * Exit 1 on any failure, so the pre-commit hook aborts the commit. Bypass
 * with `git commit --no-verify`; CI (`--all`) is the backstop for that.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

let failures = 0;
let checked = 0;
let skipped = 0;
const fail = (file, msg) => { console.log(`FAIL  ${file}: ${msg}`); failures++; };
const ok = (file) => { checked++; console.log(`  OK  ${file}`); };

function git(args, cwd = ROOT) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (r.error) throw r.error;
  return r;
}

/**
 * Content of a path for the given mode. Staged mode reads the INDEX blob
 * (the exact bytes that would be committed — never the working tree).
 * Commit mode reads <sha>:path. --all reads HEAD:path (the committed
 * content CI cares about), falling back to the index, then the working
 * tree, so a locally staged-only file is still checked.
 */
function readSource(file, mode, sha) {
  const specs = mode === 'all'
    ? [`HEAD:${file}`, `:${file}`]
    : [mode === 'commit' ? `${sha}:${file}` : `:${file}`];
  for (const spec of specs) {
    const r = git(['cat-file', '-p', spec]);
    if (r.status === 0) return r.stdout;
  }
  if (mode === 'all') {
    try { return readFileSync(path.join(ROOT, file), 'utf8'); } catch { return null; }
  }
  return null; // e.g. staged deletion
}

function inIndex(file) {
  return git(['cat-file', '-e', `:${file}`]).status === 0;
}

/** True if the blob exists at the given index path (committed or staged). */
function indexPackageJson() {
  const r = git(['cat-file', '-p', ':package.json']);
  if (r.status !== 0) return null;
  try { return JSON.parse(r.stdout); } catch { return null; }
}

// Parse-only check of JS text; --input-type=module parses both ESM and
// CJS-looking code (a module cannot use `with`, but the repo doesn't).
function syntaxCheckJs(label, text) {
  const r = spawnSync(process.execPath, ['--input-type=module', '--check', '-'], {
    input: text, encoding: 'utf8',
  });
  if (r.status !== 0) {
    // node prints the offending source lines before the error; surface the
    // actual error line (not the source echo or the version trailer).
    const lines = (r.stderr || '').trim().split(/\r?\n/);
    const err = lines.find((l) => /(SyntaxError|Error:)/.test(l)) || lines[0] || 'unknown error';
    fail(label, `syntax error: ${err.trim()}`);
    return false;
  }
  return true;
}

// All quoted import/export specifiers: `from 'x'`, `import 'x'`,
// `export ... from 'x'`, dynamic `import('x')` with a string literal.
const IMPORT_RE = /\b(?:import|export)\b[^;"']*?\bfrom\s*['"]([^'"\n]+)['"]|\bimport\s*\(\s*['"]([^'"\n]+)['"]\s*\)|\bimport\s*['"]([^'"\n]+)['"]/g;

function isNodeBuiltin(spec) {
  if (spec.startsWith('node:')) return true;
  return builtinModules.includes(spec);
}

/** Bare package name: 'confusables/package.json' -> 'confusables', '@scope/pkg' -> '@scope/pkg'. */
function bareName(spec) {
  const parts = spec.split('/');
  return parts[0].startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

/**
 * Every import in `text` must resolve: relative specifiers point at files
 * present in the index; bare specifiers are node builtins or declared deps.
 */
function checkImports(file, text, pkg) {
  let bad = 0;
  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(text)) !== null) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (!spec) continue;
    if (spec.startsWith('.')) {
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), spec));
      if (!inIndex(resolved)) {
        fail(file, `import '${spec}' resolves to ${resolved}, which is NOT in the index (uncommitted or unstaged)`);
        bad++;
      }
    } else if (!isNodeBuiltin(spec)) {
      const name = bareName(spec);
      const declared = pkg && (
        (pkg.dependencies && name in pkg.dependencies)
        || (pkg.devDependencies && name in pkg.devDependencies)
      );
      if (!declared) {
        fail(file, `import '${spec}' — bare package '${name}' is not declared in package.json dependencies/devDependencies`);
        bad++;
      }
    }
  }
  return bad === 0;
}

function checkHtml(file, text, pkg) {
  // Inline module import specifiers must resolve (the messenger.html ->
  // ./aegis/*-not-committed class of bug). Extraction is best-effort: a
  // script embedding '</script>' inside a string truncates its block, so
  // imports after that point are not seen (the headless suites cover the
  // scripts themselves).
  const scripts = [...text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];
  scripts.forEach((s, i) => {
    const body = s[1];
    if (!body.trim()) return;
    checkImports(`${file} <script #${i}>`, body, pkg);
  });
}

function checkFile(file, mode, sha) {
  const ext = path.extname(file).toLowerCase();
  if (!['.js', '.mjs', '.cjs', '.json', '.html'].includes(ext)) { skipped++; return; }
  const text = readSource(file, mode, sha);
  if (text === null) { skipped++; return; } // staged deletion / not in commit
  // Vendored third-party code (public/vendor/) self-imports via the page
  // import map, not package.json — skip its import checks.
  if (file.startsWith('public/vendor/')) { ok(file); return; }
  const pkg = ext !== '.json' || file === 'package.json' ? indexPackageJson() : null;
  if (ext === '.json') {
    try { JSON.parse(text); ok(file); }
    catch (e) { fail(file, `invalid JSON: ${e.message}`); }
    return;
  }
  if (ext === '.html') { checkHtml(file, text, pkg); ok(file); return; }
  if (syntaxCheckJs(file, text)) {
    checkImports(file, text, pkg);
    ok(file);
  }
}

function listFiles(mode, sha) {
  if (mode === 'all') {
    const r = git(['ls-files', '-z']);
    return r.stdout.split('\0').filter(Boolean);
  }
  const r = git(['diff-tree', '--no-commit-id', '--name-only', '-r', '-z', sha ?? 'HEAD']);
  return r.stdout.split('\0').filter(Boolean);
}

function main() {
  const args = process.argv.slice(2);
  let mode = 'staged';
  let sha = null;
  if (args.includes('--all')) mode = 'all';
  const ci = args.indexOf('--commit');
  if (ci !== -1 && args[ci + 1]) { mode = 'commit'; sha = args[ci + 1]; }

  let files;
  if (mode === 'staged') {
    const r = git(['diff', '--cached', '--name-only', '-z']);
    files = r.stdout.split('\0').filter(Boolean);
    if (files.length === 0) {
      console.log('[verify-staged] nothing staged — nothing to verify.');
      process.exit(0);
    }
  } else {
    files = listFiles(mode, sha);
  }

  console.log(`[verify-staged] mode=${mode}${sha ? ` sha=${sha}` : ''} — ${files.length} file(s) in set`);
  for (const f of files) checkFile(f, mode, sha);

  console.log(`[verify-staged] ${checked} checked, ${skipped} skipped, ${failures} failed`);
  if (failures > 0) {
    console.log('[verify-staged] FAILED — the staged/committed content is broken; fix before committing (or run `git commit --no-verify` to bypass this check only).');
    process.exit(1);
  }
  console.log('[verify-staged] OK');
  process.exit(0);
}

main();
