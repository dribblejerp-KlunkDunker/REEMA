/**
 * ags-fix-lib.mjs — shared re-application logic for the @agentskill.sh/cli
 * `remote.map` parsing fix (see upstream/ags-update-remote-map.patch).
 *
 * @agentskill.sh/cli <=2.0.2's `ags update` crashes with
 * `TypeError: remote.map is not a function`: the /agent/skills/version
 * endpoint returns `{ versions: { "<slug>": { contentSha } } }` — an OBJECT
 * keyed by slug — but the CLI assumed an array.
 *
 * Imported by:
 *   - tools/patch-ags-cli.mjs    (the postinstall re-apply hook)
 *   - tools/check-ags-update.mjs (the detector that SELF-HEALS on regression)
 *
 * `patch()` is idempotent: it returns 'skip-already-fixed' when the fix is
 * present (locally patched or upstream-fixed), 'skip-not-installed' when the
 * file is absent, 'patched' after re-applying, and 'error' (with a loud FATAL
 * message already printed) when the dist changed shape unexpectedly.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

// The buggy expression as shipped in the @agentskill.sh/cli <=2.0.2 dist,
// tolerant of tsc formatting ((r) vs r, whitespace around =>).
export const BUGGY = /\bnew Map\(remote\.map\(\(?r\)?\s*=>\s*\[r\.slug,\s*r\.contentSha\]\)\)/;
export const FIXED = 'new Map(Object.entries(remote.versions).map(([slug, v]) => [slug, v.contentSha]))';
export const FIX_MARKER = 'Object.entries(remote.versions)';

// Returns one of: 'skip-not-installed' | 'skip-already-fixed' | 'patched' | 'error'
export function patch(updateJs) {
  if (!existsSync(updateJs)) return 'skip-not-installed';
  const src = readFileSync(updateJs, 'utf8');

  if (src.includes(FIX_MARKER)) return 'skip-already-fixed';

  if (!BUGGY.test(src)) {
    console.error(`[ags-fix] FATAL: ${updateJs} has neither the buggy remote.map expression nor the versions-object fix.`);
    console.error('[ags-fix] The @agentskill.sh/cli dist changed shape — refresh tools/patch-ags-cli.mjs (see upstream/ags-update-remote-map.patch) before the next install clobbers a working copy.');
    return 'error';
  }

  const patched = src.replace(BUGGY, FIXED);
  if (!patched.includes(FIX_MARKER) || BUGGY.test(patched)) {
    console.error('[ags-fix] FATAL: replacement did not take — refusing to continue.');
    return 'error';
  }
  writeFileSync(updateJs, patched);
  return 'patched';
}
