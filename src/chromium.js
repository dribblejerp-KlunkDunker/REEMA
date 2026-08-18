/**
 * Resolve the headless-browser driver for the browser E2E stages.
 *
 * Two sources, in priority order:
 *
 *   1. The CodeGPT VS Code extension ships a pre-bundled patchright + Chromium
 *      (the browser-automation skill's driver) — this keeps local development
 *      working without any npm browser install.
 *   2. An npm-installed `patchright` (devDependency) whose Chromium has been
 *      downloaded with `npx patchright install chromium` — this is the CI
 *      path. The browser binary is checked before returning, so a patchright
 *      package without its Chromium still skips cleanly instead of failing at
 *      launch time.
 *
 * Returns a Playwright-compatible `chromium` object, or null when no usable
 * driver is available — callers then skip with exit 0.
 */
import { createRequire } from 'node:module';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const EXTENSION_BASES = [
  'C:/Users/dribb/.vscode/extensions/',
  'C:/Users/dribb/.vscode-insiders/extensions/',
];

const chromiumOf = (mod) => mod?.chromium ?? mod?.default?.chromium ?? null;

function extensionRoots() {
  const roots = [];
  for (const base of EXTENSION_BASES) {
    if (!existsSync(base)) continue;
    const dirs = readdirSync(base)
      .filter((d) => d.startsWith('danielsanmedium.dscodegpt-'))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    if (dirs.length) roots.push(join(base, dirs[dirs.length - 1], 'standalone') + '/');
  }
  return roots;
}

export function resolveChromium() {
  // 1. CodeGPT extension (local dev). No existence check here: its bundled
  //    Chromium lives outside the default Playwright cache, so it is returned
  //    on trust, exactly as before.
  for (const root of extensionRoots()) {
    try {
      const chromium = chromiumOf(createRequire(root)('patchright'));
      if (chromium) return chromium;
    } catch { /* try the next source */ }
  }

  // 2. npm-installed patchright (CI). Require the downloaded browser so an
  //    installed package without its binary degrades to a skip, not a crash.
  try {
    const chromium = chromiumOf(createRequire(import.meta.url)('patchright'));
    if (chromium && existsSync(chromium.executablePath())) return chromium;
  } catch { /* not installed */ }

  return null;
}
