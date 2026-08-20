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
      if (chromium) { console.log('::notice::browser driver: codegpt extension'); return chromium; }
    } catch { /* try the next source */ }
  }

  // 2. npm-installed patchright (CI). Return the driver if it exposes launch();
  //    the workflow installs the browser before this runs, and relying on
  //    executablePath() existence proved unreliable across platforms.
  try {
    const chromium = chromiumOf(createRequire(import.meta.url)('patchright'));
    if (chromium?.launch) { console.log('::notice::browser driver: npm patchright'); return chromium; }
    console.log('::notice::browser driver: npm patchright loaded but no chromium.launch');
  } catch (err) {
    console.log('::notice::browser driver: npm patchright not loadable (' + err.message + ')');
  }

  console.log('::notice::browser driver: none (browser stages will skip)');
  return null;
}

/**
 * Launch the resolved driver for the browser E2E stages.
 *
 * The relay is now TLS-on by default and presents the committed self-signed dev
 * cert (tools/certs/dev-cert.pem), so headless Chromium must not reject that
 * certificate when a page opens a `wss://` relay connection. The fingerprint
 * pinning that protects real clients lives in src/tls.js (Node) — the browser
 * can't do TOFU fingerprint pinning on a raw WebSocket, so the harness trusts
 * the loopback dev cert by ignoring certificate errors instead. This is the
 * test-harness analogue of "pin the dev cert", scoped to the headless driver.
 */
export function launchBrowser(chromium, opts = {}) {
  return chromium.launch({
    headless: opts.headless ?? true,
    args: ['--ignore-certificate-errors', ...(opts.args || [])],
    ...(opts.proxy ? { proxy: opts.proxy } : {}),
  });
}
