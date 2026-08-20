// Minimal static file server for public/. ES modules and import maps do not
// work from file:// URLs, so the browser client needs a real HTTP origin.
// Loopback only — this serves the app, not the relay.
//
// Performance: the page is ~1.2 MB uncompressed; Brotli cuts that to ~250 KB
// total, so every response is compressed when the client accepts it, and
// non-HTML assets carry a 1-day cache so a reload does not re-download the
// crypto stack. Compressed variants are cached in memory per file mtime. The
// heavy crypto is no longer part of the initial page either way: libsodium
// (643 KB raw -> ~180 KB brotli) is injected by browser-crypto.js on the idle
// bootstrap, and the @noble/post-quantum graph (~67 KB brotli) is dynamically
// imported on first session — first paint fetches only HTML/CSS/fonts/core JS.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { brotliCompressSync, gzipSync, constants as Z } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT = fileURLToPath(new URL('..', import.meta.url));
const ROOT = path.join(PROJECT, 'public');
const HOST = '127.0.0.1';
const PORT = Number(process.env.UI_PORT || 8000);

// ---- Vendor integrity at startup ----
// public/vendor/ holds the entire runtime crypto stack (libsodium, @noble,
// age-encryption). A tampered or substituted file on disk would be served as
// the app's "backdoored cipher", so verify every vendored file against the
// committed SHA-256 pins in tools/vendor-manifest.json before serving, and
// refuse to serve any /vendor/ path when the check fails.
const vendorIntegrityErrors = [];
try {
  const manifest = JSON.parse(readFileSync(path.join(PROJECT, 'tools', 'vendor-manifest.json'), 'utf8'));
  for (const [file, expected] of Object.entries(manifest)) {
    const p = path.join(ROOT, 'vendor', file);
    if (!existsSync(p)) { vendorIntegrityErrors.push(`MISSING ${file}`); continue; }
    const actual = createHash('sha256').update(readFileSync(p)).digest('hex');
    if (actual !== expected) vendorIntegrityErrors.push(`MISMATCH ${file}`);
  }
} catch (err) {
  vendorIntegrityErrors.push(`manifest unreadable: ${err.message}`);
}
if (vendorIntegrityErrors.length) {
  console.error(`[ui] VENDOR INTEGRITY CHECK FAILED (${vendorIntegrityErrors.length} issue(s)) — refusing to serve public/vendor/:`);
  for (const e of vendorIntegrityErrors.slice(0, 12)) console.error(`[ui]   ${e}`);
  console.error('[ui] run "npm run check:vendor" for a full report, or "npm run vendor" to re-pin after an intentional change.');
}

// public/aegis/ holds the vendored AEGIS brain (verdict gate + DID binding).
// A tampered copy would decide whether a message is flagged before it leaves
// the device, so it gets the same startup-integrity + refuse-to-serve treatment
// as the crypto stack. Pins live in tools/vendor-aegis-manifest.json.
const aegisIntegrityErrors = [];
try {
  const manifest = JSON.parse(readFileSync(path.join(PROJECT, 'tools', 'vendor-aegis-manifest.json'), 'utf8'));
  for (const [file, meta] of Object.entries(manifest)) {
    const p = path.join(ROOT, 'aegis', file);
    if (!existsSync(p)) { aegisIntegrityErrors.push(`MISSING ${file}`); continue; }
    const actual = createHash('sha256').update(readFileSync(p)).digest('hex');
    if (actual !== meta.sha256) aegisIntegrityErrors.push(`MISMATCH ${file}`);
  }
} catch (err) {
  aegisIntegrityErrors.push(`manifest unreadable: ${err.message}`);
}
if (aegisIntegrityErrors.length) {
  console.error(`[ui] AEGIS INTEGRITY CHECK FAILED (${aegisIntegrityErrors.length} issue(s)) — refusing to serve public/aegis/:`);
  for (const e of aegisIntegrityErrors.slice(0, 12)) console.error(`[ui]   ${e}`);
  console.error('[ui] run "npm run check:aegis" for a full report, or "npm run vendor:aegis" to re-pin after an intentional change.');
}

// ---- AEGIS dashboard mount (same origin => shared IndexedDB) ----
// Serving SOVEREIGN // AEGIS at /dashboard/ puts the dashboard and the messenger
// on ONE origin, so they share the `sovereign-aegis-attempts` IndexedDB and the
// messenger's near-share misses move the dashboard's stop-skill mastery with no
// export/import step. Optional: when AEGIS_ROOT is absent or not a directory the
// mount is simply not served (the messenger works standalone as before).
const AEGIS_ROOT = (() => {
  const candidate = process.env.AEGIS_ROOT
    || 'C:/Users/dribb/AI PROJECT FOLDER/blackvault-app/BLACKVAULT DASHBOARD/perimeter-suite/sovereign-aegis';
  try {
    // path.resolve normalises the separators so the containment check below compares
    // like with like: the env default uses forward slashes on Windows while path.join()
    // emits backslashes, so an un-normalised root would fail its own startsWith guard.
    const resolved = path.resolve(candidate);
    return existsSync(resolved) ? resolved : null;
  } catch { return null; }
})();

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

// Only text-like assets compress meaningfully; below this size the overhead
// of encoding + the extra header is not worth it.
const MIN_COMPRESS = 1024;
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.json', '.txt', '.md', '.svg', '.map']);

// absPath -> { mtimeMs, br, gz }. Brotli q9 is ~2-3% larger than q11 but
// compresses the big files in tens of ms; cached, so it is paid once per edit.
const cache = new Map();

async function getAsset(filePath) {
  const st = await stat(filePath);
  const hit = cache.get(filePath);
  if (hit && hit.mtimeMs === st.mtimeMs) return hit;
  const raw = await readFile(filePath);
  const ext = path.extname(filePath);
  const compress = COMPRESSIBLE.has(ext) && raw.length >= MIN_COMPRESS;
  const entry = {
    mtimeMs: st.mtimeMs,
    raw,
    br: compress ? brotliCompressSync(raw, { params: { [Z.BROTLI_PARAM_QUALITY]: 9 } }) : null,
    gz: compress ? gzipSync(raw, { level: 9 }) : null,
  };
  cache.set(filePath, entry);
  return entry;
}

// Serve one file (from public/ or the AEGIS mount) with the same compression and
// cache policy. HTML revalidates every load; other assets cache for a day.
async function serveAsset(res, filePath, acceptEncoding) {
  const entry = await getAsset(filePath);
  const type = TYPES[path.extname(filePath)] || 'application/octet-stream';
  const cacheControl = path.extname(filePath) === '.html' ? 'no-cache' : 'public, max-age=86400';
  if (entry.br && /\bbr\b/.test(acceptEncoding)) {
    send(res, 200, entry.br, {
      'Content-Type': type,
      'Content-Encoding': 'br',
      'Cache-Control': cacheControl,
      'Vary': 'Accept-Encoding',
    });
  } else if (entry.gz && /\bgzip\b/.test(acceptEncoding)) {
    send(res, 200, entry.gz, {
      'Content-Type': type,
      'Content-Encoding': 'gzip',
      'Cache-Control': cacheControl,
      'Vary': 'Accept-Encoding',
    });
  } else {
    send(res, 200, entry.raw, { 'Content-Type': type, 'Cache-Control': cacheControl });
  }
}

function send(res, status, body, headers) {
  res.writeHead(status, headers);
  res.end(body);
}

createServer(async (req, res) => {
  // A malformed percent-encoding (e.g. /%) makes decodeURIComponent throw; an
  // unhandled rejection here would crash the whole server on one bad request.
  try {
    const urlPath = decodeURIComponent(new URL(req.url, `http://${HOST}`).pathname);

    // AEGIS dashboard mount: /dashboard -> AEGIS_ROOT/index.html. Same origin as
    // the messenger, so the two apps share the `sovereign-aegis-attempts` IndexedDB
    // and a near-share miss moves the dashboard's stop-skill mastery automatically.
    if (AEGIS_ROOT && (urlPath === '/dashboard' || urlPath.startsWith('/dashboard/'))) {
      // The slashless form must redirect: index.html uses relative asset URLs
      // (css/..., js/..., data/...), and against /dashboard (no trailing slash) those
      // resolve as the messenger root, which breaks the dashboard's boot. 308 keeps any
      // future non-GET semantics, though this is a GET-only static mount.
      if (urlPath === '/dashboard') {
        send(res, 308, 'Redirecting to /dashboard/', {
          'Content-Type': 'text/plain',
          'Location': '/dashboard/',
        });
        return;
      }
      const dashRel = urlPath.slice('/dashboard/'.length) || 'index.html';
      const dashPath = path.join(AEGIS_ROOT, dashRel);
      if (!dashPath.startsWith(AEGIS_ROOT + path.sep) && dashPath !== AEGIS_ROOT) {
        send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain' });
        return;
      }
      await serveAsset(res, dashPath, req.headers['accept-encoding'] || '');
      return;
    }

    const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
    const filePath = path.join(ROOT, rel);

    // Refuse anything that escapes public/
    if (!filePath.startsWith(ROOT + path.sep) && filePath !== path.join(ROOT, 'index.html')) {
      send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain' });
      return;
    }

    // Startup integrity failed: never hand the page a potentially tampered
    // crypto module, even for a single request.
    if (vendorIntegrityErrors.length && urlPath.startsWith('/vendor/')) {
      send(res, 503, 'Vendor integrity check failed — refusing to serve potentially tampered crypto. Run "npm run check:vendor".', { 'Content-Type': 'text/plain' });
      return;
    }

    // Same for the verdict gate: never serve a tampered AEGIS module.
    if (aegisIntegrityErrors.length && urlPath.startsWith('/aegis/')) {
      send(res, 503, 'AEGIS integrity check failed — refusing to serve potentially tampered verdict logic. Run "npm run check:aegis".', { 'Content-Type': 'text/plain' });
      return;
    }

    await serveAsset(res, filePath, req.headers['accept-encoding'] || '');
  } catch (err) {
    if (err && err.code === 'ENOENT') send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
    else send(res, 400, 'Bad request', { 'Content-Type': 'text/plain' });
  }
}).listen(PORT, HOST, () => {
  console.log(`[ui] serving public/ at http://${HOST}:${PORT}`);
  if (AEGIS_ROOT) console.log(`[ui] AEGIS dashboard mounted at http://${HOST}:${PORT}/dashboard/ (shared origin => shared attempt log)`);
  else console.log('[ui] AEGIS dashboard not mounted — set AEGIS_ROOT to the sovereign-aegis directory to enable it');
  console.log('[ui] start the relay too:  npm run server');
});
