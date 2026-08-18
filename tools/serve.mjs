// Minimal static file server for public/. ES modules and import maps do not
// work from file:// URLs, so the browser client needs a real HTTP origin.
// Loopback only — this serves the app, not the relay.
//
// Performance: the page is ~1.2 MB uncompressed (the vendored libsodium build
// alone is 643 KB). Brotli cuts that to ~250 KB total (libsodium 643 KB -> ~180
// KB), so every response is compressed when the client accepts it, and
// non-HTML assets carry a 1-day cache so a reload does not re-download the
// crypto stack. Compressed variants are cached in memory per file mtime.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { brotliCompressSync, gzipSync, constants as Z } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(fileURLToPath(new URL('..', import.meta.url)), 'public');
const HOST = '127.0.0.1';
const PORT = Number(process.env.UI_PORT || 8000);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
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

function send(res, status, body, headers) {
  res.writeHead(status, headers);
  res.end(body);
}

createServer(async (req, res) => {
  // A malformed percent-encoding (e.g. /%) makes decodeURIComponent throw; an
  // unhandled rejection here would crash the whole server on one bad request.
  try {
    const urlPath = decodeURIComponent(new URL(req.url, `http://${HOST}`).pathname);
    const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
    const filePath = path.join(ROOT, rel);

    // Refuse anything that escapes public/
    if (!filePath.startsWith(ROOT + path.sep) && filePath !== path.join(ROOT, 'index.html')) {
      send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain' });
      return;
    }

    const entry = await getAsset(filePath);
    const type = TYPES[path.extname(filePath)] || 'application/octet-stream';
    const accept = req.headers['accept-encoding'] || '';

    // HTML is revalidated every load (dev correctness); everything else gets
    // a 1-day cache so the 180 KB brotli crypto stack is not re-downloaded on
    // every reload. Vary lets proxies keep both encodings.
    const cacheControl = path.extname(filePath) === '.html'
      ? 'no-cache'
      : 'public, max-age=86400';

    if (entry.br && /\bbr\b/.test(accept)) {
      send(res, 200, entry.br, {
        'Content-Type': type,
        'Content-Encoding': 'br',
        'Cache-Control': cacheControl,
        'Vary': 'Accept-Encoding',
      });
    } else if (entry.gz && /\bgzip\b/.test(accept)) {
      send(res, 200, entry.gz, {
        'Content-Type': type,
        'Content-Encoding': 'gzip',
        'Cache-Control': cacheControl,
        'Vary': 'Accept-Encoding',
      });
    } else {
      send(res, 200, entry.raw, { 'Content-Type': type, 'Cache-Control': cacheControl });
    }
  } catch (err) {
    if (err && err.code === 'ENOENT') send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
    else send(res, 400, 'Bad request', { 'Content-Type': 'text/plain' });
  }
}).listen(PORT, HOST, () => {
  console.log(`[ui] serving public/ at http://${HOST}:${PORT}`);
  console.log('[ui] start the relay too:  npm run server');
});
