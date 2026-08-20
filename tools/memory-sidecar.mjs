// tools/memory-sidecar.mjs
// Loopback Hindsight sidecar for the browser dashboard.
//
// A browser page cannot spawn (or even reach directly) a Hindsight daemon the
// way the CLI client does — the daemon is a separate OS process with no CORS
// and no origin protection. This sidecar bridges the two:
//
//   browser (dashboard)  --loopback HTTP-->  sidecar  --HTTP-->  Hindsight daemon
//        http://127.0.0.1:8878                    http://127.0.0.1:8877
//
// The sidecar:
//   * owns the daemon lifecycle — spawns it via uvx on first use (same profile
//     + env as tools/live-memory-demo.mjs) or reuses one already running
//     (HINDSIGHT_URL);
//   * exposes a NARROW API (health / retain / recall / bank) with a hard
//     bank-id whitelist (bv-<16 hex>, the identity-derived pattern), so it can
//     never be used to touch arbitrary banks;
//   * defends against DNS-rebinding / drive-by use: loopback-only Host check,
//     cross-site Origin / Sec-Fetch-Site rejection, no credentials, CORS
//     allow-listed to loopback origins only.
//
// Usage:
//   node tools/memory-sidecar.mjs [--port 8878] [--daemon-url http://127.0.0.1:8877]
//   MEMORY_SIDECAR_PORT / HINDSIGHT_URL / MEMORY_NO_SPAWN=1 overrides.
//   npm run memory-sidecar

import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';

const PORT = Number(process.env.MEMORY_SIDECAR_PORT || 8878);
const DAEMON_URL = (process.env.HINDSIGHT_URL || 'http://127.0.0.1:8877').replace(/\/+$/, '');
const SPAWN_DAEMON = process.env.MEMORY_NO_SPAWN !== '1';
const DAEMON_PORT = Number(process.env.MEMORY_DAEMON_PORT || 8877);
const BANK_RE = /^bv-[0-9a-f]{16}$/;
const MAX_BODY = 128 * 1024;
const DAEMON_TIMEOUT_MS = 15_000;
const READY_TIMEOUT_MS = 180_000; // first-ever run downloads the embed model

let spawnedByUs = false;
let daemonProc = null;
let daemonHealthy = false;

function log(...args) {
  console.log(`[memory-sidecar]`, ...args);
}

async function fetchJson(url, { method = 'GET', body, timeoutMs = DAEMON_TIMEOUT_MS } = {}) {
  const res = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  if (!res.ok) {
    const detail = json && (json.detail || json.error) ? JSON.stringify(json.detail || json.error) : text.slice(0, 200);
    throw new Error(`${method} ${url} -> ${res.status}: ${detail}`);
  }
  return json;
}

async function daemonHealth() {
  try {
    const h = await fetchJson(`${DAEMON_URL}/health`, { timeoutMs: 3000 });
    return !!(h && h.status === 'healthy');
  } catch {
    return false;
  }
}

/** Mirror the demo's profile/env so the CLI and browser share one daemon. */
async function spawnDaemon() {
  log('daemon not healthy at', DAEMON_URL, '— spawning via uvx...');
  const envArgs = [
    '--env', 'HINDSIGHT_API_LLM_PROVIDER=none',
    '--env', 'HINDSIGHT_API_EMBEDDINGS_LOCAL_FORCE_CPU=1',
    '--env', 'HINDSIGHT_API_RERANKER_LOCAL_FORCE_CPU=1',
    '--env', 'HINDSIGHT_EMBED_DAEMON_IDLE_TIMEOUT=0',
  ];
  const profile = spawnSync('uvx', ['hindsight-embed', '-p', 'bv-memory', 'profile', 'create', 'bv-memory', '--merge', '--port', String(DAEMON_PORT), ...envArgs], { encoding: 'utf8' });
  if (profile.status !== 0) {
    throw new Error(`profile create failed: ${(profile.stderr || profile.stdout || '').slice(0, 300)}`);
  }
  daemonProc = spawn('uvx', ['hindsight-embed', '-p', 'bv-memory', 'daemon', 'start'], { stdio: 'ignore' });
  daemonProc.on('error', (err) => log('daemon spawn error:', err.message));
  spawnedByUs = true;
  const start = Date.now();
  while (Date.now() - start < READY_TIMEOUT_MS) {
    if (await daemonHealth()) { log('daemon healthy'); return; }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error('daemon did not become healthy in time — check uvx/hindsight-embed');
}

async function stopDaemon() {
  if (!spawnedByUs) return;
  try {
    spawnSync('uvx', ['hindsight-embed', '-p', 'bv-memory', 'daemon', 'stop'], { stdio: 'ignore' });
    log('daemon stopped');
  } catch {
    /* best effort */
  }
}

// ---- request guards -------------------------------------------------------

function isLoopbackHost(host) {
  if (!host) return false;
  const h = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]';
}

function isLoopbackOrigin(origin) {
  if (!origin) return true; // no Origin header (same-origin CLI, curl)
  try {
    const u = new URL(origin);
    return u.protocol === 'http:' || u.protocol === 'https:'
      ? isLoopbackHost(u.host)
      : false;
  } catch {
    return false;
  }
}

function guard(req) {
  // Layer 1: the request must be addressed to the loopback sidecar itself.
  if (!isLoopbackHost(req.headers.host || '')) return 'loopback host required';
  // Layer 2: a browser page fetching this cross-origin sends Origin and
  // Sec-Fetch-Site. Reject anything that is not a loopback origin / not
  // same-origin-ish — this is what stops a random website from using the
  // sidecar as a proxy to the daemon (DNS-rebinding / drive-by).
  const origin = req.headers.origin;
  if (origin && !isLoopbackOrigin(origin)) return 'cross-origin request rejected';
  const sfs = req.headers['sec-fetch-site'];
  if (sfs && sfs === 'cross-site') return 'cross-site request rejected';
  return null;
}

function corsHeaders(req) {
  const origin = req.headers.origin;
  const headers = {
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };
  if (origin && isLoopbackOrigin(origin)) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers['content-length'] || 0);
    if (len > MAX_BODY) { reject(new Error('body too large')); return; }
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (Buffer.byteLength(data) > MAX_BODY) { reject(new Error('body too large')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function handle(req, res) {
  const g = guard(req);
  if (g) return send(res, 403, { error: g }, corsHeaders(req));
  const base = corsHeaders(req);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      ...base,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'content-type',
      'Access-Control-Max-Age': '600',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    daemonHealthy = await daemonHealth();
    return send(res, 200, {
      sidecar: 'ok',
      daemon: daemonHealthy,
      daemonUrl: DAEMON_URL,
      bankPattern: 'bv-[0-9a-f]{16}',
    }, base);
  }

  if ((req.method === 'POST' || req.method === 'PUT') && url.pathname.startsWith('/v1/memory/')) {
    let body;
    try {
      body = JSON.parse((await readBody(req)) || '{}');
    } catch {
      return send(res, 400, { error: 'invalid or oversized JSON body' }, base);
    }
    const bank = body.bank;
    if (typeof bank !== 'string' || !BANK_RE.test(bank)) {
      return send(res, 400, { error: 'bank must match bv-[0-9a-f]{16}' }, base);
    }
    if (!daemonHealthy) daemonHealthy = await daemonHealth();
    if (!daemonHealthy) return send(res, 503, { ok: false, error: 'hindsight daemon unavailable' }, base);

    try {
      switch (url.pathname) {
        case '/v1/memory/retain': {
          const text = typeof body.text === 'string' ? body.text : '';
          if (!text.trim()) return send(res, 400, { error: 'text required' }, base);
          const item = { content: text };
          if (typeof body.context === 'string' && body.context) item.context = body.context;
          // Default async (fire-and-forget); the receive path requests wait:true
          // so a chained recall sees the just-retained memory indexed.
          const r = await fetchJson(`${DAEMON_URL}/v1/default/banks/${bank}/memories`, {
            method: 'POST',
            body: { items: [item], async: body.wait !== true },
          });
          return send(res, 200, { ok: true, async: true, operationId: r.operation_id || null }, base);
        }
        case '/v1/memory/recall': {
          const query = typeof body.query === 'string' ? body.query : '';
          if (!query.trim()) return send(res, 400, { error: 'query required' }, base);
          const limit = Number.isInteger(body.limit) && body.limit > 0 ? body.limit : 5;
          const recallBody = { query, limit };
          // Per-session tag scheme passthrough (tags + tags_match) so the
          // browser adapter can scope recall to one session with all_strict.
          if (Array.isArray(body.tags) && body.tags.length) recallBody.tags = body.tags;
          if (typeof body.tags_match === 'string') recallBody.tags_match = body.tags_match;
          const r = await fetchJson(`${DAEMON_URL}/v1/default/banks/${bank}/memories/recall`, {
            method: 'POST',
            body: recallBody,
          });
          const results = Array.isArray(r.results)
            ? r.results.map((m) => ({
                text: m.text,
                type: m.type || 'world',
                context: m.context || null,
                score: m.scores && typeof m.scores.final === 'number' ? m.scores.final : null,
              }))
            : [];
          return send(res, 200, { ok: true, results }, base);
        }
        case '/v1/memory/bank': {
          const mission = typeof body.mission === 'string' && body.mission ? body.mission
            : 'Per-conversation recall for the BlackVault messenger.';
          await fetchJson(`${DAEMON_URL}/v1/default/banks/${bank}`, {
            method: 'PUT',
            body: { name: bank, mission, disposition: { skepticism: 3, literalism: 3, empathy: 3 } },
          });
          return send(res, 200, { ok: true }, base);
        }
        default:
          return send(res, 404, { error: 'unknown memory endpoint' }, base);
      }
    } catch (err) {
      // Daemon-side failure: report as a non-throwing ok:false so the browser
      // adapter's best-effort contract holds (memory must never break chat).
      return send(res, 200, { ok: false, error: err.message }, base);
    }
  }

  return send(res, 404, { error: 'not found' }, base);
}

const server = createServer((req, res) => {
  handle(req, res).catch((err) => send(res, 500, { error: err.message }, corsHeaders(req)));
});

async function main() {
  if (await daemonHealth()) {
    log('reusing healthy daemon at', DAEMON_URL);
    daemonHealthy = true;
  } else if (SPAWN_DAEMON) {
    await spawnDaemon();
    daemonHealthy = true;
  } else {
    log('MEMORY_NO_SPAWN=1 and daemon not healthy — serving with daemon=down');
  }
  server.listen(PORT, '127.0.0.1', () => {
    log(`loopback sidecar on http://127.0.0.1:${PORT} -> daemon ${DAEMON_URL}`);
    log(`dashboard: open the app and it will auto-detect (or pass ?memory=http://127.0.0.1:${PORT})`);
  });
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    log('shutting down...');
    server.close();
    await stopDaemon();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error('[memory-sidecar] fatal:', err.message);
  process.exit(1);
});
