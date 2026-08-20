// public/memory.js
// Browser-side memory adapter — the dashboard's counterpart to src/memory.js.
//
// A browser page cannot talk to a Hindsight daemon directly (separate OS
// process, no CORS, no origin protection), so this adapter targets the
// loopback sidecar (tools/memory-sidecar.mjs) instead:
//
//   dashboard --> http://127.0.0.1:8878/v1/memory/*  -->  Hindsight daemon
//
// API contract is deliberately IDENTICAL to src/memory.js so the messenger
// code paths (retain on send, retain+recall on receive) are symmetric between
// the CLI and the browser:
//
//   const mem = createMemory({ baseUrl, bankId });
//   await mem.retain(text, { context: 'sent' });            // fire-and-forget
//   const r = await mem.recall(text);                       // { ok, results }
//
// Best-effort by design: every method resolves, never throws, and logs the
// first failure once per instance — memory must never break the chat.
//
// Plain ESM (global fetch + AbortSignal only): runs in the browser via the
// import map and in Node for smoke tests.

const DEFAULT_TIMEOUT_MS = 10_000;

export function createMemory({
  baseUrl,
  bankId,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  logger = null,
} = {}) {
  if (!baseUrl) {
    throw new Error('createMemory: baseUrl is required (e.g. http://127.0.0.1:8878)');
  }
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const bank = String(bankId || 'blackvault');
  let warned = false;

  const log = (level, ...args) => {
    if (logger && typeof logger[level] === 'function') logger[level](...args);
  };

  async function sidecar(method, path, body) {
    const res = await fetch(`${cleanBase}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    if (!res.ok) {
      const detail = json && (json.error || json.detail) ? JSON.stringify(json.error || json.detail) : text.slice(0, 200);
      throw new Error(`${method} ${path} -> ${res.status}: ${detail}`);
    }
    return json;
  }

  function recordError(what, err) {
    if (!warned) {
      warned = true;
      log('warn', `[memory] ${what} failed (${err.message}); further memory errors will be silent`);
    }
    return { ok: false, error: err.message };
  }

  /** Probe the sidecar + daemon. Returns { ok, daemon } — null when unreachable. */
  async function health() {
    try {
      const h = await sidecar('GET', '/health');
      return { ok: true, daemon: !!h.daemon };
    } catch {
      return { ok: false, daemon: false };
    }
  }

  async function ensureBank({ mission } = {}) {
    try {
      await sidecar('PUT', '/v1/memory/bank', { bank, mission });
      return { ok: true };
    } catch (err) {
      return recordError('ensureBank', err);
    }
  }

  async function retain(text, { context, wait = false } = {}) {
    if (text == null || String(text).trim() === '') return { ok: true, skipped: true };
    try {
      // Fire-and-forget by default so the send path is never blocked; the
      // receive path passes wait:true so a chained recall sees it indexed.
      const r = await sidecar('POST', '/v1/memory/retain', { bank, text: String(text), context, wait });
      return { ok: !!r.ok, async: true, operationId: r.operationId || null, ...(r.error ? { error: r.error } : {}) };
    } catch (err) {
      return recordError('retain', err);
    }
  }

  async function recall(query, { limit = 5, tags, tagsMatch } = {}) {
    if (query == null || String(query).trim() === '') return { ok: true, results: [] };
    try {
      const body = { bank, query: String(query), limit };
      // Per-session tag scheme: pass { tags: [sessionTag(peer)], tagsMatch:
      // 'all_strict' } to scope a recall to one session (see src/memory.js).
      if (Array.isArray(tags) && tags.length) body.tags = tags;
      if (tagsMatch) body.tags_match = tagsMatch;
      const r = await sidecar('POST', '/v1/memory/recall', body);
      return { ok: !!r.ok, results: Array.isArray(r.results) ? r.results : [], ...(r.error ? { error: r.error } : {}) };
    } catch (err) {
      return recordError('recall', err);
    }
  }

  return { bankId: bank, health, ensureBank, retain, recall, close() {} };
}
