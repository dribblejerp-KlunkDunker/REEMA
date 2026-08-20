// src/memory.js
// Client-side memory layer for the BlackVault messenger.
//
// Speaks the Hindsight REST API directly (global fetch, zero dependencies) so
// no SDK install is needed and the wire contract is explicit. This layer is
// deliberately *best-effort*: memory is an enhancement, and a failure here
// must never break the messaging path — every method resolves, never throws,
// and logs the first failure once per instance.
//
// BANK-PER-TENANT: each tenant (identity, conversation, or app) gets its own
// isolated Hindsight bank, created from a reusable TEMPLATE — a bank manifest
// carrying missions (retain/reflect), disposition traits (skepticism,
// literalism, empathy — affect reflect only, scale 1-5), directives, and
// mental models. Templates make tenant onboarding declarative: `createMemory({
// tenant: 'code-review' })` provisions a fully-configured bank. See
// TENANT_TEMPLATES below and the bank import/config endpoints in the contract.
//
// PER-SESSION TAGS (inside a tenant bank): every retained memory carries two
// scope tags — `session:<sha256(peerAddress) hex, first 12>` (the conversation
// scope, derived by sessionTag()) and `direction:sent|received`. Session-scoped
// recall MUST use tags_match 'all_strict' (AND-match, excludes untagged), so a
// memory from another session can never match. The hash keeps base64 special
// characters out of tag values and the full address out of the tag inventory.
//
// Wire contract (hindsight-docs openapi.json):
//   retain   POST /v1/default/banks/{bank_id}/memories
//            { items: [{ content, context?, document_id?, timestamp?, tags? }], async }
//   recall   POST /v1/default/banks/{bank_id}/memories/recall
//            { query, limit?, tags?, tags_match? } -> { results: [{ text, ... }] }
//            tags_match: any | all | any_strict | all_strict | exact
//   bank     PUT  /v1/default/banks/{bank_id}   (create; idempotent)
//   template POST /v1/default/banks/{bank_id}/import
//            { version: '1', bank?: BankTemplateConfig, directives?, mental_models? }
//   config   GET|PATCH /v1/default/banks/{bank_id}/config
//            PATCH body { updates: { reflect_mission?, disposition_skepticism?, ... } }
//   banks    GET /v1/default/banks  -> { banks: [{ bank_id, mission, disposition, ... }] }
//   delete   DELETE /v1/default/banks/{bank_id}

import { createHash } from 'node:crypto';

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Per-session tag: `session:<sha256(peerAddress) hex, first 12>`. Deterministic
 * per peer, short, free of base64 special characters, and does not leak the
 * full address into the bank's tag inventory. The browser twin (public/memory.js)
 * derives the same value with crypto.subtle('SHA-256').
 */
export function sessionTag(peerAddress) {
  return `session:${createHash('sha256').update(String(peerAddress)).digest('hex').slice(0, 12)}`;
}

function sanitizeBankId(id) {
  // Hindsight bank ids are validated server-side; keep ours conservative
  // (lowercase alphanumerics + dash/underscore) so a derived id can't 400.
  return String(id).replace(/[^a-z0-9_-]/gi, '').toLowerCase().slice(0, 64);
}

/**
 * Reusable bank templates for the bank-per-tenant setup. Missions follow the
 * best-practices guidance (specific fact types to extract, explicit ignores,
 * persona for reflect); disposition profiles come from the common agent
 * profiles table. Dispositions affect reflect only (not recall).
 */
export const TENANT_TEMPLATES = {
  'personal-assistant': {
    version: '1',
    bank: {
      reflect_mission: 'You are a personal assistant who remembers everything important to the user. ' +
        'Personalize every response using what you know about their preferences, schedule, and ongoing projects.',
      retain_mission: 'Extract personal preferences, ongoing commitments, deadlines, health info, and ' +
        'relationship details. Ignore filler phrases and pleasantries.',
      observations_mission: 'Identify evolving preferences, recurring patterns, behavioral shifts, and ' +
        'contradictions with prior knowledge. Focus on durable patterns, not transient states.',
      disposition_skepticism: 2,
      disposition_literalism: 2,
      disposition_empathy: 4,
      enable_observations: true,
    },
    directives: [
      { name: 'Be concise', content: 'Prefer short, actionable answers.', priority: 10 },
    ],
  },
  'code-review': {
    version: '1',
    bank: {
      reflect_mission: 'You are a senior developer reviewing code. Be direct and opinionated, cite the ' +
        'specific lines or decisions you are referencing, and separate real bugs from style nits.',
      retain_mission: 'Extract technical decisions, API design choices, architectural trade-offs, blockers, ' +
        'and error messages. Ignore greetings, small talk, and scheduling logistics.',
      observations_mission: 'Track recurring design patterns, repeated bugs, and architectural drift across ' +
        'reviews. Flag contradictions with prior decisions.',
      disposition_skepticism: 4,
      disposition_literalism: 5,
      disposition_empathy: 1,
      enable_observations: true,
    },
    directives: [
      { name: 'Quote the code', content: 'Reference exact functions and line numbers in every review.', priority: 10 },
    ],
  },
  'support': {
    version: '1',
    bank: {
      reflect_mission: 'You are a support agent with full context of this customer history. Reference past ' +
        'tickets and resolutions where relevant. Be concise and solution-focused.',
      retain_mission: 'Extract customer issues, resolutions, and sentiment. Capture product names, error ' +
        'codes, and what fixed the problem. Ignore pleasantries.',
      observations_mission: 'Track recurring customer pain points and sentiment shifts over time.',
      disposition_skepticism: 2,
      disposition_literalism: 3,
      disposition_empathy: 4,
      enable_observations: true,
    },
    directives: [
      { name: 'Solutions first', content: 'Lead every answer with the fix, then explain why.', priority: 10 },
    ],
  },
};

export function createMemory({
  baseUrl,
  bankId,
  tenant = null,
  template = null,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  logger = null,
} = {}) {
  if (!baseUrl) {
    throw new Error('createMemory: baseUrl is required (e.g. http://127.0.0.1:8888)');
  }
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const bank = sanitizeBankId(bankId || 'blackvault');
  // Template precedence: explicit `template` wins over a named `tenant` preset.
  const resolvedTemplate = template || (tenant ? TENANT_TEMPLATES[tenant] : null);
  let warned = false; // log the first failure once, then stay quiet

  const log = (level, ...args) => {
    if (logger && typeof logger[level] === 'function') logger[level](...args);
  };

  async function request(method, path, body) {
    const ctl = AbortSignal.timeout(timeoutMs);
    const res = await fetch(`${cleanBase}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctl,
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const detail = json && (json.detail || json.error) ? JSON.stringify(json.detail || json.error) : text.slice(0, 200);
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

  /**
   * Provision the tenant bank: create it (idempotent) and apply the template.
   * With a template this sets missions, dispositions, directives, and mental
   * models in one import; without one it falls back to a mission-only config
   * patch (the modern, non-deprecated path). Best-effort: banks auto-create on
   * first retain, so a failure here never blocks the messaging path.
   */
  async function ensureBank({ template: tpl = null, tenant: tn = null, mission } = {}) {
    const t = tpl || (tn ? TENANT_TEMPLATES[tn] : null) || resolvedTemplate;
    try {
      await request('PUT', `/v1/default/banks/${bank}`, { name: bank });
      if (t) {
        const result = await request('POST', `/v1/default/banks/${bank}/import`, t);
        return { ok: true, bank, templateApplied: true, result };
      }
      if (mission) {
        await request('PATCH', `/v1/default/banks/${bank}/config`, {
          updates: { reflect_mission: mission },
        });
      }
      return { ok: true, bank };
    } catch (err) {
      return recordError('ensureBank', err);
    }
  }

  /** Apply (or re-apply) a bank template manifest to this tenant bank. */
  async function applyTemplate(template) {
    try {
      const result = await request('POST', `/v1/default/banks/${bank}/import`, template);
      return { ok: true, result };
    } catch (err) {
      return recordError('applyTemplate', err);
    }
  }

  /** Read the tenant bank's effective config (missions, dispositions, …). */
  async function getConfig() {
    try {
      const res = await request('GET', `/v1/default/banks/${bank}/config`);
      return { ok: true, config: res.config || res };
    } catch (err) {
      return recordError('getConfig', err);
    }
  }

  /** Patch config fields, e.g. { reflect_mission, disposition_empathy }. */
  async function updateConfig(updates) {
    if (!updates || typeof updates !== 'object' || !Object.keys(updates).length) {
      return { ok: true, skipped: true };
    }
    try {
      const res = await request('PATCH', `/v1/default/banks/${bank}/config`, { updates });
      return { ok: true, config: res.config || res };
    } catch (err) {
      return recordError('updateConfig', err);
    }
  }

  /** List all banks (every tenant), for tenant inventory / cleanup tooling. */
  async function listBanks() {
    try {
      const res = await request('GET', '/v1/default/banks');
      return { ok: true, banks: Array.isArray(res.banks) ? res.banks : [] };
    } catch (err) {
      return recordError('listBanks', err);
    }
  }

  /** Delete this tenant bank and all its memories (prototype cleanup). */
  async function deleteBank() {
    try {
      await request('DELETE', `/v1/default/banks/${bank}`);
      return { ok: true, bank };
    } catch (err) {
      return recordError('deleteBank', err);
    }
  }

  /** Store one memory. Defaults to async (fire-and-forget) so the send path
   *  is never blocked; pass { wait: true } for a deterministic round-trip. */
  async function retain(text, { context, documentId, timestamp, tags, wait = false } = {}) {
    if (text == null || String(text).trim() === '') return { ok: true, skipped: true };
    const item = { content: String(text) };
    if (context) item.context = String(context);
    if (documentId) item.document_id = String(documentId);
    if (timestamp) item.timestamp = timestamp;
    if (tags && tags.length) item.tags = tags;
    try {
      const res = await request('POST', `/v1/default/banks/${bank}/memories`, {
        items: [item],
        async: !wait,
      });
      return {
        ok: true,
        async: !!res.async,
        operationId: res.operation_id || null,
        itemsCount: res.items_count ?? 1,
      };
    } catch (err) {
      return recordError('retain', err);
    }
  }

  /** Search the bank. Returns { ok, results: [{text,type,context,score}], error }.
   *  results are ordered by final score, best first.
   *
   *  Tag filters enforce the per-session scheme: pass { tags: [sessionTag(peer)],
   *  tagsMatch: 'all_strict' } to scope a recall to one session — AND-match,
   *  untagged excluded, so no other session's memories can surface. */
  async function recall(query, { limit = 5, tags, tagsMatch } = {}) {
    if (query == null || String(query).trim() === '') return { ok: true, results: [] };
    const body = { query: String(query), limit };
    if (Array.isArray(tags) && tags.length) body.tags = tags;
    if (tagsMatch) body.tags_match = tagsMatch;
    try {
      const res = await request('POST', `/v1/default/banks/${bank}/memories/recall`, body);
      const results = Array.isArray(res.results)
        ? res.results.map((r) => ({
            text: r.text,
            type: r.type || 'world',
            context: r.context || null,
            score: r.scores && typeof r.scores.final === 'number' ? r.scores.final : null,
          }))
        : [];
      return { ok: true, results };
    } catch (err) {
      return recordError('recall', err);
    }
  }

  return {
    bankId: bank,
    tenant: tenant || null,
    template: resolvedTemplate,
    ensureBank,
    applyTemplate,
    getConfig,
    updateConfig,
    listBanks,
    deleteBank,
    retain,
    recall,
    // Kept for API symmetry; nothing to tear down (the daemon owns its
    // process and profile, the client is stateless HTTP).
    close() {},
  };
}
