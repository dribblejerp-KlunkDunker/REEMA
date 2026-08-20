/**
 * SOVEREIGN // AEGIS — Append-only attempt log
 *
 * WHY THIS EXISTS
 * ---------------
 * Before this module the application had 87 content items, 48 assessable items, and zero
 * records of whether anyone ever got anything right. SM-2 held an ease factor, Arena held
 * an ELO, and neither was connected to the 24 fallacies, 39 DISARM techniques or 20 SIFT
 * scenarios the app teaches. Nothing could adapt, and nothing could be evaluated.
 *
 * This is the single place attempts are written. One record per right/wrong moment,
 * tagged with the SKILL it exercised rather than the screen it happened on.
 *
 * DESIGN: APPEND-ONLY, RAW EVENTS
 * -------------------------------
 * Records are never updated and derived mastery is never stored. Mastery is recomputed
 * from this log by js/competency.js on load. That is deliberate: the estimator is the
 * part most likely to be wrong, and storing its output would freeze today's guess into
 * the data. With raw events, changing the estimator is a recompute rather than a
 * migration. Re-tagging content is likewise a recompute.
 *
 * `v` is present on every record from day one. A schema version costs one byte and saves
 * a migration.
 *
 * DURABILITY AND PRIVACY
 * ----------------------
 * IndexedDB, same rationale as js/persist.js: localStorage is wiped by routine browser
 * cleanup, and losing months of practice history to that would be a serious failure.
 * This data never leaves the device — it is a record of exactly what someone is bad at,
 * which makes it the most sensitive data in the application. If sync is ever built, this
 * should be the last thing to sync and only end-to-end encrypted.
 *
 * @module attemptlog
 */

const DB_NAME = 'sovereign-aegis-attempts';
const DB_VERSION = 1;
const STORE = 'attempts';

/**
 * Current record schema version.
 *
 * v1 → v2 added `confidence`. Additive and non-breaking: v1 records stay valid and read as
 * `confidence: null`, which every consumer must treat as "not stated" rather than as a value.
 * No migration runs — the log is append-only and mastery is recomputed from raw events, so a
 * schema addition is a recompute, not a rewrite. That property is the whole reason `v` was
 * stamped on every record from day one.
 */
export const SCHEMA_VERSION = 2;

/**
 * The permitted confidence vocabulary — stated certainty at the moment of answering, BEFORE
 * feedback. Three levels rather than a slider: a slider invites false precision from a judgement
 * nobody can make to 1%, and three buckets are enough to draw a reliability curve.
 *
 * This module validates the words and nothing more. What each one is worth as a probability is a
 * scoring judgement and lives in js/competency.js, so it can be re-fitted against this log without
 * a migration.
 */
export const CONFIDENCE_VALUES = Object.freeze(['sure', 'unsure', 'guess']);

/**
 * Normalise a confidence value. Anything unrecognised becomes null — "not stated" — because a
 * guessed confidence would corrupt the one measurement confidence exists to provide.
 * @param {*} value
 * @returns {'sure'|'unsure'|'guess'|null}
 */
export function normaliseConfidence(value) {
  return CONFIDENCE_VALUES.includes(value) ? value : null;
}

function openDb() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB unavailable'));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        // Keys are time-ordered ids, so a key range is a time range.
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(req && req.result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

/**
 * Monotonic, lexicographically sortable id: 13 hex chars of timestamp + 8 random.
 * Sorting by id therefore sorts by time, which is what makes readSince() a range scan.
 * @param {number} ts
 * @returns {string}
 */
function makeId(ts) {
  const time = ts.toString(16).padStart(13, '0');
  let rand = '';
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const b = new Uint8Array(4);
    crypto.getRandomValues(b);
    rand = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  } else {
    rand = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0');
  }
  return `att_${time}${rand}`;
}

/**
 * Validate and normalise an attempt. Rejects rather than storing something the
 * estimator would later have to guess about.
 * @param {object} a
 * @returns {{ok: true, record: object} | {ok: false, reason: string}}
 */
export function normaliseAttempt(a) {
  if (!a || typeof a !== 'object') return { ok: false, reason: 'attempt is not an object' };
  if (typeof a.skillId !== 'string' || !a.skillId) return { ok: false, reason: 'skillId is required' };
  if (typeof a.itemId !== 'string' || !a.itemId) return { ok: false, reason: 'itemId is required' };
  if (typeof a.correct !== 'boolean') return { ok: false, reason: 'correct must be a boolean' };

  const ts = Number.isFinite(a.ts) ? a.ts : Date.now();
  const latencyMs = Number.isFinite(a.latencyMs) && a.latencyMs >= 0 ? Math.round(a.latencyMs) : null;

  return {
    ok: true,
    record: {
      // An imported v1 record keeps its own `v`. Restamping it as v2 would claim a confidence
      // measurement was taken when it was not, which is the one lie this schema must not tell.
      v: a.v === 1 ? 1 : SCHEMA_VERSION,
      id: typeof a.id === 'string' && a.id ? a.id : makeId(ts),
      ts,
      skillId: a.skillId,
      itemId: a.itemId,
      correct: a.correct,
      latencyMs,
      context: typeof a.context === 'string' ? a.context : 'unknown',
      heldOut: a.heldOut === true,
      confidence: normaliseConfidence(a.confidence)
    }
  };
}

export const AttemptLog = {
  /** @returns {boolean} whether attempts can be durably recorded here */
  isAvailable() {
    return typeof indexedDB !== 'undefined';
  },

  /**
   * Record one attempt.
   *
   * Callers are expected NOT to await this — it resolves after the IndexedDB
   * transaction commits, and a dropped attempt costs one data point whereas a blocked
   * quiz answer costs the user's attention.
   *
   * @param {object} attempt
   * @returns {Promise<{ok: boolean, id?: string, reason?: string}>}
   */
  async append(attempt) {
    const n = normaliseAttempt(attempt);
    if (!n.ok) return { ok: false, reason: n.reason };
    let db;
    try {
      db = await openDb();
    } catch (e) {
      return { ok: false, reason: `store unavailable: ${e.message}` };
    }
    try {
      await tx(db, 'readwrite', (s) => s.put(n.record, n.record.id));
      return { ok: true, id: n.record.id };
    } catch (e) {
      return { ok: false, reason: e.message };
    } finally {
      db.close();
    }
  },

  /**
   * Every attempt, oldest first.
   * @returns {Promise<object[]>}
   */
  async readAll() {
    let db;
    try { db = await openDb(); } catch { return []; }
    try {
      const all = await tx(db, 'readonly', (s) => s.getAll());
      return (all || []).sort((a, b) => a.ts - b.ts);
    } catch {
      return [];
    } finally {
      db.close();
    }
  },

  /**
   * Attempts at or after a timestamp. Uses a key range, since ids sort by time.
   * @param {number} timestamp
   * @returns {Promise<object[]>}
   */
  async readSince(timestamp) {
    let db;
    try { db = await openDb(); } catch { return []; }
    try {
      const lower = `att_${Number(timestamp).toString(16).padStart(13, '0')}`;
      const range = IDBKeyRange.lowerBound(lower);
      const rows = await tx(db, 'readonly', (s) => s.getAll(range));
      return (rows || []).filter((r) => r.ts >= timestamp).sort((a, b) => a.ts - b.ts);
    } catch {
      return [];
    } finally {
      db.close();
    }
  },

  /** @returns {Promise<number>} */
  async count() {
    let db;
    try { db = await openDb(); } catch { return 0; }
    try {
      return (await tx(db, 'readonly', (s) => s.count())) || 0;
    } catch {
      return 0;
    } finally {
      db.close();
    }
  },

  /**
   * Export the log as a portable JSON string. This is the operator's real backup —
   * IndexedDB still dies with the browser profile.
   * @returns {Promise<string>}
   */
  async export() {
    const attempts = await this.readAll();
    return JSON.stringify({
      format: 'sovereign-aegis-attempt-log',
      v: SCHEMA_VERSION,
      exportedAt: Date.now(),
      count: attempts.length,
      attempts
    }, null, 2);
  },

  /**
   * Import a previously exported log. Validates every record and rejects the whole file
   * rather than half-loading it — matching the pack-import behaviour hardened during the
   * security audit. Deduplicates by attempt id, so importing twice is a no-op.
   *
   * @param {string} json
   * @returns {Promise<{ok: boolean, imported?: number, skipped?: number, reason?: string}>}
   */
  async import(json) {
    let parsed;
    try {
      parsed = JSON.parse(json);
    } catch (e) {
      return { ok: false, reason: `not valid JSON: ${e.message}` };
    }
    if (!parsed || parsed.format !== 'sovereign-aegis-attempt-log') {
      return { ok: false, reason: 'not an attempt-log export' };
    }
    if (!Array.isArray(parsed.attempts)) {
      return { ok: false, reason: 'export contains no attempts array' };
    }

    // Validate everything BEFORE writing anything.
    const records = [];
    for (const [i, a] of parsed.attempts.entries()) {
      const n = normaliseAttempt(a);
      if (!n.ok) return { ok: false, reason: `record ${i} invalid: ${n.reason}` };
      records.push(n.record);
    }

    let db;
    try { db = await openDb(); } catch (e) { return { ok: false, reason: e.message }; }
    try {
      const existing = new Set((await tx(db, 'readonly', (s) => s.getAllKeys())) || []);
      const fresh = records.filter((r) => !existing.has(r.id));
      if (fresh.length) {
        await tx(db, 'readwrite', (s) => {
          for (const r of fresh) s.put(r, r.id);
          return null;
        });
      }
      return { ok: true, imported: fresh.length, skipped: records.length - fresh.length };
    } catch (e) {
      return { ok: false, reason: e.message };
    } finally {
      db.close();
    }
  },

  /** Wipe the log. Wired into Hard Reset alongside the state mirror and key vault. */
  async clear() {
    let db;
    try { db = await openDb(); } catch { return false; }
    try {
      await tx(db, 'readwrite', (s) => s.clear());
      return true;
    } catch {
      return false;
    } finally {
      db.close();
    }
  }
};

export default AttemptLog;
