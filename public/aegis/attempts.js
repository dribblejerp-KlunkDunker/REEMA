/**
 * SOVEREIGN // AEGIS — one way to record an attempt
 *
 * WHY THIS EXISTS SEPARATELY FROM attemptlog.js
 * --------------------------------------------
 * `js/attemptlog.js` is storage: one record in, one record out. But eight modules have a
 * right/wrong moment, and each of them needs the same four decisions made the same way:
 *
 *   1. one record per tested SKILL, not per screen — the estimator filters by skillId, so an
 *      item that tests two skills is evidence about both;
 *   2. never awaited — append() resolves after the IndexedDB transaction commits, and a
 *      dropped attempt costs one sample where a stalled quiz costs the session;
 *   3. an untagged item warns once and is dropped, rather than being written under a guessed
 *      skill — a wrong data point is worse than a missing one;
 *   4. `heldOut` is carried from the content, never decided at the call site.
 *
 * If each module made those decisions for itself, they would drift, and the drift would show
 * up as quietly wrong mastery numbers months later. So they are made once, here.
 *
 * This module deliberately has no opinion about *what* counts as correct. That judgement
 * belongs to the module that owns the interaction — a self-graded recall, a multiple-choice
 * answer and a branching decision are not the same kind of evidence, and pretending
 * otherwise here would hide the difference.
 *
 * @module attempts
 */

import { AttemptLog, normaliseConfidence } from './attemptlog.js';
import { Confidence } from './confidence.js';

/** Contexts seen so far. Free-form by design — the log stores whatever it is given. */
export const CONTEXTS = Object.freeze({
  ARENA: 'arena',
  SM2: 'sm2',
  SIFT: 'sift',
  FALLACY_DRILL: 'fallacy-drill',
  INOCULATION: 'inoculation',
  SANDBOX: 'sandbox',
  FORENSICS: 'forensics',
  // The messenger's real-world share gate: a near-share of a flagged claim.
  // Recorded device-locally by the messenger (see ROADMAP-messenger.md Phase 4);
  // never synced, per the product decision.
  MESSENGER: 'messenger'
});

/** Warn once per context, not once per question. */
const warned = new Set();

/**
 * Record one right/wrong moment against every skill it tests.
 *
 * Fire-and-forget: returns immediately. The returned promise is for tests, not for callers
 * in the UI — awaiting it in a click handler is the mistake this module exists to prevent.
 *
 * @param {object} attempt
 * @param {string[]} attempt.skillIds - from the content's `tests` array
 * @param {string} attempt.itemId - stable id of the thing answered
 * @param {boolean} attempt.correct
 * @param {string} attempt.context - one of CONTEXTS
 * @param {number|null} [attempt.latencyMs]
 * @param {boolean} [attempt.heldOut]
 * @param {'sure'|'unsure'|'guess'|null} [attempt.confidence] - omit to read the live control
 * @returns {Promise<{recorded: number, reason?: string}>}
 */
export function recordAttempt({ skillIds, itemId, correct, context, latencyMs = null, heldOut = false, confidence }) {
  const ids = Array.isArray(skillIds) ? skillIds.filter((s) => typeof s === 'string' && s) : [];

  // Read the shared control when the caller did not state a value. Doing it here rather than at
  // six call sites means the control cannot be forgotten in one module and silently produce
  // uncalibratable records — which would be invisible until someone tried to draw the curve.
  const conf = confidence === undefined ? Confidence.current() : normaliseConfidence(confidence);

  if (!ids.length) {
    // An untagged item is invisible to the estimator — the exact failure the competency
    // spine exists to fix. tools/tag-skills.mjs exits non-zero on untagged content, so this
    // should be unreachable in a shipped build.
    if (!warned.has(context)) {
      warned.add(context);
      console.warn(`[attempts] "${itemId}" (${context}) has no tests[] — not recorded. Run tools/tag-skills.mjs.`);
    }
    return Promise.resolve({ recorded: 0, reason: 'untagged' });
  }
  if (typeof correct !== 'boolean') {
    console.warn(`[attempts] "${itemId}" (${context}) passed a non-boolean correct — not recorded.`);
    return Promise.resolve({ recorded: 0, reason: 'correct must be a boolean' });
  }

  const writes = ids.map((skillId) =>
    AttemptLog.append({
      skillId,
      itemId: String(itemId),
      correct,
      latencyMs: Number.isFinite(latencyMs) && latencyMs >= 0 ? latencyMs : null,
      context,
      heldOut: heldOut === true,
      confidence: conf
    }).then((r) => {
      if (!r.ok) console.warn(`[attempts] not recorded (${skillId}): ${r.reason}`);
      return r.ok;
    })
  );

  return Promise.all(writes).then((rs) => ({ recorded: rs.filter(Boolean).length }));
}

/**
 * A stopwatch for latency, so every module measures it the same way: from when the item
 * became answerable to when it was answered. Returns a function that yields elapsed ms.
 *
 * @returns {() => number}
 */
export function startTimer() {
  const t0 = Date.now();
  return () => Math.max(0, Date.now() - t0);
}

/** Test seam: forget which contexts have already warned. */
export function _resetWarnings() {
  warned.clear();
}

export default { recordAttempt, startTimer, CONTEXTS };
