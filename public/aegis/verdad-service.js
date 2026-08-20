/**
 * SOVEREIGN // AEGIS — VERDAD as a message-oriented service
 *
 * This is the contract a messenger imports. It wraps VerdadEngine (pure, DOM-free) with
 * the two calls the product actually needs:
 *
 *   analyzeMessage(text)  — full structured verdict for rendering an inbound message
 *   shouldShare(text)     — the fast pre-send gate ("do I share this draft?")
 *
 * WHY THIS EXISTS SEPARATELY FROM js/modules/verdad.js
 * ---------------------------------------------------
 * js/modules/verdad.js mixes the pure engine with the AEGIS view that renders it. A
 * messenger must not import a view. This module is deliberately UI-free so both the
 * AEGIS view and the messenger can share ONE verdict logic instead of drifting into two.
 *
 * Load-bearing invariants (asserted in tests/test-verdad-service.js):
 *   - `recommendation` derives ONLY from `manipulationRisk`, never from `veracityScore`.
 *     A prompt injection that puffs the LLM's score must not be able to unlock a `block`.
 *   - `shouldShare` defaults to offline heuristics: no network, no fact-check fetch, no
 *     Gemini, so the gate is milliseconds and works air-gapped.
 *   - no DOM, no storage. Everything here is importable from Node.
 *
 * @module verdad-service
 */

import { VerdadEngine } from './modules/verdad.js';
import { searchFactChecks } from './factcheck.js';

/**
 * Recommendation thresholds. Tunable, and exported precisely because they are a policy
 * judgement, not a measurement — they should be fitted once real share decisions exist.
 * A `block` is advisory in the UI (the operator always has the final say), matching the
 * "locks are advisory, never enforced" philosophy of ROADMAP.md Phase 3.
 */
export const THRESHOLDS = Object.freeze({
  blockRisk: 70,
  cautionRisk: 40
});

/** Clamp a risk score into [0, 100]; non-finite input reads as 0 (no signal). */
function clamp(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(100, v));
}

/**
 * Map a manipulation risk to a share recommendation. Pure and total: same risk, same
 * answer, every time, in every environment.
 *
 * @param {{manipulationRisk?: number}} result
 * @returns {{recommendation: 'share'|'caution'|'block', verdictClass: string, risk: number}}
 */
export function classify(result) {
  const risk = clamp(result && result.manipulationRisk);
  let recommendation = 'share';
  if (risk >= THRESHOLDS.blockRisk) recommendation = 'block';
  else if (risk >= THRESHOLDS.cautionRisk) recommendation = 'caution';

  const verdictClass =
    recommendation === 'block' ? 'unreliable' :
    recommendation === 'caution' ? 'unverified' : 'plausible';

  return { recommendation, verdictClass, risk };
}

/** One human sentence for the recommendation. */
export function headlineFor(result) {
  switch (result && result.recommendation) {
    case 'block': return 'High manipulation risk — do not share.';
    case 'caution': return 'Treat this claim with caution before sharing.';
    default: return 'No strong manipulation signal detected.';
  }
}

/** Why this recommendation — concrete markers, not a score alone. */
export function reasonFor(result) {
  const flags = [];
  const et = result && result.emotionalTriggers ? result.emotionalTriggers : {};
  if (et.urgency > 50) flags.push('artificial urgency');
  if (et.outrage > 50) flags.push('outrage framing');
  if (et.conspiracy > 50) flags.push('conspiracy cues');
  const fallacies = (result && Array.isArray(result.detectedFallacies)) ? result.detectedFallacies : [];
  if (fallacies.length) flags.push(`${fallacies.length} fallacy pattern${fallacies.length === 1 ? '' : 's'}`);
  if (result && result.manipulationRisk != null) flags.push(`manipulation risk ${Math.round(result.manipulationRisk)}%`);
  return flags.length ? flags.join('; ') + '.' : 'No manipulation markers found.';
}

/**
 * Full analysis of one message. `withFactChecks` additionally fetches published
 * fact-check citations (separate evidence channel — human reviewers, not the model).
 *
 * @param {string} text
 * @param {{apiKey?: string|null, mode?: string, withFactChecks?: boolean, factCheckApiKey?: string|null}} [options]
 */
export async function analyzeMessage(text, options = {}) {
  const result = await VerdadEngine.analyzeClaim(text, {
    apiKey: options.apiKey ?? null,
    mode: options.mode ?? 'auto'
  });

  const { recommendation, verdictClass } = classify(result);
  const base = { ...result, claimText: text, recommendation, verdictClass };
  base.headline = headlineFor(base);
  base.reason = reasonFor(base);

  if (options.withFactChecks === true) {
    base.factChecks = await searchFactChecks(text, options.factCheckApiKey ?? null);
  } else {
    base.factChecks = null;
  }

  return base;
}

/**
 * The pre-send gate. Offline by default: it must be fast enough to run between the
 * operator pressing send and the message leaving the device, and it must not phone home
 * with the draft. A caller can opt into live mode explicitly.
 *
 * @param {string} text
 * @param {{mode?: string, apiKey?: string|null}} [options]
 * @returns {Promise<{allow: boolean, recommendation: string, headline: string, reason: string, result: object}>}
 */
export async function shouldShare(text, options = {}) {
  const result = await analyzeMessage(text, {
    ...options,
    mode: options.mode ?? 'offline',
    withFactChecks: false
  });
  return {
    allow: result.recommendation !== 'block',
    recommendation: result.recommendation,
    headline: result.headline,
    reason: result.reason,
    result
  };
}

export default { analyzeMessage, shouldShare, classify, headlineFor, reasonFor, THRESHOLDS };
