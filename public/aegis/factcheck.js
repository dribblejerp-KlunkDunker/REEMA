/**
 * SOVEREIGN // AEGIS — Published fact-check lookup (Google Fact Check Tools API)
 *
 * WHY THIS EXISTS
 * ---------------
 * VERDAD previously had two modes: offline lexical heuristics, and "live" mode that
 * asked Gemini what it thought. Neither consults a corpus of *published fact-checks*.
 * An LLM asked "is this claim true" produces a plausible-sounding opinion from training
 * data — which is precisely the epistemic failure this application exists to teach
 * people to resist. Using one as the authority is self-undermining.
 *
 * This queries the Google Fact Check Tools API, which indexes ClaimReview markup
 * published by IFCN-signatory fact-checkers (PolitiFact, Full Fact, AFP, Snopes, Reuters
 * Fact Check, and hundreds more). Results are *citations to human fact-checkers*, with
 * publisher, rating and URL — checkable primary sources, not model recall.
 *
 * HONEST LIMITS
 * -------------
 * - Coverage is sparse. Most claims have never been formally fact-checked, and "no
 *   result" means "nobody has published a review", NOT "false" and NOT "true". The
 *   caller must render that distinction.
 * - Matching is keyword-based on the API side. A returned review may concern a related
 *   but distinct claim; the reviewed claim text is always surfaced so the operator can
 *   judge relevance themselves.
 * - Ratings are the publisher's words, not normalised. "Mostly False" from one outlet is
 *   not calibrated against "Misleading" from another. We do not average them into a
 *   score, because that would invent precision that does not exist.
 *
 * Free API key: https://console.cloud.google.com → enable "Fact Check Tools API".
 *
 * @module factcheck
 */

const ENDPOINT = 'https://factchecktools.googleapis.com/v1alpha1/claims:search';

/** Test seam — mirrors VerdadEngine.fetchImpl. Null uses global fetch. */
export const transport = { fetchImpl: null };

/**
 * Reduce a claim to a query likely to match indexed ClaimReview entries.
 * The API matches on keywords, so emotive framing and filler hurt recall.
 *
 * @param {string} text
 * @returns {string}
 */
export function buildQuery(text) {
  const STOP = new Set([
    'the','a','an','and','or','but','if','then','than','that','this','these','those',
    'is','are','was','were','be','been','being','am','do','does','did','have','has','had',
    'i','you','he','she','it','we','they','them','his','her','its','their','our','your','my',
    'to','of','in','on','at','by','for','with','from','as','into','about','after','before',
    'not','no','very','just','really','actually','literally','breaking','urgent','share',
    'now','immediately','shocking','confirmed','proven','totally','completely','absolutely'
  ]);
  const words = String(text || '')
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, ' ')
    .replace(/[^\p{L}\p{N}\s'-]/gu, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !STOP.has(w));

  // Keep the most distinctive terms: longer words carry more retrieval signal, but
  // preserve original order so multi-word entities stay adjacent where possible.
  const ranked = [...new Set(words)].sort((a, b) => b.length - a.length).slice(0, 8);
  const ordered = words.filter(w => ranked.includes(w));
  return [...new Set(ordered)].slice(0, 8).join(' ');
}

/**
 * Search published fact-checks for a claim.
 *
 * @param {string} text - the claim as the user entered it
 * @param {string} apiKey - Google Cloud API key with Fact Check Tools enabled
 * @param {{languageCode?: string, pageSize?: number}} [opts]
 * @returns {Promise<{
 *   status: 'ok'|'no-key'|'no-results'|'error',
 *   query: string,
 *   reviews: {publisher: string, title: string, url: string, rating: string,
 *             reviewedClaim: string, reviewDate: string|null, claimant: string|null}[],
 *   message: string
 * }>}
 */
export async function searchFactChecks(text, apiKey, opts = {}) {
  const query = buildQuery(text);

  if (!apiKey || typeof apiKey !== 'string' || !apiKey.trim()) {
    return { status: 'no-key', query, reviews: [], message: 'No Fact Check API key configured.' };
  }
  if (!query) {
    return { status: 'no-results', query, reviews: [], message: 'Claim contained no searchable terms.' };
  }

  const url = `${ENDPOINT}?query=${encodeURIComponent(query)}`
    + `&languageCode=${encodeURIComponent(opts.languageCode || 'en')}`
    + `&pageSize=${encodeURIComponent(String(opts.pageSize || 10))}`
    + `&key=${encodeURIComponent(apiKey)}`;

  const doFetch = transport.fetchImpl || fetch;
  let res;
  try {
    res = await doFetch(url, { method: 'GET' });
  } catch (e) {
    return { status: 'error', query, reviews: [], message: `Network error: ${e.message}` };
  }

  if (!res.ok) {
    const hint = res.status === 403
      ? 'Key rejected — is the Fact Check Tools API enabled for this project?'
      : res.status === 429 ? 'Rate limited by the API.' : `HTTP ${res.status}`;
    return { status: 'error', query, reviews: [], message: hint };
  }

  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: 'error', query, reviews: [], message: `Malformed response: ${e.message}` };
  }

  const claims = Array.isArray(data.claims) ? data.claims : [];
  const reviews = [];
  for (const c of claims) {
    for (const r of (c.claimReview || [])) {
      reviews.push({
        publisher: (r.publisher && (r.publisher.name || r.publisher.site)) || 'Unknown publisher',
        title: r.title || '',
        url: r.url || '',
        rating: r.textualRating || 'No rating given',
        reviewedClaim: c.text || '',
        reviewDate: r.reviewDate || null,
        claimant: c.claimant || null
      });
    }
  }

  if (!reviews.length) {
    return {
      status: 'no-results',
      query,
      reviews: [],
      // Phrasing matters: absence of a review is not a truth value.
      message: 'No published fact-check found for these terms. This is not evidence the claim is true or false — most claims have never been formally reviewed.'
    };
  }

  return {
    status: 'ok',
    query,
    reviews,
    message: `${reviews.length} published fact-check${reviews.length === 1 ? '' : 's'} matched. Read the sources — ratings are each publisher's own wording and are not comparable across outlets.`
  };
}

export default { searchFactChecks, buildQuery, transport };
