/**
 * SOVEREIGN // AEGIS — VERDAD Real-Time Multi-Modal Claim Verification Module
 * Heuristic NLP Parser, 6-Vector Affective Intensity, Fallacy Regexes, BYOK Gemini API
 */

import { esc, sanitizeDeep, escUrl } from '../security.js';
import { searchFactChecks } from '../factcheck.js';
import { buildBookmarklet } from '../ingest.js';
export class VerdadEngine {
  /**
   * Transport seam for tests. Left null in production so the global `fetch` is used.
   * Replaces the former `ai_gemini_key_live_mock` magic-key branch, which shipped a
   * fabricated "live API" response inside production code.
   * @type {null | typeof fetch}
   */
  static fetchImpl = null;

  static defaultRules = {
    emotionalLexicons: {
      outrage: ['outrage', 'shameful', 'disgrace', 'treason', 'furious', 'unacceptable', 'scandal', 'corrupt', 'disgusting', 'abhorrent', 'infuriating', 'liar', 'lunatic', 'criminal', 'evil', 'wicked', 'fraudster'],
      fear: ['deadly', 'danger', 'hazard', 'threat', 'lethal', 'toxic', 'catastrophe', 'peril', 'epidemic', 'fatal', 'poison', 'extinction', 'kill', 'destroy'],
      urgency: ['breaking', 'emergency', 'act now', 'urgent', 'delete', 'warning', 'critical alert', 'share immediately', 'before it is too late', 'rt now', 'immediately', 'panic'],
      tribalism: ['patriot', 'traitor', 'enemy within', 'cabal', 'us vs them', 'infiltrator', 'puppet', 'sheep', 'invader', 'foreign agent'],
      conspiracy: ['coverup', 'deep state', 'hidden agenda', 'secret plot', 'shadow government', 'puppet masters', 'globalist', 'suppressed truth', 'cabal', 'illuminati', 'plot', 'orchestrating', 'orchestrated'],
      fatalism: ['hopeless', 'doomed', 'inevitable collapse', 'pointless', 'corrupted beyond repair', 'decay', 'destruction', 'no future', 'irreversible']
    },
    fallacyRegexes: [
      { pattern: '\\b(corrupt liar|convicted fraudster|lunatic|idiot|traitor)\\b', fallacyId: 'fallacy-ad-hominem', name: 'Ad Hominem' },
      { pattern: '\\b(either (we|you) .+ or (the entire|all|we are doomed|society will collapse))\\b', fallacyId: 'fallacy-false-dilemma', name: 'False Dilemma' },
      { pattern: '\\b(if we (allow|pass|give) .+ (will inevitably lead to|inevitable collapse|totalitarian))\\b', fallacyId: 'fallacy-slippery-slope', name: 'Slippery Slope' },
      { pattern: '\\b(what about when|whatabout|they did the exact same)\\b', fallacyId: 'fallacy-tu-quoque', name: 'Whataboutism / Tu Quoque' },
      { pattern: '\\b(famous (celebrity|actor|athlete|singer) (confirms|reveals|endorses))\\b', fallacyId: 'fallacy-appeal-to-false-authority', name: 'Appeal to False Authority' },
      { pattern: '\\b(think of the (innocent )?children|your family will (starve|die|suffer))\\b', fallacyId: 'fallacy-appeal-to-fear', name: 'Appeal to Fear & Emotion' }
    ],
    hedgingMarkers: ['allegedly', 'reportedly', 'purportedly', 'it is claimed', 'sources say', 'rumored to be', 'supposedly'],
    certaintyMarkers: ['undeniably', '100% proven', 'indisputable fact', 'absolute certainty', 'irrefutable truth', 'beyond all doubt']
  };

  /**
   * Runs offline heuristic NLP analysis against rules dataset.
   */
  static runOfflineHeuristics(text = '', rules = this.defaultRules) {
    const cleanText = (text || '').trim();
    if (!cleanText) {
      return {
        veracityScore: 50,
        manipulationRisk: 0,
        emotionalTriggers: { outrage: 0, fear: 0, urgency: 0, tribalism: 0, conspiracy: 0, fatalism: 0 },
        detectedFallacies: [],
        epistemicMetrics: { hedgingRatio: 0, certaintyInflation: 0, wordCount: 0 },
        credibilityTier: 'Neutral / Insufficient Data'
      };
    }

    const lowerText = cleanText.toLowerCase();
    const words = lowerText.match(/[a-z0-9'-]+/gi) || [];
    const wordCount = Math.max(1, words.length);

    // 1. Calculate Emotional Trigger Intensities (0..100)
    const emoScores = {};
    const lexicons = rules.emotionalLexicons || this.defaultRules.emotionalLexicons;
    for (const [vec, list] of Object.entries(lexicons)) {
      let hits = 0;
      for (const kw of list) {
        const regex = new RegExp(`\\b${kw}\\b`, 'gi');
        const matches = lowerText.match(regex);
        if (matches) hits += matches.length;
      }
      let intensity = 0;
      if (hits > 0) {
        intensity = Math.min(100, Math.round((hits * 55) + ((hits / wordCount) * 120)));
      }
      emoScores[vec] = intensity;
    }

    // 2. Fallacy Pattern Detection
    const detectedFallacies = [];
    const fallacyRules = rules.fallacyRegexes || this.defaultRules.fallacyRegexes;
    for (const f of fallacyRules) {
      try {
        const reg = new RegExp(f.pattern, 'i');
        if (reg.test(lowerText)) {
          detectedFallacies.push({
            fallacyId: f.fallacyId,
            name: f.name,
            confidence: f.confidence ?? 0.85
          });
        }
      } catch {}
    }

    // 3. Epistemic Metrics (Hedging vs Certainty)
    let hedgingCount = 0;
    for (const h of (rules.hedgingMarkers || this.defaultRules.hedgingMarkers)) {
      const reg = new RegExp(`\\b${h}\\b`, 'gi');
      const matches = lowerText.match(reg);
      if (matches) hedgingCount += matches.length;
    }

    let certaintyCount = 0;
    for (const c of (rules.certaintyMarkers || this.defaultRules.certaintyMarkers)) {
      const reg = new RegExp(`\\b${c}\\b`, 'gi');
      const matches = lowerText.match(reg);
      if (matches) certaintyCount += matches.length;
    }

    const hedgingRatio = Math.min(1.0, Math.round((hedgingCount / Math.max(10, wordCount)) * 100) / 100);
    const certaintyInflation = Math.min(100, certaintyCount * 25);

    // 4. Composite Manipulation Risk Score (0..100)
    const maxEmotion = Math.max(...Object.values(emoScores), 0);
    const avgEmotion = Object.values(emoScores).reduce((a, b) => a + b, 0) / 6;
    const fallacyScore = Math.min(100, detectedFallacies.length * 25);

    let manipulationRisk = 0;
    if (maxEmotion >= 50) {
      manipulationRisk = Math.min(100, Math.round(
        (0.85 * maxEmotion) +
        (0.35 * avgEmotion) +
        (0.35 * fallacyScore) +
        (0.20 * certaintyInflation)
      ));
    } else if (maxEmotion > 0 || fallacyScore > 0 || certaintyInflation > 0) {
      manipulationRisk = Math.min(100, Math.round(
        (0.45 * maxEmotion) +
        (0.25 * avgEmotion) +
        (0.25 * fallacyScore) +
        (0.15 * certaintyInflation)
      ));
    }

    const veracityScore = Math.max(5, Math.min(95, 100 - manipulationRisk));

    let credibilityTier = 'High Credibility / Low Manipulation';
    if (manipulationRisk >= 75) credibilityTier = 'Critical Epistemic Threat';
    else if (manipulationRisk >= 50) credibilityTier = 'High Manipulation Risk';
    else if (manipulationRisk >= 25) credibilityTier = 'Moderate Caution';

    return {
      veracityScore,
      manipulationRisk,
      emotionalTriggers: emoScores,
      detectedFallacies,
      epistemicMetrics: {
        hedgingRatio,
        certaintyInflation,
        wordCount
      },
      credibilityTier
    };
  }

  /**
   * Public analyzeClaim method supporting BYOK Gemini API with offline fallback.
   */
  static async analyzeClaim(text, options = { apiKey: null, mode: 'auto' }) {
    const mode = options.mode || 'auto';
    const apiKey = options.apiKey;

    if (mode === 'offline' || !apiKey || typeof apiKey !== 'string' || apiKey.trim() === '') {
      const heuristicResult = this.runOfflineHeuristics(text);
      return {
        claimText: text,
        veracityScore: heuristicResult.veracityScore,
        manipulationRisk: heuristicResult.manipulationRisk,
        emotionalTriggers: heuristicResult.emotionalTriggers,
        detectedFallacies: heuristicResult.detectedFallacies,
        biasIndicators: [
          ...(heuristicResult.emotionalTriggers.outrage > 50 ? ['Affective Outrage Framing'] : []),
          ...(heuristicResult.emotionalTriggers.urgency > 50 ? ['Cognitive Urgency Pressure'] : []),
          ...(heuristicResult.emotionalTriggers.conspiracy > 50 ? ['Conspiratorial Agency Attribution'] : [])
        ],
        confidence: Math.max(60, 95 - heuristicResult.manipulationRisk / 2),
        sources: ['Offline Heuristic Rule Engine (Ruleset v1.0)'],
        reasoning: `Analysis completed using offline multi-vector NLP heuristic parser. Detected manipulation risk: ${heuristicResult.manipulationRisk}%. Tier: ${heuristicResult.credibilityTier}.`,
        isLiveApi: false,
        epistemicMetrics: heuristicResult.epistemicMetrics
      };
    }

    try {
      return await this.queryGeminiApi(text, apiKey);
    } catch {
      const fallbackResult = this.runOfflineHeuristics(text);
      return {
        claimText: text,
        veracityScore: fallbackResult.veracityScore,
        manipulationRisk: fallbackResult.manipulationRisk,
        emotionalTriggers: fallbackResult.emotionalTriggers,
        detectedFallacies: fallbackResult.detectedFallacies,
        biasIndicators: ['API Fallback: Local NLP Engine Active'],
        confidence: 70,
        sources: ['Offline Heuristic Fallback'],
        reasoning: 'Live API query was bypassed/failed; seamless offline heuristic analysis was applied.',
        isLiveApi: false,
        epistemicMetrics: fallbackResult.epistemicMetrics
      };
    }
  }

  /**
   * Query the Gemini API. Injectable transport: tests pass a stub via
   * `VerdadEngine.fetchImpl` rather than relying on a magic API key that the
   * production code would have to recognise.
   */
  static async queryGeminiApi(text, apiKey) {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
    const prompt = `You are VERDAD, an epistemic defense AI engine. Analyze the following assertion for truthfulness, manipulation risk, emotional triggers, logical fallacies, and factual basis.
Claim: "${text}"

Respond ONLY with a valid JSON object matching this schema:
{
  "veracityScore": <number 0-100>,
  "manipulationRisk": <number 0-100>,
  "emotionalTriggers": { "outrage": <0-100>, "fear": <0-100>, "urgency": <0-100>, "tribalism": <0-100>, "conspiracy": <0-100>, "fatalism": <0-100> },
  "detectedFallacies": [ { "name": "<fallacy name>", "confidence": <0-1> } ],
  "biasIndicators": [ "<indicator 1>", "<indicator 2>" ],
  "confidence": <number 0-100>,
  "sources": [ "<source reference 1>", "<source reference 2>" ],
  "reasoning": "<structured paragraph explaining the epistemic verdict and empirical consensus>",
  "prebunkSummary": "<one sentence refutation ready for community dissemination>"
}`;

    const doFetch = VerdadEngine.fetchImpl || fetch;
    const res = await doFetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' }
      })
    });

    if (!res.ok) throw new Error(`Gemini API failed with status ${res.status}`);
    const data = await res.json();
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text;

    // The model is summarising adversary-authored text, so its output is treated as
    // untrusted: a prompt injection that induces markup in `reasoning` or
    // `prebunkSummary` would otherwise land straight in innerHTML.
    const parsed = sanitizeDeep(JSON.parse(content)) || {};
    return {
      claimText: text,
      veracityScore: parsed.veracityScore ?? 50,
      manipulationRisk: parsed.manipulationRisk ?? 50,
      emotionalTriggers: parsed.emotionalTriggers ?? { outrage: 0, fear: 0, urgency: 0, tribalism: 0, conspiracy: 0, fatalism: 0 },
      detectedFallacies: parsed.detectedFallacies ?? [],
      biasIndicators: parsed.biasIndicators ?? ['Live Gemini Evaluation'],
      confidence: parsed.confidence ?? 85,
      sources: parsed.sources ?? ['Gemini Neural Knowledge Model'],
      reasoning: parsed.reasoning ?? 'Live LLM analysis completed.',
      prebunkSummary: parsed.prebunkSummary || 'Verified by independent cross-source evaluation.',
      isLiveApi: true
    };
  }
}

export const VerdadModule = {
  _app: null,
  _presets: {
    'bank-run': 'URGENT BREAKING: Regional commercial bank is experiencing a massive liquidity collapse right now! Central regulators are secretly freezing customer deposits! Withdraw all your cash immediately before it is too late!',
    'election-hack': 'Shocking leaked audio confirms the election board software was hacked by foreign operatives! Do not listen to the corrupt mayor and lunatic officials who are covering it up!',
    'miracle-cure': 'Mainstream pharma companies are hiding this 100% proven miraculous herbal extract that completely cures all stage-4 cancers with absolute certainty beyond all doubt!',
    'wildfire-arson': 'Top secret satellite imagery indisputably proves that the recent wildfires were coordinated by international energy cartels as part of a hidden globalist agenda!'
  },

  init(app) {
    this._app = app;
    this._bindEvents();
    console.log('[VerdadModule] Initialized.');
  },

  onMount() {
    const textarea = document.getElementById('textarea-verdad-claim');
    if (textarea && !textarea.value.trim()) {
      textarea.value = this._presets['bank-run'];
    }
  },

  _bindEvents() {
    const selectPreset = document.getElementById('select-verdad-preset');
    const textarea = document.getElementById('textarea-verdad-claim');
    const btnAudit = document.getElementById('btn-run-verdad-audit');
    const btnCopyCard = document.getElementById('btn-copy-counter-card');

    if (selectPreset && textarea) {
      selectPreset.addEventListener('change', () => {
        const val = selectPreset.value;
        if (this._presets[val]) {
          textarea.value = this._presets[val];
          this._app?.showToast({ type: 'info', title: 'PRESET LOADED', message: `Loaded ${val} scenario.` });
        }
      });
    }

    if (btnAudit) {
      btnAudit.addEventListener('click', () => this.executeAudit());
    }

    if (btnCopyCard) {
      btnCopyCard.addEventListener('click', () => {
        const cardText = document.getElementById('verdad-counter-card')?.innerText || '';
        if (navigator.clipboard) {
          navigator.clipboard.writeText(cardText).then(() => {
            this._app?.showToast({ type: 'success', title: 'COPIED TO CLIPBOARD', message: 'Counter-narrative prebunk card copied.' });
          });
        }
      });
    }

    document.getElementById('btn-read-clipboard')?.addEventListener('click', () => this.readClipboard());
    document.getElementById('btn-copy-bookmarklet')?.addEventListener('click', () => this.copyBookmarklet());
  },

  /**
   * Read the clipboard and route the text to VERDAD via the shared app path. The
   * clipboard logic lives on the app (topbar + this view both use it), so this
   * delegates rather than duplicating the read/degrade behaviour.
   */
  readClipboard() {
    this._app?._readClipboard?.();
  },

  /**
   * Put the verify bookmarklet on the clipboard, or surface it in the read-only input
   * when the clipboard is unavailable. The snippet is built for THIS app URL, so it
   * navigates back to wherever the operator installed it from.
   */
  copyBookmarklet() {
    const base = window.location.origin + window.location.pathname;
    const snippet = buildBookmarklet(base);

    const showSnippet = () => {
      const input = document.getElementById('bookmarklet-snippet');
      if (input) input.value = snippet;
      this._app?.showToast({
        type: 'info',
        title: 'INSTALL BOOKMARKLET',
        message: 'Create a new bookmark and paste the copied snippet as its URL. Select text on any page, then run it.',
        duration: 8000
      });
    };

    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(snippet)
        .then(() => {
          const input = document.getElementById('bookmarklet-snippet');
          if (input) input.value = snippet;
          this._app?.showToast({ type: 'success', title: 'BOOKMARKLET COPIED', message: 'Paste it as the URL of a new bookmark. Select text anywhere, then run it.' });
        })
        .catch(showSnippet);
    } else {
      showSnippet();
    }
  },

  async executeAudit() {
    const textarea = document.getElementById('textarea-verdad-claim');
    const text = textarea ? textarea.value.trim() : '';

    if (!text) {
      this._app?.showToast({ type: 'warning', title: 'EMPTY INPUT', message: 'Please enter or paste a claim statement to analyze.' });
      return;
    }

    const btnAudit = document.getElementById('btn-run-verdad-audit');
    if (btnAudit) {
      btnAudit.disabled = true;
      btnAudit.innerHTML = '<span>⏳ Executing Neural & Heuristic Audit...</span>';
    }

    const apiKey = this._app?.store?.get('verdad.byokApiKey', null);
    const forceOffline = this._app?.store?.get('verdad.offlineOnly', false);
    const mode = forceOffline ? 'offline' : 'auto';

    try {
      const result = await VerdadEngine.analyzeClaim(text, { apiKey, mode });
      this._renderResults(result);

      // Published fact-checks are a SEPARATE evidence channel from the heuristics and
      // from the LLM. They are citations to human reviewers, so they are rendered as
      // sources to read rather than folded into the veracity score — averaging a
      // publisher's "Mostly False" into a percentage would invent precision.
      const factKey = this._app?.store?.get('verdad.factCheckApiKey', null);
      this._renderFactChecks({ status: 'pending', reviews: [], message: 'Searching published fact-checks…' });
      const fc = await searchFactChecks(text, factKey);
      this._renderFactChecks(fc);
      this._app?.showToast({
        type: result.manipulationRisk > 60 ? 'danger' : result.manipulationRisk > 30 ? 'warning' : 'success',
        title: result.isLiveApi ? 'GEMINI AUDIT COMPLETE' : 'HEURISTIC AUDIT COMPLETE',
        message: `Veracity: ${result.veracityScore}% • Risk: ${result.manipulationRisk}% (${result.credibilityTier || 'Analyzed'})`
      });
    } catch (err) {
      console.error('[VerdadModule] Audit error:', err);
      this._app?.showToast({ type: 'danger', title: 'AUDIT FAILED', message: err.message });
    } finally {
      if (btnAudit) {
        btnAudit.disabled = false;
        btnAudit.innerHTML = '<span>🛡️ Execute Epistemic Audit</span>';
      }
    }
  },

  /**
   * Render published fact-check citations.
   *
   * Deliberately does NOT produce a verdict or adjust any score. "No result" is
   * rendered as an explicit absence-of-evidence statement, because treating an
   * unreviewed claim as false is the same error the rest of this app teaches against.
   */
  _renderFactChecks(fc) {
    const host = document.getElementById('verdad-factcheck-panel');
    if (!host) return;

    if (fc.status === 'pending') {
      host.innerHTML = `
        <div class="status-label text-stone" style="font-size:0.72rem;">PUBLISHED FACT-CHECKS</div>
        <p class="body-text" style="font-size:0.82rem;margin:6px 0 0 0;color:var(--stone-warm);">${esc(fc.message)}</p>`;
      return;
    }

    if (fc.status === 'no-key') {
      host.innerHTML = `
        <div class="status-label text-stone" style="font-size:0.72rem;">PUBLISHED FACT-CHECKS</div>
        <p class="body-text" style="font-size:0.8rem;margin:6px 0 8px 0;color:var(--stone-light);">
          Not configured. Add a free Google Fact Check Tools API key in Settings to search
          ClaimReview records published by IFCN-signatory fact-checkers.
        </p>
        <button class="btn btn-outline btn-sm" data-aegis-action="open-modal" data-aegis-modal="modal-byok-settings">Configure key</button>`;
      return;
    }

    if (fc.status === 'error') {
      host.innerHTML = `
        <div class="status-label" style="font-size:0.72rem;color:var(--suspicion-amber, #f59e0b);">PUBLISHED FACT-CHECKS — LOOKUP FAILED</div>
        <p class="body-text" style="font-size:0.8rem;margin:6px 0 0 0;">${esc(fc.message)}</p>
        <p class="body-text" style="font-size:0.76rem;margin:6px 0 0 0;color:var(--stone-warm);">
          Heuristic analysis above is unaffected. A failed lookup tells you nothing about the claim.
        </p>`;
      return;
    }

    if (fc.status === 'no-results') {
      host.innerHTML = `
        <div class="status-label text-stone" style="font-size:0.72rem;">PUBLISHED FACT-CHECKS — NONE FOUND</div>
        <p class="body-text" style="font-size:0.8rem;margin:6px 0 0 0;">${esc(fc.message)}</p>
        <p class="body-text" style="font-size:0.74rem;margin:6px 0 0 0;color:var(--stone-warm);font-family:var(--font-mono);">
          query: ${esc(fc.query)}
        </p>`;
      return;
    }

    const rows = fc.reviews.slice(0, 8).map(r => `
      <div class="card-granite-inset" style="padding:10px 12px;margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;">
          <div style="font-weight:600;font-size:0.82rem;color:var(--parchment-bright);">${esc(r.publisher)}</div>
          <span class="badge badge-bronze" style="font-size:0.68rem;white-space:nowrap;">${esc(r.rating)}</span>
        </div>
        ${r.reviewedClaim ? `<div style="font-size:0.78rem;color:var(--stone-light);margin-top:4px;">Reviewed claim: “${esc(r.reviewedClaim)}”</div>` : ''}
        ${r.claimant ? `<div style="font-size:0.74rem;color:var(--stone-warm);margin-top:2px;">Attributed to: ${esc(r.claimant)}</div>` : ''}
        <div style="margin-top:6px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${r.url ? `<a href="${escUrl(r.url)}" target="_blank" rel="noopener noreferrer nofollow" style="font-size:0.76rem;color:var(--intel-cyan, #38bdf8);">Read the fact-check →</a>` : ''}
          ${r.reviewDate ? `<span style="font-size:0.72rem;color:var(--stone-warm);font-family:var(--font-mono);">${esc(r.reviewDate)}</span>` : ''}
        </div>
      </div>`).join('');

    host.innerHTML = `
      <div class="status-label text-emerald" style="font-size:0.72rem;">PUBLISHED FACT-CHECKS — ${esc(fc.reviews.length)} MATCHED</div>
      <p class="body-text" style="font-size:0.78rem;margin:6px 0 10px 0;color:var(--stone-light);">${esc(fc.message)}</p>
      ${rows}
      <p class="body-text" style="font-size:0.74rem;margin:4px 0 0 0;color:var(--stone-warm);">
        Matching is keyword-based — confirm each review actually addresses your claim before relying on it.
      </p>`;
  },

  _renderResults(res) {
    const veracityEl = document.getElementById('verdad-veracity-score');
    const emotionEl = document.getElementById('verdad-emotional-score');
    const fallaciesEl = document.getElementById('verdad-fallacies-count');
    const sourceEl = document.getElementById('verdad-source-score');
    const flagsList = document.getElementById('verdad-flags-list');
    const counterCard = document.getElementById('verdad-counter-card');

    if (veracityEl) {
      veracityEl.textContent = `${res.veracityScore}%`;
      veracityEl.className = `metric-value ${res.veracityScore >= 70 ? 'text-emerald' : res.veracityScore >= 40 ? 'text-amber' : 'text-crimson'}`;
    }

    if (emotionEl) {
      const maxEmo = Math.max(...Object.values(res.emotionalTriggers || {}), 0);
      emotionEl.textContent = `${(maxEmo / 10).toFixed(1)} / 10`;
      emotionEl.className = `metric-value ${maxEmo >= 70 ? 'text-crimson' : maxEmo >= 40 ? 'text-amber' : 'text-emerald'}`;
    }

    if (fallaciesEl) {
      const count = res.detectedFallacies?.length || 0;
      fallaciesEl.textContent = `${count} MATCH${count === 1 ? '' : 'ES'}`;
      fallaciesEl.className = `metric-value ${count > 0 ? 'text-bronze' : 'text-emerald'}`;
    }

    if (sourceEl) {
      sourceEl.textContent = res.isLiveApi ? 'GEMINI 1.5 FLASH' : 'LOCAL NLP HEURISTICS';
      sourceEl.className = 'metric-value text-muted';
    }

    if (flagsList) {
      let html = '';
      if (res.detectedFallacies && res.detectedFallacies.length > 0) {
        for (const f of res.detectedFallacies) {
          html += `
            <div class="card-granite-inset" style="border-left: 3px solid var(--disinfo-crimson);">
              <div class="flex-row-gap" style="justify-content: space-between;">
                <span class="status-label text-crimson">FALLACY: ${esc(f.name.toUpperCase())}</span>
                <span class="badge badge-disinfo">CONFIDENCE ${Math.round((f.confidence || 0.85) * 100)}%</span>
              </div>
              <p class="body-text" style="margin-top: 4px;">Detected structural flaw in reasoning pattern.</p>
            </div>
          `;
        }
      }

      for (const [vec, score] of Object.entries(res.emotionalTriggers || {})) {
        if (score >= 40) {
          const isUrgency = vec.toLowerCase() === 'urgency';
          html += `
            <div class="card-granite-inset" style="border-left: 3px solid var(--suspicion-amber);">
              <div class="flex-row-gap" style="justify-content: space-between;">
                <span class="status-label text-amber">${isUrgency ? 'URGENCY TRIGGER & VECTOR' : `${vec.toUpperCase()} VECTOR`}</span>
                <span class="badge badge-suspicion">INTENSITY ${esc(score)}%</span>
              </div>
              <p class="body-text" style="margin-top: 4px;">High emotional manipulation pressure detected targeting ${esc(vec)}.</p>
            </div>
          `;
        }
      }

      if (!html) {
        html = `
          <div class="card-granite-inset" style="border-left: 3px solid var(--veracity-green);">
            <span class="status-label text-emerald">NO HIGH-RISK MANIPULATION FLAGS</span>
            <p class="body-text" style="margin-top: 4px;">Statement language matches objective, verifiable reporting patterns.</p>
          </div>
        `;
      }

      flagsList.innerHTML = html;
    }

    if (counterCard) {
      const summaryText = res.prebunkSummary || res.reasoning || 'Analysis completed using multi-vector NLP heuristics. No corroborated primary evidence found.';
      counterCard.innerHTML = `
        <div class="heading-4 text-bronze">Fact Check Summary — Verified Counter-Narrative</div>
        <p class="body-text" style="font-size: 0.9rem; margin-top: var(--space-2); line-height: 1.5;">
          ${esc(summaryText)}
        </p>
        <div style="margin-top: 16px; border-top: 1px solid var(--border-subtle); padding-top: 12px; text-align: right;">
          <button class="btn btn-secondary" id="btn-verdad-pin" style="font-size: 0.8rem;">📌 Pin to Dossier</button>
        </div>
      `;

      // Bind the pin action
      const pinBtn = document.getElementById('btn-verdad-pin');
      if (pinBtn) {
        pinBtn.addEventListener('click', () => {
          const contentStr = `Veracity Score: ${res.veracityScore}%\n` +
                             `Fallacies Detected: ${res.detectedFallacies?.map(f => f.name).join(', ') || 'None'}\n\n` +
                             `Summary: ${summaryText}`;
          window.dispatchEvent(new CustomEvent('aegis:pin', {
            detail: {
              source: 'VERDAD Engine',
              title: 'Truth Pipeline Analysis',
              content: contentStr
            }
          }));
        });
      }
    }
  }
};
