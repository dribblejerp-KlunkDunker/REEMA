/**
 * Headless XSS regression for the DISARM analysis pipeline, wired into `npm test`.
 *
 * The protection view's `runAnalysis()` sends the pasted claim to the Gemini
 * API and renders the model's response. The claim is attacker-controlled, so
 * the model's output is untrusted: a prompt injection can make it echo the
 * claim's markup into `flags` (innerHTML), or emit hostile values for
 * `verdictClass` (className), `score` (style.color branches), and
 * `sourceCredibility` (style.color). This page also holds the E2EE private
 * keys in localStorage, so a render-path XSS is a key-theft primitive.
 *
 * This test drives the REAL pipeline in a headless browser:
 *
 *   1. local-rule fallback (no API key) with attacker-crafted pasted text —
 *      user text must never reach the DOM as markup;
 *   2. Gemini path with a hostile model response that ECHOES the pasted claim
 *      (the realistic injection vector) plus hostile enums and would-be
 *      executable elements (`<img onerror=alert(1)>`);
 *   3. a well-behaved model response — the allowlists must not break
 *      legitimate rendering.
 *
 * Assertions: no dialog/alert and no page error fired, no executable element
 * ever entered `#analysis-result`, no raw (unescaped) attacker tag-openers in
 * any innerHTML sink, and the enum/score allowlists still pass legit values.
 *
 * Self-contained: spawns its own static UI server on a dedicated loopback
 * port. Skips gracefully (exit 0) when the headless browser is not resolvable.
 */
import { spawn } from 'node:child_process';
import { resolveChromium } from './chromium.js';

const UI_PORT = Number(process.env.XSS_UI_PORT || 8019);
const UI_URL = `http://127.0.0.1:${UI_PORT}/`;

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

async function waitForHttp(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`UI server did not answer ${url}`);
}

// The attacker-crafted claim the test pastes through the pipeline. If it ever
// reaches an innerHTML sink unescaped, the <img onerror> executes an alert.
const ATTACKER_TEXT =
  'They are hiding the cure! <img src=x onerror=alert(1)> <script>alert(1)</script> share before it is too late';

// Hostile model response: echoes the pasted claim (prompt-injection path) and
// returns hostile enums plus would-be executable elements.
function hostilePayload() {
  return {
    score: '<img src=x onerror=alert(1)>',               // non-finite -> clamp 50
    verdictText: `<script>alert(1)</script>HIGH MANIPULATION RISK`,
    verdictClass: 'vp-danger x" onmouseover="alert(1) hidden', // not allowlisted
    emotionalTrigger: '<svg onload=alert(1)>',
    sourceCredibility: '<img src=x onerror=alert(1)>',   // not allowlisted
    flags: [
      `echo of claim: ${ATTACKER_TEXT}`,                 // the realistic injection
      '<img src=x onerror=alert(1)>',
      '<script>alert(1)</script>'
    ]
  };
}

// Well-behaved model response: legit values must still pass the allowlists.
function benignPayload() {
  return {
    score: 92,
    verdictText: 'HIGH MANIPULATION RISK',
    verdictClass: 'vp-danger',
    emotionalTrigger: 'FEAR+ANGER',
    sourceCredibility: 'LOW',
    flags: ['<b>plain-text flag with simple markup</b>']
  };
}

async function main() {
  const chromium = resolveChromium();
  if (!chromium) {
    console.log('[xss-regression] SKIP: headless browser (patchright) not resolvable — install the CodeGPT extension, or add patchright plus `npx patchright install chromium`, to enable this test.');
    return;
  }

  // ---- Spawn this test's own UI server ----
  const ui = spawn(process.execPath, ['tools/serve.mjs'], {
    env: { ...process.env, UI_PORT: String(UI_PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let uiErr = '';
  ui.stderr.on('data', (d) => { uiErr += d; });

  try {
    await waitForHttp(UI_URL, 15000);
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      const dialogs = [];
      const pageErrors = [];
      page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss().catch(() => {}); });
      page.on('pageerror', (e) => pageErrors.push(String(e)));

      // Stub the Gemini endpoint at the network layer: the page's own fetch()
      // receives the hostile or benign JSON body.
      let hostile = true;
      await page.route('**/generativelanguage.googleapis.com/**', (route) => {
        const payload = hostile ? hostilePayload() : benignPayload();
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            candidates: [{ content: { parts: [{ text: JSON.stringify(payload) }] } }]
          })
        });
      });

      await page.goto(UI_URL, { waitUntil: 'domcontentloaded' });

      // Drive the real UI: paste the attacker text and click ANALYZE (inline
      // onclick fires in the main world; page.evaluate is an isolated world,
      // so the click happens via the button element like a real user).
      const pasteAndAnalyze = () => page.evaluate((text) => {
        document.getElementById('analyze-input').value = text;
        // The FIRST `.analyze-btn` in DOM order is the real protection-view
        // ANALYZE button; the "System 2 — ANALYZE CONTENT" stub (a toast) is
        // not an `.analyze-btn`, so the class selector cannot hit it.
        document.querySelector('button.analyze-btn').click();
      }, ATTACKER_TEXT);

      const snap = () => page.evaluate(() => {
        const panel = document.getElementById('analysis-result');
        const pill = panel.querySelector('.verdict-pill');
        const sigVals = [...panel.querySelectorAll('.sig-val')].map((e) => ({
          text: e.textContent, color: e.style.color
        }));
        const flagList = panel.querySelector('.flag-list');
        const flagHtml = flagList ? flagList.innerHTML : '';
        return {
          panelHtml: panel.innerHTML,
          pillClass: pill.className,
          pillText: pill.textContent,
          pillChildCount: pill.children.length,
          sigVals,
          flagHtml,
          badElements: panel.querySelectorAll('img, script, svg, iframe, object, embed').length,
        };
      });

      // ---- Leg 1: local-rule fallback (no key) with attacker text ----
      await pasteAndAnalyze();
      await page.waitForFunction(
        () => (document.querySelector('.flag-list')?.innerHTML || '').includes('BYOK Hint'),
        null, { timeout: 15000 }
      );
      let s = await snap();
      check('local fallback: no attacker markup reaches any innerHTML sink',
        !s.panelHtml.includes('<img') && !s.panelHtml.includes('<script'), '');
      check('local fallback: no executable elements created', s.badElements === 0, `bad=${s.badElements}`);
      check('local fallback: verdict pill is a constant (text-only)', s.pillChildCount === 0, s.pillText);
      check('local fallback: no alert/dialog and no page error', dialogs.length === 0 && pageErrors.length === 0,
        `dialogs=${dialogs.length} pageErrors=${pageErrors.length}`);

      // ---- Leg 2: Gemini path with hostile echo payload ----
      // Save the fake BYOK key through the real UI (BYOK modal). The key is
      // per-session in-memory: assert nothing lands in localStorage /
      // sessionStorage / window.*, and the AI pill confirms it is active.
      await page.evaluate(() => {
        document.getElementById('byok-btn').click();
        document.getElementById('gemini-key-input').value = 'fake-key';
        document.querySelector('#byok-modal button.analyze-btn').click();
      });
      const hygiene = await page.evaluate(() => ({
        ls: localStorage.getItem('SOVEREIGN_GEMINI_KEY'),
        ss: sessionStorage.getItem('SOVEREIGN_GEMINI_KEY'),
        inWindow: 'SOVEREIGN_GEMINI_KEY' in window,
        bindingInWindow: 'sessionGeminiKey' in window,
        pill: document.getElementById('ai-status-pill')?.textContent || ''
      }));
      check('key hygiene: nothing in localStorage after save', hygiene.ls === null, String(hygiene.ls));
      check('key hygiene: nothing in sessionStorage after save', hygiene.ss === null, String(hygiene.ss));
      check('key hygiene: no window property exposes the key', !hygiene.inWindow && !hygiene.bindingInWindow);
      check('key hygiene: AI pill reports GEMINI LIVE (in-memory key active)',
        hygiene.pill.includes('GEMINI 2.5 LIVE'), hygiene.pill);
      await pasteAndAnalyze();
      await page.waitForFunction(
        () => (document.querySelector('.flag-list')?.innerHTML || '').includes('Live AI Active'),
        null, { timeout: 15000 }
      );
      s = await snap();

      check('gemini hostile: no alert/dialog and no page error fired',
        dialogs.length === 0 && pageErrors.length === 0, `dialogs=${dialogs.length} pageErrors=${pageErrors.length}`);
      check('gemini hostile: zero executable elements in the result panel',
        s.badElements === 0, `bad=${s.badElements}`);
      check('gemini hostile: no raw tag-openers from model output in innerHTML',
        !s.panelHtml.includes('<img') && !s.panelHtml.includes('<script') && !s.panelHtml.includes('<svg'),
        s.panelHtml.slice(0, 140));
      check('gemini hostile: pasted claim echo reaches innerHTML only escaped',
        s.flagHtml.includes('echo of claim: They are hiding the cure! &lt;img') &&
        s.flagHtml.includes('&lt;script&gt;'),
        s.flagHtml.slice(0, 160));
      check('gemini hostile: verdictClass allowlisted (vp-suspect), no child elements',
        s.pillClass === 'verdict-pill vp-suspect' && s.pillChildCount === 0, s.pillClass);
      check('gemini hostile: verdictText is inert text (literal, not parsed)',
        s.pillText.includes('<script>alert(1)</script>'), s.pillText.slice(0, 80));
      check('gemini hostile: score clamped (non-numeric -> 50%)',
        s.sigVals[0].text === '50%', s.sigVals[0].text);
      check('gemini hostile: sourceCredibility allowlisted (VERIFY)',
        s.sigVals[2].text === 'VERIFY', s.sigVals[2].text);
      check('gemini hostile: emotionalTrigger stays inert text',
        s.sigVals[1].text.includes('<svg'), s.sigVals[1].text.slice(0, 60));

      // ---- Per-session semantics: a reload forgets the key ----
      await page.reload({ waitUntil: 'domcontentloaded' });
      const afterReload = await page.evaluate(() => ({
        pill: document.getElementById('ai-status-pill')?.textContent || '',
        ls: localStorage.getItem('SOVEREIGN_GEMINI_KEY')
      }));
      check('per-session: reload forgets the key (back to LOCAL)',
        afterReload.pill.includes('AI: LOCAL') && !afterReload.pill.includes('GEMINI'), afterReload.pill);
      check('per-session: reload leaves no storage remnant', afterReload.ls === null, String(afterReload.ls));

      // ---- Leg 3: well-behaved model response (key re-entered for the session) ----
      hostile = false;
      await page.evaluate(() => {
        document.getElementById('byok-btn').click();
        document.getElementById('gemini-key-input').value = 'fake-key';
        document.querySelector('#byok-modal button.analyze-btn').click();
      });
      await pasteAndAnalyze();
      await page.waitForFunction(
        () => document.querySelector('.verdict-pill')?.textContent === 'HIGH MANIPULATION RISK' &&
          (document.querySelector('.flag-list')?.innerHTML || '').includes('plain-text flag'),
        null, { timeout: 15000 }
      );
      s = await snap();
      check('gemini benign: legit verdictClass passes allowlist',
        s.pillClass === 'verdict-pill vp-danger', s.pillClass);
      check('gemini benign: legit score renders as-is (92%)',
        s.sigVals[0].text === '92%', s.sigVals[0].text);
      check('gemini benign: legit sourceCredibility passes (LOW)',
        s.sigVals[2].text === 'LOW', s.sigVals[2].text);
      check('gemini benign: simple flag markup still escaped, no elements',
        s.flagHtml.includes('&lt;b&gt;plain-text flag') && s.badElements === 0, s.flagHtml.slice(0, 100));
      check('gemini benign: no alert/dialog and no page error fired',
        dialogs.length === 0 && pageErrors.length === 0, `dialogs=${dialogs.length} pageErrors=${pageErrors.length}`);
    } finally {
      await browser.close();
    }
  } catch (err) {
    console.error('[xss-regression] ERROR:', err.message);
    if (uiErr.trim()) console.error('[xss-regression] ui stderr:', uiErr.trim().slice(0, 600));
    failures++;
  } finally {
    ui.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nXSS REGRESSION PASSED' : `\n${failures} XSS REGRESSION CHECK(S) FAILED`);
}

await main();
process.exit(failures === 0 ? 0 : 1);
