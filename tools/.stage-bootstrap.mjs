/**
 * SCRATCH STAGER (bootstrap-only splice) — stages:
 *   public/index.html    = HEAD + idle-deferred bootstrap (probe, ensureE2EE/
 *                          whenE2EEReady, gates on existing flows, cached-bundle,
 *                          requestIdleCallback) — WITHOUT group/memory/vault/
 *                          sanitize/directory-shard work.
 *   src/browser-e2e.js   = HEAD + paint-before-identity / lazy-load / reload
 *                          guards — WITHOUT allConsole, group-WS, vault, memory legs.
 *
 * Verification happens via tools/verify-staged.mjs on the staged set, then a
 * temp worktree at HEAD + these blobs is used to run src/browser-e2e.js.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';

const git = (args, opts = {}) => execFileSync('git', args, { encoding: 'utf8', ...opts });
const head = (p) => git(['show', `HEAD:${p}`]);

// ---------- staged index.html ----------
let h = head('public/index.html');

// 0. Drop the libsodium <script defer> tags: HEAD's browser-crypto.js already
// lazy-injects the vendored scripts on first init() (the idle-time bootstrap),
// and the browser-e2e guard asserts no libsodium fetch lands before FCP.
// Keeping the defer tags would make a fresh clone fail that guard.
const sodiumAnchor = `<!-- defer: the sodium globals are only used by the E2EE module below, which
     runs after deferred classic scripts — no parse-time dependency, so these
     745 KB must not block parsing. -->
<script defer src="./vendor/libsodium/libsodium.js"></script>
<script defer src="./vendor/libsodium/libsodium-wrappers.js"></script>
`;
const sodiumReplace = `<!-- libsodium is NOT loaded here: public/browser-crypto.js injects the vendored
     scripts on first init() (the idle-time bootstrap), so their ~192 KB brotli
     transfer (wrapper + inline WASM) stays out of the initial parse — the same
     deferral as the @noble/post-quantum graph. -->
`;
if (!h.includes(sodiumAnchor)) throw new Error('sodium anchor not found');
h = h.replace(sodiumAnchor, sodiumReplace);

// 1. Probe block (timing) after OTK_POOL_SIZE, before "Multi-session state".
const probe = `  // ---- Bootstrap timing probe (browser E2E) ----
  // Records when the page first paints (FCP, with a first-rAF fallback) and
  // when the E2EE identity first exists, so src/browser-e2e.js can assert the
  // idle-deferred bootstrap never blocks first paint: identity creation must
  // not precede first paint. The values are mirrored to localStorage because
  // the E2E's page.evaluate runs in an isolated world — same-origin storage
  // is shared, the window global is not. Harmless in production; if the probe
  // is ever removed, the E2E check fails loudly.
  window.__e2eeBootstrapTiming = { fcpMs: null, identityMs: null, firstNobleMs: null, firstSodiumMs: null };
  const storeTiming = () => {
    try { localStorage.setItem('__e2ee_timing', JSON.stringify(window.__e2eeBootstrapTiming)); } catch { /* private mode */ }
  };
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === 'first-contentful-paint' && window.__e2eeBootstrapTiming.fcpMs === null) {
          window.__e2eeBootstrapTiming.fcpMs = entry.startTime;
          storeTiming();
        }
      }
    }).observe({ type: 'paint', buffered: true });
  } catch { /* engines without PerformanceObserver: fall back to first rAF */ }
  // Lazy-load lock-in: record when the FIRST @noble/post-quantum module and
  // the FIRST vendored libsodium script are fetched (resource timing covers
  // cache hits too, so a browser-cached fetch still counts). If a static
  // import or <script> tag ever re-enters the initial page, the fetch would
  // start at module-eval — before first paint — and the browser E2E fails.
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const t = window.__e2eeBootstrapTiming;
        if (entry.name.includes('/@noble/') && t.firstNobleMs === null) {
          t.firstNobleMs = entry.startTime;
          storeTiming();
        } else if (entry.name.includes('/libsodium/') && t.firstSodiumMs === null) {
          t.firstSodiumMs = entry.startTime;
          storeTiming();
        }
      }
    }).observe({ type: 'resource', buffered: true });
  } catch { /* no resource timing: markers stay null and the E2E fails loudly */ }
  if (window.__e2eeBootstrapTiming.fcpMs === null) {
    const markPaint = () => {
      if (window.__e2eeBootstrapTiming.fcpMs === null) {
        window.__e2eeBootstrapTiming.fcpMs = performance.now();
        storeTiming();
      }
    };
    requestAnimationFrame(markPaint);
    addEventListener('load', markPaint);
  }
  const markIdentityExists = () => {
    if (window.__e2eeBootstrapTiming.identityMs === null) {
      window.__e2eeBootstrapTiming.identityMs = performance.now();
      storeTiming();
    }
  };
`;
const otkAnchor = '  const OTK_POOL_SIZE = 20;\n\n  // Multi-session state\n';
if (!h.includes(otkAnchor)) throw new Error('probe anchor not found');
h = h.replace(otkAnchor, '  const OTK_POOL_SIZE = 20;\n\n' + probe + '\n  // Multi-session state\n');

// 2. Deferred bootstrap (ensureE2EE/whenE2EEReady) after activePeerPk.
const deferBlock = `  let activePeerPk = null; // currently viewed session's peer pk

  // ---- Deferred E2EE bootstrap ----
  // startE2EE() is expensive (libsodium ready-wait, ML-KEM/ML-DSA keygen,
  // relay connect), so it is scheduled on requestIdleCallback and the
  // send/open paths await it instead of blocking first paint.
  let e2eeReady = null;
  function ensureE2EE() {
    if (!e2eeReady) e2eeReady = startE2EE().catch((err) => { e2eeReady = null; throw err; });
    return e2eeReady;
  }
  async function whenE2EEReady() {
    try { await ensureE2EE(); return true; }
    catch (err) {
      console.error('[E2EE] bootstrap failed:', err);
      showToast('⚠️ Crypto bootstrap failed — ' + err.message);
      return false;
    }
  }
`;
const activeAnchor = "  let activePeerPk = null; // currently viewed session's peer pk\n";
if (!h.includes(activeAnchor)) throw new Error('defer anchor not found');
h = h.replace(activeAnchor, deferBlock);

// 3. markIdentityExists() in restoreIdentityFromData (after updateUIWithKeys;).
const restAnchor = `    updateUIWithKeys();
  }
`;
if (!h.includes(restAnchor)) throw new Error('restore anchor not found');
h = h.replace(restAnchor, `    updateUIWithKeys();
    markIdentityExists();
  }
`);

// 4. markIdentityExists() in generateNewE2EEIdentity (after persistIdentity).
const genAnchor = `    myId.newOneTimePrekeys(OTK_POOL_SIZE);
    persistIdentity();
`;
if (!h.includes(genAnchor)) throw new Error('gen anchor not found');
h = h.replace(genAnchor, `    myId.newOneTimePrekeys(OTK_POOL_SIZE);
    persistIdentity();
    markIdentityExists();
`);

// 5. Cached bundle (returning user skips PQ on registration) + publishToRelay.
const cacheBlock = `  // The shareable prekey bundle is static per identity (public key material
  // plus a self-signature over it), so it is cached in localStorage after the
  // first publish. Re-publishing a returning user's cached bundle needs no
  // ML-DSA-65 — the only PQ need in the registration path — which keeps the
  // @noble/post-quantum graph unfetched on reload until a session is actually
  // established. A rotated or vault-imported identity has a different
  // staticDhPk, so the cache naturally misses and re-signs.
  function myCachedBundle() {
    const b = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);
    const cached = localStorage.getItem('e2ee_bundle_v6');
    if (cached) {
      try {
        const bundle = JSON.parse(cached);
        if (bundle && bundle.v === 6 && bundle.staticDhPk === b(myId.pk)) return bundle;
      } catch { /* corrupted cache — rebuild */ }
    }
    return null;
  }
  function buildCachedBundle() {
    const bundle = myId.makeBundle();
    localStorage.setItem('e2ee_bundle_v6', JSON.stringify(bundle));
    return bundle;
  }

  async function publishToRelay() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    let bundle = myCachedBundle();
    if (!bundle) {
      // Fresh or rotated identity: self-sign the bundle now (PQ was already
      // loaded by keygen). Returning users skip this entirely.
      await loadPQ();
      bundle = buildCachedBundle();
    }
`;
const pubAnchor = `  async function publishToRelay() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    await loadPQ(); // makeBundle self-signs the bundle with ML-DSA-65
`;
if (!h.includes(pubAnchor)) throw new Error('publish anchor not found');
h = h.replace(pubAnchor, cacheBlock);

// 6. shareMyKey: async + gate + loadPQ.
const shareAnchor = `  window.shareMyKey = function() {
    // v5: the shareable identity is the self-signed prekey bundle, not a bare
    // X25519 key — it carries everything a peer needs to establish a session.
`;
if (!h.includes(shareAnchor)) throw new Error('share anchor not found');
h = h.replace(shareAnchor, `  window.shareMyKey = async function() {
    if (!(await whenE2EEReady())) return;
    await loadPQ(); // makeBundle self-signs with ML-DSA-65
    // v5: the shareable identity is the self-signed prekey bundle, not a bare
    // X25519 key — it carries everything a peer needs to establish a session.
`);

// 7. rotateIdentity wrapper (after shareMyKey's closing "};").
const rotateBlock = `  };

  // ROTATE is gated separately: generateNewE2EEIdentity() is also called by
  // the deferred bootstrap itself, so the button routes through this wrapper
  // to await readiness first (gating the bare function would deadlock it on
  // its own bootstrap).
  window.rotateIdentity = async function() {
    if (!(await whenE2EEReady())) return;
    await generateNewE2EEIdentity();
  };

  // ---- Vault at rest (age format) ----
`;
const vaultAnchor = `  };

  // ---- Vault at rest (age format) ----
`;
if (!h.includes(vaultAnchor)) throw new Error('rotate anchor not found');
h = h.replace(vaultAnchor, rotateBlock);

// 8. vaultExport gate.
const veAnchor = `  window.vaultExport = async function() {
    const passphrase = document.getElementById('vault-passphrase').value;
`;
if (!h.includes(veAnchor)) throw new Error('vaultExport anchor not found');
h = h.replace(veAnchor, `  window.vaultExport = async function() {
    if (!(await whenE2EEReady())) return;
    const passphrase = document.getElementById('vault-passphrase').value;
`);

// 9. vaultImport gate.
const viAnchor = `  window.vaultImport = async function() {
    const armored = document.getElementById('vault-import-in').value.trim();
    if (!armored) { showToast('Paste an armored age vault first'); return; }
`;
if (!h.includes(viAnchor)) throw new Error('vaultImport anchor not found');
h = h.replace(viAnchor, `  window.vaultImport = async function() {
    if (!(await whenE2EEReady())) return;
    const armored = document.getElementById('vault-import-in').value.trim();
    if (!armored) { showToast('Paste an armored age vault first'); return; }
`);

// 10. uiSendE2EEMessage gate.
const sendAnchor = `      if (!raw || !text) { showToast('Enter a peer bundle or address and a message.'); return; }
      await loadPQ(); // session establish/encrypt needs ML-KEM-768
`;
if (!h.includes(sendAnchor)) throw new Error('send anchor not found');
h = h.replace(sendAnchor, `      if (!raw || !text) { showToast('Enter a peer bundle or address and a message.'); return; }
      // The bootstrap runs on idle time; bring it up on demand if the user
      // acts before it has finished.
      if (!(await whenE2EEReady())) return;
      await loadPQ(); // session establish/encrypt needs ML-KEM-768
`);

// 11. Bottom: defer startE2EE() to requestIdleCallback.
const bootAnchor = `  startE2EE().catch(console.error);
</script>`;
const bootBlock = `  // Defer the expensive E2EE bootstrap (libsodium ready-wait + keygen + relay
  // connect) to idle time so first paint and interactivity are not blocked.
  // The timeout guarantees it still runs on busy pages; send/open await it
  // through whenE2EEReady() anyway.
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(() => { ensureE2EE().catch(console.error); }, { timeout: 5000 });
  } else {
    setTimeout(() => { ensureE2EE().catch(console.error); }, 0);
  }
</script>`;
if (!h.includes(bootAnchor)) throw new Error('bottom anchor not found');
h = h.replace(bootAnchor, bootBlock);

// 12. ROTATE button routes through the gated wrapper.
const btnAnchor = `onclick="generateNewE2EEIdentity()"`;
if (!h.includes(btnAnchor)) throw new Error('button anchor not found');
h = h.replace(btnAnchor, `onclick="rotateIdentity()"`);

writeFileSync('.staged-index.html', h);

// ---------- staged browser-e2e.js ----------
let b = head('src/browser-e2e.js');

// newPage timing guards (paint-before-identity, noble lazy, sodium lazy) —
// WITHOUT the allConsole console-handler change (sanitize-audit thread).
const newPageAnchor = `      page.on('requestfailed', (r) => failedRequests.push(\`\${tag}: \${r.url()}\`));
      await page.goto(UI_URL, { timeout: 120000 });
      await waitReady(page);
      return page;
    };`;
const newPageBlock = `      page.on('requestfailed', (r) => failedRequests.push(\`\${tag}: \${r.url()}\`));
      await page.goto(UI_URL, { timeout: 120000 });
      await waitReady(page);
      // Deferred-bootstrap guard: the E2EE identity must NOT exist at first
      // paint. index.html records FCP (paint PerformanceObserver, first-rAF
      // fallback) and the moment identity creation completes; identity must
      // land no earlier than first paint. An eager bootstrap would create the
      // identity at module-eval time, well before FCP, and fail this check.
      const timing = await page.evaluate(() => {
        const raw = localStorage.getItem('__e2ee_timing');
        return raw ? JSON.parse(raw) : null;
      });
      const probeOk = !!timing && timing.fcpMs !== null && timing.identityMs !== null;
      check(\`\${tag}: dashboard painted before the E2EE identity existed (idle-deferred bootstrap)\`,
        probeOk && timing.identityMs >= timing.fcpMs,
        probeOk ? \`FCP \${timing.fcpMs.toFixed(1)}ms, identity \${timing.identityMs.toFixed(1)}ms\`
                : timing ? \`probe incomplete (fcp=\${timing.fcpMs}, identity=\${timing.identityMs})\` : 'probe missing');
      // Lazy-load lock-in: the first @noble/post-quantum fetch must land at or
      // after first paint — the modules are pulled by the deferred bootstrap's
      // crypto work (keygen/session), never during initial module evaluation.
      // A static @noble import would fetch before FCP and fail this.
      const lazyOk = !!timing && timing.firstNobleMs !== null && timing.fcpMs !== null;
      check(\`\${tag}: no @noble/post-quantum modules fetched during the initial page load (lazy-load win)\`,
        lazyOk && timing.firstNobleMs >= timing.fcpMs,
        lazyOk ? \`first @noble fetch \${timing.firstNobleMs.toFixed(1)}ms (FCP \${timing.fcpMs.toFixed(1)}ms)\`
               : timing ? \`probe incomplete (fcp=\${timing.fcpMs}, firstNoble=\${timing.firstNobleMs})\` : 'probe missing');
      // Same lazy treatment for libsodium: it is injected by browser-crypto.js
      // on the idle bootstrap, so its first fetch must also land at/after FCP.
      // A re-added <script defer> tag would fetch it during initial load and
      // fail this.
      const sodiumOk = !!timing && timing.firstSodiumMs !== null && timing.fcpMs !== null;
      check(\`\${tag}: vendored libsodium (WASM) is not fetched during the initial parse (lazy-load win)\`,
        sodiumOk && timing.firstSodiumMs >= timing.fcpMs,
        sodiumOk ? \`first libsodium fetch \${timing.firstSodiumMs.toFixed(1)}ms (FCP \${timing.fcpMs.toFixed(1)}ms)\`
                 : timing ? \`probe incomplete (fcp=\${timing.fcpMs}, firstSodium=\${timing.firstSodiumMs})\` : 'probe missing');
      return page;
    };`;
if (!b.includes(newPageAnchor)) throw new Error('newPage anchor not found');
b = b.replace(newPageAnchor, newPageBlock);

writeFileSync('.staged-browser-e2e.js', b);
console.log('staged blobs written: .staged-index.html, .staged-browser-e2e.js');
