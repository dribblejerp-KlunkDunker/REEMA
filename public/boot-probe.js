/**
 * Shared bootstrap timing probe + readiness gate.
 *
 * Used by both public/index.html and public/messenger.html so the
 * "paint-before-identity" / lazy-load guards and the idle-deferred E2EE
 * bootstrap live in one place instead of drifting apart.
 *
 *   bootTiming(...)     — records FCP (first-contentful-paint, with a
 *                         first-rAF fallback) plus optional resource-fetch
 *                         markers, and exposes markIdentityExists(). Mirrors
 *                         everything into localStorage['__e2ee_timing']
 *                         because a test's page.evaluate() runs in an isolated
 *                         world: same-origin storage is shared, the window
 *                         global is not. Harmless in production; if the probe
 *                         is ever removed the E2E/smoke checks fail loudly.
 *   createBootGate(...) — single-flight readiness gate around the heavy
 *                         bootstrap (libsodium ready-wait + WASM, PQ keygen,
 *                         relay connect) so send/open paths can await it while
 *                         first paint is never blocked.
 *   deferBoot(...)      — schedules that bootstrap on idle time (with a
 *                         fallback for engines without requestIdleCallback).
 */

const TIMING_KEY = '__e2ee_timing';

/**
 * @param {object} [opts]
 * @param {Array<{field: string, namePart: string}>} [opts.resourceMarkers]
 *   Optional resource-timing markers. For each, the first fetched resource
 *   whose URL contains `namePart` records `performance.now()`-time into
 *   `timing[field]` (e.g. first @noble / first libsodium fetch — the
 *   lazy-load lock-in). Omit to track only FCP + identity.
 * @returns {{ markIdentityExists: () => void }}
 */
export function bootTiming({ resourceMarkers = [] } = {}) {
  const timing = { fcpMs: null, identityMs: null };
  for (const m of resourceMarkers) timing[m.field] = null;
  window.__e2eeBootstrapTiming = timing;

  const store = () => {
    try { localStorage.setItem(TIMING_KEY, JSON.stringify(timing)); } catch { /* private mode */ }
  };

  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === 'first-contentful-paint' && timing.fcpMs === null) {
          timing.fcpMs = entry.startTime;
          store();
        }
      }
    }).observe({ type: 'paint', buffered: true });
  } catch { /* engines without PerformanceObserver: fall back to first rAF */ }

  // Lazy-load lock-in: record when the configured modules/scripts are FIRST
  // fetched (resource timing covers cache hits too). A static import or
  // <script> tag would fetch during module-eval — before first paint — and
  // fail the E2E. Skipped entirely when no markers are configured.
  if (resourceMarkers.length) {
    try {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          for (const m of resourceMarkers) {
            if (timing[m.field] === null && entry.name.includes(m.namePart)) {
              timing[m.field] = entry.startTime;
              store();
            }
          }
        }
      }).observe({ type: 'resource', buffered: true });
    } catch { /* no resource timing: markers stay null and the E2E fails loudly */ }
  }

  if (timing.fcpMs === null) {
    const markPaint = () => {
      if (timing.fcpMs === null) {
        timing.fcpMs = performance.now();
        store();
      }
    };
    requestAnimationFrame(markPaint);
    addEventListener('load', markPaint);
  }

  const markIdentityExists = () => {
    if (timing.identityMs === null) {
      timing.identityMs = performance.now();
      store();
    }
  };

  return { markIdentityExists };
}

/**
 * Single-flight readiness gate: every caller of whenReady()/ensure() awaits
 * the SAME bootstrap promise, and a failure resets it so a retry re-runs the
 * bootstrap instead of replaying a rejection forever.
 *
 * @param {() => Promise<*>} bootstrap — the heavy E2EE bootstrap function
 * @param {(err: Error) => void} onError — page-specific failure reporting
 * @returns {{ ensure: () => Promise<*>, whenReady: () => Promise<boolean> }}
 */
export function createBootGate(bootstrap, onError) {
  let ready = null;
  const ensure = () => {
    if (!ready) ready = bootstrap().catch((err) => { ready = null; throw err; });
    return ready;
  };
  const whenReady = async () => {
    try { await ensure(); return true; }
    catch (err) {
      onError(err);
      return false;
    }
  };
  return { ensure, whenReady };
}

/**
 * Kick the bootstrap off on idle time so first paint and interactivity are
 * not blocked; the timeout guarantees it still runs on busy pages, and the
 * send/open paths await it through whenReady() anyway.
 *
 * @param {() => Promise<*>} ensure — the gate's ensure() function
 * @param {{ idleTimeoutMs?: number }} [opts]
 */
export function deferBoot(ensure, { idleTimeoutMs = 5000 } = {}) {
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(() => { ensure().catch(console.error); }, { timeout: idleTimeoutMs });
  } else {
    setTimeout(() => { ensure().catch(console.error); }, 0);
  }
}
