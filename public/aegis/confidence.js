/**
 * SOVEREIGN // AEGIS — the confidence control
 *
 * WHY A SHARED CONTROL RATHER THAN SIX
 * ------------------------------------
 * Six surfaces record attempts, and every one of them needs to ask the same question in the same
 * words with the same three answers. Six copies would drift — different wording, different
 * defaults, one of them quietly forgotten — and a module that forgets to ask produces records that
 * are permanently uncalibratable without ever raising an error. So the markup, the vocabulary and
 * the persistence live here once.
 *
 * THE DESIGN PROBLEM THIS SOLVES
 * ------------------------------
 * Asking "how sure are you?" on every question is a second mandatory tap, and in the Arena — whose
 * entire character is rapid fire under a timer — a second mandatory tap would wreck the thing.
 *
 * So this is a MODIFIER, not a question. It holds its setting across questions, across modules and
 * across reloads, and it is read at answer time. The operator sets it when their certainty changes
 * and otherwise ignores it, which makes the common case cost nothing. That is the only reason
 * confidence capture can be applied to all six surfaces without making any of them worse.
 *
 * The cost of that choice, stated plainly: a stale setting is a wrong measurement. Someone who sets
 * "sure" and forgets will look overconfident. Mitigations here are (a) the control is always
 * visible next to the answer, never in a menu, and (b) the reliability curve reports the sample
 * size behind every bin, so a curve built from one stale setting reads as thin rather than as fact.
 *
 * WHAT IS DELIBERATELY NOT HERE
 * -----------------------------
 * No scoring, no wagering, no effect on mastery. This module reports what the operator said. What
 * that is worth is js/competency.js's problem.
 *
 * @module confidence
 */

import { normaliseConfidence } from './attemptlog.js';

/** Storage key for the sticky setting. */
const STORE_KEY = 'confidence.level';

/** Default when nothing is set. 'unsure' rather than 'sure' — an unset control must not flatter. */
const DEFAULT_LEVEL = 'unsure';

/**
 * The three levels, in the order they render. Wording matters: these are what the operator is
 * claiming about themselves, and "Certain" invites bravado where "I'm sure" invites a judgement.
 */
export const LEVELS = [
  { id: 'sure', label: 'SURE', hint: 'I could defend this answer' },
  { id: 'unsure', label: 'UNSURE', hint: 'I think so, but I could be talked out of it' },
  { id: 'guess', label: 'GUESSING', hint: 'Narrowed it down, no more than that' }
];

const CLASS = 'aegis-confidence';

export const Confidence = {
  /** @type {object|null} the app, for the state store — set by AegisApp during boot */
  _app: null,
  /** In-memory fallback so this works before the store exists and in tests. */
  _level: DEFAULT_LEVEL,

  /**
   * @param {object} app
   */
  init(app) {
    this._app = app || null;
    const stored = this._app && this._app.store ? this._app.store.get(STORE_KEY) : null;
    this._level = normaliseConfidence(stored) || DEFAULT_LEVEL;
  },

  /** @returns {'sure'|'unsure'|'guess'} the operator's current stated certainty */
  current() {
    return this._level;
  },

  /**
   * @param {string} level
   * @returns {boolean} whether it was accepted
   */
  set(level) {
    const clean = normaliseConfidence(level);
    if (!clean) return false;
    this._level = clean;
    if (this._app && this._app.store) this._app.store.set(STORE_KEY, clean);
    this._syncAll();
    return true;
  },

  /**
   * Insert the control as the first child of `host`, or move the existing one there.
   *
   * Idempotent: mounting twice into the same host is a no-op, so a module that re-renders its
   * panel on every question cannot accumulate controls.
   *
   * @param {HTMLElement|null} host
   * @param {{label?: string}} [opts]
   * @returns {HTMLElement|null}
   */
  mount(host, opts = {}) {
    if (!host || typeof document === 'undefined') return null;
    const existing = host.querySelector(`:scope > .${CLASS}`);
    if (existing) { this._sync(existing); return existing; }

    const wrap = document.createElement('div');
    wrap.className = CLASS;
    wrap.setAttribute('role', 'radiogroup');
    wrap.setAttribute('aria-label', 'How confident are you in your answer?');

    const caption = document.createElement('div');
    caption.className = 'status-label text-muted';
    caption.style.marginBottom = '6px';
    // textContent throughout: this module builds DOM rather than markup, so there is no
    // interpolation for anything to be injected into.
    caption.textContent = opts.label || 'BEFORE YOU ANSWER — HOW SURE ARE YOU?';
    wrap.appendChild(caption);

    const bar = document.createElement('div');
    bar.className = 'aegis-conf-bar';
    for (const lv of LEVELS) {
      const btn = document.createElement('button');
      btn.type = 'button';
      // DELIBERATELY NOT `.subtab-btn`, despite looking identical to one.
      //
      // The first version reused `.subtab-btn` for visual consistency and the selection silently
      // vanished: AegisApp.switchSubTab() does
      //     viewContainer.querySelectorAll('.subtab-btn') → remove 'active' unless data-subtab matches
      // so every subtab switch stripped this control's selected state, and _bindDOM() binds a
      // subtab-navigation click handler to every .subtab-btn in the document. Borrowing a class
      // means inheriting its behaviour, not just its appearance.
      //
      // So: own class, own CSS (css/components.css), and selection tracked through aria-checked —
      // which is the correct semantics for a radio anyway, and which nothing else in the app
      // touches.
      btn.className = 'aegis-conf-btn';
      btn.dataset.confidence = lv.id;
      btn.textContent = lv.label;
      btn.title = lv.hint;
      btn.setAttribute('role', 'radio');
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.set(lv.id);
      });
      bar.appendChild(btn);
    }
    wrap.appendChild(bar);

    host.insertBefore(wrap, host.firstChild);
    this._sync(wrap);
    return wrap;
  },

  /**
   * Reflect the current level onto one mounted control.
   * @private
   */
  _sync(wrap) {
    if (!wrap) return;
    wrap.querySelectorAll('[data-confidence]').forEach((btn) => {
      const on = btn.dataset.confidence === this._level;
      // aria-checked is the single source of truth for both semantics and styling. No 'active'
      // class — see the note in mount() for why borrowing one cost an afternoon.
      btn.setAttribute('aria-checked', on ? 'true' : 'false');
    });
  },

  /**
   * Reflect onto every mounted control. Several can be mounted at once — the Arena's and the
   * Memory Vault's both exist in the DOM even though only one is visible — and they must not
   * disagree about what the operator last said.
   * @private
   */
  _syncAll() {
    if (typeof document === 'undefined') return;
    document.querySelectorAll(`.${CLASS}`).forEach((w) => this._sync(w));
  },

  /** Test seam. */
  _reset() {
    this._app = null;
    this._level = DEFAULT_LEVEL;
  }
};

export default Confidence;
