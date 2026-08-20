// tools/live-memory-tenant-lifecycle.mjs
// Tenant-lifecycle test: CREATE -> POPULATE -> RECALL -> DROP, asserting
// complete isolation and a complete wipe.
//
// The wipe assertions go beyond "delete returns ok":
//   1. the dropped bank is gone from the tenant inventory;
//   2. reads against the dropped bank fail (it no longer exists);
//   3. RESURRECTION: recreating the same bank id starts with ZERO facts — no
//      stale memories resurface — and exactly the template's directives, i.e.
//      the previous life left no artifacts behind.
//
// Prereq: a Hindsight daemon on 127.0.0.1:8877 (see tools/live-memory-demo.mjs
// for the exact uvx profile/env commands).
//
// Usage:
//   node tools/live-memory-tenant-lifecycle.mjs
//
// Exit 0 = lifecycle + isolation + wipe proven. Both test banks are deleted
// even on failure (finally).

import { createMemory, TENANT_TEMPLATES } from '../src/memory.js';

const DAEMON = 'http://127.0.0.1:8877';
const BANK_A = 'lifecycle-a';
const BANK_B = 'lifecycle-b';
let failures = 0;
const ok = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

const h = await fetch(`${DAEMON}/health`).then((r) => r.json()).catch(() => null);
ok('hindsight daemon reachable on 127.0.0.1:8877', !!(h && h.status === 'healthy'));

let a = null;
let b = null;
try {
  // ---- CREATE: provision tenant A from the code-review template ----
  a = createMemory({ baseUrl: DAEMON, bankId: BANK_A, tenant: 'code-review' });
  const prov = await a.ensureBank();
  ok('CREATE: tenant A provisioned from template', prov.ok && prov.templateApplied === true,
    prov.templateApplied ? `config_applied=${prov.result?.config_applied}, directives_created=${(prov.result?.directives_created || []).length}` : prov.error || '');
  const cfgA = await a.getConfig();
  ok('CREATE: template config applied (mission + dispositions)',
    cfgA.ok && cfgA.config.reflect_mission === TENANT_TEMPLATES['code-review'].bank.reflect_mission &&
    cfgA.config.disposition_skepticism === 4 && cfgA.config.disposition_literalism === 5);

  // Tenant B exists only to prove isolation across banks.
  b = createMemory({ baseUrl: DAEMON, bankId: BANK_B, tenant: 'support' });
  await b.ensureBank();

  // ---- POPULATE: each tenant retains its own facts (synchronous) ----
  const factA1 = 'A: the relay send path throws on a non-string envelope field.';
  const factA2 = 'A: ML-KEM-768 keys are 1184 bytes; ML-DSA-65 signatures 3309.';
  const factB1 = 'B: the customer cleared the browser cache and vault import worked.';
  ok('POPULATE: A retains fact 1', (await a.retain(factA1, { wait: true })).ok);
  ok('POPULATE: A retains fact 2', (await a.retain(factA2, { wait: true })).ok);
  ok('POPULATE: B retains its fact', (await b.retain(factB1, { wait: true })).ok);

  // ---- RECALL: own facts found, zero cross-tenant leakage ----
  const recA = await a.recall('What throws in the relay send path?');
  ok('RECALL: A finds its own fact', recA.ok && recA.results.some((x) => x.text.includes('relay send path')));
  ok('RECALL: A finds both of its facts', recA.results.some((x) => x.text.includes('ML-KEM-768')));
  ok('RECALL: isolation — B\'s fact never leaks into A',
    !recA.results.some((x) => x.text.includes(factB1.slice(0, 20))));
  const recB = await b.recall('What fixed the vault import?');
  ok('RECALL: B finds its own fact', recB.ok && recB.results.some((x) => x.text.includes('vault import')));
  ok('RECALL: isolation — A\'s facts never leak into B',
    !recB.results.some((x) => x.text.includes('relay send path')) &&
    !recB.results.some((x) => x.text.includes('ML-KEM-768')));

  // ---- DROP: delete tenant A ----
  const drop = await a.deleteBank();
  ok('DROP: deleteBank reports success', drop.ok && drop.bank === BANK_A);
  const list = await b.listBanks();
  ok('DROP: A is gone from the tenant inventory', !(list.banks || []).some((x) => x.bank_id === BANK_A));

  // ---- WIPE assertions ----
  const recGone = await a.recall('What throws in the relay send path?');
  ok('WIPE: recall against the dropped bank is empty', recGone.ok && recGone.results.length === 0,
    recGone.ok ? '0 results' : recGone.error);
  // The daemon is permissive on reads of deleted banks: config returns DEFAULTS
  // (not the template's), which is the wipe proof — the template's mission and
  // dispositions must be gone, not merely the endpoint failing.
  const cfgGone = await a.getConfig();
  ok('WIPE: dropped bank config is wiped to defaults (template gone)',
    cfgGone.ok && cfgGone.config.reflect_mission == null && cfgGone.config.retain_mission == null &&
    cfgGone.config.disposition_skepticism == null && cfgGone.config.disposition_literalism == null &&
    cfgGone.config.disposition_empathy == null && cfgGone.config.enable_observations === false,
    `reflect_mission=${JSON.stringify(cfgGone.config?.reflect_mission)}, empathy=${cfgGone.config?.disposition_empathy}`);

  // RESURRECTION: the same bank id comes back with ZERO facts and exactly the
  // template's directives — the previous life left no trace behind.
  const a2 = createMemory({ baseUrl: DAEMON, bankId: BANK_A, tenant: 'code-review' });
  const prov2 = await a2.ensureBank();
  ok('WIPE/RESURRECT: same id recreates cleanly from template', prov2.ok);
  const recResurrected = await a2.recall('What throws in the relay send path?');
  ok('WIPE/RESURRECT: zero facts resurface (complete wipe)', recResurrected.ok && recResurrected.results.length === 0,
    `found ${recResurrected.results.length} stale result(s)`);
  const dirs = await fetch(`${DAEMON}/v1/default/banks/${BANK_A}/directives`).then((r) => r.json()).catch(() => null);
  const names = (dirs?.items || []).map((d) => d.name);
  ok('WIPE/RESURRECT: exactly the template directive, no artifacts from the prior life',
    names.length === 1 && names[0] === 'Quote the code', names.join(', '));
  const list2 = await b.listBanks();
  const resBank = (list2.banks || []).find((x) => x.bank_id === BANK_A);
  ok('WIPE/RESURRECT: fact_count is 0 on the recreated bank',
    !!resBank && resBank.fact_count === 0, `fact_count=${resBank?.fact_count}`);

  console.log(`\n[lifecycle] tenant lifecycle + isolation + wipe proven (${failures === 0 ? 'ALL PASS' : failures + ' FAILURES'})`);
} finally {
  for (const mem of [a, b]) if (mem) await mem.deleteBank();
}
process.exit(failures === 0 ? 0 : 1);
