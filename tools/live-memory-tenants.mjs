// tools/live-memory-tenants.mjs
// Live prototype of the bank-per-tenant setup wired into src/memory.js:
// each tenant gets its own isolated Hindsight bank, provisioned from a
// reusable TEMPLATE (missions + dispositions + directives) and verified live.
//
// Prereq: a Hindsight daemon on 127.0.0.1:8877 (see tools/live-memory-demo.mjs
// for the exact uvx profile/env commands).
//
// Usage:
//   node tools/live-memory-tenants.mjs
//
// Exit 0 = bank-per-tenant with templates is proven end-to-end. The three
// prototype banks are deleted at the end (DELETE exists and is exercised).

import { createMemory, TENANT_TEMPLATES } from '../src/memory.js';

const DAEMON = 'http://127.0.0.1:8877';
let failures = 0;
const ok = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

const h = await fetch(`${DAEMON}/health`).then((r) => r.json()).catch(() => null);
ok('hindsight daemon reachable on 127.0.0.1:8877', !!(h && h.status === 'healthy'));

const tenants = [
  { id: 'tenant-alice', tenant: 'personal-assistant', fact: 'Alice prefers dark mode and a hardware wallet.', probe: 'What does Alice prefer?' },
  { id: 'tenant-bob', tenant: 'code-review', fact: 'Bob blocked on an unhandled rejection in the relay send path.', probe: 'What blockers did Bob hit?' },
  { id: 'tenant-carol', tenant: 'support', fact: 'Carol reported a 500 on vault import; clearing the cache fixed it.', probe: 'What fixed Carol issue?' },
];

const clients = [];
try {
  for (const t of tenants) {
    const mem = createMemory({ baseUrl: DAEMON, bankId: t.id, tenant: t.tenant });
    clients.push(mem);
    ok(`template resolved for '${t.tenant}'`, !!mem.template, mem.template ? `dispositions ${mem.template.bank.disposition_skepticism}/${mem.template.bank.disposition_literalism}/${mem.template.bank.disposition_empathy}` : 'none');
    const prov = await mem.ensureBank();
    ok(`provisioned bank '${t.id}' from template`, prov.ok && prov.templateApplied === true,
      prov.templateApplied ? `config_applied=${prov.result?.config_applied}, directives_created=${(prov.result?.directives_created || []).length}` : prov.error || '');
  }

  // Verify each bank's config carries the template's mission + dispositions.
  for (const t of tenants) {
    const mem = clients.find((c) => c.bankId === t.id);
    const cfg = await mem.getConfig();
    const c = cfg.config || {};
    const tpl = TENANT_TEMPLATES[t.tenant].bank;
    ok(`'${t.id}' reflect_mission applied`, cfg.ok && c.reflect_mission === tpl.reflect_mission);
    ok(`'${t.id}' dispositions applied (${tpl.disposition_skepticism}/${tpl.disposition_literalism}/${tpl.disposition_empathy})`,
      cfg.ok && c.disposition_skepticism === tpl.disposition_skepticism &&
      c.disposition_literalism === tpl.disposition_literalism &&
      c.disposition_empathy === tpl.disposition_empathy);
  }

  // Template directives landed in each bank (import carries them).
  for (const t of tenants) {
    const dirs = await fetch(`${DAEMON}/v1/default/banks/${t.id}/directives`).then((r) => r.json()).catch(() => null);
    const names = (dirs?.items || []).map((d) => d.name);
    ok(`'${t.id}' template directive applied`, names.includes(TENANT_TEMPLATES[t.tenant].directives[0].name), names.join(', '));
  }

  // Tenant isolation: retain each tenant's fact, then prove recall never
  // crosses bank boundaries (Bob's facts never surface in Alice's bank).
  for (const t of tenants) {
    const mem = clients.find((c) => c.bankId === t.id);
    const r = await mem.retain(t.fact, { wait: true });
    ok(`'${t.id}' retained its own fact`, r.ok);
  }
  for (const t of tenants) {
    const mem = clients.find((c) => c.bankId === t.id);
    const rec = await mem.recall(t.probe);
    ok(`'${t.id}' recall returns its own fact`, rec.ok && rec.results.some((x) => x.text.includes(t.fact.slice(0, 20))));
    for (const other of tenants) {
      if (other.id === t.id) continue;
      ok(`'${t.id}' isolation: no '${other.id}' facts leaked in`,
        !rec.results.some((x) => x.text.includes(other.fact.slice(0, 20))));
    }
  }

  // Explicit template overrides the tenant preset; updateConfig patches live.
  const override = createMemory({ baseUrl: DAEMON, bankId: 'tenant-override', tenant: 'support', template: TENANT_TEMPLATES['code-review'] });
  await override.ensureBank();
  ok('explicit template overrides tenant preset', override.template.bank.disposition_literalism === 5);
  const upd = await override.updateConfig({ reflect_mission: 'Patched mission.', disposition_empathy: 5 });
  const after = await override.getConfig();
  ok('updateConfig patches mission + disposition live',
    upd.ok && after.config.reflect_mission === 'Patched mission.' && after.config.disposition_empathy === 5);
  await override.deleteBank();

  // Inventory: listBanks sees every tenant.
  const list = await clients[0].listBanks();
  const ids = (list.banks || []).map((b) => b.bank_id);
  ok('listBanks inventories all tenant banks', tenants.every((t) => ids.includes(t.id)), ids.join(', '));

  console.log(`\n[tenants] bank-per-tenant + templates proven (${failures === 0 ? 'ALL PASS' : failures + ' FAILURES'})`);
} finally {
  for (const mem of clients) await mem.deleteBank();
}
process.exit(failures === 0 ? 0 : 1);
