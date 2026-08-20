// tools/live-memory-session-tags.mjs
// Per-session tag scheme INSIDE a tenant bank — design + verification.
//
// Scheme (see src/memory.js): one tenant bank holds memories from every
// conversation; each memory carries exactly two scope tags:
//   session:<sha256(peerAddress) hex, first 12>   (sessionTag())
//   direction:sent|received
// Session-scoped recall uses tags_match 'all_strict' (AND-match, excludes
// untagged), so a memory from another session — or an untagged one — can
// never surface. This harness verifies that invariant live against the daemon.
//
// Prereq: a Hindsight daemon on 127.0.0.1:8877 (see tools/live-memory-demo.mjs
// for the exact uvx profile/env commands).
//
// Usage:
//   node tools/live-memory-session-tags.mjs
//
// Exit 0 = per-session isolation under all_strict is proven. The test bank is
// deleted even on failure (finally).

import { createMemory, sessionTag } from '../src/memory.js';

const DAEMON = 'http://127.0.0.1:8877';
const BANK = 'session-tags';
let failures = 0;
const ok = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

const h = await fetch(`${DAEMON}/health`).then((r) => r.json()).catch(() => null);
ok('hindsight daemon reachable on 127.0.0.1:8877', !!(h && h.status === 'healthy'));

// Synthetic but realistic peer addresses (44-char base64, like real routing
// addresses) — the tag derivation must be per-peer deterministic.
const ADDR_A = 'A'.repeat(44);
const ADDR_B = 'B'.repeat(44);
const TAG_A = sessionTag(ADDR_A);
const TAG_B = sessionTag(ADDR_B);
ok('session tags are derived (deterministic, short, no base64 specials)',
  TAG_A !== TAG_B && /^session:[0-9a-f]{12}$/.test(TAG_A) && /^session:[0-9a-f]{12}$/.test(TAG_B),
  `${TAG_A} / ${TAG_B}`);

const mem = createMemory({ baseUrl: DAEMON, bankId: BANK, tenant: 'support' });
try {
  const prov = await mem.ensureBank();
  ok('tenant bank provisioned from template', prov.ok && prov.templateApplied === true);

  // ---- POPULATE: two sessions + an untagged memory in ONE tenant bank ----
  const A1 = 'A: Alice prefers dark mode.';
  const A2 = 'A: Alice keeps her seed phrase in a hardware wallet.';
  const B1 = 'B: Bob prefers light mode.';
  const U = 'untagged note with no session.';
  ok('retain A1 (session A, sent)', (await mem.retain(A1, { tags: [TAG_A, 'direction:sent'], wait: true })).ok);
  ok('retain A2 (session A, received)', (await mem.retain(A2, { tags: [TAG_A, 'direction:received'], wait: true })).ok);
  ok('retain B1 (session B, sent)', (await mem.retain(B1, { tags: [TAG_B, 'direction:sent'], wait: true })).ok);
  ok('retain untagged', (await mem.retain(U, { tags: [], wait: true })).ok);

  // ---- all_strict: session-scoped recall cannot cross sessions ----
  const inResults = (r, needle) => r.results.some((x) => x.text.includes(needle));

  const ra = await mem.recall('preferences', { tags: [TAG_A], tagsMatch: 'all_strict', limit: 10 });
  ok('all_strict [session A] returns both A memories', inResults(ra, 'dark mode') && inResults(ra, 'hardware wallet'));
  ok('all_strict [session A] excludes session B', !inResults(ra, 'light mode'), ra.results.map((x) => x.text.slice(0, 16)).join(', '));
  ok('all_strict [session A] excludes untagged', !inResults(ra, 'untagged note'));

  const rb = await mem.recall('preferences', { tags: [TAG_B], tagsMatch: 'all_strict', limit: 10 });
  ok('all_strict [session B] returns B only', inResults(rb, 'light mode') && !inResults(rb, 'dark mode') && !inResults(rb, 'untagged note'));

  // Finer granularity: direction tags within the session.
  const rsent = await mem.recall('preferences', { tags: [TAG_A, 'direction:sent'], tagsMatch: 'all_strict', limit: 10 });
  ok('all_strict [session A, direction:sent] = A1 only',
    inResults(rsent, 'dark mode') && !inResults(rsent, 'hardware wallet') && !inResults(rsent, 'light mode'));
  const rrecv = await mem.recall('preferences', { tags: [TAG_A, 'direction:received'], tagsMatch: 'all_strict', limit: 10 });
  ok('all_strict [session A, direction:received] = A2 only',
    inResults(rrecv, 'hardware wallet') && !inResults(rrecv, 'dark mode'));

  // The strongest cross-session probe: query semantically ABOUT session B while
  // scoped to session A — all_strict must still return nothing.
  const cross = await mem.recall('What does Bob prefer, light or dark?', { tags: [TAG_A], tagsMatch: 'all_strict', limit: 10 });
  ok('all_strict [session A] cannot reach B even when the query is about B',
    cross.results.length === 0 || !inResults(cross, 'light mode'),
    `results=${cross.results.length}`);

  // Contrast: 'any' (OR, includes untagged) — proves all_strict is what enforces
  // the boundary, and that the scheme is a deliberate choice, not accidental.
  const loose = await mem.recall('preferences', { tags: [TAG_A], tagsMatch: 'any', limit: 10 });
  ok('contrast: tags_match "any" with [session A] includes untagged (all_strict is the enforcement)',
    inResults(loose, 'untagged note'));

  // Tag vocabulary is controlled and countable (GET /tags inventory).
  const tags = await fetch(`${DAEMON}/v1/default/banks/${BANK}/tags`).then((r) => r.json()).catch(() => null);
  const counts = Object.fromEntries((tags?.items || []).map((t) => [t.tag, t.count]));
  ok('tag inventory holds exactly the controlled vocabulary',
    counts[TAG_A] === 2 && counts[TAG_B] === 1 &&
    counts['direction:sent'] === 2 && counts['direction:received'] === 1,
    JSON.stringify(counts));

  console.log(`\n[tags] per-session all_strict isolation proven (${failures === 0 ? 'ALL PASS' : failures + ' FAILURES'})`);
} finally {
  await mem.deleteBank();
}
process.exit(failures === 0 ? 0 : 1);
