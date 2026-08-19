# BlackVault-Reema — Roadmap

Consolidated findings and recommendations from the security review of the
BlackVault-Reema prototype, plus the v5 prekey-bundle and v6
key-directory overhauls. Status reflects the current state of the working tree.

**Legend:** ✅ done · 🔜 next · 🟡 later · ⚠️ operational

---

## 0. Protocol v6 — prekey bundles + one-time prekeys + key directory (done)

The structural fix is in: every peer publishes a **self-signed prekey bundle**
`{ staticDhPk, signPk, signedDhPk, kemPk, signature }` plus a **one-time
prekey pool**, registered with the relay under a **bound routing address**
`BLAKE2b(signPk || dhPk)` with proof-of-possession. Sessions are established
from the *verified* bundle, and the sender mixes one consumed one-time prekey
into the root (X3DH `DH3`).

- **Post-quantum bootstrap.** The root key is hybrid from the start
  (`BLAKE2b(64, DH(signedDhSk, peer.signedDhPk), DH(staticSk, peer.staticPk))`,
  then mixed with the one-time-prekey shared secret), and the first message
  carries a KEM encapsulation to the peer's published `kemPk`.
- **Bootstrap forward secrecy.** Each new session consumes a fresh one-time
  prekey served by the directory, so the first message is no longer
  deterministic per identity (README Limitation 7 is closed).
- **The last initiator/responder race is closed.** Either side may send the
  first message; two peers who both send first before receiving converge (the
  bootstrap chains derive from the same initial root, which is *not* advanced
  by the first send). Verified end-to-end by `src/test.js`, `src/demo.js` and
  the headless two-context browser E2E (`src/browser-e2e.js` in `npm test`).
- **The v4 pre-reply forgery is structurally impossible.** The peer signing
  key is pinned from the verified bundle at session creation — never from a
  received message — and no key is ever derived from a null receiving chain.
- **Authenticated registration.** The relay verifies the bundle's self-signature
  and that the claimed address equals `deriveAddress(signPk, dhPk)`, so a
  hostile client cannot claim an offline user's address (README Limitation 1
  is closed).
- **Key directory removes TOFU for the bootstrap.** Address mode fetches the
  bundle + one-time prekey from the directory and re-verifies both; bundle mode
  remains for offline first contact (README Limitation 2 is closed).

Design notes and tradeoffs:

- The bootstrap root is deliberately **not** advanced by the first send
  (`_firstSend` / `_establishFirst` derive chains from the initial root only),
  so simultaneous firsts converge; the root advances on the first DH ratchet.
- In the simultaneous case exactly one side (the one with the larger static
  key — a deterministic, symmetric rule) proactively ratchets its sending key,
  so forward secrecy advances instead of pinning the conversation to the
  bootstrap ephemerals.
- First messages are replayed safely: a duplicate `first` flag on an
  established session is refused (a replayed first would otherwise re-derive
  the root from an advanced state and corrupt the session).
- **Crash recovery is closed** by the one-shot `firstBuilt` flag (persisted in
  `serialize()`/`restore()` and written *before* the send is observable) plus a
  **delivery receipt**: the receiver auto-acks the first message it establishes
  from, so a crashed sender never re-flags as `first` and its receiving chain
  is established even without a hand-typed reply (regressions in `demo.js` and
  `src/browser-e2e.js`). The only residual is a crash in the single synchronous
  persist→send gap (README Limitation 5).
- **Migration is in place:** v4 keyfiles (sign + static DH) gain fresh
  signed-prekey + ML-KEM keypairs on first load, preserving the routing
  address and signing identity; v5 identities gain an empty one-time-prekey
  pool on first load. Old sessions are dropped on version bumps (different
  ratchet roots). The browser does the same for `e2ee_identity` in
  `localStorage`.
- The shareable identity is an ~11 KB bundle (11,684 base64 chars ≈ 8.8 KB
  raw — JSON + ML-DSA signature + ML-KEM key); the 44-char bound address is the
  cheap shareable handle once the directory is available. **Measured, not
  guessed:** `src/doc-consistency.js` (part of `npm test`) recomputes the
  bundle size and fails if this figure drifts.

---

## 1. Confirmed vulnerabilities (all reproduced, now fixed)

| # | Severity | Finding | Root cause | Fix (in tree) |
|---|---|---|---|---|
| 1 | **CRITICAL** | Pre-reply message forgery + permanent lockout | An initiator awaiting its first reply has `CKr === null`; `KDF_CK(null)` is a **public constant**, so anyone knowing both public keys could forge a message the initiator accepts and poison the TOFU pin, locking out the real peer. | ✅ Structurally fixed in v5: the pin comes from the verified prekey bundle at session creation, and no key is derived from a null chain (regressions in `demo.js`, `fuzz.js`, `poc-null-ckr-initiator.mjs`). |
| 2 | **HIGH** | Static server crashes on one malformed URL | `tools/serve.mjs` calls `decodeURIComponent(...)` in an async handler with no guard; `GET /%` throws → unhandled rejection → process exit. | ✅ Request handler is exception-safe; malformed URLs return 400. |
| 3 | **HIGH** | Unauthenticated session flood | Relay accepts any envelope with a non-empty `ciphertext`; clients allocate a full `Session` (ML-KEM keygen) per unknown sender before decrypting and never evict. | ✅ Relay structurally validates envelopes; both clients run a cheap self-consistency gate before allocation, require a coherent bundle for first contact, and evict never-delivered sessions. |
| 4 | **MEDIUM** | Relay `online` map leak + mis-delivery | `register` never releases a connection's previous address; `dropClient` only deletes the latest pk → stale routes, blocked owners, unbounded growth. | ✅ `register` releases the previous address before taking the new one. |
| 5 | **MEDIUM** | Browser double-initiator deadlock | `openSession()` eagerly created an initiator session; two peers who both open each other's share links both became initiators and could never decrypt. | ✅ Removed at the root in v5: there is no initiator role; sessions are created on first send or first receive from a bundle. |

**Verification:** `npm run demo`, `npm test` (integration + fuzzer + browser
E2E),
`scratch/validate-v5-core.mjs`, `scratch/browser-e2e-v5.mjs` (two-context
browser E2E through the real relay), `scratch/verify-relay-v5.mjs`,
`scratch/poc-null-ckr-initiator.mjs` (both attacks REJECTED),
`scratch/serve-crash-poc.mjs` (server survives), `scratch/poc-online-leak.mjs`
(`online` stays flat), `scratch/poc-session-flood.mjs` (0 allocations).

---

## 2. Architectural change (done)

**One crypto implementation, not two.** `src/crypto.js` and
`public/browser-crypto.js` were ~90% duplicated security-critical code (the
reason bug #1 existed twice, and error strings had already drifted).

- `public/crypto-core.js` — the whole protocol (v5: Identity with 8 keypairs,
  Session, signingPayload, bundle encode/decode), environment-agnostic, with
  sodium injected via `useSodium()`. Runs in Node and the browser (import map →
  `public/vendor/`) unchanged.
- `src/crypto.js` / `public/browser-crypto.js` — thin adapters; public API
  (`init`, `Identity`, `Session`, `signingPayload`, `encodeBundle`,
  `decodeBundle`) is shared by both clients.
- Consequence: **a fix in the core is a fix in both clients.**

---

## 3. Recommendations, prioritized

### ✅ P0 — X3DH-style prekey bundles + one-time prekeys + key directory

See Section 0. The structural fix for the last initiator/responder race, the
classical-only bootstrap, and the v4 pre-reply forgery — extended in v6 with
one-time prekeys (bootstrap forward secrecy), a relay key directory (TOFU-free
address mode), and bound routing addresses with proof-of-possession
(authenticated registration). Implemented as protocol v6 with in-place
v4→v5→v6 migration.

### ✅ P1 — Session persistence

Sessions survive a restart (a reload no longer desyncs the ratchet forever).

- `Session.serialize()` / `Session.restore()` in `public/crypto-core.js`
  (round-trip asserted in `npm run demo`).
- `src/sessions.js` — encrypted-at-rest store for the CLI (crypto_secretbox,
  key derived from the identity's own static DH secret; a rotated identity
  simply fails to decrypt and sessions are dropped). Wired into `src/client.js`
  (load on start, save on send/receive/evict/close; restored sessions are
  keyed by their own `peerDhPk` so a stale map key is dropped).
- Browser: same scheme in `public/index.html` via `localStorage`
  (`e2ee_sessions`), cleared on identity rotation and on v4→v5 migration.

### ✅ P1 — Fuzz / property harness into `npm test`

`src/fuzz.js` is wired into `npm test` (see `package.json` for the exact stage
chain — `test.js`, `fuzz.js`, `browser-e2e.js`, `xss-regression.js`,
`doc-consistency.js`):

- 1500 seeded mutation iterations against a live session (bit flips, counter
  bumps, replays, attacker re-signatures), asserting no acceptance unless the
  plaintext is a known corpus message, byte-identical state after every
  rejection, and liveness throughout;
- a bootstrap pass feeding mutations to a fresh session, asserting it accepts
  nothing but the genuine first message: the v5 bootstrap forgery (foreign
  signing key) and the null-chain guard.

The byte-level differential test became moot once both clients shared one core
— which is precisely the point of the dedup. Its residual form (do the two
ENVIRONMENTS agree — libsodium-wrappers + npm @noble vs vendored libsodium +
import-mapped @noble?) is covered by the Node-vs-browser interop leg of
`src/browser-e2e.js`: a pure-Node peer and the browser peer exchange envelopes
through the relay in both directions, part of `npm test`.

### ✅ P2 — Shrink steady-state envelopes ~50%

Implemented as a v5 wire rule. Steady-state envelopes dropped from ~10.7 KB to
~5.0 KB (**53% smaller**): three fields constant within a DH ratchet epoch are
omitted and reconstructed by the receiver from a per-epoch `epochs` cache:
`senderSignPk` (pinned from the bundle), `header.pq_pk`, and `header.pq_ct`
(the per-epoch ML-KEM ciphertext, reused until the next ratchet). Every epoch's
**first** message always carries all three, populating the cache; the relay
validates them as optional-but-size-checked. The `epochs` cache also replaced
`seenDhr` for replay rejection and is persisted with the session.

Trade-off (documented in README): a message that omits the fields can only be
reconstructed after the receiver has seen the epoch's first message. The relay
is FIFO, so a genuinely malicious reordering relay is required to trigger it;
cross-epoch reordering and skip-then-recover both work via the cache (regression
tests in `demo.js`).

Not done: dropping the redundant bundle field from first messages once a key
directory exists (still open, needs a key directory first).

### ✅ P2 — Relay-side fixed-size padding

`src/server.js` pads every delivery to a fixed 12 KB bucket
(`DELIVERY_PAD_BUCKET`), so a network observer cannot read plaintext length off
the ciphertext size. Clients ignore the extra `pad` field. (Relay→client only —
the relay cannot pad what it receives; clients already pad plaintext to
256-byte blocks.)

### ✅ P2 — Automated browser E2E (headless, two contexts, in `npm test`)

`src/browser-e2e.js` is now a proper step of `npm test` (skipped gracefully
with a notice when the headless browser can't be resolved). It is
self-contained: it spawns its own relay (TCP/WS) and static server on
dedicated loopback ports, points the page at them via the `?relay=` query
param, and drives two incognito contexts through the real relay:

- full A→B→A message flow (first contact, reply, ratchet);
- the steady-state shrink: same-epoch second messages must be the small
  (~5 KB) form, epoch-first messages the large form;
- **reload both pages**: sessions restored from `localStorage`, tabs
  reactivated, and the conversation continues in both directions;
- **Node-vs-browser differential**: a pure-Node peer (TCP) and the browser
  peer (WS) exchange envelopes through the relay in both directions — the
  residual divergence risk after the single-core dedup is the two
  environments, and this leg proves they share one wire format;
- hard assertions: zero console errors, zero failed requests, PASS/FAIL exit
  code.

Findings it surfaced: (1) `page.evaluate` runs in an isolated world, so the
test drives the SEND button (the real user path) rather than calling
`window.uiSendE2EEMessage`; (2) after a reload the **active session is not
persisted**, so incoming messages decrypt but don't appear in the live feed
until the user clicks the conversation tab — a minor UX gap (messages are
safe; they render when the session is opened).

`scratch/browser-e2e-v5.mjs` remains as a manual simultaneous-first harness.

### ✅ P2 — Headless XSS regression for the Gemini render path (in `npm test`)

`src/xss-regression.js` pastes attacker-crafted text through the DISARM
analysis pipeline in a headless browser (its own static server, graceful skip
without a browser). The Gemini endpoint is stubbed at the network layer with a
hostile model response that **echoes the pasted claim** (the prompt-injection
vector) plus hostile `verdictClass` / `score` / `sourceCredibility` and
would-be executable elements (`<img onerror=alert(1)>`). It asserts that no
alert/dialog or page error fires, no `img`/`script`/`svg` element ever enters
`#analysis-result`, no raw attacker tag-opener reaches any innerHTML sink
(only escaped `&lt;` forms), and the enum/score allowlists still pass a
well-behaved response. The test also asserts key hygiene for the BYOK
credential: after saving through the real modal, nothing lives in
`localStorage`/`sessionStorage`/`window.*`, and a reload forgets the key.

### ✅ P2 — Lazy / deferral of session creation

Both clients (`src/client.js`, `public/index.html`) run a cheap
self-consistency gate before allocating a Session: the envelope must be signed
by its own `senderSignPk` (an ML-DSA verify, not an ML-KEM keygen), first
contact must carry a coherent prekey bundle, and never-delivered sessions are
evicted. The relay's structural validation blocks the junk upstream.

---

## 4. Operational notes ⚠️

- **`.identity.json` holds a live private key in plaintext** in a OneDrive-synced
  folder. The 0o600 mode is largely advisory on Windows, and OneDrive syncs the
  file to the cloud. It is gitignored, but if this copy is shared further,
  **treat the key as exposed and rotate it**. A real app should use an OS
  keychain or secure enclave.
- **Registration is authenticated** (v6): a client publishes its identity-bound
  address `BLAKE2b(signPk || dhPk)` together with its self-signed bundle; the
  relay verifies the bundle and that the address matches, so a hostile client
  cannot claim an offline user's address without their signing key.
- **Metadata is visible to the relay** (README Limitation 3): who talks to whom
  and when. Padding hides length, not timing/volume/graph; Tor hides the client
  IP from the relay, not from a global passive adversary. A mixnet is the only
  real answer (README roadmap: "Not started").
- **v4→v5→v6 migration** drops persisted sessions by design on version bumps
  (different ratchet roots) but preserves the identity keys. The CLI prints a
  notice when it migrates a v4 keyfile; v5 identities silently gain an empty
  one-time-prekey pool.

---

## 5. Verification commands

```bash
npm run demo        # two-party demo + security assertions (v6: bootstrap forgery, null-chain, serialize round-trip, crash recovery)
npm test            # integration + fuzzer + headless two-context browser E2E + XSS regression + messenger smoke + doc-consistency
node src/fuzz.js    # the fuzzer alone (seeded, reproducible)
node src/browser-e2e.js  # the browser E2E alone (spawns its own servers; skips if no browser)
node src/messenger-smoke.js  # the messenger smoke alone (A-B-A through public/messenger.html; skips if no browser)
node src/doc-consistency.js  # doc-vs-code checks: bundle size, cited files, ports, npm-test stages
node src/index.js address  # print the 44-char bound routing address
node src/index.js bundle   # print the full self-signed prekey bundle
node src/server.js  # relay (TCP 7980 / WS 8080)
node tools/serve.mjs  # static UI (http://127.0.0.1:8000, + /messenger.html)
```

Scratch harnesses (gitignored; the PoCs document the v4 bugs and now show the
v5 fixes):

- `scratch/validate-v5-core.mjs` → all core assertions, incl. simultaneous
  firsts, replay guards, persistence round-trip
- `scratch/browser-e2e-v5.mjs` → two-context browser E2E through the real relay
  (needs `npm run server` + `npm run serve` running)
- `scratch/verify-relay-v5.mjs` → real-relay v5 envelope relay + junk rejection
- `scratch/poc-null-ckr-initiator.mjs` → both v4-equivalent attacks REJECTED
  (foreign-signing-key first message; null-chain message), genuine reply works
- `scratch/poc-double-initiator.mjs` → simultaneous first messages converge
- `scratch/poc-session-flood.mjs` → junk dies at the relay and the client gate;
  0 sessions allocated (was 300 in v4)
- `scratch/poc-online-leak.mjs` → `online` stays flat across the flood
- `scratch/serve-crash-poc.mjs` → server survives `/%` (400)

The CLI writes encrypted session state to `.sessions.json` (gitignored, next to
`.identity.json`). Delete it to reset all sessions without touching keys.

---

## 6. Completion checklist — "is the encryption done?"

Each item below is tied to a proving test in the tree. The encryption layer is
**complete for a local test client** when every row is green.

| # | Capability | Proof |
|---|---|---|
| 1 | Hybrid PQ bootstrap (X25519 + ML-KEM-768) | `src/demo.js` (root/epoch assertions) |
| 2 | No initiator/responder role; simultaneous firsts converge | `src/demo.js`, `src/test.js` |
| 3 | One-time prekeys give bootstrap forward secrecy | `src/test.js` (OTK consumed + burned) |
| 4 | Key directory + bound address + proof-of-possession | `src/test.js` (publish/fetch-directory/claim-rejected) |
| 5 | Authenticated registration (no offline-address theft) | `src/test.js` |
| 6 | Double Ratchet + replay + skip window + atomic commit | `src/demo.js`, `src/fuzz.js` |
| 7 | Steady-state envelope shrink (~53%) | `src/browser-e2e.js` (size assertion) |
| 8 | Session persistence at rest (encrypted) | `src/demo.js` (serialize round-trip), `src/browser-e2e.js` (reloads) |
| 9 | Crash recovery (no duplicate-first re-flag stall) | `src/demo.js` (`firstBuilt` regression) |
| 16 | Delivery receipts (auto-ack establishes the sender's receiving chain) | `src/demo.js`, `src/browser-e2e.js` |
| 10 | Active-session auto-restore after reload | `src/browser-e2e.js` |
| 11 | Node ↔ browser interop over one wire format | `src/browser-e2e.js` (interop leg) |
| 12 | Mutation fuzzer (no forged/tampered acceptance) | `src/fuzz.js` (1500 iterations) |
| 13 | Gemini render-path XSS + key hygiene | `src/xss-regression.js` |
| 14 | Docs ↔ code drift | `src/doc-consistency.js` |
| 15 | Minimal two-party test app over the core | `src/messenger-smoke.js` (headless A→B→A, in `npm test`) |

**Remaining non-crypto items (documented, out of scope for the core):** relay
metadata (mixnet), OS-keychain storage for the CLI identity key, and the
residual encrypt→persist crash window (README Limitation 5).

---

## 7. Design — MLS group messaging (2026-08-18) 🟡

Design sketch for multi-party (group) conversations mapped onto the existing
v6 relay **without changing the client wire protocol**. Status: **design +
relay prototype + client GroupSession prototype (2026-08-18)** —
`isPlausibleEnvelope` accepts opaque `{ v: 6, mode: 'group', ciphertext }`
envelopes and a `subscribe` verb enables fan-out/queued delivery; a client-side
`GroupSession` (`public/group-core.js`) derives `groupId = BLAKE2b-32(creator ‖
label ‖ nonce)` (the same 44-char b64 shape the relay routes on), welcomes
members over existing pair sessions, encrypts under per-epoch shared keys
(XSalsa20-Poly1305, per-sender counters), and ratchets epochs via encrypted
Commit envelopes. The pair flow is byte-for-byte unchanged; `src/test.js`
covers the whole lifecycle end-to-end through the real relay (junk rejection,
fan-out, opacity, offline flush, welcome, replay/non-member rejection,
epoch ratchet, and a member joining at epoch 1).

### The core insight: the relay is already MLS's Delivery Service

The current relay is a ciphertext-only, store-and-forward key directory —
precisely MLS's **Delivery Service (DS) + Authentication Service (AS)**
combined. Its verbs map 1:1:

| Current v6 primitive | MLS (RFC 9420) equivalent |
|---|---|
| `publish {address, bundle, oneTimePrekeys}` | Publish a signed `KeyPackage` to the DS/AS |
| `fetch-directory {address}` → bundle + one OTK | Fetch a member's `KeyPackage` to Add them |
| `send {toPk, envelope, fromPk}` | `PrivateMessage` / `Welcome` / `Commit` addressed by `group_id` |
| routing `address` — `BLAKE2b-32(signPk \|\| staticDhPk)`, 44-char b64 | `group_id` — any 32-byte value, **same 44-char b64 shape** |
| `envelope` (opaque to the relay) | MLS message (opaque to the relay) |
| OTK pool (consumed server-side on fetch) | `KeyPackage.init_key` (single-use HPKE) |
| `online` / `inbox` maps | DS presence + store-and-forward queues |

The decisive point: **`group_id` is structurally identical to today's routing
address** — an opaque base64 blob used only as a `Map` key. The relay needs
**zero new routing logic**; a group is "just another address" from its
perspective.

### What stays byte-for-byte (no wire change)

- Newline TCP + WebSocket framing, and all four verb names (`publish`,
  `fetch-directory`, `send`, `ping`).
- The `online`, `inbox`, `directory` maps and their queue/sweep behavior.
- Authenticated registration: the self-signed-bundle proof-of-possession check
  becomes the KeyPackage signature check (same identity-pinning idea).

### What changes client-side (the relay never sees it)

1. **KeyPackage replaces the prekey bundle for group adds.** Today's
   self-signed bundle is already ~80% of a KeyPackage — it carries the
   credential (ML-DSA-65 `signPk`), the static/init DH keys (`staticDhPk`,
   `signedDhPk`), and a self-signature. Add MLS's `init_key` (an ephemeral
   HPKE public key), `cipher_suite`, and leaf extensions, published under the
   same authenticated address.
2. **`group_id` derivation.** `group_id = BLAKE2b-32(creator_address ||
   group_label || nonce)` — 32 bytes, so it reuses the existing 44-char shape
   the relay already treats as opaque.
3. **Group lifecycle (all client-side):**
   - **Create** — the creator `fetch-directory`s each invitee's KeyPackage,
     builds a ratchet tree, and emits one `Commit` (to the group) plus one
     `Welcome` per member (HPKE-encrypted to their `init_key`).
   - **Add** — any member proposes `Add`; the committer sends `Commit` +
     `Welcome`. The Welcome to the new member is a normal `send` to *their*
     address.
   - **Send** — an application message is `send {toPk: group_id, envelope:
     mls_private_message}`.
   - **Remove / leave** — a `Remove` proposal + `Commit`; every remaining
     member advances the epoch and wipes the old epoch secrets.
   - **One-time prekey exhaustion** — each Add consumes one KeyPackage; the
     relay's existing consume-on-fetch behavior already matches MLS's "one
     KeyPackage per Add" rule, and clients must replenish their published OTK
     pool as it drains.

### Security properties (what MLS buys, at what cost)

- **Post-compromise security** — removing a member and ratcheting the tree
  wipes old epoch secrets, so a leaked leaf key does not decrypt past or
  future traffic after the next Commit.
- **Sender authenticity** — application messages are signed by the sender's
  leaf; membership changes are `Commit`-authenticated.
- **The relay's exposure is unchanged** — it still sees only ciphertext,
  addresses/group_ids, and timing; group membership and plaintext stay
  client-side.

### Open decisions before implementation

1. **Which MLS library** — `openmls/openmls` or `awslabs/mls-rs` (both Rust →
   WASM for the browser), vs. hand-rolling (not recommended — MLS is subtle;
   the ratchet-tree machinery and validation rules are beyond what
   `crypto-core.js` hand-derives today).
2. **Where the ratchet tree lives** — client-side `localStorage`/disk,
   encrypted by the identity key like `sessions.js` does today.
3. **Welcome transport** — the prototype rides a normal `send` to the new
   member's address inside an existing pair-session envelope (no new verb); a
   dedicated `welcome` verb remains the alternative.
