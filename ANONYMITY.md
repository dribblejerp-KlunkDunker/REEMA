# ANONYMITY — threat model, honest scorecard, and build order

**Status:** decisions made 2026-08-19. This document is the authority for what
"anonymity" means in this project and the order in which we build toward it.

**The one rule.** Anonymity tooling that overclaims is more dangerous than no
tooling at all: it makes people take risks they would not otherwise take. Every
feature below ships with a test that proves what it *does* hide, and this
document states what it *does not*. Nothing may ever claim more than it proves.

---

## 1. The adversary we are defending against

"Best for anonymity" has no meaning without naming the observer. We design
against the strongest realistic adversary, because a weaker one is then covered
for free:

| # | Adversary | What it can do |
|---|---|---|
| A | **Passive network observer** | Watch all traffic between clients and the relay (timing, sizes, IPs). |
| B | **Active network observer** | Also block, replay, and inject traffic (censorship, MITM). |
| C | **Coercible / compromised relay** | Read everything the relay sees, be seized or subpoenaed, and log metadata. |
| D | **Malicious peer** | Join a group, send hostile traffic, try to learn other members' identities. |
| E | **Compromised endpoint** | Read plaintext *before* encryption, keylog, screenshot. |

The design must make **A, B, C, D** learn as little as possible *by
construction*. **E is out of scope for any messenger** — it is an OPSEC/OS
problem, and we say so in §6 rather than pretending otherwise.

---

## 2. Where the code actually is today (honest scorecard)

**Protected (content):** post-quantum hybrid E2EE (ML-KEM-768 + X25519,
ML-DSA-65 signatures, Double Ratchet forward secrecy), a ciphertext-only relay
that never sees plaintext, and a serious test/fuzz/interop suite.

**Leaking (metadata) — this is the gap that matters:**

- **The relay no longer logs every recipient** — the per-message
  `relaying ciphertext to <address>` line was removed 2026-08-19 and replaced
  with an aggregate counter (ANONYMITY.md §3.6). **Sealed sender built
  2026-08-19**: `fromPk` is gone from the wire (the relay routes by `toPk` and
  an opaque per-session `deliveryToken`), so the relay can no longer read the
  sender's address off a `send`. It can still correlate senders via the static
  `senderDhPk`/`senderSignPk` the Double Ratchet needs in plaintext — hiding
  those (an encrypted sender header) is the next hardening, not yet built.
- **`fetch-shard` is now the only lookup**: the relay serves a WHOLE shard
  (k-anonymity = shard population), so it cannot answer "who looked up whom" —
  but a fetch followed by an immediate `send {toPk}` is still
  timing-correlated (needs cover traffic/mixing).
- **`subscribe` reveals group membership**: the relay knows who belongs to which
  `group_id` and when they join/leave.
- **The relay is a single, centralized, coercible process.** One seizure or
  subpoena yields the entire graph.
- **Browser transport anonymity is opt-in via a Tor shell, not in-page.** A
  page cannot do per-connection SOCKS, so the browser equivalent of the CLI's
  Tor path is `tools/messenger-tor.mjs`: it launches Chromium with its proxy
  set to the local Tor SOCKS5 listener and requires a REMOTE `wss://` relay
  (fails closed — refuses to start without Tor). The browser still cannot
  TOFU-pin a raw WebSocket's certificate, so a self-signed remote relay is
  refused rather than silently trusted. A directly-opened browser tab still
  exposes its IP.
- **The client↔relay link was plaintext** (TCP/WS, no TLS). **TLS is default-on
  since 2026-08-19** (committed dev cert, `TLS_OFF=1` opts out, fingerprint-pinned
  and fails closed — `src/tls.js`, `src/tls-regression.js`; `src/test-tls.js` pins
  the dev cert across the whole test harness). Plaintext is now the explicit
  opt-out, not the default.
- **No cover traffic** — message timing/sizes correlate senders to recipients
  even through Tor. The relay-side mixing added 2026-08-19 (`MIX_WINDOW_MS`)
  only breaks timing when several messages share a window; its anonymity set is
  usually **1**. It is defense-in-depth, *not* anonymity.

**Conclusion:** content is strong; anonymity is essentially absent. The relay
is one seizeable box that already holds the social graph.

---

## 3. Design principles (non-negotiable)

1. **The relay is untrusted and learns nothing.** It must not be *able* to see
   sender, recipient, or group membership — not merely be *told* not to look.
2. **Fails closed.** An anonymity control that silently degrades is worse than
   absent: it creates false belief. If a control is unavailable, refuse to send,
   never quietly downgrade.
3. **No silent downgrade, ever.** Every fallback must be explicit and loud.
4. **k-anonymity is the unit of truth.** Every claim is stated as "hidden among
   k others," never as "anonymous."
5. **One observer is one too many.** Metadata must not concentrate in any single
   party that can be seized.
6. **Minimize at the source, retain nothing.** Metadata an observer has already
   recorded cannot be "destroyed", "vaulted for destruction", or poisoned — the
   adversary's copy is not yours to erase. The only real defences are: never
   emit it (sealed sender, private directory), never persist it (the relay is
   memory-only and deletes on delivery), and never log it (aggregate counters
   only). The "encrypted vault" pattern is correct for *your own* sensitive data
   (identity, sessions — already age-encrypted), not for an adversary's copy of
   your metadata.

   **Built 2026-08-19:** the relay is memory-only; `QUEUE_TTL_MS` (env) is the
   "metadata timer" — undelivered messages self-destruct after it — and
   per-identity log lines are OFF by default (`RELAY_VERBOSE=1` re-enables for
   debugging). Proven by `src/retention-regression.js`. `RELAY_EPHEMERAL=1`
   goes further: store-and-forward is disabled entirely, so an undelivered
   message is never written in the first place (dropped at acceptance) — proven
   by `src/ephemeral-regression.js`.

---

## 4. The build order (decided)

### Phase 1 — Kill the graph: sealed sender + private directory lookup
*The highest-leverage, most testable increment. This is why we start here, not
with Tor: Tor hides IPs, but the relay already knows the graph — so Tor alone
would pay the latency and still leave the core leak untouched.*

**Sealed sender built 2026-08-19** (`DESIGN-sealed-sender.md`,
`src/sealed-sender-regression.js`): `fromPk` is dropped from the wire, the
envelope carries an opaque per-session delivery token (derived from the
bootstrap DH secrets, so it is identical on both sides), and an instrumented
relay proves its own logs can no longer reconstruct who sent. **Private
directory lookup built 2026-08-19** (`src/private-directory-regression.js`):
`fetch-directory` is replaced by `fetch-shard` (whole-shard fetch), and the
instrumented relay's verbose log records the shard, never the address. **Phase 1
is now complete.**

- **Sealed sender** (Signal's property): the relay cannot learn who sent a
  message. The envelope is authenticated end-to-end in a way the relay cannot
  read; the relay only sees a ciphertext and a delivery address it cannot link
  to a sender identity.
- **Private directory lookup** (built): `fetch-directory` became `fetch-shard` —
  the requester names a shard (the first byte of the address), the relay serves
  every entry in it, and the requester selects the target client-side from the
  self-signed bundles. The relay's own log can only record "served shard #k".
  One honest tradeoff: the relay no longer consumes prekeys server-side (it
  cannot know which entry was wanted), so single-use is enforced recipient-side
  — the recipient burns the prekey on first receive, and deterministic
  per-sender selection keeps two distinct senders from colliding on the same
  prekey.
- **Acceptance:** a test where the relay is instrumented to record everything it
  can see, and proves it cannot reconstruct who sent a message or who looked up
  whom — even from its own logs.

### Phase 2 — Transport anonymity + cover traffic
**Built 2026-08-19 (three increments):**
1. **TLS on the link** — the relay serves TLS on TCP + WSS **by default**
   (committed dev cert; `TLS_CERT`/`TLS_KEY` override, `TLS_OFF=1` opts out, and
   a missing keypair refuses to start). The client pins the cert's SHA-256
   fingerprint and fails closed on mismatch (`src/tls.js`,
   `src/tls-regression.js` proves the wire is encrypted and a wrong pin refuses;
   `src/test-tls.js` pins the dev cert across the harness).
2. **Cover traffic** — the relay DISCARDS `mode:'cover'` frames (never queued or
   delivered, `src/cover-regression.js`), the CLI emits a cadence (`--cover`,
   `src/cover.js`), and cover/real frames of equal payload serialize to equal
   length.
3. **Browser Tor shell** — `tools/messenger-tor.mjs` launches the browser with
   its proxy set to the local Tor SOCKS5 listener and requires a REMOTE
   `wss://` relay, failing closed when Tor is unreachable or the relay is
   loopback/plaintext. Proven by `src/browser-tor-regression.js`: a mock SOCKS5
   proxy stands in for Tor, the relay is reachable ONLY through it, and the
   browser's WebSocket is shown to traverse the proxy (CONNECT recorded) while a
   full A→B→A conversation still delivers. `resolveTorProxy()` throws when Tor
   is down.

Remaining: constant-rate cover traffic, the bundled/pinned Tor daemon, and
obfs4 bridges are not yet done. (TLS is now default-on for the relay; the
browser messenger cannot fingerprint-pin a raw WebSocket, so it relies on
standard CA validation for a remote relay — a self-signed relay is refused, as
stated in §2.)

- Bundle a **pinned, signature-verified** Tor daemon for the desktop shell (no
  runtime download of an unverifiable binary), route all traffic through
  `src/tor.js`'s SOCKS5 path, fails closed, with **obfs4 bridges** so censored
  networks still work.
- Add **constant-rate cover traffic** (dummy messages on a fixed cadence,
  relay-discarded) so timing/size correlation dies even at low traffic. This is
  what makes the latency actually *buy* anonymity.
- **Acceptance:** no packet leaves the device except through Tor (asserted);
  an observer correlating entry/exit timing cannot distinguish real from cover
  traffic.

### Phase 3 — Remove the single trusted relay
- Federate or threshold-split the directory + relay so no one operator holds the
  whole graph. This is the fix for "one seizure = everything."
- **Acceptance:** any single operator's data is insufficient to reconstruct a
  contact between two users.

### Phase 4 — Private groups
- Group membership, roster changes, and join/leave are themselves metadata.
  Sender keys or MLS over the Phase 1–3 substrate, with membership hiding.
- **Acceptance:** the relay cannot tell which members belong to a group, only
  that *some* opaque group traffic exists.

### Phase 5 — Trustworthiness and the endpoint
- Reproducible builds, an **independent third-party audit**, and formal
  verification of the crypto core (our own tests are engineering, not audit).
- Disappearing messages + secure deletion guidance, and an explicit OPSEC
  section in the app (see §6).

---

## 5. What each phase does *not* buy (state in the UI)

- Phase 1 hides *who talks to whom* from the relay; it does **not** hide IPs
  (still Phase 2) or timing.
- Phase 2 hides IPs and timing correlation; it does **not** remove the relay as
  a single seizeable observer (Phase 3).
- Phases 1–4 together do **not** protect against a **compromised endpoint** (E),
  a **malicious group member**, or **correlation with the physical world** (who
  meets whom, where, when).
- None of it protects against the **weakest member's OPSEC**. A group is only as
  anonymous as its least careful member.

---

## 6. What no messenger can protect against (be honest with users)

1. A **compromised device** reads plaintext before encryption. No protocol fixes
   this — only device hygiene does.
2. **Legal compulsion and physical seizure.** Technology delays; it does not
   remove the physical world.
3. **One member who leaks, is arrested, or has poor OPSEC.**
4. **Traffic correlation with real life**: meeting in person, location data,
   payment records, a SIM card. The strongest cryptography in history cannot
   un-correlate that.

The app must surface this — not bury it — so a user never mistakes "the relay
can't see my graph" for "I cannot be identified."
