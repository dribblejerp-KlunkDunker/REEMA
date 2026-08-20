# Design — sealed sender + private directory lookup (ANONYMITY.md Phase 1)

**Status:** both halves implemented 2026-08-19. Sealed sender (`src/server.js`,
`src/client.js`, `public/crypto-core.js`; proven by
`src/sealed-sender-regression.js`) and private directory lookup
(`src/server.js` `fetch-shard`, `public/crypto-core.js` `directoryShard` /
`selectOneTimePrekey`; proven by `src/private-directory-regression.js`). Grounded
in the real `src/server.js` protocol v6.

## The goal, stated as a test

The relay is untrusted (adversary C). After this work, a test instruments the
relay to record **everything its own code path observes**, and proves it cannot
answer two questions:

1. **Who sent a message?** (sealed sender)
2. **Who looked up whom?** (private directory lookup)

If the relay's own logs can answer either, the test fails.

## What leaks today (grounded in src/server.js)

| Leak | Mechanism | What the relay learns |
|---|---|---|
| Sender identity | `send` carries `fromPk` in the clear (`msg.fromPk`) and the relay echoes it into `message` deliveries | sender address for every message |
| Recipient identity | `toPk` is the routing key the relay must read to route | recipient address for every message |
| Social graph | `fetch-directory` asks for one address | "requester R is about to talk to X" |
| Group membership | `subscribe` binds a connection to a `group_id` | who belongs to which group |
| Every IP | the client↔relay link is **plaintext TCP/WS** | a network observer reads all of the above directly |

## Sealed sender

**The property:** the relay can route a message to its recipient without ever
learning the sender's identity.

**Design.** The relay does not need `fromPk` to do its job — it only needs a
delivery address and an opaque ciphertext. So:

1. **Remove `fromPk` from the wire.** The `send` verb becomes
   `{ type:'send', toPk, envelope }` only. The relay forwards the envelope and
   a per-session opaque **delivery token**, never a sender identity.
2. **The sender's identity moves inside the sealed envelope**, which is already
   end-to-end authenticated by the Double Ratchet — the recipient learns and
   verifies the sender during `Session.decrypt`, not from a plaintext field.
3. **Session lookup without a plaintext sender**: the recipient must know which
   session to try. Add a per-session **delivery token** (a random 32-byte id
   negotiated when the session is established, stored client-side). The
   recipient maps token → session. Tokens are unlinkable to the sender's
   address and rotated per session, so the relay cannot accumulate a sender
   graph from tokens.

**Replay/abuse guard:** the relay still needs a cheap way to reject a hostile
client flooding arbitrary recipients. A per-sender **rate-limit token** (a
short-lived, blinded capability the relay can count but not link to an identity)
preserves the anti-flood property without re-introducing identity.

**Honest limit (state it):** sealed sender hides the **sender** from the relay;
it does **not** hide the **recipient** (`toPk` is the routing key) and does not
hide anything from a **network observer**, because the link is plaintext. Those
are the TLS step and the "no single relay" phase respectively.

**Built 2026-08-19, with one deliberate refinement:** the token is *derived*
(`BLAKE2b-32(domain ‖ static_ss ‖ signed_ss ‖ otk_ss)`) rather than "a random
id negotiated" — derivation makes it identical on both sides with no extra
round trip, which the no-initiator/responder + offline-queueing model requires.
It still rotates per session (the one-time prekey is mixed in) and is unlinkable
to the sender's address. Two remaining limits are stated rather than papered
over: (1) the token is NOT covered by the envelope signature (a relay could swap
it to force a drop, never a wrong-session decrypt), and (2) `senderDhPk` /
`senderSignPk` stay in the envelope plaintext because the Double Ratchet needs
them — so a determined relay can still correlate senders by static key until the
encrypted-sender-header work lands.

## Private directory lookup

**The property:** a requester can obtain a peer's bundle + one-time prekey
without the relay learning *which* entry was requested.

**Design.** `fetch-directory` currently reveals the exact address. Replace it
with **directory sharding + whole-shard fetch**:

1. The directory is split into **shards** by a fixed hash prefix of the address.
2. A requester fetches the **entire shard** containing the target address — the
   relay sees "fetched shard #k", never "fetched address X".
3. **k-anonymity = shard size**: the requester is hidden among everyone else in
   the shard. Shard size is a dial, not a fixed constant.
4. Client-side, the requester selects the target bundle from the downloaded
   shard (the shard is authenticated — bundles are self-signed, so a tampering
   relay cannot forge one without detection).

**Why sharding and not single-server PIR first:** true single-server keyword-PIR
either costs several rounds and bandwidth proportional to the whole directory,
or needs multiple non-colluding servers (which is the Phase 3 federation work).
Sharding is the honest, deployable first step; it degrades gracefully (a small
directory has weak k-anonymity, which is stated), and it is replaced by PIR or
a threshold directory in Phase 3.

**Built 2026-08-19, with one deliberate refinement.** The design did not specify
how the one-time prekey survives whole-shard fetch. Since the relay cannot know
WHICH entry a requester wanted, it can no longer consume the prekey
server-side; instead (1) the shard serves each entry's full prekey pool, (2)
the sender selects one deterministically per (sender, recipient) —
`selectOneTimePrekey` hashes the pair so two distinct senders derive distinct
prekeys — and (3) the recipient burns the prekey on first receive and
republishes its smaller pool. Single-use is therefore enforced client-side; the
only residual is pool exhaustion when more distinct senders contact one
recipient than it has prekeys, which is a liveness retry, not a confidentiality
break. The acceptance test asserts all four legs (shard granularity in the
instrumented relay's log, delivery, tamper detection, recipient-side burn).

**Honest limit:** k-anonymity equals the shard population, not "anonymous."
A requester who fetches one shard and immediately messages one address within it
is still correlated by timing — which is why this pairs with Phase 2 cover
traffic and mixing, not in isolation.

## Acceptance tests

1. **Relay-recorded-observation test**: run the full send/fetch flow with an
   instrumented relay that logs every field it reads. Assert the log contains
   no sender identity for a `send`, and no "requester → address" pair for a
   `fetch-directory`.
2. **Delivery test**: a sealed message still decrypts and verifies the sender
   end-to-end (the security property is not weakened).
3. **Abuse test**: a hostile client flooding a recipient is rate-limited without
   the relay learning the sender's address.
4. **Tamper test**: a relay that swaps a shard entry is detected (bundle
   self-signature fails).

## What this buys and does not buy

- **Buys:** the relay can no longer build the *sender* graph or the *lookup*
  graph from its own logs.
- **Does not buy:** recipient identity from the relay, anything from a network
  observer (needs TLS), or sender/recipient hiding from a relay that is also a
  global passive observer (needs Phase 2 cover traffic + Phase 3 no-single-relay).
