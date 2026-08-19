# BlackVault-Reema — Post-Quantum E2EE Messaging Prototype

[![CI](https://github.com/dribblejerp-KlunkDunker/REEMA/actions/workflows/ci.yml/badge.svg)](https://github.com/dribblejerp-KlunkDunker/REEMA/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

BlackVault-Reema is a self-contained, post-quantum end-to-end encrypted
messaging prototype: a hybrid Double Ratchet (X25519 + ML-KEM-768 with
ML-DSA-65 signatures), X3DH-style prekey bundles and a one-time-prekey key
directory, a ciphertext-only relay, and interoperating Node CLI and browser
clients — hardened by a mutation fuzzer, a real-relay integration suite, and
headless browser E2E tests.

> **What this proves:** the relay can *only ever see ciphertext*. It cannot read
> messages, and it cannot forge them.

---

## Protocol v6

| Purpose | Algorithm | Notes |
|---|---|---|
| Key exchange | **X25519** ECDH | static + signed prekey + one-time prekey + per-epoch ephemerals |
| Key encapsulation | **ML-KEM-768** (FIPS 203) | mixed into the root and every epoch |
| Signatures | **ML-DSA-65** (FIPS 204) | over header + nonce + ciphertext (+ bundle + otk id) |
| Symmetric AEAD | **XSalsa20-Poly1305** | `crypto_secretbox` |
| Ratchet | Signal-style Double Ratchet | DH + KEM epochs, per-message chain keys |
| Bootstrap | **self-signed prekey bundles + one-time prekeys** | X3DH-style; no initiator/responder role; per-session forward secrecy |
| Key directory | relay-served `{ bundle, oneTimePrekey }` | address-keyed; proof-of-possession registration |

Confidentiality is **hybrid**: an attacker must break *both* X25519 and
ML-KEM-768. Authentication is post-quantum only (ML-DSA-65), so there is no
classical signature dependency.

**v6 prekey bundles + one-time prekeys + key directory.** Every peer publishes
a self-signed bundle `{ v, staticDhPk, signPk, signedDhPk, kemPk, signature }`
and a pool of one-time prekeys, registered with the relay under a **bound
routing address** `BLAKE2b(signPk || dhPk)` with proof-of-possession (the
registration must carry a signature that verifies against the bundle's
`signPk`). A session is established from the peer's *verified* bundle, and the
sender mixes one consumed one-time prekey into the root (X3DH `DH3`), so:

- the root key is post-quantum from the start —
  `BLAKE2b(64, DH(signedDhSk, peer.signedDhPk), DH(staticSk, peer.staticPk))`,
  further mixed with the one-time-prekey shared secret when one is used,
  symmetric and computable by both sides;
- the **first message is post-quantum too**: its chain derives from
  `DH(eph, peer.signedDhPk)` mixed with an ML-KEM encapsulation to the peer's
  `kemPk`, and it carries the sender's bundle so the receiver can establish;
- the **bootstrap has its own forward secrecy**: each new session consumes a
  fresh one-time prekey served by the directory, so the first message is not
  deterministic per identity;
- there is **no initiator/responder role** — two peers who both send their
  first message before receiving still converge.

Senders may still address a peer by bundle (offline / no directory); address
mode fetches the bundle + a one-time prekey from the directory instead, which
removes trust-on-first-use for the bootstrap.

### Envelope

```jsonc
{
  "v": 6,
  "senderDhPk":   "…",  // X25519 public key, 32 bytes (the routing address is derived from it)
  "senderSignPk": "…",  // ML-DSA-65 public key, 1952 bytes — FIRST message only
  "header": { "dh": "…", "pq_pk": "…", "pq_ct": "…", "pn": 0, "n": 0,
              "first": true,           // only on the very first message
              "bundle": { … },         // sender's prekey bundle, only on first
              "otk_id": 3 },           // consumed one-time prekey id, only on first
  "nonce":      "…",
  "ciphertext": "…",
  "signature":  "…"     // ML-DSA-65, 3309 bytes
}
```

**Steady-state messages are ~53% smaller** (~5 KB vs ~11 KB): three fields that
are constant within a DH ratchet epoch are **omitted** and reconstructed by the
receiver from a per-epoch cache (`epochs`):

- `senderSignPk` — the signing key is pinned at session creation;
- `header.pq_pk` — the sender's per-epoch ML-KEM public key;
- `header.pq_ct` — the per-epoch ML-KEM ciphertext (reused for every message in
  the epoch until the next ratchet).

Every epoch's **first** message always carries all three, which is what
populates the receiver's cache; later same-epoch messages omit them. The relay
validates them as optional-but-size-checked, so a half-shrunk envelope is still
rejected. Trade-off: if a relay reorders messages so an epoch's first message
arrives after a later one, the later one cannot be reconstructed (the relay is
FIFO, so this needs a deliberately malicious reorderer).

The first message carries the sender's prekey bundle (~11 KB base64 ≈ 8.8 KB
raw; measured by `npm test`'s doc-consistency check — `node src/index.js info`
prints the live number). Plaintext is
padded to 256-byte blocks before encryption so ciphertext length does not leak
exact message length.

**The signature covers the header, not just the ciphertext.** Every
variable-length field is length-prefixed into a canonical byte string
(`signingPayload`) before signing — including the `first` flag — so a relay or
network attacker cannot mutate `n`, `pn`, `dh`, the KEM fields or the bootstrap
flag on a validly-signed envelope. The recipient's public key is signed but
never transmitted, binding each envelope to one conversation.

---

## Layout

```
├── package.json
├── src/
│   ├── crypto.js      # thin Node adapter over public/crypto-core.js
│   ├── identity.js    # persistent keypairs -> .identity.json (project root)
│   ├── sessions.js    # encrypted session persistence -> .sessions.json
│   ├── server.js      # ciphertext-only relay (TCP + WebSocket)
│   ├── client.js      # CLI messaging client, Tor-routed by default
│   ├── tor.js         # SOCKS5 routing, fails closed
│   ├── demo.js        # two-party demo + security assertions
│   ├── test.js        # integration test through the relay
│   ├── fuzz.js        # mutation fuzzer for ratchet state integrity
│   ├── browser-e2e.js # headless two-context browser E2E (npm test)
│   ├── xss-regression.js   # headless XSS regression for the Gemini render path (npm test)
│   ├── messenger-smoke.js   # headless A-B-A smoke test of public/messenger.html (npm test)
│   ├── doc-consistency.js  # doc-vs-code checks (bundle size, cited files, ports, npm-test stages)
│   ├── vault.js       # Node entry for the vault-at-rest layer (re-exports vault-core)
│   └── index.js       # keygen / bundle / pubkey / info / vault-*
├── public/
│   ├── crypto-core.js # shared Identity, Session (Double Ratchet), signingPayload
│   ├── vault-core.js  # shared vault-at-rest core (age format) — Node + browser
│   ├── browser-crypto.js   # thin browser adapter over crypto-core.js
│   ├── index.html     # dashboard UI with an E2EE Network tab + age vault panel
│   ├── messenger.html # minimal two-party messaging app over the same core
│   ├── fonts/         # self-hosted fonts (SIL OFL 1.1) + local fonts.css
│   └── vendor/        # vendored libsodium + @noble + age-encryption — no CDN at runtime
└── tools/
    ├── vendor.mjs     # regenerate public/vendor from node_modules
    ├── fetch-fonts.mjs    # regenerate public/fonts from Google Fonts (latin subsets only)
    └── serve.mjs      # static server: brotli/gzip + cache headers (loopback only)
```

## Run it

```bash
npm install
```

Two-party demo and security assertions:

```bash
npm run demo
```

Integration test through the relay, plus the mutation fuzzer, a headless
two-context browser E2E, a headless XSS regression for the Gemini render path,
a headless messenger smoke test (an A→B→A flow through `public/messenger.html`),
and a doc-consistency check that keeps the README/ROADMAP bundle-size figures
tied to the measured value. The three browser stages skip gracefully if the
headless browser isn't available:

```bash
npm test
```

The browser E2E (`src/browser-e2e.js`) is self-contained — it spawns its own
relay and static server on dedicated loopback ports and drives a real
A→B→A conversation in two incognito contexts, then reloads both pages to prove
the sessions survive in `localStorage` and the ratchet continues. It ends with
a Node-vs-browser differential leg: a pure-Node peer and the browser peer
exchange envelopes through the relay in both directions, proving the two
stacks share one wire format. It points the page at its own relay via the
`?relay=ws://host:port` query parameter.

Browser client — one command (relay + static server + opens the messenger):

```bash
npm run messenger
```

Override the loopback ports with `MESSENGER_HOST`, `MESSENGER_RELAY_PORT`,
`MESSENGER_WS_PORT`, or `MESSENGER_UI_PORT`. Ctrl+C stops both servers. Open a
second profile (private/incognito window) at the printed URL for a two-party
conversation.

Browser client — three terminals:

```bash
npm run server
```

```bash
npm run serve
```

Then open <http://127.0.0.1:8000/> in two separate browser profiles (or one
normal and one private window — they need separate `localStorage`), go to the
**E2EE Network** tab, and click **SHARE** to copy your 44-char bound routing
address (or the full prekey bundle for offline first contact). Paste the other
side's address/bundle and send — either side may send the first message. For a
minimal test client over the same core and relay, open
<http://127.0.0.1:8000/messenger.html> in two profiles instead.

CLI client — two terminals. First print your bound routing address (or the
full prekey bundle for offline first contact):

```bash
node src/index.js address   # 44-char bound routing address
node src/index.js bundle    # full self-signed prekey bundle (offline)
```

Then start the client with **the peer's** address or bundle — not your own,
since a session is established from the peer's verified bundle:

```bash
node src/client.js "<peer's 44-char address>"   # resolves via the key directory
node src/client.js "<peer's full bundle>"       # offline, no directory
```

The CLI routes through Tor (SOCKS5 on 127.0.0.1:9050) by default and **refuses
to connect if Tor is unavailable**. Use `--no-tor` for a direct connection, or
`--allow-direct-fallback` to try Tor and accept a direct link if it is not
running.

### Vault at rest (age format)

Exported vaults are standard [age](https://age-encryption.org) files (the
single implementation lives in `public/vault-core.js`, via the author's
official `age-encryption` TypeScript package, vendored into `public/vendor/`),
so a BlackVault backup decrypts with the `age`/`rage` CLIs and is never locked
into this codebase. ASCII armor (PEM) is the default so a vault survives text
transport:

```bash
node src/index.js vault-keygen                  # new age identity + age1... recipient
node src/index.js vault-keygen --hybrid         # PQ hybrid (X25519 + ML-KEM-768) keypair
node src/index.js vault-export <file> <age1...>  # -> <file>.age (PEM-armored)
node src/index.js vault-import <file.age> <AGE-SECRET-KEY>  # decrypt to stdout
```

Passphrase encryption is available too — set `AGE_PASSPHRASE` and omit the
recipient/identity argument. The programmatic API is `exportVault()` /
`importVault()` (X25519 recipients, scrypt passphrases, and **post-quantum
hybrid** X25519 + ML-KEM-768 recipients via `generateVaultIdentity({ hybrid:
true })` — `AGE-SECRET-KEY-PQ-1...` / `age1pq1...`, wrapping the file key in an
`mlkem768x25519` stanza so a quantum attacker cannot harvest-and-break the
X25519 layer alone; needs age v1.2.0+ tooling). The format is standard
age v1, so backups decrypt with the reference `age`/`rage` CLIs; the
classical/passphrase/hybrid export-import round-trips are asserted in `npm test`.

**The dashboard UI has a Vault at Rest panel** (E2EE Network tab): generate an
age keypair (with a **PQ hybrid** checkbox for the ML-KEM-768 variant), encrypt
a backup of the current E2EE identity (all 8 keypairs + one-time-prekey pool,
the same JSON `persistIdentity` writes) to a recipient/passphrase,
download/copy the armored `.age`, and later decrypt & restore it — the vault
core is lazy-imported so nothing age-related loads at first paint. The headless
browser E2E exports in one context and restores in another (both classical and
hybrid), asserting the identity keys and routing address survive exactly.

---

## Security properties

- **Post-quantum bootstrap** — the root key and the very first message are
  hybrid (X25519 + ML-KEM-768); there is no classical-only window.
- **Forward secrecy** — chain keys advance per message; a compromised key does
  not reveal earlier messages.
- **Break-in recovery** — each reply starts a new DH + ML-KEM epoch.
- **Post-quantum authentication** — ML-DSA-65 over the whole envelope.
- **Tamper detection** — any change to ciphertext *or header* fails signature
  verification.
- **Bounded key derivation** — `MAX_SKIP` (1000) caps skipped-key derivation, so
  a large `n` cannot drive a receiver into unbounded CPU and memory use.
- **Atomic decryption** — the ratchet advances on a snapshot that is committed
  only after the Poly1305 tag verifies; a failed decryption leaves state
  byte-for-byte unchanged. Without this, any envelope reaching a receiver — a
  replay of a genuinely-signed old message, or a forgery signed with an
  attacker's own key — would be an unauthenticated remote kill switch.
- **No key derived from an uninitialized chain** — a session that has not
  received a first message has no receiving chain, and the decrypt path refuses
  to derive a message key from a null chain (KDF on a null chain key is a
  public constant — the v4 pre-reply forgery).
- **Key pinning from a verified bundle** — the peer's signing key is pinned at
  session creation from the *verified, self-signed prekey bundle*, never from a
  received message, so no received envelope can install a foreign key.
- **Replay protection** — stale ratchet epochs and duplicate first messages are
  refused, so a replay cannot rewind the ratchet or corrupt an established
  session.
- **Delivery receipts** — a receiver auto-acks the first message it establishes
  from (an ordinary encrypted message, invisible in the feed), so the sender's
  receiving chain is established immediately and the bootstrap crash-recovery
  edge is closed.
- **One crypto implementation** — Node and browser share a single core
  (`public/crypto-core.js`); a fix is a fix in both clients.
- **No CDN** — all cryptography is served from `public/vendor/`, and the UI's
  fonts are self-hosted in `public/fonts/` (regenerate with `tools/fetch-fonts.mjs`;
  every woff2 is verified against committed SHA-256 pins in `tools/fonts-manifest.json`,
  so even the font CDN cannot silently substitute bytes).
  A CDN can serve different bytes to different visitors; for a messaging app that
  means it can serve a backdoored cipher.

## Limitations

These are real and deliberate. Read them before treating this as more than a
prototype.

1. **Metadata.** The relay sees who talks to whom and when. Padding hides exact
   message length; it does not hide timing, volume, or the social graph. Tor
   hides the client IP from the relay but not from a global passive adversary.

2. **`.identity.json` holds private keys** in plaintext at the project root. It
   is gitignored. A real app should use an OS keychain or secure enclave.

3. **`public/index.html` is a demo dashboard.** Most of it is mock UI for an
   unrelated analysis tool; only the **E2EE Network** tab is backed by real
   cryptography. `public/messenger.html` is a clean, minimal two-party client
   over the same core and relay.

4. **The key directory is availability-trusted, not identity-trusted.** Address
   mode fetches the bundle + a one-time prekey from the relay's directory; the
   client re-verifies the bundle and that its derived address matches, and the
   relay enforces proof-of-possession at registration, so a malicious relay
   cannot substitute a different identity. It *can* withhold, replay, or
   exhaust one-time prekeys (denial-of-delivery) — the same trust you already
   place in the relay to deliver ciphertext.

5. **Bootstrap crash recovery is closed via delivery receipts.** The receiver
   auto-acks every first message it establishes from with an encrypted delivery
   receipt, and the sender's ratchet state is persisted *before* the send is
   observable, so a sender that crashes and restarts no longer re-flags as
   `first` (the duplicate-first stall is gone — regression in `demo.js`) and its
   receiving chain is established even if the peer never types a reply. The
   only residual is a crash in the single synchronous gap between the persist
   and the `ws.send` (the message would be lost but marked sent) — not a
   realistic failure window in a single-threaded runtime.

## Roadmap

| Layer | Status |
|---|---|
| E2E encryption | Done |
| Post-quantum hybrid ratchet | Done |
| Forward secrecy / break-in recovery | Done |
| PQ-protected session bootstrap (prekey bundles + one-time prekeys) | Done |
| Ciphertext-only relay | Done |
| Key directory (address mode, proof-of-possession) | Done |
| Authenticated registration (bound addresses) | Done |
| Auto-Tor routing (CLI) | Done, fails closed |
| Test messaging app (`public/messenger.html`) | Done |
| Metadata resistance (mixnet) | Not started |
