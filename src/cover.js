/**
 * Cover traffic (ANONYMITY.md Phase 2 — first increment).
 *
 * Dummy envelopes the relay DISCARDS, emitted on a fixed cadence so a client's
 * link carries a steady stream of uniform-size frames regardless of when real
 * messages flow. That is what breaks a passive observer's send-time →
 * deliver-time and size correlation.
 *
 * HONEST LIMIT (state it in the UI, per ANONYMITY.md §5): the relay — and any
 * observer who can read the client→relay link — can still see `mode: 'cover'`,
 * because that link is not yet TLS'd. Cover traffic therefore currently hides
 * from an observer who sees only *timing and size*, not the application layer.
 * Full indistinguishability from a network observer requires TLS on the
 * client→relay transport, which is the next step after this machinery.
 */

export const COVER_MODE = 'cover';

// Sized to the same ballpark as a v6 envelope so a cover frame and a real
// frame look alike to a size-only observer. The relay discards it either way.
export const COVER_PAYLOAD_BYTES = 9 * 1024;

/** A fixed-size dummy envelope. `sodium` is a bound libsodium (from init()). */
export function makeCoverEnvelope(sodium, bytes = COVER_PAYLOAD_BYTES) {
  const ciphertext = sodium.to_base64(
    sodium.randombytes_buf(bytes),
    sodium.base64_variants.ORIGINAL
  );
  return { v: 6, mode: COVER_MODE, ciphertext };
}

/**
 * A fresh opaque sink id (44 b64 chars, address-shaped) each call, so cover
 * frames are not correlated to any real peer address. The relay discards cover
 * before routing, so this id is never queued or delivered.
 */
export function makeCoverSinkAddress(sodium) {
  return sodium.to_base64(
    sodium.randombytes_buf(32),
    sodium.base64_variants.ORIGINAL
  );
}

/**
 * Start a cover cadence: call `send(coverEnvelope)` every `intervalMs` until
 * `stop()` is called. Returns { stop }. The caller owns the actual transport
 * write (so the CLI and the browser messenger can share this module).
 */
export function startCoverCadence(sodium, send, { intervalMs = 5000, bytes = COVER_PAYLOAD_BYTES } = {}) {
  if (!(intervalMs > 0)) return { stop() {} };
  const tick = () => {
    try { send(makeCoverEnvelope(sodium, bytes)); } catch { /* never break the message path */ }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  return { stop: () => clearInterval(timer) };
}
