/**
 * TLS for the client↔relay link (ANONYMITY.md §2).
 *
 * The relay is self-hosted and may present a self-signed certificate, so the
 * client does NOT rely on the system CA store — it pins the relay certificate's
 * SHA-256 fingerprint (trust-on-first-use). This is the self-signed analogue of
 * Signal's certificate pinning: the operator shares the fingerprint out-of-band
 * exactly once, and every subsequent connection verifies it.
 *
 * FAILS CLOSED: a missing pin or a mismatched fingerprint refuses the
 * connection rather than silently accepting whatever certificate arrives.
 */
import tls from 'node:tls';
import { createHash } from 'node:crypto';

/** SHA-256 fingerprint of a DER certificate, lowercase hex, no colons. */
export function sha256Fingerprint(der) {
  return createHash('sha256').update(der).digest('hex');
}

/** Normalise a fingerprint from the colon form openssl prints. */
export function normaliseFingerprint(fp) {
  return String(fp).replace(/:/g, '').toLowerCase();
}

/**
 * Connect to the relay over TLS and verify the pinned fingerprint.
 *
 * @param {string} host relay host (used as the TLS servername)
 * @param {number} port relay port
 * @param {{pin: string, socket?: import('node:net').Socket}} [opts]
 *   pin — required SHA-256 fingerprint (colon or hex form);
 *   socket — an existing raw stream to upgrade (e.g. a Tor SOCKS tunnel).
 * @returns {Promise<import('node:tls').TLSSocket>}
 */
export function createTlsSocket(host, port, { pin, socket: existing } = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      // Self-signed: skip CA validation and pin the cert fingerprint instead.
      rejectUnauthorized: false,
    };
    // SNI/servername must be a DNS name, not an IP literal — Node rejects
    // `servername: '127.0.0.1'`. Hostname verification is skipped anyway
    // (rejectUnauthorized:false + manual pin), so omit it for IP hosts.
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes(':')) {
      opts.servername = host;
    }
    if (existing) opts.socket = existing;
    else { opts.host = host; opts.port = port; }

    const socket = tls.connect(opts, () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.raw) {
        socket.destroy();
        reject(new Error('relay sent no certificate'));
        return;
      }
      const actual = sha256Fingerprint(cert.raw);
      if (!pin || actual !== normaliseFingerprint(pin)) {
        socket.destroy();
        reject(new Error(
          `relay certificate fingerprint mismatch (got ${actual}, expected ${pin || '(none)'})`
        ));
        return;
      }
      resolve(socket);
    });
    socket.once('error', reject);
  });
}
