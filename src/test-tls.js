/**
 * Shared TLS test harness (ANONYMITY.md §2).
 *
 * The relay is now TLS-on by default, so every suite that spawns it and talks
 * to it must connect over TLS with the committed loopback dev cert pinned. This
 * module centralises that: the fingerprint is derived from the cert at test
 * time (regenerating tools/certs/dev-cert.pem updates the pin automatically),
 * and `connectRelay` exposes the same newline client interface the suites'
 * old `connectTcp` used ({ send, once, socket }).
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createTlsSocket, sha256Fingerprint } from './tls.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const DEV_CERT = path.join(ROOT, 'tools', 'certs', 'dev-cert.pem');
export const DEV_KEY = path.join(ROOT, 'tools', 'certs', 'dev-key.pem');

/** SHA-256 fingerprint of the committed dev cert's DER bytes. */
export function committedFingerprint() {
  const pem = readFileSync(DEV_CERT, 'utf8');
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return sha256Fingerprint(Buffer.from(b64, 'base64'));
}

/**
 * Connect to the default-on TLS relay with the dev-cert pin. Returns a
 * newline-framed client compatible with the suites' previous connectTcp helper.
 *
 * @param {number} port
 * @param {string} [host]
 * @returns {Promise<{socket: import('node:tls').TLSSocket, send: Function, once: Function}>}
 */
export function connectRelay(port, host = '127.0.0.1') {
  return createTlsSocket(host, port, { pin: committedFingerprint() }).then((sock) => {
    sock.setEncoding('utf8');
    let buffer = '';
    const handlers = {};
    const messages = []; // message deliveries only, { ts, type, envelope, ... }
    sock.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.type === 'message') messages.push({ ts: Date.now(), ...msg });
        const h = handlers[msg.type];
        if (h) { delete handlers[msg.type]; h(msg); }
      }
    });
    return {
      socket: sock,
      send: (obj) => sock.write(JSON.stringify(obj) + '\n'),
      once: (t) => new Promise((res) => { handlers[t] = (m) => { delete handlers[t]; res(m); }; }),
      messages,
    };
  });
}
