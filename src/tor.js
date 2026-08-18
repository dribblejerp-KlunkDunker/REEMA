import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { SocksClient } = require('socks');

/**
 * Optional Tor routing.
 *
 * If Tor is running locally (SOCKS5 on 127.0.0.1:9050) the client connects to
 * the relay through it, hiding the client's IP from the relay.
 *
 * Fails CLOSED by default: if Tor was requested but is unreachable, the
 * connection is refused rather than silently downgraded to a direct link.
 * Silently dropping an anonymity control is worse than not connecting —
 * the user would believe they are anonymous when they are not. Pass
 * `allowDirectFallback: true` to opt into the old behaviour.
 */

const TOR_PROXY = {
  host: process.env.TOR_HOST || '127.0.0.1',
  port: Number(process.env.TOR_PORT || 9050),
  type: 5,
};

async function directConnect(host, port) {
  const net = await import('node:net');
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

/**
 * Create a TCP socket, optionally routed through Tor's SOCKS5 proxy.
 * @param {string} host
 * @param {number} port
 * @param {object} [opts]
 * @param {boolean} [opts.useTor=true]
 * @param {boolean} [opts.allowDirectFallback=false]
 * @returns {Promise<import('node:net').Socket>}
 */
export async function createTorSocket(host, port, { useTor = true, allowDirectFallback = false } = {}) {
  if (!useTor) return directConnect(host, port);

  try {
    const { socket } = await SocksClient.createConnection({
      proxy: TOR_PROXY,
      command: 'connect',
      destination: { host, port },
    });
    return socket;
  } catch (err) {
    const detail = `Tor proxy at ${TOR_PROXY.host}:${TOR_PROXY.port} not reachable (${err.code || err.message})`;

    if (!allowDirectFallback) {
      throw new Error(
        `${detail}. Refusing to fall back to a direct connection — that would expose your IP ` +
        `to the relay while you believe you are on Tor.\n` +
        `Start Tor, or re-run with --no-tor (direct, not anonymous) ` +
        `or --allow-direct-fallback (try Tor, accept direct if unavailable).`
      );
    }

    console.warn(`[tor] ${detail}. Falling back to a DIRECT connection — your IP is visible to the relay.`);
    return directConnect(host, port);
  }
}

/** True if a Tor SOCKS proxy appears to be running locally. */
export async function isTorAvailable() {
  const net = await import('node:net');
  return new Promise((resolve) => {
    const socket = net.connect(TOR_PROXY.port, TOR_PROXY.host);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
}
