/**
 * Launch the local messenger (`npm run messenger`).
 *
 * Starts the ciphertext-only relay and the static server on their default
 * loopback ports, waits for both to answer, then opens public/messenger.html
 * in the default browser. Ctrl+C stops both servers.
 *
 * The messenger opens a single profile; open a second profile (a private /
 * incognito window) to have two identities in the same browser, or run this in
 * two browsers.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';

// Namespaced overrides (MESSENGER_*) so a generic PORT/WS_PORT/HOST in the
// shell cannot collide with the defaults below.
const HOST = process.env.MESSENGER_HOST || '127.0.0.1';
const PORT = Number(process.env.MESSENGER_RELAY_PORT || 7980);      // relay TCP
const WS_PORT = Number(process.env.MESSENGER_WS_PORT || 8080);      // relay WebSocket
const UI_PORT = Number(process.env.MESSENGER_UI_PORT || 8000);      // static server
const URL = `http://${HOST}:${UI_PORT}/messenger.html?relay=ws://${HOST}:${WS_PORT}`;

function waitForTcp(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const socket = connect(port, HOST);
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`relay did not listen on ${HOST}:${port}`));
        else setTimeout(tryOnce, 200);
      });
    };
    tryOnce();
  });
}

async function waitForHttp(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const res = await fetch(url); if (res.ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`static server did not answer ${url}`);
}

function openBrowser(url) {
  try {
    if (process.platform === 'win32') spawn('cmd', ['/c', 'start', '', url], { stdio: 'ignore', detached: true }).unref();
    else if (process.platform === 'darwin') spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    else spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
    return true;
  } catch {
    return false;
  }
}

const relay = spawn(process.execPath, ['src/server.js'], {
  env: { ...process.env, HOST, PORT: String(PORT), WS_PORT: String(WS_PORT) },
  stdio: 'inherit',
});
const ui = spawn(process.execPath, ['tools/serve.mjs'], {
  env: { ...process.env, UI_PORT: String(UI_PORT) },
  stdio: 'inherit',
});

let shuttingDown = false;
function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  relay.kill('SIGTERM');
  ui.kill('SIGTERM');
  setTimeout(() => process.exit(code), 200);
}
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
relay.on('exit', () => shutdown(1));
ui.on('exit', () => shutdown(1));

try {
  await waitForTcp(PORT);
  await waitForHttp(`http://${HOST}:${UI_PORT}/messenger.html`);
  const opened = openBrowser(URL);
  console.log(`\nMessenger ready. ${opened ? 'Opened' : 'Open'} ${URL}`);
  console.log(`Relay: TCP ${HOST}:${PORT} · WebSocket ${WS_PORT} · UI ${UI_PORT}`);
  console.log('Open a second profile (private/incognito window) for a two-party conversation.');
  console.log('Press Ctrl+C to stop.\n');
  await new Promise(() => {}); // keep running until a signal arrives
} catch (err) {
  console.error('[messenger] failed to start:', err.message);
  shutdown(1);
}
