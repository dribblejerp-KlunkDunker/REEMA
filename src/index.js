import { init, encodeBundle, Identity } from './crypto.js';
import { loadOrCreateIdentity, KEYFILE } from './identity.js';

/**
 * CLI entry point.
 *
 *   node src/index.js keygen   -> create (or load) the identity keypairs
 *   node src/index.js bundle   -> print the shareable v6 prekey bundle
 *   node src/index.js address  -> print the 44-char bound routing address
 *   node src/index.js pubkey   -> print the X25519 static public key
 *   node src/index.js info     -> print key sizes and the keyfile location
 *
 * In protocol v6 the shareable identity is a self-signed prekey bundle (not a
 * bare X25519 key): it carries the static DH key, signing key, signed prekey
 * and ML-KEM key plus a self-signature, so a peer can establish a session
 * with no key directory. Share it with your peer; they pass it to the client:
 *   node src/client.js "<peer's bundle>"
 */

async function main() {
  const sodium = await init();
  const cmd = process.argv[2] || 'info';
  const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL);

  const id = loadOrCreateIdentity(sodium);

  switch (cmd) {
    case 'keygen':
      console.log(`Identity stored at: ${KEYFILE}`);
      console.log('X25519 public key :', b64(id.pk));
      console.log('Prekey bundle     :', encodeBundle(id.makeBundle()));
      break;

    case 'bundle':
      console.log(encodeBundle(id.makeBundle()));
      break;

    case 'address':
      console.log(b64(Identity.deriveAddress(id.signPk, id.pk)));
      break;

    case 'pubkey':
      console.log(b64(id.pk));
      break;

    case 'info':
      console.log('Protocol          : v6 (X25519 + ML-KEM-768, ML-DSA-65 signatures, prekey bundles + one-time prekeys)');
      console.log(`Identity file     : ${KEYFILE}`);
      console.log('X25519 public key :', b64(id.pk), `(${id.pk.length} bytes — the static DH key)`);
      console.log('Routing address   :', b64(Identity.deriveAddress(id.signPk, id.pk)), '(44 chars — BLAKE2b(signPk || dhPk))');
      console.log('ML-DSA public key :', `${id.signPk.length} bytes (sent in every envelope)`);
      console.log('Signed prekey     :', `${id.signedDhPk.length} bytes (X25519, rotated per identity)`);
      console.log('ML-KEM public key :', `${id.kemPk.length} bytes (post-quantum bootstrap)`);
      console.log('Shareable bundle  :', `${encodeBundle(id.makeBundle()).length} b64 chars (what you send to a peer)`);
      console.log('\nRun "node src/demo.js" for the full two-party demo.');
      break;

    default:
      console.log('Usage: node src/index.js [keygen|bundle|address|pubkey|info]');
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
