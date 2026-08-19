import { init, encodeBundle, Identity } from './crypto.js';
import { loadOrCreateIdentity, KEYFILE } from './identity.js';
import { generateVaultIdentity, exportVault, importVault } from './vault.js';
import { readFileSync, writeFileSync } from 'node:fs';

/**
 * CLI entry point.
 *
 *   node src/index.js keygen   -> create (or load) the identity keypairs
 *   node src/index.js bundle   -> print the shareable v6 prekey bundle
 *   node src/index.js address  -> print the 44-char bound routing address
 *   node src/index.js pubkey   -> print the X25519 static public key
 *   node src/index.js info     -> print key sizes and the keyfile location
 *
 *   node src/index.js vault-keygen                    -> new age identity + recipient
 *   node src/index.js vault-export <file> <recipient> -> age-encrypt <file> to <file>.age
 *   node src/index.js vault-import <file.age> <id>    -> age-decrypt to stdout
 *
 * In protocol v6 the shareable identity is a self-signed prekey bundle (not a
 * bare X25519 key): it carries the static DH key, signing key, signed prekey
 * and ML-KEM key plus a self-signature, so a peer can establish a session
 * with no key directory. Share it with your peer; they pass it to the client:
 *   node src/client.js "<peer's bundle>"
 */

async function main() {
  const cmd = process.argv[2] || 'info';

  if (cmd.startsWith('vault-')) {
    await vaultCommand(cmd, process.argv.slice(3));
    return;
  }

  const sodium = await init();
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
      console.log('Usage: node src/index.js [keygen|bundle|address|pubkey|info|vault-keygen|vault-export|vault-import]');
  }
}

/**
 * Vault-at-rest commands (age format).
 *   vault-keygen [--hybrid]                  print a new age identity + recipient
 *   vault-export <file> <age1-recipient>      encrypt <file> to <file>.age
 *   vault-import <file.age> <AGE-SECRET-KEY>  decrypt to stdout
 * A passphrase may be supplied via the AGE_PASSPHRASE env var in place of the
 * recipient/identity argument. --hybrid mints a post-quantum hybrid keypair
 * (X25519 + ML-KEM-768: AGE-SECRET-KEY-PQ-1... / age1pq1...); decrypt it with
 * the same hybrid identity (needs age v1.2.0+ tooling).
 */
async function vaultCommand(cmd, args) {
  const passphrase = process.env.AGE_PASSPHRASE || null;

  if (cmd === 'vault-keygen') {
    const hybrid = args.includes('--hybrid');
    const { identity, recipient } = await generateVaultIdentity({ hybrid });
    console.log(`# ${hybrid ? 'hybrid PQ age identity' : 'age identity'} — SECRET, back it up and never commit:`);
    console.log(identity);
    console.log('# recipient (public, safe to share):');
    console.log(recipient);
    return;
  }

  if (cmd === 'vault-export') {
    const [file, recipient] = args;
    if (!file) return console.error('Usage: node src/index.js vault-export <file> <age1-recipient>');
    if (!recipient && !passphrase) return console.error('vault-export: provide a recipient arg or AGE_PASSPHRASE');
    const plaintext = readFileSync(file);
    const armored = await exportVault(plaintext, { recipient, passphrase });
    const target = `${file}.age`;
    writeFileSync(target, armored);
    console.log(`encrypted ${file} -> ${target} (${armored.length} armored chars)`);
    return;
  }

  if (cmd === 'vault-import') {
    const [file, identity] = args;
    if (!file) return console.error('Usage: node src/index.js vault-import <file.age> [AGE-SECRET-KEY]');
    if (!identity && !passphrase) return console.error('vault-import: provide an identity arg or AGE_PASSPHRASE');
    const ciphertext = readFileSync(file, 'utf8');
    const out = await importVault(ciphertext, { identities: identity ? [identity] : [], passphrase });
    process.stdout.write(Buffer.from(out));
    return;
  }

  console.error(`unknown vault command: ${cmd}`);
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
