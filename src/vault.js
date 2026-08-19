/**
 * Vault-at-rest (age format) — Node entry point.
 *
 * The single implementation lives in `public/vault-core.js` (like
 * `crypto-core.js`): the browser dashboard lazy-imports it directly through
 * the import map, and this module re-exports it for the Node CLI
 * (`src/index.js` vault-* commands) and the test suite.
 */
export { generateVaultIdentity, exportVault, importVault } from '../public/vault-core.js';
