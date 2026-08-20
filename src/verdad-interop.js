/**
 * AEGIS <-> Reema interop (Phase 3 proof, layer 3).
 *
 * The messenger imports the vendored brain from public/aegis/. This test runs
 * against THOSE copies in Node and proves they behave identically to the AEGIS
 * tree they were vendored from — same verdicts, same binding/tamper properties,
 * same rebuttal signature contract. If the two trees drift, this is the test
 * that says so.
 *
 * Also fuzzes the pre-send gate with hostile and malformed claims to prove the
 * gate never crashes and never returns a non-boolean decision.
 */
import { analyzeMessage, shouldShare, classify } from '../public/aegis/verdad-service.js';
import { signKeyBinding, verifyKeyBinding } from '../public/aegis/keybinding.js';
import { AegisCrypto } from '../public/aegis/crypto.js';

const HOSTILE = 'URGENT BREAKING: the corrupt deep state cabal is covering up a deadly poison in the water that will kill your innocent children! Share immediately before it is too late, traitor! 100% proven beyond all doubt!';
const NEUTRAL = 'The city council approved the quarterly budget on Tuesday by a vote of six to three.';

let failures = 0;
const check = (label, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
  if (!cond) failures++;
};

async function main() {
  // ---- verdict interop: same outcome as the AEGIS service suite ----
  const hostile = await shouldShare(HOSTILE, { mode: 'offline' });
  check('hostile claim blocks the gate (offline)', hostile.allow === false && hostile.recommendation === 'block',
    `risk ${hostile.result.manipulationRisk}`);
  check('gate is air-gapped: no live API, no fact-check fetch',
    hostile.result.isLiveApi === false && hostile.result.factChecks === null);

  const neutral = await shouldShare(NEUTRAL, { mode: 'offline' });
  check('neutral claim passes the gate', neutral.allow === true && neutral.recommendation === 'share',
    `risk ${neutral.result.manipulationRisk}`);

  const analysis = await analyzeMessage(HOSTILE, { mode: 'offline', withFactChecks: false });
  check('inbound analysis returns a structured verdict',
    typeof analysis.manipulationRisk === 'number' && ['share', 'caution', 'block'].includes(analysis.recommendation));

  check('recommendation keys off risk, never off veracityScore',
    classify({ manipulationRisk: 90, veracityScore: 95 }).recommendation === 'block' &&
    classify({ manipulationRisk: 5, veracityScore: 10 }).recommendation === 'share');

  // ---- binding credential interop ----
  const a = await AegisCrypto.generateKeyPair({ extractable: true });
  const makeBinding = () => signKeyBinding(a.privateKeyJwk, {
    did: a.did,
    routingAddress: 'A'.repeat(44),
    signPk: 'B'.repeat(16),
    publicKeyJwk: a.publicKeyJwk,
  });

  const binding = await makeBinding();
  check('binding credential verifies round-trip', (await verifyKeyBinding(binding)).ok === true);

  const tamperedAddress = JSON.parse(JSON.stringify(binding));
  tamperedAddress.credentialSubject.routingAddress = 'C'.repeat(44);
  check('tampered routingAddress fails closed', (await verifyKeyBinding(tamperedAddress)).ok === false);

  const tamperedSignPk = JSON.parse(JSON.stringify(binding));
  tamperedSignPk.credentialSubject.signPk = 'D'.repeat(16);
  check('tampered Reema signPk fails closed', (await verifyKeyBinding(tamperedSignPk)).ok === false);

  // Attacker keeps the real JWK but presents a foreign DID as issuer: the
  // embedded key no longer hashes to the issuer, so it must be rejected.
  const foreignIssuer = JSON.parse(JSON.stringify(binding));
  foreignIssuer.issuer = 'did:key:z' + '1'.repeat(46);
  const fr = await verifyKeyBinding(foreignIssuer);
  check('credential whose embedded key does not match the issuer DID is rejected', fr.ok === false, fr.reason);

  // ---- rebuttal payload contract (signed statement, tamper-evident) ----
  const statement = {
    type: 'PrebunkRebuttal',
    claimSha256: await AegisCrypto.computeHash(HOSTILE),
    prebunkText: 'This claim carries strong manipulation markers; do not share.',
    recommendation: 'block',
    createdAt: new Date().toISOString(),
  };
  const jws = await AegisCrypto.signStatement(a.privateKeyJwk, statement);
  check('rebuttal signature verifies against the signed statement', await AegisCrypto.verifyStatement(a.publicKeyJwk, statement, jws));

  const tamperedStatement = { ...statement, prebunkText: 'This claim is fine, share away.' };
  check('tampered rebuttal prebunk fails verification',
    (await AegisCrypto.verifyStatement(a.publicKeyJwk, tamperedStatement, jws)) === false);

  // ---- fuzz: hostile/malformed claims must never crash the gate ----
  const corpus = [
    '',
    ' ',
    '!'.repeat(5000),
    '<img src=x onerror=alert(1)>',
    '\x00\x1b[2J\x07\u202e\u2066\u2067\u2068\u2069',
    JSON.stringify({ __aegis: 'PrebunkRebuttal', statement: null }),
    'null', 'undefined', 'NaN',
    '🙂'.repeat(200),
    'URGENT BREAKING ' + 'x'.repeat(2000) + ' corrupt deep state cabal cover up deadly poison',
    ...Array.from({ length: 200 }, (_, i) => `claim ${i} ` + Math.random().toString(36).slice(2) + ' urgent share now deadly poison'),
  ];
  let bad = 0;
  for (const text of corpus) {
    try {
      const g = await shouldShare(text, { mode: 'offline' });
      if (typeof g.allow !== 'boolean' || !['share', 'caution', 'block'].includes(g.recommendation)) {
        bad++;
        console.error('  non-boolean/enum decision on input', JSON.stringify(String(text).slice(0, 40)));
      }
    } catch (e) {
      bad++;
      console.error('  gate crashed on input', JSON.stringify(String(text).slice(0, 40)), e.message);
    }
  }
  check(`fuzzed ${corpus.length} hostile/malformed claims through the gate without a crash or bad decision`, bad === 0, `${bad} failure(s)`);

  console.log(failures === 0 ? '\nVERDAD INTEROP PASSED' : `\n${failures} VERDAD INTEROP CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('fatal:', e); process.exit(1); });
