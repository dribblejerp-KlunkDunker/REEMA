// Walk the ESM import graph from the noble entrypoints and copy only the
// reachable modules into public/vendor/, preserving package layout so the
// import map + relative specifiers resolve unchanged.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.argv[2];
const NM = path.join(ROOT, 'node_modules');
const OUT = path.join(ROOT, 'public', 'vendor');

const ENTRIES = [
  '@noble/post-quantum/ml-kem.js',
  '@noble/post-quantum/ml-dsa.js',
];

const IMPORT_RE = /(?:^|\s)(?:import|export)\s+(?:[\s\S]*?\sfrom\s+)?['"]([^'"]+)['"]/g;

function resolveSpec(spec, fromSpec) {
  if (spec.startsWith('.')) {
    return path.posix.normalize(path.posix.join(path.posix.dirname(fromSpec), spec));
  }
  return spec; // bare @noble/... specifier, already package-relative
}

const seen = new Set();
const queue = [...ENTRIES];
const copied = [];

while (queue.length) {
  const spec = queue.shift();
  if (seen.has(spec)) continue;
  seen.add(spec);

  const src = path.join(NM, spec);
  const dest = path.join(OUT, spec);
  let code;
  try {
    code = readFileSync(src, 'utf8');
  } catch (e) {
    console.error(`MISSING: ${spec} (${e.code})`);
    process.exitCode = 1;
    continue;
  }

  mkdirSync(path.dirname(dest), { recursive: true });
  copyFileSync(src, dest);
  copied.push(spec);

  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(code)) !== null) {
    queue.push(resolveSpec(m[1], spec));
  }
}

// libsodium classic scripts
mkdirSync(path.join(OUT, 'libsodium'), { recursive: true });
for (const [from, to] of [
  ['libsodium/dist/modules/libsodium.js', 'libsodium/libsodium.js'],
  ['libsodium-wrappers/dist/modules/libsodium-wrappers.js', 'libsodium/libsodium-wrappers.js'],
]) {
  copyFileSync(path.join(NM, from), path.join(OUT, to));
  copied.push(to);
}

console.log(`vendored ${copied.length} files into public/vendor/`);
for (const c of copied.sort()) console.log('  ' + c);

const pkgs = [...new Set(copied.filter((c) => c.startsWith('@noble/')).map((c) => c.split('/').slice(0, 2).join('/')))];
console.log('\nimport map packages:', pkgs.join(', '));
writeFileSync(path.join(OUT, 'MANIFEST.txt'),
  `Vendored from node_modules at build time. Regenerate with: npm run vendor\n\n${copied.sort().join('\n')}\n`);
