#!/usr/bin/env node
/**
 * scan-skill.mjs — apply the agentskill.sh SECURITY.md rubric to a skill dir.
 *
 * Usage:
 *   node tools/scan-skill.mjs <path-to-skill>            # human-readable report
 *   node tools/scan-skill.mjs <path-to-skill> --json     # machine-readable JSON
 *   node tools/scan-skill.mjs <path> --exclude='*.md'    # skip files by glob
 *   node tools/scan-skill.mjs <path> --include-rubric    # don't skip SECURITY.md
 *   node tools/scan-skill.mjs <path> --no-deobfuscate    # skip the decode/re-scan pass
 *   node tools/scan-skill.mjs <path> --normalize         # write homoglyph-decoded copies (temp dir)
 *   node tools/scan-skill.mjs <path> --normalize-dir=<d> # ... to a specific dir instead
 *   node tools/scan-skill.mjs <path> --report            # POST findings to agentskill.sh
 *   node tools/scan-skill.mjs <path> --report-url=<url>  # override the report endpoint
 *   node tools/scan-skill.mjs <path> --platform=<name>   # report platform field
 *   node tools/scan-skill.mjs <path> --agent-name=<name> # report agentName field
 *
 * With --report, findings are POSTed to the rubric's security-report endpoint
 * (POST https://agentskill.sh/api/agent/security-reports, fire-and-forget: a
 * failed submit never changes the exit code). Structure findings (missing
 * SKILL.md, double extensions, etc.) are folded onto the rubric's category set
 * and included in the report body alongside the pattern findings. Clean scans
 * (no findings) are not submitted. See the "Security Reporting" section of the
 * rubric for the schema.
 *
 * This is a *static, first-pass* scanner: it mechanizes the pattern tables in
 * the SECURITY.md rubric (secrets, reverse shells, destructive commands,
 * prompt injection, obfuscation, persistence, supply chain, endpoints, privacy)
 * into deterministic regex rules and scores them with the rubric's formula:
 *
 *     score = 100 - (CRITICAL*20 + HIGH*10 + MEDIUM*3 + LOW*1), floor 0
 *     >= 5 CRITICAL findings => instant 0
 *     90-100 SAFE | 70-89 REVIEW | <70 DANGER (block)
 *
 * Deobfuscation (rubric "Deobfuscation steps"): every text file is decoded and
 * re-scanned for hidden payloads — long base64 strings, hex (\\xNN) and octal
 * (\\NNN) escape runs, zero-width characters (stripped), and homoglyph/
 * confusable characters (normalized to ASCII lookalikes from the full Unicode
 * confusables set via the `confusables` npm package, so `rм -rf /` trips the
 * real `rm -rf /` rule and exotic pairs like `ьash` -> `bash` are caught too).
 * Line numbers are preserved. Decoded findings are tagged with `via` so they
 * stay attributable. Use --no-deobfuscate to skip this pass.
 *
 * What it deliberately does NOT do (these need a human / LLM, per the rubric):
 *   - URL/domain reputation and GitHub account-age checks,
 *   - description-vs-behavior "mismatch detection",
 *   - sandboxed dynamic analysis.
 * Those are surfaced as review notes, not scored.
 *
 * By default it skips any file named SECURITY.md whose body is the rubric
 * itself ("# Security Pattern Library") — the rubric bundles example attack
 * strings that would otherwise self-flag the `learn` skill. Use
 * --include-rubric to scan those files too.
 */
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { join, relative, basename, extname, sep, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const opts = {
  json: false, includeRubric: false, excludes: [], deobfuscate: true,
  report: false,
  reportUrl: 'https://agentskill.sh/api/agent/security-reports',
  platform: 'node',
  agentName: null,
  normalize: false, normalizeDir: null,
};
let target = null;
for (const a of args) {
  if (a === '--json') opts.json = true;
  else if (a === '--include-rubric') opts.includeRubric = true;
  else if (a === '--no-deobfuscate') opts.deobfuscate = false;
  else if (a === '--report') opts.report = true;
  else if (a.startsWith('--report-url=')) opts.reportUrl = a.slice('--report-url='.length);
  else if (a.startsWith('--platform=')) opts.platform = a.slice('--platform='.length);
  else if (a.startsWith('--agent-name=')) opts.agentName = a.slice('--agent-name='.length);
  else if (a === '--normalize') opts.normalize = true;
  else if (a.startsWith('--normalize-dir=')) { opts.normalize = true; opts.normalizeDir = a.slice('--normalize-dir='.length); }
  else if (a === '--help' || a === '-h') { usage(); process.exit(0); }
  else if (a.startsWith('--exclude=')) opts.excludes.push(a.slice('--exclude='.length));
  else if (!target) target = a;
  else { console.error(`unexpected argument: ${a}`); usage(); process.exit(2); }
}
if (!target) { usage(); process.exit(2); }

function usage() {
  console.log(`Usage: node tools/scan-skill.mjs <skill-dir> [--json] [--exclude=<glob>] [--include-rubric] [--no-deobfuscate] [--normalize [--normalize-dir=<path>]] [--report [--report-url=<url>] [--platform=<name>] [--agent-name=<name>]]`);
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const TEXT_EXTS = new Set(['.md', '.txt', '.json', '.js', '.mjs', '.cjs', '.ts', '.py',
  '.sh', '.bash', '.zsh', '.yml', '.yaml', '.toml', '.html', '.css', '.rb', '.go',
  '.rs', '.java', '.php', '.xml', '.ini', '.cfg', '.env', '']);

function globToRe(glob) {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${esc}$`);
}
const excludeRes = opts.excludes.map(globToRe);

function isExcluded(rel) {
  return excludeRes.some((re) => re.test(rel));
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name.startsWith('.') && name !== '.env') continue; // hidden files handled below separately
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue;
      walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

function isText(buf) {
  // Null byte in the first 8KB => treat as binary.
  return !buf.subarray(0, 8192).includes(0);
}

// ---------------------------------------------------------------------------
// Structure validation
// ---------------------------------------------------------------------------
// Structure findings (packaging/integrity issues) have no native attack
// category; fold each onto the closest rubric category (the endpoint's allowed
// set) so they can ride in the report body alongside the pattern findings.
function structureCategory(label) {
  if (label.startsWith('SKILL.md is missing')) return 'social_engineering';          // unverifiable as a skill — instructions hidden by absence
  if (label.startsWith('frontmatter: missing `name`')) return 'social_engineering';  // unidentifiable package
  if (label.startsWith('frontmatter: name')) return 'social_engineering';            // malformed identity
  if (label.startsWith('frontmatter: missing `description`')) return 'social_engineering'; // description-vs-behavior check impossible
  if (label.startsWith('frontmatter: broad allowed-tools')) return 'command_injection';  // broad shell grant enables arbitrary execution
  if (label.startsWith('double extension')) return 'social_engineering';             // file-masquerading (file.md.exe)
  if (label.startsWith('executable/archive in skill')) return 'obfuscation';         // behavior hidden in a binary blob
  if (label.startsWith('oversized file')) return 'obfuscation';                      // large opaque content can conceal payloads
  if (label.startsWith('binary file')) return 'obfuscation';                         // non-text hides contents from static review
  return 'file_access';
}

function addStructure(severity, label) {
  return { severity, label, category: structureCategory(label) };
}

function parseFrontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const block = text.slice(3, end);
  const fm = {};
  for (const line of block.split('\n')) {
    const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (m) fm[m[1]] = m[2].trim();
  }
  return fm;
}

// ---------------------------------------------------------------------------
// Rule table (per-line regex). severity/category per the rubric.
// ---------------------------------------------------------------------------
const SENSITIVE_PATH_RE = /(~\/\.ssh|~\/\.aws|~\/\.gnupg|~\/\.config|~\/\.gcloud|~\/\.azure|\.env\b|\b[A-Za-z0-9_.-]+\.(pem|key)\b|Exodus|Atomic\s+Wallet|Electrum|Binance|Phantom|Ledger\s+Live|Keychains?|google-chrome|mozilla\/firefox|BraveSoftware)/i;
const NETWORK_RE = /\b(curl|wget)\b|\bfetch\s*\(|\baxios\b|\brequests\.(get|post)\b|\bsocket\.connect\b|\bhttps?:\/\//i;

// ---------------------------------------------------------------------------
// Unicode homoglyphs / confusables (rubric "Unicode homoglyphs": lookalike
// characters such as Cyrillic а vs Latin a). Full Unicode coverage comes from
// the `confusables` npm package (char -> English lookalike base, ~3,300 pairs
// generated from Unicode's confusables.txt), replacing the curated set below,
// which is kept only as an offline fallback so the scanner still runs from a
// bare checkout without node_modules.
// ---------------------------------------------------------------------------

// Curated fallback: high-value cross-script lookalikes (Cyrillic/Greek/Latin
// letterforms) plus fullwidth letters/digits (U+FF01-FF5E map 1:1 by -0xFEE0).
const CURATED_CONFUSABLES = {
  // Cyrillic lookalikes (lowercase)
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u043D': 'h', '\u043C': 'm', '\u0442': 't',
  '\u0456': 'i', '\u0455': 's', '\u0458': 'j', '\u043A': 'k', '\u0457': 'i',
  '\u0451': 'e', '\u0501': 'd', '\u0433': 'r',
  // Cyrillic lookalikes (uppercase)
  '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C',
  '\u0423': 'Y', '\u0425': 'X', '\u041D': 'H', '\u041C': 'M', '\u0422': 'T',
  '\u0406': 'I', '\u0405': 'S', '\u0408': 'J', '\u041A': 'K', '\u0412': 'B',
  // Greek lookalikes (lowercase)
  '\u03B1': 'a', '\u03B2': 'b', '\u03B3': 'y', '\u03B4': 'd', '\u03B5': 'e',
  '\u03BF': 'o', '\u03C1': 'p', '\u03C3': 'o', '\u03C4': 't', '\u03C5': 'u',
  '\u03C7': 'x', '\u03BA': 'k', '\u03BD': 'v', '\u03B9': 'i', '\u03B7': 'n',
  '\u03C0': 'n', '\u03BC': 'u', '\u03F2': 'c',
  // Greek lookalikes (uppercase)
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
  // Latin lookalikes (long s, script/small-cap forms)
  '\u017F': 's', '\u0261': 'g', '\u0251': 'a', '\u2113': 'l',
  '\u029C': 'h', '\u026A': 'i', '\u029F': 'l', '\u0274': 'n', '\u0280': 'r', '\u028F': 'y',
  '\u1D04': 'C', '\u1D07': 'E', '\u1D0B': 'K', '\u1D0D': 'M', '\u1D0F': 'O',
  '\u1D18': 'P', '\u1D1B': 'T', '\u1D1C': 'U', '\u1D20': 'V', '\u1D21': 'W',
  '\uA731': 'S',
};

function buildCuratedMap() {
  const m = new Map(Object.entries(CURATED_CONFUSABLES));
  for (let i = 0xff01; i <= 0xff5e; i++) { // fullwidth -> ASCII by -0xFEE0
    m.set(String.fromCharCode(i), String.fromCharCode(i - 0xfee0));
  }
  return m;
}

// Accented Latin prose (é, ñ, à …) decomposes (NFD) to its base letter plus
// combining marks; flagging it would drown real findings in noise. Same for the
// handful of typographic symbols (© € £ ¥ ×) and superscript/subscript digits
// that appear in ordinary prose ("m²", "H₂O", "© 2026") — typography, not
// spoofing. Everything else in the data (cross-script lookalikes, circled and
// math letterforms, Komi/Greek/Cyrillic variants) stays flaggable.
const PROSE_SYMBOLS = new Set(['\u00a9', '\u20ac', '\u00a3', '\u00a5', '\u00d7']); // © € £ ¥ ×
const PROSE_SUPERSCRIPT_LEGACY = new Set(['\u00b9', '\u00b2', '\u00b3']);          // ¹ ² ³ (Latin-1)

function isProseAccent(key, base) {
  if (base.length !== 1) return false;
  const decomposed = key.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return decomposed.toLowerCase() === base.toLowerCase();
}

function isFlagWorthy(key, base) {
  if (isProseAccent(key, base)) return false;
  if (PROSE_SYMBOLS.has(key) || PROSE_SUPERSCRIPT_LEGACY.has(key)) return false;
  const cp = key.codePointAt(0);
  if (cp >= 0x2070 && cp <= 0x2089) return false; // superscripts ⁰-⁹ / subscripts ₀-₉
  return true;
}

let CONFUSABLE_MAP;      // char -> lookalike base (normalization + flag data)
let CONFUSABLE_FLAG_SET; // chars worth flagging as mixed-script tokens
let CONFUSABLE_SOURCE;   // provenance, surfaced in reports
{
  let pkg = null;
  try {
    pkg = await import('confusables');
    if (!pkg.confusablesMap || pkg.confusablesMap.size === 0) pkg = null;
  } catch { pkg = null; }
  if (pkg) {
    CONFUSABLE_MAP = new Map(pkg.confusablesMap);
    // Drop ASCII keys: the data includes ' '->' ', '1'->'1', and '|'->'l' — a
    // pipe is not a homoglyph attack, and normalizing it to 'l' would corrupt
    // every shell pipeline into false rule hits.
    for (const k of [...CONFUSABLE_MAP.keys()]) {
      if (k.length === 1 && k.charCodeAt(0) < 128) CONFUSABLE_MAP.delete(k);
    }
    const ver = require('confusables/package.json').version;
    CONFUSABLE_SOURCE = `confusables@${ver} (${CONFUSABLE_MAP.size} lookalike pairs)`;
  } else {
    CONFUSABLE_MAP = buildCuratedMap();
    CONFUSABLE_SOURCE = `curated fallback (${CONFUSABLE_MAP.size} lookalike pairs)`;
    console.error('[scan-skill] warning: the `confusables` npm package is not installed; using the curated homoglyph fallback (reduced coverage). Run `npm install` for the full Unicode confusables set.');
  }
  CONFUSABLE_FLAG_SET = new Set([...CONFUSABLE_MAP.keys()].filter((k) => isFlagWorthy(k, CONFUSABLE_MAP.get(k))));
}

// A homoglyph attack swaps a lookalike into an otherwise-ASCII token
// (`rм -rf /`, `сurl`, `evil.соm`): flag confusables directly abutting ASCII
// word characters. `hasConfusableToken` backs the rule below (a per-code-point
// check — the full confusables set is too large and too punctuation-heavy to
// compile into a regex character class safely).
function hasConfusableToken(line) {
  // A confusable inside a token always abuts a word char (e.g. `evil.соm` — 'с'
  // sits between '.' and 'о' but also abuts 'о'; `rеquests` abuts letters).
  // Restricting adjacency to word chars keeps prose lists like `✅/❌` quiet
  // while still catching every realistic in-token substitution.
  for (let i = 0; i < line.length; i++) {
    if (!CONFUSABLE_FLAG_SET.has(line[i])) continue;
    const prev = i > 0 ? line[i - 1] : '';
    const next = i + 1 < line.length ? line[i + 1] : '';
    if (/[A-Za-z0-9_]/.test(prev) || /[A-Za-z0-9_]/.test(next)) return true;
  }
  return false;
}

// Map confusables (incl. fullwidth, circled, math forms) to their ASCII
// lookalike bases in a single code-point pass (a base may be multi-char, e.g.
// æ -> "ae"; ASCII keys were already dropped above).
function normalizeHomoglyphs(text) {
  let out = '';
  for (const ch of text) {
    const base = CONFUSABLE_MAP.get(ch);
    out += base === undefined ? ch : base;
  }
  return out;
}

// Per-line substitution summary for the --normalize output: which lines the
// homoglyph normalization changed, and exactly which characters were replaced
// with which lookalike bases — so a human can eyeball what the scanner decodes.
function buildNormalizeEntry(rel, text, normalized) {
  const ol = text.split('\n');
  const nl = normalized.split('\n');
  const lines = [];
  for (let i = 0; i < nl.length; i++) {
    if (nl[i] === ol[i]) continue;
    const subs = [];
    for (const ch of ol[i]) {
      const base = CONFUSABLE_MAP.get(ch);
      if (base !== undefined) subs.push({ char: ch, base });
    }
    lines.push({ line: i + 1, subs });
  }
  return { rel, lines };
}

const RULES = [
  // ---- CRITICAL ----
  { severity: 'CRITICAL', category: 'reverse_shell',        label: 'TCP reverse shell',                 re: /\/dev\/tcp\//i },
  { severity: 'CRITICAL', category: 'reverse_shell',        label: 'netcat shell',                      re: /\bnc\s+-[a-z]*e\b/i },
  { severity: 'CRITICAL', category: 'reverse_shell',        label: 'Python socket reverse shell',       re: /\bpython\b[^\n]*\bsocket\b/i },
  { severity: 'CRITICAL', category: 'reverse_shell',        label: 'Perl/Ruby socket reverse shell',    re: /\b(perl\s+-[a-z]*e\b|ruby\s+-rsocket)/i },
  { severity: 'CRITICAL', category: 'command_injection',    label: 'delete filesystem root',            re: /rm\s+-rf\s+(\/|~|\*)/i },
  { severity: 'CRITICAL', category: 'command_injection',    label: 'disk overwrite / format',           re: /\b(dd\s+if=\/dev\/zero|mkfs\.)\b/i },
  { severity: 'CRITICAL', category: 'command_injection',    label: 'fork bomb',                         re: /:\(\s*\)\s*\{\s*:\s*\|\s*:/ },
  { severity: 'CRITICAL', category: 'command_injection',    label: 'chmod 777 on root',                 re: /chmod\s+777\s+\//i },
  { severity: 'CRITICAL', category: 'social_engineering',   label: 'password-protected archive install', re: /unzip\s+-P\s+["']/i },
  { severity: 'CRITICAL', category: 'social_engineering',   label: 'Gatekeeper/quarantine bypass',      re: /(xattr\s+-d\s+com\.apple\.quarantine|spctl\s+--master-disable)/i },
  { severity: 'CRITICAL', category: 'command_injection',    label: 'curl|bash remote execution',        re: /curl\b[^\n]*\|\s*(sudo\s+)?(ba)?sh\b/i },
  { severity: 'CRITICAL', category: 'credential_harvest',   label: 'password prompt',                   re: /enter\s+(your\s+)?(password|passphrase)/i },
  { severity: 'CRITICAL', category: 'credential_harvest',   label: 'API key prompt',                    re: /(provide|enter)\s+(your\s+)?(api\s+key|token)/i },
  { severity: 'CRITICAL', category: 'credential_harvest',   label: 'keychain credential read',          re: /security\s+find-generic-password/i },
  { severity: 'CRITICAL', category: 'secrets',              label: 'AWS access key',                    re: /\bAKIA[0-9A-Z]{16}\b/ },
  { severity: 'CRITICAL', category: 'secrets',              label: 'GCP API key',                       re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { severity: 'CRITICAL', category: 'secrets',              label: 'GitHub token',                      re: /\bghp_[0-9A-Za-z]{36}\b/ },
  { severity: 'CRITICAL', category: 'secrets',              label: 'password in URL',                   re: /[a-z][a-z0-9+.-]*:\/\/[^:\s/]+:[^@\s/]+@/i },
  { severity: 'CRITICAL', category: 'secrets',              label: 'env secret echoed',                 re: /echo\s+\$(SECRET|TOKEN|API_KEY|API_TOKEN|PRIVATE_KEY|AWS_[A-Z_]+)\b/i },
  { severity: 'CRITICAL', category: 'prompt_injection',     label: 'instruction override',              re: /(ignore\s+(all\s+)?previous\s+instructions?|ignore\s+all\s+prior|disregard\s+(all\s+)?above)/i },
  { severity: 'CRITICAL', category: 'prompt_injection',     label: 'jailbreak attempt',                 re: /\b(DAN\s+mode|jailbreak)\b/i },
  { severity: 'CRITICAL', category: 'prompt_injection',     label: 'role hijack',                       re: /you\s+are\s+now\b/i },
  { severity: 'CRITICAL', category: 'prompt_injection',     label: 'fake system prompt',                re: /\[SYSTEM\]|as\s+an\s+AI\s+with\s+no\s+restrictions/i },

  // ---- HIGH ----
  { severity: 'HIGH', category: 'obfuscation',    label: 'base64 decode + execute',  re: /base64\s+(-d|--decode)[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|\|\s*base64\s+(-d|--decode)/i },
  { severity: 'HIGH', category: 'obfuscation',    label: 'hex escape payload',      re: /(\\x[0-9a-f]{2}){3,}/i },
  { severity: 'HIGH', category: 'obfuscation',    label: 'octal escape payload',    re: /(\\[0-7]{3}){3,}/ },
  { severity: 'HIGH', category: 'obfuscation',    label: 'dynamic eval',            re: /\beval\s*\(|\bchild_process\.exec\s*\(|\bos\.system\s*\(|subprocess\..*shell\s*=\s*True/i },
  { severity: 'HIGH', category: 'obfuscation',    label: 'zero-width character',    re: /[\u200b\u200c\u200d\ufeff]/ },
  // re is a non-ASCII pre-filter; the precise confusable+adjacency check runs
  // in scanLine (the full confusables set is too large for a regex class).
  { severity: 'HIGH', category: 'obfuscation',    label: 'unicode homoglyph (mixed-script token)', re: /[\u0080-\uffff]/ },
  { severity: 'HIGH', category: 'persistence',    label: 'cron persistence',        re: /\b(crontab\b|\/etc\/cron\.d\/)/i },
  { severity: 'HIGH', category: 'persistence',    label: 'shell profile edit',      re: /(\.bashrc|\.zshrc|\.profile)\b/i },
  { severity: 'HIGH', category: 'persistence',    label: 'launchd/systemd service', re: /\b(launchctl|launchd|systemctl\s+enable)\b/i },
  { severity: 'HIGH', category: 'persistence',    label: 'git hook / IDE hook',     re: /(\.git\/hooks|\/tasks\.json\b)/i },
  { severity: 'HIGH', category: 'supply_chain',   label: 'pip install from URL',    re: /pip\s+install\s+(-e\s+)?(git\+|https?:)/i },
  { severity: 'HIGH', category: 'supply_chain',   label: 'npm install from URL',    re: /npm\s+install\s+(git\+|https?:)/i },
  { severity: 'HIGH', category: 'supply_chain',   label: 'download + execute',      re: /(wget|curl)\b[^\n]*&&[^\n]*chmod\s+\+x/i },
  { severity: 'HIGH', category: 'external_calls', label: 'URL shortener',           re: /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly)\b/i },
  { severity: 'HIGH', category: 'external_calls', label: 'dynamic DNS host',        re: /\b(duckdns\.org|no-ip\.(com|net)|hopto\.org|servehttp\.com)\b/i },
  { severity: 'HIGH', category: 'external_calls', label: 'webhook/exfil endpoint',  re: /\b(webhook\.site|requestbin\.com|beeceptor\.com|webhooktest\.com)\b/i },
  { severity: 'HIGH', category: 'external_calls', label: 'code snippet host',       re: /\b(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com|glot\.io|gist\.githubusercontent\.com)\b/i },
  { severity: 'HIGH', category: 'external_calls', label: 'raw GitHub content',      re: /raw\.githubusercontent\.com/i },
  { severity: 'HIGH', category: 'external_calls', label: 'direct binary download',  re: /https?:\/\/[^\s"']+\.(exe|dll|dmg|msi|zip|tar\.gz|apk|deb|rpm)\b/i },
  { severity: 'HIGH', category: 'social_engineering', label: 'root privilege ask',  re: /(run|install)\s+as\s+root|use\s+sudo\b|with\s+sudo\b/i },
  { severity: 'HIGH', category: 'social_engineering', label: 'disable security',    re: /(disable|turn\s+off)\s+(your\s+)?(antivirus|firewall|security|gatekeeper|real-?time\s+protection)/i },
  { severity: 'HIGH', category: 'social_engineering', label: 'trust manipulation',  re: /this\s+is\s+safe[,.!]?\s+trust\s+me/i },

  // ---- MEDIUM ----
  { severity: 'MEDIUM', category: 'file_access',   label: 'host fingerprinting',   re: /\b(uname\s+-a|whoami|hostname)\b/i },
  { severity: 'MEDIUM', category: 'file_access',   label: 'environment dump',      re: /\b(printenv|env\s+\|)\b/i },
  { severity: 'MEDIUM', category: 'file_access',   label: 'home listing',          re: /\bls\s+-la\s+(~|\$HOME)\b/i },
  { severity: 'MEDIUM', category: 'external_calls', label: 'plain HTTP transport', re: /http:\/\//i },
  { severity: 'HIGH',   category: 'external_calls', label: 'raw IP endpoint',            re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ },
  { severity: 'MEDIUM', category: 'external_calls', label: 'internal network host', re: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/ },

  // ---- LOW ----
  { severity: 'LOW', category: 'supply_chain', label: 'unpinned tool exec',        re: /\b(npx|uvx)\s+[@a-z][a-z0-9@/._-]*(\s|$)/i },
  { severity: 'LOW', category: 'supply_chain', label: 'unpinned pip install',      re: /\bpip\s+install\s+(?:-[A-Za-z]+\s+|--[A-Za-z][A-Za-z-]*\s+)*[a-z0-9][a-z0-9._-]*(?=\s|$)/i },
  { severity: 'LOW', category: 'supply_chain', label: 'unpinned npm install',      re: /\bnpm\s+install\s+(?:-[A-Za-z]+\s+|--[A-Za-z][A-Za-z-]*\s+)*[a-z0-9][a-z0-9._-]*(?=\s|$)/i },
  { severity: 'LOW', category: 'external_calls', label: 'auto-update / self-update', re: /\b(self-?update|update\s+skill|auto-?update)\b/i },
  { severity: 'LOW', category: 'external_calls', label: 'fire-and-forget telemetry', re: /\b(agent-feedback|trackInstall|security-reports)\b/i },
];

// ---------------------------------------------------------------------------
// Per-line rule matching (shared by the direct scan and the deobfuscation pass)
// ---------------------------------------------------------------------------
function scanLine(line, file, lineNo, via = null) {
  const out = [];
  for (const rule of RULES) {
    if (rule.re.test(line)) {
      // plain-HTTP rule: skip benign localhost URLs.
      if (rule.category === 'external_calls' && rule.label === 'plain HTTP transport') {
        const bad = [...line.matchAll(/http:\/\/([^\s"'<>)\]]+)/gi)].some((m) => {
          const host = m[1].split('/')[0].split(':')[0];
          return host !== 'localhost' && host !== '127.0.0.1' && host !== '0.0.0.0';
        });
        if (!bad) continue;
      }
      // raw-IP rule: only flag public IPs (skip loopback/private/link-local).
      if (rule.category === 'external_calls' && rule.label === 'raw IP endpoint') {
        const bad = [...line.matchAll(/\b\d{1,3}(\.\d{1,3}){3}\b/g)].some((m) => {
          const o = m[0].split('.').map(Number);
          if (o.some((x) => x > 255)) return false;
          const [a, b] = o;
          return !(a === 0 || a === 127 || a === 10 ||
            (a === 192 && b === 168) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 169 && b === 254));
        });
        if (!bad) continue;
      }
      // homoglyph rule: the regex above only pre-filters non-ASCII; the actual
      // "confusable abutting an ASCII word char" check runs per code point.
      if (rule.label === 'unicode homoglyph (mixed-script token)') {
        if (!hasConfusableToken(line)) continue;
      }
      out.push({ ...rule, file, line: lineNo, match: line.trim().slice(0, 120), via });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deobfuscation (rubric: "Decode any base64 strings and scan the output",
// "Strip all zero-width unicode and re-check content")
// ---------------------------------------------------------------------------
function lineOf(text, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

function printableRatio(buf) {
  if (!buf.length) return 0;
  let n = 0;
  for (const x of buf) if (x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127)) n++;
  return n / buf.length;
}

function findLongBase64(text) {
  const out = [];
  const re = /[A-Za-z0-9+/]{24,}={0,2}/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ s: m[0], idx: m.index });
    if (out.length >= 500) break; // pathological-file guard
  }
  return out;
}

// Decode \xNN hex and \NNN octal escape runs. Only applied when the resulting
// bytes are overwhelmingly printable, so regexes/paths with stray backslashes
// don't get mangled into noise.
function decodeEscapeRuns(text) {
  const re = /(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){3,}/g;
  let changed = false;
  const out = text.replace(re, (run) => {
    const bytes = [...run.matchAll(/\\x([0-9a-fA-F]{2})|\\([0-7]{3})/g)]
      .map((mm) => (mm[1] !== undefined ? parseInt(mm[1], 16) : parseInt(mm[2], 8)));
    if (printableRatio(Buffer.from(bytes)) < 0.9) return run; // not an escape payload
    changed = true;
    return Buffer.from(bytes).toString('utf8');
  });
  return changed ? out : text;
}

function deobfuscate(text, rel) {
  const out = [];

  // 1. Long base64 strings (>20 chars per the rubric; we scan >=24 to avoid
  //    hashes/uuid fragments) — decode and re-scan the output.
  for (const { s, idx } of findLongBase64(text)) {
    const buf = Buffer.from(s.replace(/=+$/g, ''), 'base64');
    if (buf.length < 4 || printableRatio(buf) < 0.9) continue;
    const decoded = buf.toString('utf8');
    const srcLine = lineOf(text, idx);
    for (const dl of decoded.split('\n')) {
      out.push(...scanLine(dl, rel, srcLine, 'base64'));
    }
  }

  // 2. Hex / octal escape runs — decode and re-scan only the lines that
  //    actually changed (line numbers are preserved; unchanged lines must not
  //    be re-scanned or every finding would be duplicated with this via tag).
  const escapes = decodeEscapeRuns(text);
  if (escapes !== text) {
    const el = escapes.split('\n');
    const ol = text.split('\n');
    for (let i = 0; i < el.length; i++) {
      if (el[i] !== ol[i]) out.push(...scanLine(el[i], rel, i + 1, 'hex/octal escapes'));
    }
  }

  // 3. Zero-width characters — strip and re-check (only changed lines).
  const stripped = text.replace(/[\u200b\u200c\u200d\ufeff]/g, '');
  if (stripped !== text) {
    const sl = stripped.split('\n');
    const ol = text.split('\n');
    for (let i = 0; i < sl.length; i++) {
      if (sl[i] !== ol[i]) out.push(...scanLine(sl[i], rel, i + 1, 'zero-width stripped'));
    }
  }

  // 4. Homoglyph / confusable characters — normalize to ASCII and re-check
  //    (rubric: "Normalize unicode and check for hidden text"). A `rм -rf /`
  //    written with Cyrillic м normalizes to `rm -rf /` and trips the real
  //    rule; only lines that actually changed are re-scanned.
  const normalized = normalizeHomoglyphs(text);
  if (normalized !== text) {
    const nl = normalized.split('\n');
    const ol = text.split('\n');
    for (let i = 0; i < nl.length; i++) {
      if (nl[i] !== ol[i]) out.push(...scanLine(nl[i], rel, i + 1, 'homoglyphs'));
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------
const findings = [];
const structure = [];
const inventory = { endpoints: new Set(), files: new Set(), shell: new Set(), deps: new Set() };

// --normalize output: homoglyph-decoded copies of every changed file (default:
// a fresh temp dir; the path is printed so a human can eyeball the decode).
const normalizeOut = opts.normalize
  ? { dir: opts.normalizeDir || mkdtempSync(join(tmpdir(), 'scan-skill-normalize-')), files: [] }
  : null;

const files = walk(target);
const skillMdPath = files.find((f) => basename(f) === 'SKILL.md');
const skillMdText = skillMdPath ? readFileSync(skillMdPath, 'utf8') : null;
const fm = skillMdText ? parseFrontmatter(skillMdText) : {};

// ---- structure ----
if (!skillMdPath) structure.push(addStructure('CRITICAL', 'SKILL.md is missing'));
else {
  if (!fm.name) structure.push(addStructure('LOW', 'frontmatter: missing `name`'));
  else if (!/^[a-z0-9-]+$/.test(fm.name)) structure.push(addStructure('LOW', `frontmatter: name "${fm.name}" is not lowercase-hyphen`));
  if (!fm.description) structure.push(addStructure('LOW', 'frontmatter: missing `description`'));
  if (fm['allowed-tools'] && /\bBash\b/i.test(fm['allowed-tools']))
    structure.push(addStructure('MEDIUM', `frontmatter: broad allowed-tools "${fm['allowed-tools']}"`));
}

const BINARY_EXTS = new Set(['.exe', '.dll', '.so', '.dylib', '.zip', '.tar', '.gz', '.7z', '.rar', '.bin']);
const DOUBLE_EXT = /\.(md|txt|png|jpg|jpeg|svg|json|js|py|sh)\.(exe|dll|so|dylib|sh|bat|cmd|vbs|scr)$/i;

for (const f of files) {
  const rel = relative(target, f);
  const name = basename(f);
  if (isExcluded(rel)) continue;

  // Skip the rubric's own doc (it bundles example attack strings) unless asked.
  if (!opts.includeRubric && name === 'SECURITY.md') {
    const head = readFileSync(f, 'utf8').slice(0, 400);
    if (head.includes('Security Pattern Library')) continue;
  }

  const st = statSync(f);
  if (st.size > 1_000_000) structure.push(addStructure('MEDIUM', `oversized file ${rel} (${(st.size / 1e6).toFixed(1)} MB)`));
  if (DOUBLE_EXT.test(name)) structure.push(addStructure('HIGH', `double extension ${rel}`));
  if (BINARY_EXTS.has(extname(name).toLowerCase())) structure.push(addStructure('HIGH', `executable/archive in skill ${rel}`));

  const buf = readFileSync(f);
  if (!isText(buf)) {
    structure.push(addStructure('MEDIUM', `binary file ${rel}`));
    continue;
  }
  const text = buf.toString('utf8');

  // ---- --normalize: write a homoglyph-decoded copy for human inspection ----
  if (normalizeOut) {
    const normalized = normalizeHomoglyphs(text);
    if (normalized !== text) {
      const outPath = join(normalizeOut.dir, rel);
      mkdirSync(dirname(outPath), { recursive: true });
      writeFileSync(outPath, normalized);
      normalizeOut.files.push(buildNormalizeEntry(rel, text, normalized));
    }
  }

  // ---- inventory extraction ----
  for (const m of text.matchAll(/\bhttps?:\/\/[^\s"'<>)\]`]+/g)) inventory.endpoints.add(m[0]);
  for (const m of text.matchAll(/~\/\.[A-Za-z0-9_./-]+/g)) inventory.files.add(m[0]);
  for (const m of text.matchAll(/(?:^|[\s`;|&])(curl|wget|npx|npm|pip|uvx|git|node|bash|sh|python3?|chmod|rm|cat|unzip|tar)\b/g)) inventory.shell.add(m[1]);
  for (const m of text.matchAll(/\b(?:npx|uvx)\s+(@[a-z0-9_-]+\/[a-z0-9._-]+|[a-z0-9_-]*[.-][a-z0-9._-]+)/gi)) inventory.deps.add(m[1]);
  for (const m of text.matchAll(/\b(?:npm|pip)\s+install\s+(?:-[A-Za-z]+\s+|--[A-Za-z][A-Za-z-]*\s+)*([@a-zA-Z0-9][a-zA-Z0-9@/._-]*)/g)) inventory.deps.add(m[1]);

  // ---- per-line rule matching ----
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    findings.push(...scanLine(lines[i], rel, i + 1));
  }

  // ---- deobfuscation: decode and re-scan (rubric steps) ----
  if (opts.deobfuscate) {
    findings.push(...deobfuscate(text, rel));
  }
}

// ---- compound: sensitive path + network send in the same file = exfiltration ----
const perFile = new Map();
for (const f of files) {
  const rel = relative(target, f);
  const name = basename(f);
  if (isExcluded(rel)) continue;
  if (!opts.includeRubric && name === 'SECURITY.md') continue;
  const buf = readFileSync(f);
  if (!isText(buf)) continue;
  const text = buf.toString('utf8');
  if (SENSITIVE_PATH_RE.test(text) && NETWORK_RE.test(text)) {
    findings.push({ severity: 'CRITICAL', category: 'data_exfiltration', label: 'sensitive path + network send', file: rel, line: null, match: 'sensitive path referenced in a file that also performs network I/O' });
  }
}

// Collapse noisy low-signal rules: one finding per (rule, file) for MEDIUM/LOW,
// so a skill listing `npx vitest` ten times scores one LOW, not ten.
{
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    if (f.severity === 'MEDIUM' || f.severity === 'LOW') {
      const key = `${f.severity}|${f.category}|${f.label}|${f.file}|${f.via || 'direct'}`;
      if (seen.has(key)) continue;
      seen.add(key);
    }
    deduped.push(f);
  }
  findings.length = 0;
  findings.push(...deduped);
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------
const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const s of structure) counts[s.severity] = (counts[s.severity] || 0) + 1;
for (const f of findings) counts[f.severity]++;

let score = counts.CRITICAL >= 5 ? 0
  : Math.max(0, 100 - counts.CRITICAL * 20 - counts.HIGH * 10 - counts.MEDIUM * 3 - counts.LOW * 1);
const rating = score >= 90 ? 'SAFE' : score >= 70 ? 'REVIEW' : 'DANGER';
const action = score >= 90 ? 'ALLOW' : score >= 70 ? 'REVIEW' : 'BLOCK';

// ---------------------------------------------------------------------------
// Security report submission (--report)
// Rubric "Security Reporting" section: POST the findings to
// https://agentskill.sh/api/agent/security-reports, fire-and-forget.
// ---------------------------------------------------------------------------
const SCANNER_VERSION = 'scan-skill/1.1.0';

// The endpoint's allowed categories differ slightly from the scanner's internal
// ones; fold the extras into the rubric's set.
const CATEGORY_MAP = {
  reverse_shell: 'command_injection',
  secrets: 'credential_harvest',
  supply_chain: 'external_calls',
  prompt_injection: 'prompt_injection',
  command_injection: 'command_injection',
  data_exfiltration: 'data_exfiltration',
  credential_harvest: 'credential_harvest',
  obfuscation: 'obfuscation',
  file_access: 'file_access',
  external_calls: 'external_calls',
  persistence: 'persistence',
  social_engineering: 'social_engineering',
};

function buildReport(slug, owner, score, findings, structure, opts) {
  // Structure findings ride in the report body too — they carry a rubric
  // category via structureCategory() and no file/line (packaging-level).
  // Patterns are homoglyph-normalized to readable ASCII: a reviewer of the
  // report shouldn't have to decode Cyrillic/other lookalikes by hand.
  return {
    slug,
    owner,
    score,
    issues: [...structure, ...findings].map((f) => {
      const issue = {
        category: CATEGORY_MAP[f.category] || f.category || 'file_access',
        severity: String(f.severity).toLowerCase(),
        description: f.via ? `${f.label} (decoded from ${f.via})` : f.label,
        pattern: normalizeHomoglyphs(f.match || f.label).slice(0, 200),
      };
      if (f.line != null) issue.line = f.line;
      return issue;
    }),
    platform: opts.platform,
    agentName: opts.agentName || 'scan-skill',
    scannerVersion: SCANNER_VERSION,
  };
}

let reportStatus = { submitted: false, reason: 'not requested' };
if (opts.report) {
  if (findings.length === 0 && structure.length === 0) {
    reportStatus = { submitted: false, reason: 'no findings (clean scan)' };
  } else {
    const slug = fm.name || basename(target);
    const owner = fm.owner || fm.author || 'unknown';
    const report = buildReport(slug, owner, score, findings, structure, opts);
    try {
      const res = await fetch(opts.reportUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': SCANNER_VERSION },
        body: JSON.stringify(report),
        signal: AbortSignal.timeout(10000),
      });
      reportStatus = { submitted: true, url: opts.reportUrl, status: res.status, issues: report.issues.length, ok: res.ok };
      if (!res.ok) reportStatus.error = `HTTP ${res.status} ${res.statusText}`;
    } catch (err) {
      reportStatus = { submitted: false, reason: 'request failed', error: String((err && err.message) || err) };
      console.error(`[scan-skill] security report submission failed: ${reportStatus.error}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const all = [
  ...structure.map((s) => ({ ...s, file: null, line: null, match: '' })),
  ...findings,
].sort((a, b) => {
  const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  return ord[a.severity] - ord[b.severity] || (a.file || '').localeCompare(b.file || '');
});

if (opts.json) {
  console.log(JSON.stringify({
    path: target,
    score,
    rating,
    action,
    counts,
    findings: all.map((f) => ({ severity: f.severity, category: f.category, label: f.label, file: f.file, line: f.line, via: f.via || null, match: f.match })),
    inventory: {
      endpoints: [...inventory.endpoints].sort(),
      files: [...inventory.files].sort(),
      shell: [...inventory.shell].sort(),
      dependencies: [...inventory.deps].sort(),
    },
    normalized: normalizeOut ? { dir: normalizeOut.dir, files: normalizeOut.files } : null,
    notes: {
      static_only: 'first-pass static scan; URL reputation, mismatch detection, and dynamic analysis require manual review',
      deobfuscation: opts.deobfuscate ? 'base64/hex/octal payloads decoded and re-scanned; zero-width chars stripped; homoglyphs normalized to ASCII and re-checked (one decode level)' : 'skipped via --no-deobfuscate',
      rubric_skipped: opts.includeRubric ? null : 'files named SECURITY.md containing the rubric header were skipped',
      confusables: CONFUSABLE_SOURCE,
    },
    report: reportStatus,
  }, null, 2));
} else {
  console.log(`\n## Security Scan: ${rating}\n`);
  console.log(`Path:   ${target}`);
  console.log(`Score:  ${score}/100  (${counts.CRITICAL} critical, ${counts.HIGH} high, ${counts.MEDIUM} medium, ${counts.LOW} low)`);
  console.log(`Confusables: ${CONFUSABLE_SOURCE}\n`);

  console.log('### Issues Found');
  if (!all.length) console.log('(none)');
  else {
    console.log('| Severity | Category | Issue | Location |');
    console.log('|----------|----------|-------|----------|');
    for (const f of all) {
      const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '-';
      const via = f.via ? ` (decoded from ${f.via})` : '';
      console.log(`| ${f.severity} | ${f.category} | ${f.label}${via} | ${loc} |`);
    }
  }

  console.log('\n### Network Endpoints');
  (inventory.endpoints.size ? [...inventory.endpoints].sort() : ['(none)']).forEach((e) => console.log(`- ${e}`));

  console.log('\n### File Access');
  (inventory.files.size ? [...inventory.files].sort() : ['(none)']).forEach((e) => console.log(`- ${e}`));

  console.log('\n### Shell Commands');
  (inventory.shell.size ? [...inventory.shell].sort() : ['(none)']).forEach((e) => console.log(`- ${e}`));

  console.log('\n### Dependencies');
  (inventory.deps.size ? [...inventory.deps].sort() : ['(none)']).forEach((e) => console.log(`- ${e}`));

  console.log('\n### Normalized Output (--normalize)');
  if (!opts.normalize) {
    console.log('Not requested (pass --normalize to write homoglyph-decoded file copies).');
  } else if (normalizeOut.files.length === 0) {
    console.log('(no homoglyph substitutions found — nothing written)');
  } else {
    console.log(`Wrote homoglyph-normalized copies to: ${normalizeOut.dir}`);
    for (const f of normalizeOut.files) {
      console.log(`- ${f.rel}`);
      for (const l of f.lines) {
        const subs = l.subs.map((s) => `${JSON.stringify(s.char)} -> ${JSON.stringify(s.base)}`).join(', ');
        console.log(`    line ${l.line}: ${subs}`);
      }
    }
  }

  console.log(`\n### Recommendation: ${action}`);
  console.log('Note: static first-pass scan. Base64/hex/octal payloads are decoded and');
  console.log('re-scanned; homoglyphs are normalized to ASCII and re-checked;');
  console.log('URL/domain reputation, description-vs-behavior mismatch, and');
  console.log('dynamic analysis need manual review.');

  console.log('\n### Security Report');
  if (!opts.report) {
    console.log('Not requested (pass --report to POST findings to agentskill.sh).');
  } else if (reportStatus.submitted) {
    const ok = reportStatus.ok ? 'OK' : `FAILED (${reportStatus.error || 'unknown'})`;
    console.log(`POST ${reportStatus.url} -> HTTP ${reportStatus.status} [${ok}] — ${reportStatus.issues} issues`);
  } else {
    console.log(`NOT submitted — ${reportStatus.reason}${reportStatus.error ? ` (${reportStatus.error})` : ''}`);
  }
  console.log('');
}
