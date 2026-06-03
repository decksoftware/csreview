// @ts-check
import { existsSync, readFileSync } from 'fs';
import { safeResolveInside } from './pathSafety.js';

/**
 * `.csreview-ignore` support.
 *
 * A gitignore-style file at the project root listing path globs whose findings
 * should be suppressed from the report (e.g. generated code, vendored copies,
 * intentional test fixtures). This is READ-ONLY: it only filters the report, it
 * never deletes or rewrites anything, and a missing/invalid file fails open
 * (no patterns) so the scan always runs.
 */

const IGNORE_FILE_NAME = '.csreview-ignore';

function normalizeFile(filePath) {
  return String(filePath || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\//, '');
}

/**
 * Parse the raw text of a `.csreview-ignore` file into pattern lines, dropping
 * blank lines and `#` comments.
 *
 * @param {string} content
 * @returns {string[]}
 */
export function parseIgnoreFile(content) {
  return String(content || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

function escapeRegExpChar(char) {
  return char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

function translateGlob(glob) {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i];
    if (char === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (char === '?') {
      out += '[^/]';
    } else {
      out += escapeRegExpChar(char);
    }
  }
  return out;
}

/**
 * Compile a single ignore pattern into a matcher descriptor.
 *
 * @param {string} rawPattern
 * @returns {{negate: boolean, re: RegExp}}
 */
export function patternToMatcher(rawPattern) {
  let pattern = String(rawPattern || '').trim();
  const negate = pattern.startsWith('!');
  if (negate) pattern = pattern.slice(1);
  const dirOnly = /\/$/.test(pattern);
  if (dirOnly) pattern = pattern.replace(/\/+$/, '');
  const anchored = pattern.startsWith('/');
  if (anchored) pattern = pattern.replace(/^\/+/, '');

  // Collapse any run of globstar tokens (`**`, optionally separated by `/`) into
  // a single `**`. Without this, a hostile `.csreview-ignore` like
  // `**/**/**/.../x` would translate to many ADJACENT unbounded `(?:.*/)?`
  // groups — the textbook catastrophic-backtracking (ReDoS) shape — and freeze
  // the scanner on a non-matching path. After collapsing, every `**` becomes a
  // single group separated by literals, which matches in linear/polynomial time.
  pattern = pattern.replace(/\*\*(?:\/?\*+)*/g, '**');

  // Defense-in-depth: refuse pathologically wildcard-heavy patterns. Fail-open —
  // an uncompilable ignore pattern simply suppresses nothing (safer default for
  // a security tool than hiding findings).
  if ((pattern.match(/\*/g) || []).length > 100) {
    return { negate, re: /(?!)/ };
  }

  const hasSlash = pattern.includes('/');
  const body = translateGlob(pattern);
  const prefix = anchored || hasSlash ? '^' : '(?:^|.*/)';
  const suffix = dirOnly ? '(?:/.*)?$' : '$';
  // ReDoS-hardened dynamic RegExp: globstar runs are collapsed and patterns with
  // >100 wildcards are refused above; the input is a sanitized glob from the
  // user's own .csreview-ignore or built-in defaults (a local dev tool), and the
  // behaviour is unit-tested (ignore.test.js "ReDoS H1"). The dynamic RegExp is
  // intrinsic to a glob matcher, so this audit finding is suppressed inline.
  // Bare nosemgrep (not rule-id-scoped) so the suppression is robust to how the
  // CI's `--config auto` resolves the rule's internal id.
  return { negate, re: new RegExp(prefix + body + suffix) }; // nosemgrep
}

/**
 * Compile a list of ignore patterns into ordered matchers (last match wins,
 * which is what makes `!negation` re-includes work).
 *
 * @param {string[]} patterns
 * @returns {Array<{negate: boolean, re: RegExp}>}
 */
export function compileIgnorePatterns(patterns = []) {
  return (Array.isArray(patterns) ? patterns : []).map(patternToMatcher);
}

/**
 * Decide whether a file path is ignored by the compiled matchers.
 *
 * @param {string} filePath
 * @param {Array<{negate: boolean, re: RegExp}>} compiled
 * @returns {boolean}
 */
export function isIgnored(filePath, compiled = []) {
  const normalized = normalizeFile(filePath);
  if (!normalized) return false;
  let ignored = false;
  for (const matcher of compiled) {
    if (matcher.re.test(normalized)) {
      ignored = !matcher.negate;
    }
  }
  return ignored;
}

/**
 * Partition findings into kept vs suppressed by the compiled ignore matchers.
 *
 * @param {Array<{file?: string}>} findings
 * @param {Array<{negate: boolean, re: RegExp}>} compiled
 * @returns {{kept: Array<object>, suppressed: Array<object>}}
 */
export function applyIgnore(findings = [], compiled = []) {
  const kept = [];
  const suppressed = [];
  if (!compiled || compiled.length === 0) {
    return { kept: [...(findings || [])], suppressed };
  }
  for (const finding of findings || []) {
    if (finding && isIgnored(finding.file, compiled)) {
      suppressed.push(finding);
    } else {
      kept.push(finding);
    }
  }
  return { kept, suppressed };
}

/**
 * Load and compile the project's `.csreview-ignore` (fail-open).
 *
 * @param {string} rootDir
 * @returns {{patterns: string[], compiled: Array<{negate: boolean, re: RegExp}>}}
 */
export function loadIgnore(rootDir) {
  try {
    const ignorePath = safeResolveInside(rootDir, IGNORE_FILE_NAME);
    if (!ignorePath || !existsSync(ignorePath)) {
      return { patterns: [], compiled: [] };
    }
    const patterns = parseIgnoreFile(readFileSync(ignorePath, 'utf8'));
    return { patterns, compiled: compileIgnorePatterns(patterns) };
  } catch {
    return { patterns: [], compiled: [] };
  }
}

/**
 * Built-in default suppression — directories and file globs that are never
 * first-party source (vendored deps, build output, generated tool caches).
 *
 * These mirror the scanner's file-discovery exclusions, but live here as a
 * single reusable list because the engine-orchestrated external tools
 * (Gitleaks/Trivy/...) scan the RAW working tree and do NOT honor the scanner's
 * discovery globs. Applying these defaults to the merged finding set scopes the
 * tools to the same surface as the built-in detector — without it a secret
 * scanner reports thousands of false positives from generated caches (e.g. an
 * entire Chrome profile under `.dart_tool/`, Gradle or Supabase local state).
 * The user's `.csreview-ignore` is layered AFTER these (last-match-wins), so a
 * project can re-include a default with a `!negation`.
 */
export const DEFAULT_IGNORE_DIRS = [
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  '.mypy_cache',
  'vendor',
  'target',
  'bin',
  'obj',
  '.trae',
  '.vscode',
  '.idea',
  'csreview-reports',
  '.csreview',
  '.dart_tool', // Flutter/Dart build cache
  '.gradle', // Gradle/Android cache
  '.supabase', // Supabase CLI local runtime state (distinct from the `supabase/` source tree)
];

/** Built-in default file globs (minified/generated artifacts and prior reports). */
export const DEFAULT_IGNORE_FILES = [
  '*.min.js',
  '*.min.css',
  'security-report.html',
  'security-findings.md',
  'csreview-report.html',
  'csreview-report.md',
  '*_security-report.html',
  '*_security-findings.md',
];

/**
 * Built-in defaults in `.csreview-ignore` (gitignore) syntax, for suppressing
 * findings from the merged report set via {@link compileIgnorePatterns}.
 * @type {string[]}
 */
export const DEFAULT_IGNORE_PATTERNS = [...DEFAULT_IGNORE_DIRS.map((d) => `${d}/`), ...DEFAULT_IGNORE_FILES];

/**
 * The same defaults expressed as recursive globs for the scanner's
 * file-discovery `ignore` option (the `glob` library's syntax).
 * @returns {string[]}
 */
export function buildScannerIgnoreGlobs() {
  return [...DEFAULT_IGNORE_DIRS.map((d) => `**/${d}/**`), ...DEFAULT_IGNORE_FILES.map((f) => `**/${f}`)];
}

export { IGNORE_FILE_NAME };
