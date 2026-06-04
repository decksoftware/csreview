// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  parseIgnoreFile,
  compileIgnorePatterns,
  patternToMatcher,
  isIgnored,
  applyIgnore,
  loadIgnore,
  DEFAULT_IGNORE_DIRS,
  DEFAULT_IGNORE_FILES,
  DEFAULT_IGNORE_PATTERNS,
  buildScannerIgnoreGlobs,
} from '../src/ignore.js';
import { runAnalysis } from '../src/index.js';

function match(pattern, file) {
  return isIgnored(file, compileIgnorePatterns([pattern]));
}

test('parseIgnoreFile drops comments and blank lines', () => {
  const patterns = parseIgnoreFile('# comment\n\n  dist/  \n*.min.js\n');
  assert.deepEqual(patterns, ['dist/', '*.min.js']);
});

test('basename glob without slash matches at any depth', () => {
  assert.ok(match('*.min.js', 'a/b/c.min.js'));
  assert.ok(match('*.min.js', 'c.min.js'));
  assert.ok(!match('*.min.js', 'c.js'));
});

test('directory pattern suppresses everything beneath it at any depth', () => {
  assert.ok(match('node_modules/', 'node_modules/x/y.js'));
  assert.ok(match('node_modules/', 'a/node_modules/z.js'));
  assert.ok(!match('node_modules/', 'src/node_modules_helper.js'));
});

test('a pattern with a slash is anchored to the project root', () => {
  assert.ok(match('src/generated/', 'src/generated/api.ts'));
  assert.ok(!match('src/generated/', 'src/other/api.ts'));
});

test('leading-slash pattern is anchored and does not match nested dirs', () => {
  assert.ok(match('/build/', 'build/main.js'));
  assert.ok(!match('/build/', 'packages/app/build/main.js'));
});

test('negation re-includes a path (last match wins)', () => {
  const compiled = compileIgnorePatterns(['dist/**', '!dist/keep.js']);
  assert.ok(isIgnored('dist/bundle.js', compiled));
  assert.ok(!isIgnored('dist/keep.js', compiled));
});

test('isIgnored normalizes backslash paths', () => {
  assert.ok(match('src/generated/', 'src\\generated\\api.ts'));
});

test('applyIgnore partitions findings and is a no-op without patterns', () => {
  const findings = [{ file: 'src/a.js' }, { file: 'dist/b.js' }];
  const { kept, suppressed } = applyIgnore(findings, compileIgnorePatterns(['dist/']));
  assert.equal(kept.length, 1);
  assert.equal(suppressed.length, 1);
  assert.equal(kept[0].file, 'src/a.js');

  const noop = applyIgnore(findings, []);
  assert.equal(noop.kept.length, 2);
  assert.equal(noop.suppressed.length, 0);
});

test('loadIgnore fails open when the file is absent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-ignore-'));
  const loaded = loadIgnore(dir);
  assert.deepEqual(loaded.patterns, []);
  assert.deepEqual(loaded.compiled, []);
});

test('runAnalysis suppresses ignored files from the report', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-ignore-proj-'));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'app.js'), 'const password = "supersecret123";\n', 'utf8');
  fs.writeFileSync(path.join(root, '.csreview-ignore'), 'src/app.js\n', 'utf8');

  const result = await runAnalysis(root, { outputDir: path.join(root, 'out'), runTools: false });

  assert.ok(result.suppressedByIgnore > 0);
  assert.ok(result.findings.every((f) => f.file !== 'src/app.js'));
});

test('globstar runs are collapsed and cannot cause catastrophic backtracking (ReDoS H1)', () => {
  // Hostile pattern: many consecutive globstar segments. Pre-fix this compiled
  // to adjacent unbounded groups and froze on a non-matching path.
  const pattern = '**/'.repeat(12) + 'x';
  const compiled = compileIgnorePatterns([pattern]);
  const nonMatching = 'a/'.repeat(30) + 'b'; // deep path that does not end in x

  const start = Date.now();
  const ignored = isIgnored(nonMatching, compiled);
  const elapsed = Date.now() - start;

  assert.equal(ignored, false);
  assert.ok(elapsed < 500, `ignore matching took ${elapsed}ms (possible ReDoS)`);

  // Collapsing preserves globstar semantics.
  assert.ok(isIgnored('a/b/c/x', compileIgnorePatterns(['**/x'])));
  assert.ok(isIgnored('x', compileIgnorePatterns(['**/x'])));
  assert.ok(isIgnored('deep/nested/x', compiled));
});

test('pathologically wildcard-heavy patterns are refused (fail-open)', () => {
  const matcher = patternToMatcher('*a'.repeat(101)); // 101 single-star tokens
  assert.equal(matcher.re.source, '(?!)'); // never-match sentinel
  // Fail-open: a refused pattern suppresses nothing.
  assert.equal(isIgnored('a'.repeat(101), compileIgnorePatterns(['*a'.repeat(101)])), false);
});

test('DEFAULT_IGNORE_DIRS covers vendored deps, build output, and generated caches', () => {
  for (const d of [
    'node_modules',
    '.git',
    'dist',
    'build',
    'vendor',
    'target',
    '__pycache__',
    '.dart_tool', // Flutter/Dart cache (the dominant external-tool noise source)
    '.gradle', // Gradle/Android cache
    '.supabase', // Supabase CLI local runtime state
    '.output', // Nuxt/Nitro build output (the DeckMidia .output false-positive source)
    'out', // Next.js static export
    'csreview-reports',
    '.csreview',
  ]) {
    assert.ok(DEFAULT_IGNORE_DIRS.includes(d), `expected DEFAULT_IGNORE_DIRS to include ${d}`);
  }
});

test('DEFAULT_IGNORE_PATTERNS are gitignore-syntax and scope external-tool findings to first-party source', () => {
  const compiled = compileIgnorePatterns(DEFAULT_IGNORE_PATTERNS);
  // the real-world noise from CaiuPixOld: a Chrome profile under .dart_tool
  assert.ok(isIgnored('flutter/apps/operator/.dart_tool/chrome-device/Default/Preferences', compiled));
  assert.ok(isIgnored('supabase-stuff/.supabase/postgres/data/x', compiled));
  assert.ok(isIgnored('android/app/.gradle/cache/x', compiled));
  // Nuxt/Nitro build output — the DeckMidia false positives (prototype pollution
  // in _nitro.mjs, JWT in bundles) all came from here.
  assert.ok(isIgnored('apps/web/.output/server/chunks/_nitro.mjs', compiled));
  assert.ok(isIgnored('a/node_modules/pkg/index.js', compiled));
  assert.ok(isIgnored('packages/web/dist/bundle.min.js', compiled));
  // root-level cache dirs (no parent component) must also match — guards against
  // an anchoring regression in the matcher (Codex M1)
  assert.ok(isIgnored('.supabase/local/x', compiled));
  assert.ok(isIgnored('.dart_tool/package_config.json', compiled));
  assert.ok(isIgnored('node_modules/pkg/index.js', compiled));
  // first-party source is never suppressed by the defaults
  assert.ok(!isIgnored('src/index.js', compiled));
  assert.ok(!isIgnored('lib/feature.dart', compiled));
  // the dot-dir default must NOT swallow the real `supabase/` source tree
  assert.ok(!isIgnored('supabase/migrations/0001_init.sql', compiled));
  // every default file glob is present in the compiled pattern set (export is intentional, Codex N1)
  for (const f of DEFAULT_IGNORE_FILES) assert.ok(DEFAULT_IGNORE_PATTERNS.includes(f), `missing default file ${f}`);
});

test('buildScannerIgnoreGlobs retains every legacy scanner exclusion and adds the new caches', () => {
  const globs = buildScannerIgnoreGlobs();
  for (const legacy of [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/build/**',
    '**/.next/**',
    '**/.nuxt/**',
    '**/coverage/**',
    '**/__pycache__/**',
    '**/.venv/**',
    '**/venv/**',
    '**/.tox/**',
    '**/.mypy_cache/**',
    '**/vendor/**',
    '**/target/**',
    '**/bin/**',
    '**/obj/**',
    '**/*.min.js',
    '**/*.min.css',
    '**/.trae/**',
    '**/.vscode/**',
    '**/.idea/**',
    '**/security-report.html',
    '**/security-findings.md',
    '**/csreview-report.html',
    '**/csreview-report.md',
    '**/*_security-report.html',
    '**/*_security-findings.md',
    '**/csreview-reports/**',
    '**/.csreview/**',
  ]) {
    assert.ok(globs.includes(legacy), `regression: lost legacy scanner glob ${legacy}`);
  }
  assert.ok(globs.includes('**/.dart_tool/**'));
  assert.ok(globs.includes('**/.gradle/**'));
  assert.ok(globs.includes('**/.supabase/**'));
});
