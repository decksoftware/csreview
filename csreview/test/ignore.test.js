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
