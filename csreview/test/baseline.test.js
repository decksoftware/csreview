// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fingerprintFinding, loadBaseline, applyBaseline, serializeBaseline, writeBaseline } from '../src/baseline.js';
import { runAnalysis } from '../src/index.js';

function finding(overrides = {}) {
  return {
    severity: 'HIGH',
    category: 'Injection',
    name: 'SQL Injection',
    file: 'src/db.js',
    line: 12,
    cwe: 'CWE-89',
    ...overrides,
  };
}

test('fingerprintFinding is stable and line-independent', () => {
  const a = fingerprintFinding(finding({ line: 12 }));
  const b = fingerprintFinding(finding({ line: 99 }));
  assert.equal(a, b);
});

test('fingerprintFinding distinguishes different files and CWEs', () => {
  assert.notEqual(fingerprintFinding(finding()), fingerprintFinding(finding({ file: 'src/other.js' })));
  assert.notEqual(fingerprintFinding(finding()), fingerprintFinding(finding({ cwe: 'CWE-79', name: 'XSS' })));
});

test('serializeBaseline dedups fingerprints and is deterministic', () => {
  const findings = [
    finding({ line: 1 }),
    finding({ line: 2 }),
    finding({ file: 'src/other.js', name: 'XSS', cwe: 'CWE-79' }),
  ];
  const first = serializeBaseline(findings);
  const second = serializeBaseline([...findings].reverse());
  assert.equal(first.version, 1);
  assert.equal(first.fingerprints.length, 2);
  assert.deepEqual(first, second); // order-independent, no timestamp
});

test('loadBaseline fails open and accepts both array and object forms', () => {
  assert.equal(loadBaseline('does-not-exist.json').size, 0);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-baseline-'));
  const objFile = path.join(dir, 'b1.json');
  fs.writeFileSync(objFile, JSON.stringify({ fingerprints: ['x|y|z'] }), 'utf8');
  assert.ok(loadBaseline(objFile).has('x|y|z'));

  const arrFile = path.join(dir, 'b2.json');
  fs.writeFileSync(arrFile, JSON.stringify(['a|b|c']), 'utf8');
  assert.ok(loadBaseline(arrFile).has('a|b|c'));

  const badFile = path.join(dir, 'b3.json');
  fs.writeFileSync(badFile, 'not json', 'utf8');
  assert.equal(loadBaseline(badFile).size, 0);
});

test('applyBaseline partitions new vs baselined findings', () => {
  const known = finding();
  const fresh = finding({ file: 'src/new.js', name: 'XSS', cwe: 'CWE-79' });
  const set = new Set([fingerprintFinding(known)]);
  const { newFindings, baselined } = applyBaseline([known, fresh], set);
  assert.equal(baselined.length, 1);
  assert.equal(newFindings.length, 1);
  assert.equal(newFindings[0].file, 'src/new.js');
});

test('writeBaseline round-trips through loadBaseline', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-baseline-rt-'));
  const file = path.join(dir, 'nested', '.csreview-baseline.json');
  writeBaseline(file, [finding()]);
  const set = loadBaseline(file);
  assert.ok(set.has(fingerprintFinding(finding())));
});

test('runAnalysis writes a baseline then suppresses it on the next run', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-baseline-proj-'));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'app.js'), 'const password = "supersecret123";\n', 'utf8');
  const baselineFile = path.join(root, '.csreview-baseline.json');
  const outputDir = path.join(root, 'out');

  const first = await runAnalysis(root, { outputDir, runTools: false, updateBaselinePath: baselineFile });
  assert.equal(first.baseline.written, baselineFile);
  assert.ok(first.totalFindings > 0); // writing the baseline does not hide this run

  const second = await runAnalysis(root, { outputDir, runTools: false, baselinePath: baselineFile });
  assert.equal(second.baseline.applied, true);
  assert.ok(second.baseline.baselinedCount > 0);
  assert.equal(second.totalFindings, 0); // all previously-seen findings are baselined
});
