import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { detectVulnerabilities } from '../src/detector.js';
import { normalizeSemgrepFinding } from '../src/index.js';

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'csr-qw-'));
}
function write(root, rel, content) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, 'utf8');
}

// --- Task 2: drop the broad, FP-prone UNSAFE_EVAL (keep precise TEMPLATE_INJECTION_EVAL) ---

test('eval with dynamic input yields exactly one CWE-95 finding (no UNSAFE_EVAL dup)', () => {
  const root = tmp();
  write(root, 'src/x.js', 'const r = eval(req.body.code);\n');
  const findings = detectVulnerabilities({ root, files: [{ path: 'src/x.js', language: 'javascript' }] });
  const cwe95 = findings.filter((f) => f.cwe === 'CWE-95');
  assert.equal(cwe95.length, 1);
  assert.ok(cwe95[0].id.startsWith('TEMPLATE_INJECTION_EVAL'));
});

test('static eval("1 + 1") is not flagged after removing the broad UNSAFE_EVAL heuristic', () => {
  const root = tmp();
  write(root, 'src/y.js', 'const z = eval("1 + 1");\n');
  const findings = detectVulnerabilities({ root, files: [{ path: 'src/y.js', language: 'javascript' }] });
  assert.equal(findings.filter((f) => f.cwe === 'CWE-95').length, 0);
});

// --- Task 3: semgrep severity can reach CRITICAL via metadata ---

test('semgrep ERROR with metadata.impact HIGH maps to CRITICAL', () => {
  const f = normalizeSemgrepFinding(
    { check_id: 'r', path: 'a.js', start: { line: 3 }, extra: { severity: 'ERROR', metadata: { impact: 'HIGH' } } },
    0,
  );
  assert.equal(f.severity, 'CRITICAL');
});

test('semgrep ERROR without high impact stays HIGH', () => {
  const f = normalizeSemgrepFinding(
    { check_id: 'r', path: 'a.js', start: { line: 3 }, extra: { severity: 'ERROR', metadata: {} } },
    0,
  );
  assert.equal(f.severity, 'HIGH');
});

// --- Task 4: suppress noisy heuristics in test/spec/docs paths (secrets stay active) ---

test('noisy heuristic kept in source but suppressed in test files', () => {
  const root = tmp();
  write(root, 'src/r.js', 'const token = Math.random();\n');
  write(root, 'src/r.test.js', 'const token = Math.random();\n');
  const inSrc = detectVulnerabilities({ root, files: [{ path: 'src/r.js', language: 'javascript' }] });
  const inTest = detectVulnerabilities({ root, files: [{ path: 'src/r.test.js', language: 'javascript' }] });
  assert.ok(inSrc.some((f) => f.id.startsWith('WEAK_RANDOM_GENERAL')));
  assert.ok(!inTest.some((f) => f.id.startsWith('WEAK_RANDOM_GENERAL')));
});
