// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectVulnerabilities } from '../src/detector.js';

// Calibration guards driven by real user feedback: the internal detector was
// "shouting fire because it saw the word match in the dictionary" — WEAK_CIPHER
// matched the "des" substring inside includes/excludes/modes, IDs collided
// (WEAK_CIPHER_0 repeated), and test fixtures cratered the score.

function scan(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-calib-'));
  for (const f of files) {
    const abs = path.join(root, f.path);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, f.code, 'utf8');
  }
  return detectVulnerabilities({
    root,
    files: files.map((f) => ({ path: f.path, language: f.language || 'javascript', kind: f.kind || 'source' })),
  });
}

test('WEAK_CIPHER does not fire on the "des" substring in includes/excludes/modes', () => {
  const findings = scan([
    { path: 'src/a.js', code: "export const f = (args) => args.includes('--no-update-check');\n" },
    { path: 'src/b.js', code: "export const ok = (ids) => ids.includes('postgres');\n" },
    { path: 'src/c.js', code: 'export const modes = (x) => x.excludes && x.decodes;\n' },
    { path: 'src/d.js', code: 'export const nodes = ["a"];\nexport const provides = true;\n' },
  ]);
  const wc = findings.filter((f) => String(f.id).startsWith('WEAK_CIPHER'));
  assert.equal(wc.length, 0, `unexpected WEAK_CIPHER FPs: ${wc.map((f) => `${f.file}:${f.line}`).join(', ')}`);
});

test('WEAK_CIPHER still detects real weak-cipher usage (recall preserved)', () => {
  const findings = scan([
    {
      path: 'src/n.js',
      code: 'import crypto from "crypto";\nexport const e = (k, iv) => crypto.createCipheriv("des-ede3-cbc", k, iv);\n',
    },
    {
      path: 'src/cjs.js',
      code: 'import CryptoJS from "crypto-js";\nexport const e = (d) => CryptoJS.DES.encrypt(d, "key");\n',
    },
    {
      path: 'src/ecb.js',
      code: 'import crypto from "crypto";\nexport const e = (k, iv) => crypto.createCipheriv("aes-128-ecb", k, iv);\n',
    },
    {
      path: 'src/J.java',
      language: 'java',
      code: 'class A { void f() throws Exception { Cipher.getInstance("DES"); } }\n',
    },
  ]);
  const wc = findings.filter((f) => f.cwe === 'CWE-327');
  assert.ok(wc.length >= 4, `expected >= 4 weak-cipher detections, got ${wc.length}`);
});

test('detector assigns globally-unique finding IDs across files (no WEAK_CIPHER_0 collision)', () => {
  const findings = scan([
    {
      path: 'src/a.js',
      code: 'import crypto from "crypto";\nexport const e = (k, iv) => crypto.createCipheriv("rc4", k, iv);\n',
    },
    {
      path: 'src/b.js',
      code: 'import crypto from "crypto";\nexport const e = (k, iv) => crypto.createCipheriv("rc4", k, iv);\n',
    },
  ]);
  const ids = findings.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, `duplicate IDs present: ${ids.join(', ')}`);
});

test('findings in non-source paths (test/fixtures) are downgraded; real source keeps its severity', () => {
  const srcFindings = scan([{ path: 'src/x.js', code: 'export const key = "AKIAIOSFODNN7EXAMPLE";\n' }]);
  const testFindings = scan([{ path: 'test/x.test.js', code: 'export const key = "AKIAIOSFODNN7EXAMPLE";\n' }]);
  const inSrc = srcFindings.find((f) => String(f.id).startsWith('AWS_ACCESS_KEY'));
  const inTest = testFindings.find((f) => String(f.id).startsWith('AWS_ACCESS_KEY'));
  assert.ok(inSrc && inTest, 'AWS key detected in both src and test');
  assert.equal(inSrc.severity, 'CRITICAL', 'real source finding keeps full severity');
  assert.equal(inTest.severity, 'LOW', 'test/fixture finding is downgraded to LOW');
  assert.equal(inTest.confidence, 'LOW');
});
