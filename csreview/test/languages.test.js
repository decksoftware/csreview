// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getLanguage, LANG_MAP, EXTENSION_TO_TECH } from '../src/languages.js';
import { detectVulnerabilities } from '../src/detector.js';

// Extension→language used to live in THREE divergent maps (index.js LANG_MAP,
// detector.js LANGUAGE_MAP, scanner.js EXTENSION_TO_TECH). The detector copy
// was already stale: .pyw never resolved to python, so Python-specific rules
// (pickle/yaml/SQL) silently skipped *.pyw files.

test('getLanguage resolves common and previously-missing extensions', () => {
  assert.equal(getLanguage('src/app.ts'), 'typescript');
  assert.equal(getLanguage('src/tool.pyw'), 'python');
  assert.equal(getLanguage('src/main.pas'), 'delphi');
  assert.equal(getLanguage('README'), 'unknown');
  assert.equal(getLanguage('archive.unknownext'), 'unknown');
});

test('language and tech maps agree on the extensions they share', () => {
  for (const ext of ['py', 'pyw', 'go', 'rs', 'kt', 'dart']) {
    assert.ok(LANG_MAP[ext], `LANG_MAP missing ${ext}`);
    assert.ok(EXTENSION_TO_TECH[ext], `EXTENSION_TO_TECH missing ${ext}`);
  }
});

test('detector applies Python-specific rules to .pyw files via the shared fallback', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-lang-'));
  const rel = 'src/loader.pyw';
  const abs = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, 'import pickle\n\ndef load(data):\n    return pickle.loads(data)\n', 'utf8');

  // No language provided: the detector must fall back to the shared map.
  const findings = detectVulnerabilities({ root, files: [{ path: rel, kind: 'source' }] });
  assert.ok(
    findings.some((f) => String(f.cwe).includes('CWE-502')),
    `expected CWE-502 from PY_DESERIALIZE on a .pyw file, got: ${findings.map((f) => f.id).join(', ') || 'none'}`,
  );
});
