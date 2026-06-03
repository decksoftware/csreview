import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { BACKENDS, detectBackends, renderDumpGuideHtml, generateDumpGuide } from '../src/dumpGuide.js';

test('detects file-based databases by extension (sqlite, firebird, access, odb, hsqldb)', () => {
  const ids = detectBackends({
    paths: ['data/app.db', 'legacy/store.fdb', 'imports/contacts.mdb', 'reports/sample.odb', 'db/hsql.script'],
  }).map((b) => b.id);
  assert.ok(ids.includes('sqlite'));
  assert.ok(ids.includes('firebird'));
  assert.ok(ids.includes('msaccess'));
  assert.ok(ids.includes('libreoffice_base'));
  assert.ok(ids.includes('hsqldb'));
});

test('detects backends by config file, dependency and connection scheme', () => {
  const ids = detectBackends({
    paths: ['supabase/config.toml'],
    deps: ['mongoose'],
    hints: ['postgres://user@localhost/db', 'jdbc:hsqldb:file:db/data'],
  }).map((b) => b.id);
  assert.ok(ids.includes('supabase'));
  assert.ok(ids.includes('mongodb'));
  assert.ok(ids.includes('postgres'));
  assert.ok(ids.includes('hsqldb'));
});

test('renders the golden-rule banner and escapes the project name (no XSS)', () => {
  const detected = detectBackends({ paths: ['app.sqlite'] });
  const html = renderDumpGuideHtml('<script>alert(1)</script>', detected);
  assert.match(html, /Golden rule/);
  assert.match(html, /SQLite/);
  assert.match(html, /File-based database/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /&lt;script&gt;/);
});

test('generateDumpGuide writes only detected backend sections', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csr-dumpguide-'));
  const out = path.join(dir, 'guide.html');
  const result = generateDumpGuide(
    { name: 'demo', files: ['db/local.fdb'], configFiles: [], depFiles: [], baasFiles: [] },
    out,
    { deps: [] },
  );
  assert.ok(fs.existsSync(out));
  const html = fs.readFileSync(out, 'utf8');
  assert.ok(result.detected.includes('firebird'));
  assert.match(html, /Firebird/);
  assert.doesNotMatch(html, /MongoDB/);
});

test('every backend entry exposes the required guidance fields', () => {
  for (const b of BACKENDS) {
    assert.ok(
      b.id && b.name && b.copy && b.restore && b.needs && b.notes,
      `backend ${b.id} is missing required fields`,
    );
  }
  const ids = BACKENDS.map((b) => b.id);
  for (const required of ['libreoffice_base', 'hsqldb', 'firebird', 'msaccess', 'sqlite']) {
    assert.ok(ids.includes(required), `missing backend ${required}`);
  }
});
