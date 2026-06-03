// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectVulnerabilities, CONFIG_MISCONFIG_PATTERNS } from '../src/detector.js';

function setup(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-misconfig-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
  return root;
}

test('flags open BaaS security rules in a baas file', () => {
  const root = setup({
    'firestore.rules': 'service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}\n',
  });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'firestore.rules', language: 'unknown', kind: 'baas' }],
  });
  assert.ok(findings.some((f) => f.id.startsWith('BAAS_OPEN_SECURITY_RULES')));
});

test('does not flag scoped BaaS rules (if request.auth)', () => {
  const root = setup({
    'firestore.rules': 'match /users/{uid} {\n  allow read, write: if request.auth.uid == uid;\n}\n',
  });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'firestore.rules', language: 'unknown', kind: 'baas' }],
  });
  assert.ok(!findings.some((f) => f.id.startsWith('BAAS_OPEN_SECURITY_RULES')));
});

test('flags Dockerfile misconfigurations in a config file', () => {
  const root = setup({ Dockerfile: 'FROM node:latest\nUSER root\nRUN chmod 777 /app\n' });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'Dockerfile', language: 'unknown', kind: 'config' }],
  });
  const ids = findings.map((f) => f.id);
  assert.ok(ids.some((id) => id.startsWith('DOCKER_UNPINNED_BASE_IMAGE')));
  assert.ok(ids.some((id) => id.startsWith('CONTAINER_RUN_AS_ROOT')));
  assert.ok(ids.some((id) => id.startsWith('WORLD_WRITABLE_PERMISSIONS')));
});

test('flags disabled Row Level Security in a baas migration', () => {
  const root = setup({
    'supabase/migrations/0001_init.sql': 'ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;\n',
  });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'supabase/migrations/0001_init.sql', language: 'sql', kind: 'baas' }],
  });
  assert.ok(findings.some((f) => f.id.startsWith('SUPABASE_RLS_DISABLED')));
});

test('flags open network ingress (0.0.0.0/0) in terraform', () => {
  const root = setup({ 'main.tf': 'resource "aws_security_group" "x" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n' });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'main.tf', language: 'terraform', kind: 'config' }],
  });
  assert.ok(findings.some((f) => f.id.startsWith('OPEN_NETWORK_INGRESS')));
});

test('does NOT apply config misconfig patterns to application source', () => {
  const root = setup({
    'src/app.js':
      'const config = { privileged: true };\nconst acl = "public-read";\nconst opt = { rejectUnauthorized: false };\n',
  });
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'src/app.js', language: 'javascript', kind: 'source' }],
  });
  assert.ok(!findings.some((f) => f.id.startsWith('CONTAINER_PRIVILEGED')));
  assert.ok(!findings.some((f) => f.id.startsWith('STORAGE_PUBLIC_ACL')));
  assert.ok(!findings.some((f) => f.id.startsWith('TLS_VERIFICATION_DISABLED')));
});

test('every config misconfig pattern exposes the required metadata fields', () => {
  for (const pattern of CONFIG_MISCONFIG_PATTERNS) {
    assert.ok(pattern.id, 'id');
    assert.ok(pattern.severity, 'severity');
    assert.ok(pattern.category, 'category');
    assert.ok(pattern.name, 'name');
    assert.ok(pattern.regex instanceof RegExp, 'regex');
    assert.ok(pattern.regex.flags.includes('g'), 'global flag');
    assert.ok(/^CWE-\d+$/.test(pattern.cwe), 'cwe');
    assert.ok(pattern.fix, 'fix');
    assert.ok(pattern.owasp, 'owasp');
  }
});
