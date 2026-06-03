// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectNodeAuditStrategy, normalizeBunAuditFindings } from '../src/index.js';

function setup(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-bun-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(root, rel), content, 'utf8');
  }
  return root;
}

test('detectNodeAuditStrategy selects bun when bun.lockb is present', () => {
  const root = setup({ 'package.json': '{"name":"app"}', 'bun.lockb': '\0binary\0' });
  const strategy = detectNodeAuditStrategy(root);
  assert.equal(strategy.command, 'bun');
  assert.equal(strategy.source, 'bun-audit');
  assert.equal(strategy.label, 'bun audit');
  assert.equal(strategy.lockfile, 'bun.lockb');
  assert.deepEqual(strategy.args, ['audit', '--json']);
});

test('detectNodeAuditStrategy selects bun for the text bun.lock too', () => {
  const root = setup({ 'package.json': '{"name":"app"}', 'bun.lock': '# bun lockfile\n' });
  const strategy = detectNodeAuditStrategy(root);
  assert.equal(strategy.command, 'bun');
  assert.equal(strategy.lockfile, 'bun.lock');
});

test('npm/pnpm lockfiles take priority over bun when both exist', () => {
  const root = setup({ 'package.json': '{"name":"app"}', 'package-lock.json': '{}', 'bun.lockb': '\0' });
  const strategy = detectNodeAuditStrategy(root);
  assert.equal(strategy.manager, 'npm');
});

test('normalizeBunAuditFindings maps npm-audit-shaped JSON to bun-audit findings', () => {
  const auditJson = {
    vulnerabilities: {
      lodash: {
        name: 'lodash',
        severity: 'high',
        isDirect: true,
        range: '<4.17.21',
        nodes: ['node_modules/lodash'],
        fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
        via: [{ title: 'Prototype Pollution', url: 'https://example.test/adv', cwe: ['CWE-1321'] }],
      },
    },
  };
  const findings = normalizeBunAuditFindings(auditJson, 'bun.lockb');
  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.id, 'BUN_AUDIT_1');
  assert.equal(finding.source, 'bun-audit');
  assert.equal(finding.file, 'bun.lockb');
  assert.match(finding.name, /^bun audit: lodash/);
  assert.equal(finding.severity, 'HIGH');
  assert.match(finding.compliance, /bun audit/);
});

test('normalizeBunAuditFindings tolerates empty input', () => {
  assert.deepEqual(normalizeBunAuditFindings({}), []);
});
