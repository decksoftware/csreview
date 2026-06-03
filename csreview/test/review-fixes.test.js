// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeNpmAuditFindings,
  normalizePnpmAuditFindings,
  normalizeOsvScannerFindings,
  normalizeBunAuditFindings,
} from '../src/index.js';
import { checkForUpdate } from '../src/updateCheck.js';
import { buildSarifLog } from '../src/reports/sarif.js';

test('SCA normalizers fail closed on null / non-object input', () => {
  for (const fn of [normalizeNpmAuditFindings, normalizePnpmAuditFindings, normalizeBunAuditFindings]) {
    assert.deepEqual(fn(null), []);
    assert.deepEqual(fn(undefined), []);
    assert.deepEqual(fn('oops'), []);
    assert.deepEqual(fn(42), []);
  }
  // A string where an object is expected must not be spread into char findings.
  assert.deepEqual(normalizeNpmAuditFindings({ vulnerabilities: 'oops' }), []);
  assert.deepEqual(normalizePnpmAuditFindings({ advisories: 'oops' }), []);
  assert.deepEqual(normalizeOsvScannerFindings(null), []);
  assert.deepEqual(normalizeOsvScannerFindings({ results: 'oops' }), []);
});

test('checkForUpdate refuses a malformed repo without fetching (SSRF pin, L2)', async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    throw new Error('fetch should not be called for an invalid repo');
  };
  const result = await checkForUpdate('0.1.0', { fetchImpl, repo: 'http://evil.com/x/y' });
  assert.equal(result.checked, false);
  assert.equal(called, false);
  assert.match(result.error, /invalid repo/);
});

test('checkForUpdate refuses a malformed branch without fetching', async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    throw new Error('fetch should not be called for an invalid branch');
  };
  const result = await checkForUpdate('0.1.0', { fetchImpl, branch: 'main && curl evil' });
  assert.equal(result.checked, false);
  assert.equal(called, false);
});

test('buildSarifLog skips null/undefined findings (nit)', () => {
  const valid = { severity: 'HIGH', cwe: 'CWE-79', category: 'XSS', name: 'x', file: 'a.js', line: 1 };
  const log = buildSarifLog({}, [null, valid, undefined], {});
  assert.equal(log.runs[0].results.length, 1);
});
