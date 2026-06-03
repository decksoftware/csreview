import assert from 'node:assert/strict';
import test from 'node:test';
import { compareVersions, checkForUpdate, scanTextForRedFlags } from '../src/updateCheck.js';
import { parseVersion, checkToolFreshness, TOOL_REGISTRY } from '../src/toolFreshness.js';

function makeFetch(routes) {
  return async (url) => {
    const key = Object.keys(routes).find((k) => String(url).includes(k));
    if (key === undefined) {
      return {
        ok: false,
        status: 404,
        async json() {
          return {};
        },
        async text() {
          return '';
        },
      };
    }
    const value = routes[key];
    return {
      ok: true,
      status: 200,
      async json() {
        return typeof value === 'string' ? JSON.parse(value) : value;
      },
      async text() {
        return typeof value === 'string' ? value : JSON.stringify(value);
      },
    };
  };
}

// ---------- updateCheck ----------

test('compareVersions orders dotted versions correctly', () => {
  assert.equal(compareVersions('1.2.0', '1.1.9'), 1);
  assert.equal(compareVersions('0.1.3', '0.1.3'), 0);
  assert.equal(compareVersions('0.1.3', '0.2.0'), -1);
  assert.equal(compareVersions('v2.0.0', '1.9.9'), 1);
});

test('checkForUpdate reports an available update from the official package.json', async () => {
  const fetchImpl = makeFetch({ 'raw.githubusercontent.com': '{"version":"0.2.0"}' });
  const result = await checkForUpdate('0.1.3', { fetchImpl });
  assert.equal(result.checked, true);
  assert.equal(result.latest, '0.2.0');
  assert.equal(result.updateAvailable, true);
});

test('checkForUpdate prefers a newer release tag when present', async () => {
  const fetchImpl = makeFetch({
    'raw.githubusercontent.com': '{"version":"0.2.0"}',
    'releases/latest': { tag_name: 'v0.3.0' },
  });
  const result = await checkForUpdate('0.2.0', { fetchImpl });
  assert.equal(result.latest, '0.3.0');
  assert.equal(result.updateAvailable, true);
  assert.match(result.source, /release/);
});

test('checkForUpdate is fail-open when offline (never throws)', async () => {
  const throwing = async () => {
    throw new Error('offline');
  };
  const offline = await checkForUpdate('0.1.3', { fetchImpl: throwing });
  assert.equal(offline.checked, false);
  assert.equal(offline.updateAvailable, false);

  const all404 = await checkForUpdate('0.1.3', { fetchImpl: makeFetch({}) });
  assert.equal(all404.checked, false);
  assert.equal(all404.updateAvailable, false);
});

test('scanTextForRedFlags catches risky changes and is clean otherwise', () => {
  const risky = scanTextForRedFlags('const x = require("child_process").execSync(cmd);');
  assert.ok(risky.some((f) => f.id === 'process-exec'));

  const dep = scanTextForRedFlags('+  "dependencies": { "evil": "1.0.0" }');
  assert.ok(dep.some((f) => f.id === 'dependency-change'));

  assert.deepEqual(scanTextForRedFlags('const safe = a + b;'), []);
});

// ---------- toolFreshness ----------

test('parseVersion extracts version from --version output', () => {
  assert.equal(parseVersion('semgrep 1.164.0'), '1.164.0');
  assert.equal(parseVersion('osv-scanner version: 2.3.8\nbuilt at ...'), '2.3.8');
  assert.equal(parseVersion('no version here'), null);
});

test('checkToolFreshness flags outdated tools and skips unavailable ones', async () => {
  const fetchImpl = makeFetch({
    'pypi.org/pypi/semgrep': { info: { version: '1.164.0' } },
    'google/osv-scanner': { tag_name: 'v2.3.8' },
  });
  const results = await checkToolFreshness(
    { semgrep: 'semgrep 1.100.0', 'osv-scanner': 'osv-scanner version: 2.3.8' },
    { fetchImpl },
  );
  assert.equal(results.length, 2); // trivy/npm/etc not installed -> skipped
  const semgrep = results.find((r) => r.name === 'semgrep');
  const osv = results.find((r) => r.name === 'osv-scanner');
  assert.equal(semgrep.status, 'outdated');
  assert.equal(osv.status, 'current');
  assert.match(semgrep.update, /pipx upgrade semgrep/);
});

test('checkToolFreshness is fail-open when offline (status unknown, never throws)', async () => {
  const throwing = async () => {
    throw new Error('offline');
  };
  const results = await checkToolFreshness({ semgrep: 'semgrep 1.100.0' }, { fetchImpl: throwing });
  assert.equal(results.length, 1);
  assert.equal(results[0].status, 'unknown');
});

test('every tool in the registry has an update hint and db mode', () => {
  for (const tool of TOOL_REGISTRY) {
    assert.ok(tool.name && tool.update && tool.dbMode, `tool ${tool.name} missing fields`);
    assert.ok(['online', 'local-db', 'bundled'].includes(tool.dbMode));
  }
});
