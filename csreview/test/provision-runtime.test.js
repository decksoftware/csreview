// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  probeOnPath,
  cacheLookup,
  fetchLatestRelease,
  downloadBuffer,
  downloadText,
  installFromArchiveAsync,
  makeSecurityToolGatherer,
} from '../src/provisionRuntime.js';

test('probeOnPath returns a version from --version output, or null when missing', async () => {
  const ok = await probeOnPath('gitleaks', ['version'], async () => ({ stdout: 'v8.18.0\n' }));
  assert.equal(ok.version, '8.18.0');
  const missing = await probeOnPath('nope', ['--version'], async () => {
    throw new Error('ENOENT');
  });
  assert.equal(missing, null);
});

test('cacheLookup finds a previously provisioned binary (bin or bin.exe)', () => {
  const gitleaksPath = path.join('/cache', 'gitleaks');
  assert.equal(cacheLookup('/cache', 'gitleaks', (p) => p === gitleaksPath).path, gitleaksPath);
  assert.equal(
    cacheLookup('/cache', 'trivy', (p) => p === path.join('/cache', 'trivy.exe')).path,
    path.join('/cache', 'trivy.exe'),
  );
  assert.equal(
    cacheLookup('/cache', 'gosec', () => false),
    null,
  );
});

test('fetchLatestRelease maps the GitHub release payload and is fail-open', async () => {
  const fetchImpl = async () => ({
    ok: true,
    json: async () => ({
      tag_name: 'v8.18.0',
      assets: [{ name: 'gitleaks_8.18.0_linux_x64.tar.gz', browser_download_url: 'https://github.com/x/a.tgz' }],
    }),
  });
  const rel = await fetchLatestRelease('gitleaks/gitleaks', /** @type {any} */ (fetchImpl));
  assert.equal(rel.tag, 'v8.18.0');
  assert.equal(rel.assets.length, 1);

  assert.equal(await fetchLatestRelease('x/y', /** @type {any} */ (async () => ({ ok: false }))), null);
  assert.equal(await fetchLatestRelease('x/y', /** @type {any} */ (undefined)), null);
});

test('downloadBuffer/downloadText refuse non-official hosts before fetching', async () => {
  let called = false;
  const fetchImpl = /** @type {any} */ (
    async () => {
      called = true;
      return { ok: true, arrayBuffer: async () => new ArrayBuffer(0), text: async () => '' };
    }
  );
  await assert.rejects(() => downloadBuffer('https://evil.com/x.tar.gz', fetchImpl), /non-official host/);
  await assert.rejects(() => downloadText('http://github.com/x', fetchImpl), /non-HTTPS/);
  assert.equal(called, false);

  const buf = await downloadBuffer('https://github.com/gitleaks/gitleaks/releases/download/v8/a.tar.gz', fetchImpl);
  assert.ok(Buffer.isBuffer(buf));
});

test('installFromArchiveAsync extracts the binary into the isolated cache dir', async () => {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-cache-'));
  const extractImpl = async (_archivePath, destDir) => {
    fs.writeFileSync(path.join(destDir, 'gitleaks'), 'fake-binary');
  };
  const res = await installFromArchiveAsync({
    buffer: Buffer.from('archive-bytes'),
    assetName: 'gitleaks_8.18.0_linux_x64.tar.gz',
    bin: 'gitleaks',
    cacheDir,
    extractImpl,
  });
  assert.ok(res.path.startsWith(cacheDir));
  assert.ok(fs.existsSync(res.path));
});

test('makeSecurityToolGatherer runs tools available on PATH (no download when provision is false)', async () => {
  const gitleaksJson = JSON.stringify([{ RuleID: 'aws', File: 'a.js', StartLine: 1, Secret: 'zzzz' }]);
  let downloaded = false;
  const execImpl = async (file, argv) => {
    if (argv.includes('version') || argv.includes('--version')) return { stdout: '1.2.3' };
    if (argv[0] === 'dir') return { stdout: gitleaksJson }; // gitleaks run
    return { stdout: '{"Results":[]}' }; // trivy run
  };
  const fetchImpl = /** @type {any} */ (
    async () => {
      downloaded = true;
      return { ok: false };
    }
  );
  const gather = makeSecurityToolGatherer({ rootDir: '/proj', provision: false, impls: { execImpl, fetchImpl } });
  const { findings, results } = await gather({ techStack: [] }, '/proj');

  assert.ok(findings.some((f) => f.source === 'gitleaks'));
  assert.ok(results.find((r) => r.tool === 'gitleaks').available);
  assert.equal(downloaded, false); // provision:false => never hits the releases API
});
