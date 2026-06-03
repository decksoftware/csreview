// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertOfficialUrl,
  ALLOWED_DOWNLOAD_HOSTS,
  platformTokens,
  pickReleaseAsset,
  pickChecksumsAsset,
  sha256,
  parseChecksums,
  verifyChecksum,
  ensureTool,
  TOOL_REGISTRY,
} from '../src/provision.js';

test('assertOfficialUrl accepts pinned official HTTPS hosts and rejects everything else', () => {
  assert.ok(ALLOWED_DOWNLOAD_HOSTS.has('github.com'));
  assert.doesNotThrow(() => assertOfficialUrl('https://github.com/gitleaks/gitleaks/releases/download/v8/x.tar.gz'));
  assert.doesNotThrow(() => assertOfficialUrl('https://objects.githubusercontent.com/abc'));
  assert.throws(() => assertOfficialUrl('http://github.com/x'), /non-HTTPS/);
  assert.throws(() => assertOfficialUrl('https://evil.com/x.tar.gz'), /non-official host/);
  assert.throws(() => assertOfficialUrl('not a url'), /not a valid URL/);
});

test('platformTokens maps node platform/arch to vendor synonym tokens', () => {
  const linux = platformTokens('linux', 'x64');
  assert.ok(linux.os.includes('linux'));
  assert.ok(linux.cpu.includes('amd64') && linux.cpu.includes('x86_64'));
  assert.equal(linux.isWindows, false);
  assert.ok(platformTokens('win32', 'x64').isWindows);
  assert.ok(platformTokens('darwin', 'arm64').os.includes('darwin'));
  assert.ok(platformTokens('darwin', 'arm64').cpu.includes('aarch64'));
});

test('pickReleaseAsset matches platform and prefers the right archive', () => {
  const assets = [
    { name: 'gitleaks_8.0.0_linux_x64.tar.gz', browser_download_url: 'https://github.com/a/linux.tgz' },
    { name: 'gitleaks_8.0.0_windows_x64.zip', browser_download_url: 'https://github.com/a/win.zip' },
    { name: 'gitleaks_8.0.0_darwin_arm64.tar.gz', browser_download_url: 'https://github.com/a/mac.tgz' },
    { name: 'gitleaks_8.0.0_checksums.txt', browser_download_url: 'https://github.com/a/checks.txt' },
  ];
  assert.match(pickReleaseAsset(assets, platformTokens('linux', 'x64')).name, /linux_x64\.tar\.gz/);
  assert.match(pickReleaseAsset(assets, platformTokens('win32', 'x64')).name, /windows_x64\.zip/);
  assert.match(pickReleaseAsset(assets, platformTokens('darwin', 'arm64')).name, /darwin_arm64\.tar\.gz/);
  assert.equal(pickReleaseAsset(assets, platformTokens('linux', 'ppc64')), null);
  assert.match(pickChecksumsAsset(assets).name, /checksums\.txt/);
});

test('sha256 / parseChecksums / verifyChecksum work together', () => {
  const buf = Buffer.from('fake-binary-bytes');
  const hash = sha256(buf);
  assert.match(hash, /^[a-f0-9]{64}$/);
  const checks = `deadbeef\n${hash}  gitleaks_8.0.0_linux_x64.tar.gz\n`;
  assert.equal(parseChecksums(checks, 'gitleaks_8.0.0_linux_x64.tar.gz'), hash);
  assert.equal(parseChecksums(checks, 'absent.tar.gz'), null);
  assert.ok(verifyChecksum(buf, hash));
  assert.ok(!verifyChecksum(buf, 'f'.repeat(64)));
  assert.ok(!verifyChecksum(buf, 'not-a-hash'));
});

const LINUX = platformTokens('linux', 'x64');

test('ensureTool: returns a tool already on PATH without downloading', async () => {
  let downloaded = false;
  const res = await ensureTool('gitleaks', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => ({ version: '8.18.0' }),
      download: async () => {
        downloaded = true;
        return '';
      },
    },
  });
  assert.equal(res.available, true);
  assert.equal(res.source, 'path');
  assert.equal(downloaded, false);
});

test('ensureTool: uses the isolated cache before downloading', async () => {
  const res = await ensureTool('gosec', {
    provision: true,
    platform: LINUX,
    io: { onPath: () => null, cacheLookup: () => ({ path: '/proj/.csreview/bin/gosec', version: '2.20.0' }) },
  });
  assert.equal(res.source, 'cache');
  assert.equal(res.path, '/proj/.csreview/bin/gosec');
});

test('ensureTool: without opt-in, does not download (fail-open, points to the flag)', async () => {
  let downloaded = false;
  const res = await ensureTool('gitleaks', {
    platform: LINUX,
    io: { onPath: () => null, cacheLookup: () => null, download: async () => ((downloaded = true), '') },
  });
  assert.equal(res.available, false);
  assert.equal(downloaded, false);
  assert.match(res.reason, /--provision-tools/);
});

test('ensureTool: opt-in happy path downloads, verifies checksum, installs', async () => {
  const buffer = Buffer.from('the-real-gitleaks-binary');
  const hash = sha256(buffer);
  let installed = false;
  const res = await ensureTool('gitleaks', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => null,
      cacheLookup: () => null,
      fetchLatestRelease: async () => ({
        tag: 'v8.18.0',
        assets: [
          {
            name: 'gitleaks_8.18.0_linux_x64.tar.gz',
            browser_download_url:
              'https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz',
          },
          {
            name: 'gitleaks_8.18.0_checksums.txt',
            browser_download_url:
              'https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_checksums.txt',
          },
        ],
      }),
      download: async (url) => (url.endsWith('checksums.txt') ? `${hash}  gitleaks_8.18.0_linux_x64.tar.gz\n` : buffer),
      install: () => {
        installed = true;
        return { path: '/proj/.csreview/bin/gitleaks', version: '8.18.0' };
      },
    },
  });
  assert.equal(res.available, true);
  assert.equal(res.source, 'provisioned');
  assert.equal(res.provisioned, true);
  assert.equal(installed, true);
});

test('ensureTool: a checksum mismatch rejects the artifact and never installs', async () => {
  const buffer = Buffer.from('tampered-binary');
  let installed = false;
  const res = await ensureTool('gitleaks', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => null,
      cacheLookup: () => null,
      fetchLatestRelease: async () => ({
        tag: 'v8.18.0',
        assets: [
          {
            name: 'gitleaks_8.18.0_linux_x64.tar.gz',
            browser_download_url:
              'https://github.com/gitleaks/gitleaks/releases/download/v8/gitleaks_8.18.0_linux_x64.tar.gz',
          },
          {
            name: 'gitleaks_8.18.0_checksums.txt',
            browser_download_url:
              'https://github.com/gitleaks/gitleaks/releases/download/v8/gitleaks_8.18.0_checksums.txt',
          },
        ],
      }),
      download: async (url) =>
        url.endsWith('checksums.txt') ? `${'a'.repeat(64)}  gitleaks_8.18.0_linux_x64.tar.gz\n` : buffer,
      install: () => ((installed = true), { path: 'x', version: 'y' }),
    },
  });
  assert.equal(res.available, false);
  assert.match(res.reason, /SHA-256 mismatch/);
  assert.equal(installed, false);
});

test('ensureTool: a non-official asset URL is refused (fail-open) and never installed', async () => {
  let installed = false;
  const res = await ensureTool('trivy', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => null,
      cacheLookup: () => null,
      fetchLatestRelease: async () => ({
        tag: 'v0.71.0',
        assets: [
          { name: 'trivy_0.71.0_linux_amd64.tar.gz', browser_download_url: 'https://evil.example.com/trivy.tar.gz' },
          { name: 'trivy_0.71.0_checksums.txt', browser_download_url: 'https://evil.example.com/checksums.txt' },
        ],
      }),
      download: async () => Buffer.from('x'),
      install: () => ((installed = true), { path: 'x' }),
    },
  });
  assert.equal(res.available, false);
  assert.match(res.reason, /non-official host/);
  assert.equal(installed, false);
});

test('ensureTool: refuses to download when no checksums file is published', async () => {
  const res = await ensureTool('gitleaks', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => null,
      cacheLookup: () => null,
      fetchLatestRelease: async () => ({
        tag: 'v8',
        assets: [{ name: 'gitleaks_8_linux_x64.tar.gz', browser_download_url: 'https://github.com/x/a.tgz' }],
      }),
      download: async () => Buffer.from('x'),
      install: () => ({ path: 'x' }),
    },
  });
  assert.equal(res.available, false);
  assert.match(res.reason, /checksums/i);
});

test('ensureTool: unknown tool fails closed', async () => {
  const res = await ensureTool('not-a-tool', { provision: true, io: {} });
  assert.equal(res.available, false);
  assert.match(res.reason, /unknown tool/);
});

test('TOOL_REGISTRY pins official repos', () => {
  assert.equal(TOOL_REGISTRY.gitleaks.repo, 'gitleaks/gitleaks');
  assert.equal(TOOL_REGISTRY.gosec.repo, 'securego/gosec');
  assert.equal(TOOL_REGISTRY.trivy.repo, 'aquasecurity/trivy');
});

test('ensureTool: a pathOnly tool (bandit) is used if on PATH but NEVER auto-downloaded (M2)', async () => {
  let releaseFetched = false;
  const res = await ensureTool('bandit', {
    provision: true,
    platform: LINUX,
    io: {
      onPath: () => null,
      cacheLookup: () => null,
      fetchLatestRelease: async () => {
        releaseFetched = true;
        return { assets: [] };
      },
    },
  });
  assert.equal(res.available, false);
  assert.match(res.reason, /pip install bandit/);
  assert.equal(releaseFetched, false); // pathOnly => never hits the releases API

  const onPath = await ensureTool('bandit', { io: { onPath: () => ({ version: '1.7.0' }) } });
  assert.equal(onPath.available, true);
  assert.equal(onPath.source, 'path');
});
