import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  OPENGREP_VERSION,
  buildOpenGrepArgs,
  classifyOpenGrepDiagnostic,
  detectLinuxLibc,
  getPrivateToolCacheRoot,
  normalizeOpenGrepFinding,
  provisionOpenGrep,
  resolveOpenGrep,
  runOpenGrep,
  selectOpenGrepArtifact,
  summarizeOpenGrepDiagnostics,
  validateOpenGrepConfig,
  validateTrustedOpenGrep,
} from '../src/opengrep.js';

const tempDirs = [];
const execFileAsync = promisify(execFile);

function tempDir(prefix = 'csreview-opengrep-') {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

test.afterEach(() => {
  while (tempDirs.length) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

test('selectOpenGrepArtifact exposes only approved OpenGrep 1.26.0 artifacts', () => {
  assert.equal(OPENGREP_VERSION, '1.26.0');
  assert.deepEqual(selectOpenGrepArtifact({ platform: 'win32', arch: 'x64' }), {
    platform: 'win32',
    arch: 'x64',
    libc: null,
    filename: 'opengrep_windows_x86.exe',
    sha256: '4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3',
    sourceUrl: 'https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_windows_x86.exe',
    maxBytes: 104857600,
  });
  assert.equal(selectOpenGrepArtifact({ platform: 'win32', arch: 'arm64' }), null);
  assert.equal(detectLinuxLibc({ platform: 'linux', reportHeader: {} }), 'musl');
  assert.equal(detectLinuxLibc({ platform: 'linux', reportHeader: { glibcVersionRuntime: '2.39' } }), 'glibc');
  assert.equal(
    selectOpenGrepArtifact({ platform: 'linux', arch: 'arm64', reportHeader: {} }).filename,
    'opengrep_musllinux_aarch64',
  );
});

test('rulepack manifest hashes match the distributed local rule source', () => {
  const ruleFile = path.resolve('rules', 'csreview.yml');
  const digest = createHash('sha256').update(readFileSync(ruleFile)).digest('hex');
  const manifest = JSON.parse(readFileSync(path.resolve('rules', 'manifest.json'), 'utf8'));

  assert.ok(manifest.rules.length >= 2);
  for (const rule of manifest.rules) {
    assert.equal(rule.sourcePath, 'rules/csreview.yml');
    assert.equal(rule.sourceHash, digest);
    assert.equal(rule.transformedHash, digest);
    assert.equal(rule.spdxLicense, 'MIT');
  }
});

test('getPrivateToolCacheRoot keeps the tool cache outside audited projects', () => {
  assert.equal(
    getPrivateToolCacheRoot({ platform: 'win32', env: { LOCALAPPDATA: 'C:\\Users\\demo\\AppData\\Local' } }),
    path.resolve('C:\\Users\\demo\\AppData\\Local', 'CSReview', 'tools'),
  );
  assert.equal(
    getPrivateToolCacheRoot({ platform: 'linux', env: { XDG_CACHE_HOME: '/var/cache/demo' }, homeDir: '/home/demo' }),
    path.resolve('/var/cache/demo', 'csreview', 'tools'),
  );
  assert.equal(
    getPrivateToolCacheRoot({ platform: 'darwin', env: {}, homeDir: '/Users/demo' }),
    path.resolve('/Users/demo', '.cache', 'csreview', 'tools'),
  );
  assert.equal(
    getPrivateToolCacheRoot({ platform: 'linux', env: { XDG_CACHE_HOME: 'relative-cache' }, homeDir: '/home/demo' }),
    path.resolve('/home/demo', '.cache', 'csreview', 'tools'),
  );
});

test('validateOpenGrepConfig accepts existing local paths and rejects remote or registry configs', () => {
  const root = tempDir();
  const localRules = path.join(root, 'rules');
  mkdirSync(localRules);

  assert.equal(validateOpenGrepConfig('./rules', { cwd: root }), localRules);
  for (const value of ['auto', 'p/security-audit', 'https://example.test/rules.yml', 'registry-rule']) {
    assert.throws(
      () => validateOpenGrepConfig(value, { cwd: root }),
      /--opengrep-config must resolve to an existing local file or directory/i,
    );
  }
});

test('buildOpenGrepArgs is offline, uses bundled rules, and never enables unsafe switches', () => {
  const args = buildOpenGrepArgs('C:\\audit-target', {
    rulepackPath: 'C:\\csreview\\rules',
    configPath: 'C:\\audit-target\\extra-rules',
    excludes: ['node_modules', 'dist'],
  });

  assert.deepEqual(args, [
    'scan',
    '--config',
    path.resolve('C:\\csreview\\rules'),
    '--config',
    path.resolve('C:\\audit-target\\extra-rules'),
    '--json',
    '--quiet',
    '--disable-version-check',
    '--exclude',
    'node_modules',
    '--exclude',
    'dist',
    path.resolve('C:\\audit-target'),
  ]);
  for (const forbidden of ['auto', '--autofix', '--allow-local-builds', '--allow-untrusted-validators']) {
    assert.ok(!args.includes(forbidden));
  }
});

test('normalizeOpenGrepFinding emits OpenGrep-owned source and stable schema', () => {
  const finding = normalizeOpenGrepFinding(
    {
      check_id: 'csreview.javascript.security.eval-detected',
      path: 'src/app.js',
      start: { line: 8 },
      extra: {
        severity: 'ERROR',
        message: 'Dynamic eval can execute attacker-controlled code.',
        lines: 'eval(userInput)',
        metadata: {
          impact: 'HIGH',
          cwe: ['CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code'],
          owasp: ['A03:2021 - Injection'],
          references: ['https://cwe.mitre.org/data/definitions/95.html'],
        },
      },
    },
    0,
  );

  assert.equal(finding.id, 'OPENGREP_1');
  assert.equal(finding.source, 'opengrep');
  assert.equal(finding.severity, 'CRITICAL');
  assert.equal(finding.cwe, 'CWE-95');
  assert.equal(finding.file, 'src/app.js');
  assert.equal(finding.line, 8);
});

test('classifyOpenGrepDiagnostic distinguishes complete, partial, and rule-error scans', () => {
  assert.equal(classifyOpenGrepDiagnostic({ results: [], paths: { skipped: [] } }), 'complete');
  assert.equal(
    classifyOpenGrepDiagnostic({ results: [], paths: { skipped: [{ path: 'vendor/app.js' }] } }),
    'partial-skips',
  );
  assert.equal(
    classifyOpenGrepDiagnostic({
      errors: [{ message: 'invalid rule' }],
      paths: { skipped: [{ path: 'vendor/app.js' }] },
    }),
    'rule-errors',
  );

  assert.deepEqual(
    summarizeOpenGrepDiagnostics({
      errors: [],
      paths: { skipped: [{ path: 'vendor/app.js', reason: 'size limit' }, 'generated/cache.js'] },
    }),
    {
      diagnostic: 'partial-skips',
      complete: false,
      ruleErrorCount: 0,
      skippedCount: 2,
      skippedReasons: ['size limit', 'generated/cache.js'],
    },
  );
});

test('runOpenGrep marks JSON scan errors unavailable instead of reporting a clean primary scan', async () => {
  const targetRoot = tempDir();
  const binaryDir = tempDir();
  const cacheRoot = tempDir();
  const binaryPath = path.join(binaryDir, 'opengrep.exe');
  const bytes = Buffer.from('trusted-test-binary');
  writeFileSync(binaryPath, bytes);
  const artifact = {
    platform: 'win32',
    arch: 'x64',
    libc: null,
    filename: 'opengrep_windows_x86.exe',
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sourceUrl: 'https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_windows_x86.exe',
    maxBytes: 1024,
  };
  const execImpl = async (_file, args) => {
    if (args[0] === '--version') return { stdout: 'opengrep 1.26.0', stderr: '' };
    return {
      stdout: JSON.stringify({ results: [], errors: [{ message: 'rule parse failed' }], paths: { skipped: [] } }),
      stderr: '',
    };
  };

  const result = await runOpenGrep(targetRoot, {
    artifact,
    platform: 'win32',
    arch: 'x64',
    cacheRoot,
    env: { PATH: binaryDir, PATHEXT: '.EXE' },
    execImpl,
  });

  assert.equal(result.available, false);
  assert.equal(result.diagnostic, 'rule-errors');
  assert.equal(result.complete, false);
  assert.equal(result.ruleErrorCount, 1);
  assert.match(result.error, /primary SAST is incomplete/i);
});

test('resolveOpenGrep ignores a legacy target-local cache', async () => {
  const targetRoot = tempDir();
  const cacheRoot = tempDir();
  const legacyDir = path.join(targetRoot, '.csreview', 'bin');
  mkdirSync(legacyDir, { recursive: true });
  writeFileSync(path.join(legacyDir, 'opengrep.exe'), 'untrusted');

  const result = await resolveOpenGrep({
    targetRoot,
    cacheRoot,
    provision: false,
    env: { PATH: '' },
    platform: 'win32',
    arch: 'x64',
  });

  assert.equal(result.available, false);
  assert.equal(result.legacyCacheIgnored, true);
  assert.match(result.reason, /--provision-tools/);
});

test('runOpenGrep rejects remote configs before resolving or executing a tool', async () => {
  const targetRoot = tempDir();
  let executed = false;
  await assert.rejects(
    runOpenGrep(targetRoot, {
      configPath: 'https://example.test/rules.yml',
      cacheRoot: tempDir(),
      env: { PATH: '' },
      execImpl: async () => {
        executed = true;
        return { stdout: '', stderr: '' };
      },
    }),
    /--opengrep-config must resolve to an existing local file or directory/i,
  );
  assert.equal(executed, false);
});

test('validateTrustedOpenGrep rejects executables inside the audited target before execution', async () => {
  const targetRoot = tempDir();
  const binaryPath = path.join(targetRoot, 'opengrep.exe');
  writeFileSync(binaryPath, 'untrusted');
  let executed = false;

  const result = await validateTrustedOpenGrep(binaryPath, {
    targetRoot,
    cacheRoot: tempDir(),
    requireManifest: false,
    execImpl: async () => {
      executed = true;
      return { stdout: '1.26.0', stderr: '' };
    },
  });

  assert.equal(result.available, false);
  assert.match(result.reason, /inside the audited target/i);
  assert.equal(executed, false);
});

test('provisionOpenGrep atomically installs only an approved digest into the private cache', async () => {
  const bytes = Buffer.from('approved-opengrep-test-binary');
  const digest = createHash('sha256').update(bytes).digest('hex');
  const targetRoot = tempDir();
  const cacheRoot = tempDir();
  const artifact = {
    platform: 'win32',
    arch: 'x64',
    libc: null,
    filename: 'opengrep_windows_x86.exe',
    sha256: digest,
    sourceUrl: 'https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_windows_x86.exe',
    maxBytes: 1024,
  };

  const result = await provisionOpenGrep({
    targetRoot,
    cacheRoot,
    artifact,
    platform: 'win32',
    arch: 'x64',
    download: async () => bytes,
    execImpl: async () => ({ stdout: 'opengrep 1.26.0', stderr: '' }),
    now: () => new Date('2026-08-19T12:00:00.000Z'),
  });

  assert.equal(result.available, true);
  assert.equal(result.source, 'provisioned');
  assert.ok('manifestPath' in result);
  assert.equal(createHash('sha256').update(readFileSync(result.path)).digest('hex'), digest);
  assert.deepEqual(JSON.parse(readFileSync(result.manifestPath, 'utf8')), {
    tool: 'opengrep',
    version: '1.26.0',
    platform: 'win32',
    arch: 'x64',
    sourceUrl: artifact.sourceUrl,
    sha256: digest,
    size: bytes.length,
    installedAt: '2026-08-19T12:00:00.000Z',
  });
});

test('provisionOpenGrep rejects an overlapping private cache before download or writes', async () => {
  const targetRoot = tempDir();
  const cacheRoot = path.join(targetRoot, '.cache', 'csreview', 'tools');
  let downloaded = false;

  const result = await provisionOpenGrep({
    targetRoot,
    cacheRoot,
    platform: 'win32',
    arch: 'x64',
    download: async () => {
      downloaded = true;
      return Buffer.from('must-not-download');
    },
  });

  assert.equal(result.available, false);
  assert.match(result.reason, /must not overlap the audited target/i);
  assert.equal(downloaded, false);
  assert.equal(existsSync(cacheRoot), false);
});

test('provisionOpenGrep resolves symlinked cache ancestors before allowing writes', async () => {
  const targetRoot = tempDir();
  const outsideRoot = tempDir();
  const realCacheAncestor = path.join(targetRoot, 'linked-cache');
  const linkedCacheAncestor = path.join(outsideRoot, 'cache-link');
  mkdirSync(realCacheAncestor);
  symlinkSync(realCacheAncestor, linkedCacheAncestor, process.platform === 'win32' ? 'junction' : 'dir');
  let downloaded = false;

  const result = await provisionOpenGrep({
    targetRoot,
    cacheRoot: path.join(linkedCacheAncestor, 'nested'),
    platform: 'win32',
    arch: 'x64',
    download: async () => {
      downloaded = true;
      return Buffer.from('must-not-download');
    },
  });

  assert.equal(result.available, false);
  assert.match(result.reason, /must not overlap the audited target/i);
  assert.equal(downloaded, false);
  assert.equal(existsSync(path.join(realCacheAncestor, 'nested')), false);
});

test('provisionOpenGrep refuses the default user cache when auditing that user home', async () => {
  const targetRoot = tempDir();
  const cacheRoot = getPrivateToolCacheRoot({ platform: 'linux', env: {}, homeDir: targetRoot });
  let downloaded = false;

  const result = await provisionOpenGrep({
    targetRoot,
    cacheRoot,
    platform: 'win32',
    arch: 'x64',
    download: async () => {
      downloaded = true;
      return Buffer.from('must-not-download');
    },
  });

  assert.equal(result.available, false);
  assert.match(result.reason, /must not overlap the audited target/i);
  assert.equal(downloaded, false);
  assert.equal(existsSync(cacheRoot), false);
});

test('provisionOpenGrep rejects wrong hashes and non-official artifact hosts without execution', async () => {
  const targetRoot = tempDir();
  const cacheRoot = tempDir();
  let executed = false;
  const base = {
    targetRoot,
    cacheRoot,
    platform: 'win32',
    arch: 'x64',
    download: async () => Buffer.from('wrong'),
    execImpl: async () => {
      executed = true;
      return { stdout: '1.26.0', stderr: '' };
    },
  };

  const wrongHash = await provisionOpenGrep({
    ...base,
    artifact: selectOpenGrepArtifact({ platform: 'win32', arch: 'x64' }),
  });
  assert.equal(wrongHash.available, false);
  assert.match(wrongHash.reason, /SHA-256 mismatch/i);

  const hostileHost = await provisionOpenGrep({
    ...base,
    artifact: {
      ...selectOpenGrepArtifact({ platform: 'win32', arch: 'x64' }),
      sourceUrl: 'https://evil.example/opengrep.exe',
    },
  });
  assert.equal(hostileHost.available, false);
  assert.match(hostileHost.reason, /non-official host/i);
  assert.equal(executed, false);
});

test(
  'bundled OpenGrep rules validate and distinguish vulnerable from safe fixtures offline',
  { skip: !process.env.CSREVIEW_OPENGREP_BIN },
  async () => {
    const binary = path.resolve(process.env.CSREVIEW_OPENGREP_BIN);
    const artifact = selectOpenGrepArtifact();
    assert.ok(artifact, 'the integration-test platform must have an approved artifact');
    assert.equal(createHash('sha256').update(readFileSync(binary)).digest('hex'), artifact.sha256);

    const runtimeHome = tempDir('csreview-opengrep-home-');
    const env = {
      ...process.env,
      OPENGREEP_LOG_FILE: path.join(runtimeHome, 'opengrep.log'),
      OPENGREP_ENABLE_VERSION_CHECK: '0',
      OPENGREP_VERSION_CACHE_PATH: path.join(runtimeHome, 'version-cache'),
      XDG_CONFIG_HOME: runtimeHome,
    };
    const ruleFile = path.resolve('rules', 'csreview.yml');
    const scanRoot = tempDir('csreview-opengrep-fixtures-');
    const positiveRoot = path.join(scanRoot, 'positive');
    const negativeRoot = path.join(scanRoot, 'negative');
    cpSync(path.resolve('test/fixtures/opengrep/positive'), positiveRoot, { recursive: true });
    cpSync(path.resolve('test/fixtures/opengrep/negative'), negativeRoot, { recursive: true });
    const positive = await execFileAsync(
      binary,
      ['scan', '--config', ruleFile, '--json', '--quiet', '--disable-version-check', '--no-git-ignore', positiveRoot],
      { cwd: path.resolve('.'), env, timeout: 30000, maxBuffer: 5 * 1024 * 1024 },
    );
    const negative = await execFileAsync(
      binary,
      ['scan', '--config', ruleFile, '--json', '--quiet', '--disable-version-check', '--no-git-ignore', negativeRoot],
      { cwd: path.resolve('.'), env, timeout: 30000, maxBuffer: 5 * 1024 * 1024 },
    );
    const positiveIds = JSON.parse(positive.stdout).results.map((result) => result.check_id);
    const negativeResults = JSON.parse(negative.stdout).results;

    assert.deepEqual(
      new Set(positiveIds),
      new Set(['rules.csreview.javascript.security.eval-detected', 'rules.csreview.python.security.pickle-loads']),
    );
    assert.deepEqual(negativeResults, []);

    const engineResult = await runOpenGrep(positiveRoot, {
      cacheRoot: tempDir('csreview-opengrep-cache-'),
      env: { ...process.env, PATH: path.dirname(binary) },
      excludes: [],
    });
    assert.equal(engineResult.available, true);
    assert.ok('version' in engineResult);
    assert.equal(engineResult.version, OPENGREP_VERSION);
    assert.equal(engineResult.rawCount, 2);
    assert.equal(engineResult.diagnostic, 'complete');
    assert.equal(engineResult.complete, true);
    assert.deepEqual(new Set(engineResult.findings.map((finding) => finding.source)), new Set(['opengrep']));
  },
);
