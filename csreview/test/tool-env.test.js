// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { withToolEnv, semgrepExcludeArgs } from '../src/index.js';

// Semgrep's update/version "phone home" check can hang the process (notably on
// Linux): `semgrep --version` prints the version then blocks on the check.
// withToolEnv forces SEMGREP_ENABLE_VERSION_CHECK=0 for every semgrep invocation
// (doctor version check, scan-path version check, and the scan itself).

test('withToolEnv forces SEMGREP_ENABLE_VERSION_CHECK=0 for semgrep and preserves the base env', () => {
  const opts = withToolEnv('semgrep', {}, { PATH: '/usr/bin' });
  assert.equal(opts.env.SEMGREP_ENABLE_VERSION_CHECK, '0');
  assert.equal(opts.env.PATH, '/usr/bin');
});

test('withToolEnv respects an explicit user-set SEMGREP_ENABLE_VERSION_CHECK', () => {
  const opts = withToolEnv('semgrep', {}, { SEMGREP_ENABLE_VERSION_CHECK: '1', PATH: '/x' });
  assert.equal(opts.env.SEMGREP_ENABLE_VERSION_CHECK, '1');
});

test('withToolEnv preserves caller options and lets a caller-provided env win', () => {
  const opts = withToolEnv('semgrep', { timeout: 10000, env: { FOO: 'bar' } }, { PATH: '/x' });
  assert.equal(opts.timeout, 10000);
  assert.equal(opts.env.FOO, 'bar');
  assert.equal(opts.env.SEMGREP_ENABLE_VERSION_CHECK, '0');
});

test('withToolEnv is a no-op for non-semgrep tools (returns options unchanged)', () => {
  const original = { timeout: 5000 };
  const opts = withToolEnv('npm', original, { PATH: '/x' });
  assert.equal(opts, original);
  assert.equal(opts.env, undefined);
});

test('semgrepExcludeArgs excludes build outputs and vendored dirs (the DeckMidia .output noise)', () => {
  const args = semgrepExcludeArgs();
  // shape: alternating --exclude <dir>
  assert.ok(args.length >= 2 && args.length % 2 === 0);
  const excluded = new Set();
  for (let i = 0; i < args.length; i += 2) {
    assert.equal(args[i], '--exclude');
    excluded.add(args[i + 1]);
  }
  for (const dir of ['node_modules', 'dist', 'build', '.nuxt', '.output', 'csreview-reports', '.git']) {
    assert.ok(excluded.has(dir), `semgrep must exclude ${dir}`);
  }
});

// --tool-timeout / --semgrep-config wiring: the scan must be able to run
// against local rules (air-gapped, no registry metrics) and a timed-out tool
// must say so explicitly — "unavailable" hid that the scan silently degraded.

test('buildSemgrepArgs defaults to --config auto without disabling metrics', async () => {
  const { buildSemgrepArgs } = await import('../src/index.js');
  const args = buildSemgrepArgs('/proj');
  const i = args.indexOf('--config');
  assert.equal(args[i + 1], 'auto');
  assert.ok(!args.includes('--metrics=off'), 'auto config requires registry metrics; must not disable them');
  assert.equal(args[args.length - 1], '/proj');
  assert.ok(args.includes('--exclude'), 'build-output excludes must be preserved');
});

test('buildSemgrepArgs uses a custom config with metrics off (offline-friendly)', async () => {
  const { buildSemgrepArgs } = await import('../src/index.js');
  const args = buildSemgrepArgs('/proj', { config: './semgrep-rules' });
  const i = args.indexOf('--config');
  assert.equal(args[i + 1], './semgrep-rules');
  assert.ok(args.includes('--metrics=off'));
});

test('toolErrorMessage explains a timeout and how to raise it', async () => {
  const { toolErrorMessage } = await import('../src/index.js');
  const err = Object.assign(new Error('Command failed: semgrep'), { killed: true, signal: 'SIGTERM' });
  const msg = toolErrorMessage('semgrep', err, 120000);
  assert.match(msg, /timed out after 120s/i);
  assert.match(msg, /--tool-timeout/);
});

test('toolErrorMessage keeps the not-found message for ENOENT', async () => {
  const { toolErrorMessage } = await import('../src/index.js');
  const err = Object.assign(new Error('spawn semgrep ENOENT'), { code: 'ENOENT' });
  assert.match(toolErrorMessage('semgrep', err), /not found in PATH/);
});
