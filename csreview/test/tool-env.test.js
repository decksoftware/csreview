// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { withToolEnv } from '../src/index.js';

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
