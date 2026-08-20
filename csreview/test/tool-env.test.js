// @ts-check
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import { DEFAULT_IGNORE_DIRS } from '../src/ignore.js';
import { toolErrorMessage } from '../src/index.js';
import { buildOpenGrepArgs, openGrepExcludeArgs } from '../src/opengrep.js';

test('OpenGrep excludes build outputs, tool caches, and vendored directories', () => {
  const args = openGrepExcludeArgs(DEFAULT_IGNORE_DIRS);
  assert.ok(args.length >= 2 && args.length % 2 === 0);
  const excluded = new Set();
  for (let i = 0; i < args.length; i += 2) {
    assert.equal(args[i], '--exclude');
    excluded.add(args[i + 1]);
  }
  for (const dir of ['node_modules', 'dist', 'build', '.nuxt', '.output', 'csreview-reports', '.csreview', '.git']) {
    assert.ok(excluded.has(dir), `OpenGrep must exclude ${dir}`);
  }
});

test('buildOpenGrepArgs always uses local rules and disables version checks', () => {
  const args = buildOpenGrepArgs('/proj', {
    rulepackPath: '/csreview/rules',
    excludes: DEFAULT_IGNORE_DIRS,
  });
  const i = args.indexOf('--config');
  assert.equal(args[i + 1], path.resolve('/csreview/rules'));
  assert.ok(args.includes('--disable-version-check'));
  assert.ok(!args.includes('auto'));
  assert.equal(args[args.length - 1], path.resolve('/proj'));
  assert.ok(args.includes('--exclude'));
});

test('buildOpenGrepArgs adds only an explicit local config after bundled rules', () => {
  const args = buildOpenGrepArgs('/proj', {
    rulepackPath: '/csreview/rules',
    configPath: '/project/local-rules',
  });
  const configs = args.flatMap((arg, index) => (arg === '--config' ? [args[index + 1]] : []));
  assert.deepEqual(configs, [path.resolve('/csreview/rules'), path.resolve('/project/local-rules')]);
});

test('toolErrorMessage explains a timeout and how to raise it', () => {
  const err = Object.assign(new Error('Command failed: opengrep'), { killed: true, signal: 'SIGTERM' });
  const msg = toolErrorMessage('opengrep', err, 120000);
  assert.match(msg, /timed out after 120s/i);
  assert.match(msg, /--tool-timeout/);
});

test('toolErrorMessage keeps the not-found message for ENOENT', () => {
  const err = Object.assign(new Error('spawn opengrep ENOENT'), { code: 'ENOENT' });
  assert.match(toolErrorMessage('opengrep', err), /not found in PATH/);
});
