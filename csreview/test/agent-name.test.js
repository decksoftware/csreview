// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeAgentName } from '../src/agentName.js';

// Report filenames embed the agent name (<agent>_security-report.html,
// <agent>_local-dast-report.html, <agent>_db-dump-guide.html). The sanitizer
// used to exist as THREE separate copies (index.js, localDast.js,
// dumpGuide.js); if they drifted, the static-scan and DAST reports for the
// same agent could land under different prefixes. One module, one behavior.

test('sanitizeAgentName normalizes names to safe lowercase file prefixes', () => {
  assert.equal(sanitizeAgentName('Claude Code'), 'claude-code');
  assert.equal(sanitizeAgentName('  GPT_5  '), 'gpt_5');
  assert.equal(sanitizeAgentName('a--b!!c'), 'a-b-c');
  assert.equal(sanitizeAgentName('-edge-'), 'edge');
});

test('sanitizeAgentName falls back to codex for empty or fully-stripped input', () => {
  assert.equal(sanitizeAgentName(''), 'codex');
  assert.equal(sanitizeAgentName(undefined), 'codex');
  assert.equal(sanitizeAgentName('***'), 'codex');
});
