// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runLocalDast } from '../src/localDast.js';

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-dast-runid-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"demo"}', 'utf8');
  return root;
}

function fakeFetch() {
  return async () => ({
    status: 200,
    headers: new Map([
      ['content-security-policy', "default-src 'self'"],
      ['x-content-type-options', 'nosniff'],
      ['x-frame-options', 'DENY'],
      ['referrer-policy', 'no-referrer'],
      ['permissions-policy', 'geolocation=()'],
    ]),
  });
}

test('runLocalDast embeds a sanitized runId and writes non-overwriting history copies', async () => {
  const root = mkProject();
  const result = await runLocalDast(root, {
    targetUrl: 'http://localhost:3000',
    confirmed: true,
    fetchImpl: fakeFetch(),
    agentName: 'codex',
    runId: '2026-06-03T04:00:00.000Z',
  });

  assert.equal(result.runId, '2026-06-03T04-00-00.000Z'); // ':' sanitized to '-'
  assert.ok(result.reports.historyMarkdown);
  assert.ok(result.reports.historyHtml);

  const md = fs.readFileSync(result.reports.markdown, 'utf8');
  assert.match(md, /\*\*Run ID\*\*: 2026-06-03T04-00-00\.000Z/);

  // History is a verbatim copy and the stable latest name is unchanged.
  const history = fs.readFileSync(result.reports.historyMarkdown, 'utf8');
  assert.equal(history, md);
  assert.equal(path.basename(result.reports.markdown), 'codex_local-dast-findings.md');
  assert.match(
    path.basename(result.reports.historyMarkdown),
    /^codex_local-dast-findings-2026-06-03T04-00-00\.000Z\.md$/,
  );
});

test('runLocalDast without a runId keeps stable names and writes no history', async () => {
  const root = mkProject();
  const result = await runLocalDast(root, {
    targetUrl: 'http://127.0.0.1:8080',
    confirmed: true,
    fetchImpl: fakeFetch(),
    agentName: 'codex',
  });

  assert.equal(result.runId, null);
  assert.equal(result.reports.historyMarkdown, undefined);
  const md = fs.readFileSync(result.reports.markdown, 'utf8');
  assert.doesNotMatch(md, /Run ID/);
});
