import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { detectSecrets, detectVulnerabilities } from '../src/detector.js';
import { runAnalysis } from '../src/index.js';

function makeTempProject() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-test-'));
}

function writeFile(root, relativePath, content) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
  return target;
}

test('detectVulnerabilities reads files relative to the project root', () => {
  const root = makeTempProject();
  writeFile(root, 'src/vuln.js', 'const password = "admin123";\n');

  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'src/vuln.js', language: 'javascript' }],
  });

  assert.ok(findings.length > 0);
  assert.equal(findings[0].file, 'src/vuln.js');
});

test('secret findings use the report schema and redact secret values', () => {
  const rawSecret = 'abcdefghijklmnop12345678';
  const findings = detectSecrets(`const apiKey = "${rawSecret}";`, 'src/config.js');

  assert.ok(findings.length > 0);
  assert.equal(findings[0].name, 'Hardcoded API Key');
  assert.equal(findings[0].fix, 'Move to env vars. Rotate the key.');
  assert.match(findings[0].vulnerableCode, /\[REDACTED/);
  assert.doesNotMatch(findings[0].vulnerableCode, new RegExp(rawSecret));
});

test('runAnalysis ignores generated reports and emits tool metadata when tool execution is disabled', async () => {
  const root = makeTempProject();
  const outputDir = path.join(root, 'out');
  writeFile(root, 'src/app.js', 'const password = "admin123";\n');
  writeFile(root, 'security-report.html', '<script>document.body.innerHTML = userInput;</script>\n');

  const result = await runAnalysis(root, { outputDir, runTools: false });

  assert.ok(result.totalFindings > 0);
  assert.ok(result.findings.every(f => f.file !== 'security-report.html'));
  assert.equal(result.toolResults.mode, 'Agent-Only');
  assert.equal(result.toolResults.semgrep.available, false);
  assert.ok(fs.existsSync(result.reports.html));
  assert.ok(fs.existsSync(result.reports.markdown));
});

test('detector completes on regex-heavy JavaScript files', () => {
  const root = path.resolve('.');
  const startedAt = Date.now();
  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'src/detector.js', language: 'javascript' }],
  });

  assert.ok(Array.isArray(findings));
  assert.ok(Date.now() - startedAt < 2000);
});
