import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { detectSecrets, detectVulnerabilities } from '../src/detector.js';
import {
  normalizeNpmAuditFindings,
  normalizeOsvScannerFindings,
  runAnalysis,
} from '../src/index.js';

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

test('package metadata declares Semgrep as a required external tool', () => {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const requiredTools = pkg.csreview?.requiredExternalTools || [];
  const recommendedTools = pkg.csreview?.recommendedExternalTools || [];
  const semgrep = requiredTools.find(tool => tool.name === 'semgrep');
  const osvScanner = recommendedTools.find(tool => tool.name === 'osv-scanner');

  assert.equal(semgrep?.required, true);
  assert.match(semgrep.install.join('\n'), /pipx install semgrep/);
  assert.equal(semgrep.verify, 'semgrep --version');
  assert.equal(osvScanner?.purpose, 'multi-ecosystem dependency vulnerability scanning');
});

test('skill requires external research when framework or security context is uncertain', () => {
  const skill = fs.readFileSync('SKILL.md', 'utf8');

  assert.match(skill, /External Research Protocol/);
  assert.match(skill, /official framework documentation/);
  assert.match(skill, /OWASP|CWE|CVE|vendor security advisory/);
  assert.match(skill, /Do not guess/i);
});

test('normalizes npm audit output into read-only dependency findings', () => {
  const findings = normalizeNpmAuditFindings({
    vulnerabilities: {
      lodash: {
        name: 'lodash',
        severity: 'high',
        isDirect: true,
        via: [{
          title: 'Prototype Pollution in lodash',
          cwe: ['CWE-1321'],
          url: 'https://github.com/advisories/GHSA-test',
        }],
        range: '<4.17.21',
        nodes: ['node_modules/lodash'],
        fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
      },
    },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].source, 'npm-audit');
  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].cwe, 'CWE-1321');
  assert.match(findings[0].fix, /Review lodash/);
  assert.doesNotMatch(findings[0].fix, /npm audit fix/i);
});

test('normalizes OSV-Scanner output into dependency findings', () => {
  const root = path.resolve('.');
  const findings = normalizeOsvScannerFindings({
    results: [{
      source: {
        path: path.join(root, 'package-lock.json'),
        type: 'lockfile',
      },
      packages: [{
        package: {
          name: 'debug',
          version: '2.6.8',
          ecosystem: 'npm',
        },
        vulnerabilities: [{
          id: 'GHSA-test',
          aliases: ['CVE-2099-0001'],
          summary: 'debug has a denial of service vulnerability',
          database_specific: { severity: 'HIGH' },
          references: [{ url: 'https://osv.dev/GHSA-test' }],
          affected: [{
            ranges: [{ events: [{ fixed: '2.6.9' }] }],
          }],
        }],
      }],
    }],
  }, root);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].source, 'osv-scanner');
  assert.equal(findings[0].file, 'package-lock.json');
  assert.equal(findings[0].severity, 'HIGH');
  assert.match(findings[0].fix, /2\.6\.9/);
});
