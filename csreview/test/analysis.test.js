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
import { generateHtmlReport } from '../src/reports/html.js';

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

test('generic vulnerability findings redact matched secret values', () => {
  const root = makeTempProject();
  const rawSecret = 'supersecretvalue123456';
  writeFile(root, 'src/auth.js', `const jwt_secret = "${rawSecret}";\n`);

  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'src/auth.js', language: 'javascript' }],
  });
  const genericFinding = findings.find(f => f.id.startsWith('HARDCODED_SECRET'));

  assert.ok(genericFinding);
  assert.match(genericFinding.vulnerableCode, /\[REDACTED/);
  assert.doesNotMatch(genericFinding.vulnerableCode, new RegExp(rawSecret));
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
  assert.equal(path.basename(result.reports.html), 'codex_security-report.html');
  assert.equal(path.basename(result.reports.markdown), 'codex_security-findings.md');
  assert.ok(fs.existsSync(result.reports.html));
  assert.ok(fs.existsSync(result.reports.markdown));
});

test('runAnalysis scans config and environment files for findings', async () => {
  const root = makeTempProject();
  const outputDir = path.join(root, 'out');
  const rawSecret = 'envsecretvalue123456';
  writeFile(root, '.env', `APP_SECRET="${rawSecret}"\n`);

  const result = await runAnalysis(root, { outputDir, runTools: false });
  const envFinding = result.findings.find(f => f.file === '.env');

  assert.ok(envFinding);
  assert.doesNotMatch(envFinding.vulnerableCode, new RegExp(rawSecret));
});

test('HTML report safely embeds JSON data and tolerates missing CWE', () => {
  const root = makeTempProject();
  const outputPath = path.join(root, 'report.html');
  const attack = '</script><script>alert(1)</script>';

  assert.doesNotThrow(() => generateHtmlReport(
    { name: `demo${attack}`, files: ['src/app.js'], configFiles: [] },
    [{
      id: 'TEST_1',
      severity: 'HIGH',
      category: 'Test',
      name: `Injected ${attack}`,
      description: `Injected ${attack}`,
      file: 'src/app.js',
      line: 1,
      vulnerableCode: attack,
      owasp: 'N/A',
      fix: 'Review manually.',
    }],
    outputPath,
    {},
  ));

  const html = fs.readFileSync(outputPath, 'utf8');
  assert.doesNotMatch(html, /<\/script><script>alert\(1\)<\/script>/);
  assert.match(html, /\\u003C\/script/);
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

test('detector skips generic vulnerability checks in minified files but still scans secrets', () => {
  const root = makeTempProject();
  const secret = 'minifiedsecret123456';
  const repeated = 'document.body.innerHTML=userInput;'.repeat(400);
  writeFile(root, 'dist/app.min.js', `${repeated}\nconst app_secret="${secret}";`);

  const findings = detectVulnerabilities({
    root,
    files: [{ path: 'dist/app.min.js', language: 'javascript' }],
  });

  assert.ok(findings.some(f => f.category === 'Secrets'));
  assert.ok(findings.every(f => !f.id.startsWith('XSS_INNERHTML')));
  assert.ok(findings.every(f => !String(f.vulnerableCode).includes(secret)));
});

test('package metadata declares Semgrep as a required external tool', () => {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const skillInstallation = pkg.csreview?.skillInstallation || {};
  const requiredTools = pkg.csreview?.requiredExternalTools || [];
  const recommendedTools = pkg.csreview?.recommendedExternalTools || [];
  const semgrep = requiredTools.find(tool => tool.name === 'semgrep');
  const osvScanner = recommendedTools.find(tool => tool.name === 'osv-scanner');

  assert.equal(skillInstallation.scope, 'global-agent-environment');
  assert.match(skillInstallation.projectInstallPolicy, /never install inside the analyzed project/i);
  assert.ok(skillInstallation.globalSkillDirectories.includes('~/.codex/skills/csreview'));
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

test('documentation aligns report handoff names and avoids exact patch instructions', () => {
  const docs = `${fs.readFileSync('../README.md', 'utf8')}\n${fs.readFileSync('SKILL.md', 'utf8')}`;

  assert.doesNotMatch(docs, /Apply the corrected code exactly as shown/i);
  assert.doesNotMatch(docs, /@csreview review security-findings\.md/i);
  assert.doesNotMatch(docs, /Native skill via `\.trae\/skills\/csreview\/SKILL\.md`/i);
  assert.doesNotMatch(docs, /Compatible via AGENTS\.md or project instructions/i);
  assert.match(docs, /@csreview review csreview-reports\/codex_security-findings\.md/);
});

test('documentation requires global skill installation by default', () => {
  const docs = `${fs.readFileSync('../README.md', 'utf8')}\n${fs.readFileSync('SKILL.md', 'utf8')}`;

  assert.match(docs, /Global Skill Installation/);
  assert.match(docs, /global agent skill/i);
  assert.match(docs, /~\/\.codex\/skills\/csreview/);
  assert.match(docs, /~\/\.trae\/skills\/csreview/);
  assert.match(docs, /MUST NOT copy, scaffold, install, update, delete, or move the CSReview skill inside the project/i);
  assert.match(docs, /unless the user explicitly asks for project-local installation/i);
});

test('skill requires explicit report path handoff for humans and coding agents', () => {
  const skill = fs.readFileSync('SKILL.md', 'utf8');

  assert.match(skill, /Report Handoff Protocol/);
  assert.match(skill, /HTML report path/);
  assert.match(skill, /Markdown report path/);
  assert.match(skill, /agent name prefix/i);
  assert.match(skill, /MUST NOT generate generic report names/i);
  assert.match(skill, /--agent-name/);
  assert.match(skill, /CSREVIEW_AGENT_NAME/);
  assert.match(skill, /codex_security-report\.html/);
  assert.match(skill, /codex_security-findings\.md/);
  assert.match(skill, /claude_security-report\.html/);
  assert.match(skill, /open.*browser/i);
  assert.match(skill, /coding agent[\s\S]*csreview-reports\/codex_security-findings\.md/i);
});

test('gitignore excludes generated analysis documents and agent reports', () => {
  const ignore = fs.readFileSync('../.gitignore', 'utf8');

  assert.match(ignore, /CSREVIEW-ANALISES\*?\.md/);
  assert.match(ignore, /\*_security-report\.html/);
  assert.match(ignore, /\*_security-findings\.md/);
  assert.match(ignore, /csreview-reports\//);
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
