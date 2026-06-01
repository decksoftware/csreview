import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { detectSecrets, detectVulnerabilities } from '../src/detector.js';
import {
  deduplicateFindings,
  normalizeNpmAuditFindings,
  normalizeOsvScannerFindings,
  runAnalysis,
} from '../src/index.js';
import { generateHtmlReport } from '../src/reports/html.js';
import { generateMarkdownReport } from '../src/reports/markdown.js';
import { normalizeLocalPath, safeResolveInside } from '../src/pathSafety.js';
import { calculateSecurityScore } from '../src/score.js';

function makeTempProject() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-test-'));
}

function writeFile(root, relativePath, content) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
  return target;
}

test('path helpers normalize local roots and reject traversal targets', () => {
  const root = makeTempProject();

  assert.equal(normalizeLocalPath(root), path.normalize(root));
  assert.equal(safeResolveInside(root, 'src/app.js'), path.join(root, 'src', 'app.js'));
  assert.equal(safeResolveInside(root, '../outside.js'), null);
  assert.equal(safeResolveInside(root, path.join(root, 'src', 'app.js')), null);
  assert.equal(safeResolveInside(root, 'C:\\outside.js'), null);
});

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

  const html = fs.readFileSync(result.reports.html, 'utf8');
  const markdown = fs.readFileSync(result.reports.markdown, 'utf8');
  assert.match(html, new RegExp(`const reportScore = ${result.score};`));
  assert.match(markdown, new RegExp(`\\*\\*Security Score\\*\\*: ${result.score}/100`));
  assert.match(html, /Potential Exploitation Path \(theoretical\)/);
  assert.match(markdown, /Potential Exploitation Path \(theoretical\)/);
  assert.match(markdown, /static-analysis hypothesis/i);
  assert.doesNotMatch(html, /Exploitation Scenario/);
  assert.doesNotMatch(markdown, /Exploitation Scenario/);
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
  assert.ok(result.score < 100);
});

test('runAnalysis sanitizes agent report names without regex-heavy processing', async () => {
  const root = makeTempProject();
  const outputDir = path.join(root, 'out');
  const agentName = `---Codex Security!!! 2026---${'!'.repeat(1000)}`;

  const result = await runAnalysis(root, { outputDir, runTools: false, agentName });

  assert.equal(path.basename(result.reports.html), 'codex-security-2026_security-report.html');
  assert.equal(path.basename(result.reports.markdown), 'codex-security-2026_security-findings.md');
});

test('shared scoring counts config-only findings against audited files', () => {
  const score = calculateSecurityScore(
    [{ severity: 'CRITICAL', file: '.env' }],
    { files: [], configFiles: ['.env'], depFiles: [], baasFiles: [] },
  );

  assert.equal(score, 0);
});

test('shared scoring does not hide critical findings in large projects', () => {
  const score = calculateSecurityScore(
    [{ severity: 'CRITICAL', file: 'src/vulnerable.js' }],
    { files: Array.from({ length: 100 }, (_, index) => `src/file-${index}.js`), configFiles: [], depFiles: [], baasFiles: [] },
  );

  assert.ok(score <= 49);
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

test('HTML report safely renders finding attributes', () => {
  const root = makeTempProject();
  const outputPath = path.join(root, 'report.html');
  const attack = 'x" onclick="alert(1)';

  generateHtmlReport(
    { name: 'demo', files: ['src/app.js'], configFiles: [] },
    [{
      id: attack,
      severity: 'HIGH',
      category: attack,
      name: attack,
      description: attack,
      file: `src/${attack}.js`,
      line: 1,
      vulnerableCode: attack,
      owasp: 'N/A',
      fix: 'Review manually.',
    }],
    outputPath,
    {},
  );

  const html = fs.readFileSync(outputPath, 'utf8');
  assert.doesNotMatch(html, /id="finding-x" onclick="alert\(1\)"/);
  assert.doesNotMatch(html, /data-category="x" onclick="alert\(1\)"/);
  assert.match(html, /x&quot; onclick=&quot;alert\(1\)/);
});

test('Markdown report uses package version and analysis duration metadata', () => {
  const root = makeTempProject();
  const outputPath = path.join(root, 'report.md');

  generateMarkdownReport(
    { name: 'demo', files: ['src/app.js'], configFiles: [] },
    [],
    outputPath,
    { packageVersion: '0.0.1', durationMs: 2500 },
  );

  const markdown = fs.readFileSync(outputPath, 'utf8');
  assert.match(markdown, /\*\*Scanner\*\*: CSReview v0\.0\.1/);
  assert.match(markdown, /\*\*Duration\*\*: 2\.50s/);
  assert.doesNotMatch(markdown, /CSReview v2\.0\.0/);
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

test('detector avoids common JavaScript false positives', () => {
  const root = makeTempProject();
  writeFile(root, 'src/regex.js', 'const match = /abc/g.exec(input);\npattern.regex.exec(line);\n');
  writeFile(root, 'src/docs.js', 'const example = "pickle.loads(user_input)";\n');
  writeFile(root, 'src/login.js', 'const passwordField = "password_input";\nconst mockPassword = "test1234";\n');
  writeFile(root, 'src/unsafe.py', 'pickle.loads(user_input)\n');

  const findings = detectVulnerabilities({
    root,
    files: [
      { path: 'src/regex.js', language: 'javascript' },
      { path: 'src/docs.js', language: 'javascript' },
      { path: 'src/login.js', language: 'javascript' },
      { path: 'src/unsafe.py', language: 'python' },
    ],
  });

  assert.ok(findings.some(f => f.file === 'src/unsafe.py' && f.id.startsWith('PY_DESERIALIZE')));
  assert.ok(findings.every(f => !(f.file === 'src/regex.js' && f.id.startsWith('UNSAFE_EVAL'))));
  assert.ok(findings.every(f => !(f.file === 'src/regex.js' && f.id.startsWith('COMMAND_INJECTION'))));
  assert.ok(findings.every(f => !(f.file === 'src/docs.js' && f.id.startsWith('PY_DESERIALIZE'))));
  assert.ok(findings.every(f => !(f.file === 'src/login.js' && f.id.startsWith('GENERIC_PASSWORD'))));
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

test('generic vulnerability evidence is only redacted for secret-like patterns', () => {
  const root = makeTempProject();
  const rawSecret = 'supersecretvalue123456';
  writeFile(root, 'src/auth.js', `const jwt_secret = "${rawSecret}";\n`);
  writeFile(root, 'src/sql.js', 'db.query("SELECT * FROM users WHERE id = " + req.params.id);\n');

  const findings = detectVulnerabilities({
    root,
    files: [
      { path: 'src/auth.js', language: 'javascript' },
      { path: 'src/sql.js', language: 'javascript' },
    ],
  });
  const secretFinding = findings.find(f => f.id.startsWith('HARDCODED_SECRET'));
  const sqlFinding = findings.find(f => f.id.startsWith('SQL_INJECTION'));

  assert.ok(secretFinding);
  assert.match(secretFinding.vulnerableCode, /\[REDACTED/);
  assert.doesNotMatch(secretFinding.vulnerableCode, new RegExp(rawSecret));
  assert.ok(sqlFinding);
  assert.match(sqlFinding.vulnerableCode, /req\.params\.id/);
  assert.doesNotMatch(sqlFinding.vulnerableCode, /\[REDACTED/);
});

test('deduplicateFindings merges detector and tool findings into confirmed evidence', () => {
  const findings = deduplicateFindings([
    {
      id: 'SQL_INJECTION_1',
      severity: 'CRITICAL',
      category: 'Injection',
      name: 'SQL Injection',
      file: 'src/app.js',
      line: 10,
      cwe: 'CWE-89',
      confidence: 'HIGH',
      references: ['https://example.test/detector'],
    },
    {
      id: 'SEMGREP_1',
      severity: 'HIGH',
      category: 'Semgrep',
      name: 'Semgrep SQL Injection',
      file: 'src/app.js',
      line: 10,
      cwe: 'CWE-89',
      confidence: 'TOOL-ONLY',
      references: ['https://example.test/semgrep'],
      source: 'semgrep',
    },
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'CRITICAL');
  assert.equal(findings[0].confidence, 'CONFIRMED');
  assert.deepEqual(findings[0].sources, ['csreview-detector', 'semgrep']);
  assert.equal(findings[0].duplicateCount, 2);
  assert.equal(findings[0].references.length, 2);
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
  assert.equal(pkg.engines.node, '>=18');
  assert.equal(pkg.author, 'decksoftware');
  assert.match(pkg.dependencies.glob, /^\^13\./);
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

test('skill recommends stack-native read-only lint and scanner tools', () => {
  const docs = `${fs.readFileSync('../README.md', 'utf8')}\n${fs.readFileSync('SKILL.md', 'utf8')}`;

  assert.match(docs, /Stack-Native Tool Recommendation Matrix/i);
  assert.match(docs, /do not install.*analyzed project/i);
  assert.match(docs, /missing recommended tool/i);
  assert.match(docs, /dotnet format analyzers/);
  assert.match(docs, /dotnet (?:package list|list package).*--vulnerable/);
  assert.match(docs, /eslint-plugin-security/);
  assert.match(docs, /eslint-plugin-react-hooks/);
  assert.match(docs, /gradlew lint/);
  assert.match(docs, /detekt/);
  assert.match(docs, /govulncheck/);
  assert.match(docs, /gosec/);
  assert.match(docs, /golangci-lint/);
});

test('README exposes the canonical SKILL.md for GitHub landing review', () => {
  const readme = fs.readFileSync('../README.md', 'utf8').replace(/\r\n/g, '\n');
  const skill = fs.readFileSync('SKILL.md', 'utf8').replace(/\r\n/g, '\n').trim();
  const mirror = readme.match(
    /<!-- BEGIN CSREVIEW_SKILL_MD -->\n````markdown\n([\s\S]*?)\n````\n<!-- END CSREVIEW_SKILL_MD -->/
  );

  assert.ok(mirror, 'README must include a mirrored full SKILL.md block');
  assert.equal(mirror[1].trim(), skill);
  assert.match(readme, /Expand the full SKILL\.md read by coding agents/i);
});

test('documentation aligns report handoff names and avoids exact patch instructions', () => {
  const docs = `${fs.readFileSync('../README.md', 'utf8')}\n${fs.readFileSync('SKILL.md', 'utf8')}`;

  assert.doesNotMatch(docs, /Apply the corrected code exactly as shown/i);
  assert.doesNotMatch(docs, /@csreview review security-findings\.md/i);
  assert.doesNotMatch(docs, /Native skill via `\.trae\/skills\/csreview\/SKILL\.md`/i);
  assert.doesNotMatch(docs, /Compatible via AGENTS\.md or project instructions/i);
  assert.doesNotMatch(docs, /perfect security score/i);
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

test('skill positions CSReview as local development-time security alignment only', () => {
  const skill = fs.readFileSync('SKILL.md', 'utf8');

  assert.match(skill, /development-time security alignment for the local workspace/i);
  assert.match(skill, /penetration tester's adversarial mindset/i);
  assert.match(skill, /static SAST \+ SCA/i);
  assert.match(skill, /does NOT perform live penetration testing against running, deployed, or production systems/i);
  assert.match(skill, /## Scope/);
  assert.match(skill, /IN SCOPE[\s\S]*local development workspace\/project/i);
  assert.match(skill, /GOAL[\s\S]*SECURITY and EFFICIENCY/i);
  assert.match(skill, /OUT OF SCOPE \/ PROHIBITED[\s\S]*DAST against running targets/i);
  assert.match(skill, /Reference documentation research[\s\S]*ALLOWED/i);
  assert.doesNotMatch(skill, new RegExp('automated pentest ' + 'level', 'i'));
});

test('skill describes exploitation paths as theoretical static-analysis hypotheses', () => {
  const skill = fs.readFileSync('SKILL.md', 'utf8');

  assert.match(skill, /Potential Exploitation Path \(theoretical, unverified\)/);
  assert.match(skill, /hypothesis derived from static analysis/i);
  assert.match(skill, /not a validated or executed exploit/i);
  assert.doesNotMatch(skill, /Exploitation Scenario/);
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
