// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeGitleaksFindings,
  normalizeBanditFindings,
  normalizeGosecFindings,
  normalizeTrivyFindings,
  runSecurityTool,
} from '../src/securityTools.js';

test('normalizeGitleaksFindings maps findings and REDACTS the raw secret', () => {
  const report = [
    {
      RuleID: 'aws-access-token',
      Description: 'AWS Access Token',
      File: 'src/config.js',
      StartLine: 12,
      Secret: 'AKIAIOSFODNN7EXAMPLE',
      Match: 'key = "AKIAIOSFODNN7EXAMPLE"',
    },
  ];
  const findings = normalizeGitleaksFindings(report);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'CRITICAL');
  assert.equal(findings[0].cwe, 'CWE-798');
  assert.equal(findings[0].source, 'gitleaks');
  assert.equal(findings[0].file, 'src/config.js');
  assert.equal(findings[0].line, 12);
  // The raw secret must never appear anywhere in the finding.
  assert.doesNotMatch(JSON.stringify(findings), /AKIAIOSFODNN7EXAMPLE/);
  assert.match(findings[0].vulnerableCode, /REDACTED/);
});

test('normalizeBanditFindings maps severity/CWE and redacts hardcoded-password (B105) code', () => {
  const report = {
    results: [
      {
        filename: 'app/db.py',
        line_number: 7,
        issue_severity: 'HIGH',
        issue_confidence: 'HIGH',
        issue_text: 'Possible SQL injection',
        test_id: 'B608',
        test_name: 'hardcoded_sql_expressions',
        issue_cwe: { id: 89 },
        code: 'query = "SELECT * FROM t WHERE id=" + uid',
        more_info: 'https://bandit.readthedocs.io/en/latest/plugins/b608.html',
      },
      {
        filename: 'app/auth.py',
        line_number: 3,
        issue_severity: 'LOW',
        test_id: 'B105',
        test_name: 'hardcoded_password_string',
        issue_cwe: { id: 259 },
        code: 'password = "SuperSecretP@ss123"',
      },
    ],
  };
  const findings = normalizeBanditFindings(report);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].cwe, 'CWE-89');
  assert.equal(findings[0].source, 'bandit');
  // B105 code (contains a password) must be redacted.
  assert.doesNotMatch(JSON.stringify(findings), /SuperSecretP@ss123/);
});

test('normalizeGosecFindings maps issues and redacts hardcoded-credential (G101) code', () => {
  const report = {
    Issues: [
      {
        severity: 'MEDIUM',
        confidence: 'HIGH',
        cwe: { id: '22' },
        rule_id: 'G304',
        details: 'Potential file inclusion via variable',
        file: 'main.go',
        line: '42',
        code: 'os.ReadFile(userPath)',
      },
      {
        severity: 'HIGH',
        cwe: { id: '798' },
        rule_id: 'G101',
        details: 'Potential hardcoded credentials',
        file: 'secrets.go',
        line: '5',
        code: 'const token = "ghp_REALLOOKINGTOKEN1234567890"',
      },
    ],
  };
  const findings = normalizeGosecFindings(report);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].cwe, 'CWE-22');
  assert.equal(findings[0].source, 'gosec');
  assert.equal(findings[1].cwe, 'CWE-798');
  assert.doesNotMatch(JSON.stringify(findings), /ghp_REALLOOKINGTOKEN1234567890/);
});

test('normalizeTrivyFindings maps misconfig + vuln + secret (secret redacted)', () => {
  const report = {
    Results: [
      {
        Target: 'Dockerfile',
        Misconfigurations: [
          {
            ID: 'DS002',
            Title: 'root user',
            Severity: 'HIGH',
            Message: 'Specify a non-root USER',
            Resolution: 'Add a non-root USER',
            CauseMetadata: { StartLine: 3 },
            References: ['https://avd.aquasec.com/misconfig/ds002'],
          },
        ],
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2024-0001',
            PkgName: 'lodash',
            InstalledVersion: '4.17.20',
            FixedVersion: '4.17.21',
            Severity: 'CRITICAL',
            Title: 'Prototype pollution',
            CweIDs: ['CWE-1321'],
          },
        ],
        Secrets: [{ RuleID: 'aws-access-key-id', Severity: 'CRITICAL', StartLine: 9, Match: 'AKIAIOSFODNN7EXAMPLE' }],
      },
    ],
  };
  const findings = normalizeTrivyFindings(report);
  assert.equal(findings.length, 3);
  const byCat = Object.fromEntries(findings.map((f) => [f.category, f]));
  assert.ok(byCat['Security Misconfiguration']);
  assert.equal(byCat['Dependency Vulnerability'].cwe, 'CWE-1321');
  assert.equal(byCat['Dependency Vulnerability'].severity, 'CRITICAL');
  assert.equal(byCat['Secrets'].cwe, 'CWE-798');
  assert.doesNotMatch(JSON.stringify(findings), /AKIAIOSFODNN7EXAMPLE/);
});

test('normalizers tolerate empty/garbage input', () => {
  assert.deepEqual(normalizeGitleaksFindings(null), []);
  assert.deepEqual(normalizeBanditFindings({}), []);
  assert.deepEqual(normalizeGosecFindings('oops'), []);
  assert.deepEqual(normalizeTrivyFindings(undefined), []);
});

test('runSecurityTool parses injected stdout and is fail-open on errors', async () => {
  const okExec = async () => ({
    stdout: JSON.stringify([{ RuleID: 'x', File: 'a.js', StartLine: 1, Secret: 'zzzz' }]),
  });
  const ok = await runSecurityTool('gitleaks', { rootDir: '/p', toolPath: 'gitleaks', exec: okExec });
  assert.equal(ok.available, true);
  assert.equal(ok.rawCount, 1);
  assert.equal(ok.findings[0].source, 'gitleaks');

  const throwExec = async () => {
    throw new Error('ENOENT');
  };
  const fail = await runSecurityTool('gitleaks', { rootDir: '/p', toolPath: 'gitleaks', exec: throwExec });
  assert.equal(fail.available, false);
  assert.match(fail.error, /ENOENT/);

  const unknown = await runSecurityTool('nope', { rootDir: '/p', toolPath: 'x', exec: okExec });
  assert.equal(unknown.available, false);
});

test('runSecurityTool passes the rootDir only as argv (no shell interpolation)', async () => {
  /** @type {string[]|null} */
  let capturedArgv = null;
  const exec = async (_path, argv) => {
    capturedArgv = argv;
    return { stdout: '{"Results":[]}' };
  };
  await runSecurityTool('trivy', { rootDir: '/proj path; rm -rf', toolPath: 'trivy', exec });
  // The (intentionally hostile) rootDir must appear verbatim as a single argv
  // element — never concatenated into a shell string.
  assert.ok(capturedArgv && capturedArgv.includes('/proj path; rm -rf'));
});
