// @ts-check
/**
 * Normalizers + runners for engine-orchestrated, stack-native security tools
 * (Gitleaks, Bandit, gosec, Trivy). Normalizers are pure functions over each
 * tool's JSON output and return the canonical Finding schema with
 * confidence 'TOOL-ONLY'; the engine's deduplication promotes to CONFIRMED when
 * a tool corroborates the heuristic detector (this is what cuts false
 * positives). Runners take an injected `exec` so unit tests never spawn a
 * process. Secret values are ALWAYS redacted — these tools surface secrets, and
 * CSReview must never copy a raw secret into its report.
 */

const SEVERITY_MAP = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  ERROR: 'HIGH',
  MEDIUM: 'MEDIUM',
  MODERATE: 'MEDIUM',
  WARNING: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
  INFORMATIONAL: 'INFO',
  UNKNOWN: 'LOW',
};

function sev(value) {
  return SEVERITY_MAP[String(value || '').toUpperCase()] || 'MEDIUM';
}

function cweOf(value) {
  const m = String(value || '').match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : 'N/A';
}

function toLine(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1;
}

function rel(file) {
  return String(file || 'unknown').replace(/\\/g, '/');
}

/** Redact a secret value to a non-reversible marker (never emit the raw value). */
function redactSecret(value) {
  const s = String(value || '');
  if (!s) return '[REDACTED]';
  const tail = s.length > 4 ? s.slice(-4) : '';
  return tail ? `[REDACTED:${s.length}:...${tail}]` : '[REDACTED]';
}

/**
 * Gitleaks `detect --report-format json` output is an array of findings.
 * @param {any} report
 * @returns {Array<object>}
 */
export function normalizeGitleaksFindings(report) {
  const items = Array.isArray(report) ? report : Array.isArray(report?.findings) ? report.findings : [];
  return items.map((f, i) => ({
    id: `GITLEAKS_${i + 1}`,
    severity: 'CRITICAL',
    category: 'Secrets',
    name: `Gitleaks: ${f.RuleID || f.Description || 'hardcoded secret'}`,
    description: f.Description || 'Gitleaks detected a hardcoded secret.',
    file: rel(f.File),
    line: toLine(f.StartLine),
    vulnerableCode: redactSecret(f.Secret || f.Match), // never the raw secret
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    vibeRisk: true,
    compliance: 'Secret detected by Gitleaks',
    fix: 'Remove the secret from source and history, rotate it, and load it from a secret manager or environment variable.',
    confidence: 'TOOL-ONLY',
    exploitation:
      'An exposed credential can be reused by anyone who can read the source, git history, package, or logs.',
    references: ['https://github.com/gitleaks/gitleaks'],
    source: 'gitleaks',
  }));
}

const BANDIT_SECRET_TESTS = new Set(['B105', 'B106', 'B107']); // hardcoded password tests

/**
 * Bandit `-f json` output: { results: [...] }.
 * @param {any} report
 * @returns {Array<object>}
 */
export function normalizeBanditFindings(report) {
  const results = Array.isArray(report?.results) ? report.results : [];
  return results.map((r, i) => {
    const cweId = r.issue_cwe && (r.issue_cwe.id ?? r.issue_cwe.ID);
    const isSecret = BANDIT_SECRET_TESTS.has(String(r.test_id || '').toUpperCase());
    const codeLine = typeof r.code === 'string' ? r.code.split('\n')[0].slice(0, 2000) : '';
    return {
      id: `BANDIT_${i + 1}`,
      severity: sev(r.issue_severity),
      category: 'Security (Python)',
      name: `Bandit ${r.test_id || ''}: ${r.test_name || 'issue'}`.trim(),
      description: r.issue_text || 'Bandit security finding.',
      file: rel(r.filename),
      line: toLine(r.line_number),
      vulnerableCode: isSecret ? redactSecret(codeLine) : codeLine || 'See Bandit output.',
      cwe: cweId ? `CWE-${cweId}` : 'N/A',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      vibeRisk: false,
      compliance: `Bandit ${r.issue_confidence || ''} confidence`.trim(),
      fix: `Review Bandit ${r.test_id || ''} and apply the secure pattern from its documentation.`.trim(),
      confidence: 'TOOL-ONLY',
      exploitation: r.more_info ? `See ${r.more_info}` : 'See the Bandit rule documentation.',
      references: [r.more_info, 'https://bandit.readthedocs.io/'].filter(Boolean),
      source: 'bandit',
    };
  });
}

/**
 * gosec `-fmt=json` output: { Issues: [...] }.
 * @param {any} report
 * @returns {Array<object>}
 */
export function normalizeGosecFindings(report) {
  const issues = Array.isArray(report?.Issues) ? report.Issues : [];
  return issues.map((g, i) => {
    const cweId = g.cwe && (g.cwe.id ?? g.cwe.ID);
    const isSecret = String(g.rule_id || '').toUpperCase() === 'G101'; // hardcoded credentials
    const code = typeof g.code === 'string' ? g.code.slice(0, 2000) : '';
    return {
      id: `GOSEC_${i + 1}`,
      severity: sev(g.severity),
      category: 'Security (Go)',
      name: `gosec ${g.rule_id || 'issue'}`.trim(),
      description: g.details || 'gosec security finding.',
      file: rel(g.file),
      line: toLine(g.line),
      vulnerableCode: isSecret ? redactSecret(code) : code || 'See gosec output.',
      cwe: cweId ? `CWE-${cweId}` : 'N/A',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      vibeRisk: false,
      compliance: `gosec ${g.confidence || ''} confidence`.trim(),
      fix: 'Review the gosec rule and apply the recommended secure API.',
      confidence: 'TOOL-ONLY',
      exploitation: 'See the gosec rule reference for exploitation context.',
      references: ['https://github.com/securego/gosec'],
      source: 'gosec',
    };
  });
}

/**
 * Trivy `--format json` output: { Results: [ { Misconfigurations, Vulnerabilities, Secrets } ] }.
 * @param {any} report
 * @returns {Array<object>}
 */
export function normalizeTrivyFindings(report) {
  const results = Array.isArray(report?.Results) ? report.Results : [];
  const out = [];
  for (const r of results) {
    const target = rel(r.Target);
    for (const m of r.Misconfigurations || []) {
      out.push({
        id: `TRIVY_MISCONF_${out.length + 1}`,
        severity: sev(m.Severity),
        category: 'Security Misconfiguration',
        name: `Trivy ${m.ID || ''}: ${m.Title || 'misconfiguration'}`.trim(),
        description: m.Description || m.Message || 'Trivy misconfiguration finding.',
        file: target,
        line: toLine(m.CauseMetadata && m.CauseMetadata.StartLine),
        vulnerableCode: m.Message || 'See Trivy cause metadata.',
        cwe: 'N/A',
        owasp: 'A05:2021-Security Misconfiguration',
        vibeRisk: false,
        compliance: m.ID || 'Trivy misconfiguration',
        fix: m.Resolution || 'Apply the remediation in the Trivy reference.',
        confidence: 'TOOL-ONLY',
        exploitation: m.Message || 'See the Trivy reference for impact.',
        references: Array.isArray(m.References) ? m.References.slice(0, 5) : [],
        source: 'trivy',
      });
    }
    for (const v of r.Vulnerabilities || []) {
      out.push({
        id: `TRIVY_VULN_${out.length + 1}`,
        severity: sev(v.Severity),
        category: 'Dependency Vulnerability',
        name: `Trivy: ${v.PkgName || 'package'} ${v.VulnerabilityID || ''}`.trim(),
        description: v.Title || v.Description || 'Known vulnerable dependency reported by Trivy.',
        file: target,
        line: 1,
        vulnerableCode: `${v.PkgName || 'package'}@${v.InstalledVersion || 'unknown'}${v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ''}`,
        cwe: Array.isArray(v.CweIDs) && v.CweIDs.length ? cweOf(v.CweIDs[0]) : 'N/A',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        vibeRisk: false,
        compliance: v.VulnerabilityID || 'Trivy dependency vulnerability',
        fix: v.FixedVersion
          ? `Update ${v.PkgName} to ${v.FixedVersion} or later when compatible.`
          : `No fixed version reported; evaluate mitigation, replacement, or removal of ${v.PkgName}.`,
        confidence: 'TOOL-ONLY',
        exploitation: 'A vulnerable dependency can be exploited when reachable from application code or build steps.',
        references: Array.isArray(v.References) ? v.References.slice(0, 5) : [],
        source: 'trivy',
      });
    }
    for (const s of r.Secrets || []) {
      out.push({
        id: `TRIVY_SECRET_${out.length + 1}`,
        severity: sev(s.Severity) || 'CRITICAL',
        category: 'Secrets',
        name: `Trivy secret: ${s.RuleID || s.Title || 'hardcoded secret'}`,
        description: s.Title || 'Trivy detected a hardcoded secret.',
        file: target,
        line: toLine(s.StartLine),
        vulnerableCode: redactSecret(s.Match), // never the raw secret
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        vibeRisk: true,
        compliance: 'Secret detected by Trivy',
        fix: 'Remove and rotate the secret; load it from a secret manager or environment variable.',
        confidence: 'TOOL-ONLY',
        exploitation: 'An exposed credential can be reused by anyone who can read the source or history.',
        references: [],
        source: 'trivy',
      });
    }
  }
  return out;
}

/**
 * Per-tool run specs: how to invoke each tool read-only with a SECURITY-ONLY
 * profile and JSON output. `argv(rootDir)` returns argv only (no shell); the
 * audited rootDir is passed as a positional arg or via cwd, never interpolated
 * into a shell string.
 */
export const RUN_SPECS = {
  gitleaks: {
    normalize: normalizeGitleaksFindings,
    argv: (rootDir) => [
      'dir',
      '--report-format',
      'json',
      '--report-path',
      '-',
      '--no-banner',
      '--exit-code',
      '0',
      rootDir,
    ],
    parsesStdout: true,
  },
  bandit: {
    normalize: normalizeBanditFindings,
    argv: (rootDir) => ['-r', rootDir, '-f', 'json', '-q', '--exit-zero'],
    parsesStdout: true,
  },
  gosec: {
    normalize: normalizeGosecFindings,
    argv: (rootDir) => ['-fmt=json', '-quiet', '-no-fail', `${rootDir.replace(/[/\\]$/, '')}/...`],
    parsesStdout: true,
  },
  trivy: {
    normalize: normalizeTrivyFindings,
    argv: (rootDir) => ['fs', '--scanners', 'vuln,misconfig,secret', '--format', 'json', '--quiet', rootDir],
    parsesStdout: true,
  },
};

/**
 * Run a normalized security tool. `exec(path, argv)` must resolve to
 * { stdout, stderr } (injected; at runtime a no-shell execFile of the resolved,
 * checksum-verified tool path). Fail-open: any error yields available:false.
 *
 * @param {string} toolKey
 * @param {{ rootDir: string, toolPath: string, exec: (path: string, argv: string[]) => Promise<{stdout: string, stderr?: string}> }} opts
 * @returns {Promise<{tool: string, available: boolean, findings: Array<object>, rawCount: number, error?: string}>}
 */
export async function runSecurityTool(toolKey, opts) {
  const spec = RUN_SPECS[toolKey];
  if (!spec) return { tool: toolKey, available: false, findings: [], rawCount: 0, error: `unknown tool ${toolKey}` };
  try {
    const { stdout } = await opts.exec(opts.toolPath, spec.argv(opts.rootDir));
    const parsed = JSON.parse(stdout || (toolKey === 'gitleaks' ? '[]' : '{}'));
    const findings = spec.normalize(parsed);
    return { tool: toolKey, available: true, findings, rawCount: findings.length };
  } catch (err) {
    return {
      tool: toolKey,
      available: false,
      findings: [],
      rawCount: 0,
      error: err && err.message ? err.message : String(err),
    };
  }
}
