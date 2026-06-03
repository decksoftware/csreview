// @ts-check
import fs from 'fs';
import path from 'path';
import { calculateSecurityScore, SEVERITY_WEIGHTS } from '../score.js';
import { originBreakdown } from './summary.js';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/**
 * Escape untrusted text for inline Markdown contexts (headings, list items,
 * table cells). Finding fields can originate from Semgrep messages, dependency
 * advisories, or scanned file paths, so they are treated as untrusted and must
 * not be able to break tables, code spans, links, or inject raw HTML.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function escapeMdInline(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\r?\n/g, ' ')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([`*_[\]|])/g, '\\$1');
}

/**
 * Render untrusted text as an inline code span that cannot break out of the
 * span or a surrounding table cell. Backticks are stripped (paths/identifiers
 * should not contain them) and pipes/newlines are neutralized.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function mdCodeSpan(value) {
  const text = String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\r?\n/g, ' ')
    .replace(/`/g, '')
    .replace(/\|/g, '\\|');
  return `\`${text}\``;
}

/**
 * Render a fenced code block whose fence is always longer than any backtick run
 * inside the snippet, so attacker-controlled code (e.g. a Semgrep snippet that
 * itself contains ```) can never break out of the block and inject Markdown.
 *
 * @param {unknown} code
 * @param {string} [language]
 * @returns {string}
 */
export function fencedCode(code, language = '') {
  const text = String(code ?? '');
  const runs = text.match(/`+/g) || [];
  let longestRun = 0;
  for (const run of runs) {
    longestRun = Math.max(longestRun, run.length);
  }
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  const safeLang = /^[a-z0-9+#.-]*$/i.test(String(language || '')) ? String(language || '') : '';
  return `${fence}${safeLang}\n${text}\n${fence}`;
}

const EXTENSION_LANGUAGE_MAP = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.py': 'python',
  '.java': 'java',
  '.go': 'go',
  '.rs': 'rust',
  '.php': 'php',
  '.rb': 'ruby',
  '.cs': 'csharp',
  '.c': 'c',
  '.cpp': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp',
  '.swift': 'swift',
  '.kt': 'kotlin',
  '.dart': 'dart',
  '.vue': 'html',
  '.html': 'html',
  '.sql': 'sql',
  '.sh': 'bash',
  '.ps1': 'powershell',
  '.pas': 'pascal',
  '.pp': 'pascal',
  '.dpr': 'pascal',
  '.lpr': 'pascal',
};

const OWASP_CATEGORY_MAP = {
  Injection: 'A03:2021',
  'Broken Authentication': 'A07:2021',
  'Sensitive Data Exposure': 'A02:2021',
  'XML External Entities': 'A05:2021',
  'Broken Access Control': 'A01:2021',
  'Access Control': 'A01:2021',
  'Security Misconfiguration': 'A05:2021',
  'Cross-Site Scripting': 'A03:2021',
  'Insecure Deserialization': 'A08:2021',
  'Dependency Vulnerability': 'A06:2021',
  'Supply Chain': 'A08:2021',
  'Memory Safety': 'A06:2021',
  'Data Leakage': 'A09:2021',
  Cryptography: 'A02:2021',
  Authentication: 'A07:2021',
  'Using Components with Known Vulnerabilities': 'A06:2021',
  'Insufficient Logging & Monitoring': 'A09:2021',
  'Server-Side Request Forgery': 'A10:2021',
  'Cryptographic Failures': 'A02:2021',
  'Identification and Authentication Failures': 'A07:2021',
  'Software and Data Integrity Failures': 'A08:2021',
  'Security Logging and Monitoring Failures': 'A09:2021',
};

function readPackageVersion() {
  try {
    const packageJson = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
    return packageJson.version || '0.0.1';
  } catch {
    return '0.0.1';
  }
}

function getLanguageFromExtension(file) {
  const ext = path.extname(file).toLowerCase();
  return EXTENSION_LANGUAGE_MAP[ext] || 'text';
}

function getCweUrl(cwe) {
  // Only build a URL from a clean CWE id. Never interpolate an arbitrary value
  // into the link target: a crafted `cwe` (e.g. from a subagent partial) such as
  // `x)](http://evil.com)` would otherwise close the Markdown link early and
  // inject an attacker-controlled live link into the report.
  const match = String(cwe || '').match(/CWE-(\d+)/i);
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : '';
}

function getOwaspUrl(owasp) {
  if (!owasp) return '';
  const match = String(owasp).match(/A(\d{2}):(\d{4})/);
  if (match) {
    const num = parseInt(match[1], 10);
    const names = [
      'A01_2021-Broken_Access_Control',
      'A02_2021-Cryptographic_Failures',
      'A03_2021-Injection',
      'A04_2021-Insecure_Design',
      'A05_2021-Security_Misconfiguration',
      'A06_2021-Vulnerable_and_Outdated_Components',
      'A07_2021-Identification_and_Authentication_Failures',
      'A08_2021-Software_and_Data_Integrity_Failures',
      'A09_2021-Security_Logging_and_Monitoring_Failures',
      'A10_2021-Server-Side_Request_Forgery_(SSRF)',
    ];
    if (num >= 1 && num <= 10) return `https://owasp.org/Top10/${names[num - 1]}/`;
  }
  return `https://owasp.org/Top10/`;
}

function sortBySeverity(findings) {
  return [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

function groupByCategory(findings) {
  const groups = {};
  for (const f of findings) {
    if (!groups[f.category]) groups[f.category] = [];
    groups[f.category].push(f);
  }
  return groups;
}

function getRiskAssessment(findings, score) {
  const counts = countBySeverity(findings);
  const categories = Object.keys(groupByCategory(findings));
  const topCategory =
    categories.length > 0
      ? categories.reduce((a, b) =>
          findings.filter((f) => f.category === a).length >= findings.filter((f) => f.category === b).length ? a : b,
        )
      : 'None';
  const safeTopCategory = escapeMdInline(topCategory);

  if (counts.CRITICAL > 0) {
    return `The application has a critical security posture with a score of ${score}/100. ${counts.CRITICAL} critical vulnerabilities were identified, primarily in ${safeTopCategory}. Immediate remediation is required to prevent potential exploitation. The most urgent issues should be addressed before any release.`;
  }
  if (counts.HIGH > 0) {
    return `The application has a concerning security posture with a score of ${score}/100. ${counts.HIGH} high-severity vulnerabilities were found, with ${safeTopCategory} being the most affected area. These issues should be prioritized in the next sprint cycle to reduce the attack surface.`;
  }
  if (counts.MEDIUM > 0) {
    return `The application has a moderate security posture with a score of ${score}/100. ${counts.MEDIUM} medium-severity findings were identified across ${categories.length} categories. While not immediately exploitable, these issues should be scheduled for remediation to improve overall security.`;
  }
  if (counts.LOW > 0 || counts.INFO > 0) {
    return `The application has a good security posture with a score of ${score}/100. Only low-severity and informational findings were detected. Consider addressing these during regular maintenance cycles.`;
  }
  return `No security findings were identified by this run. The score is ${score}/100, but this does not prove the application is secure; it means CSReview and the available external tools did not detect reportable issues in the analyzed scope.`;
}

function getTopPriorityFixes(findings, limit = 5) {
  const sorted = sortBySeverity(findings);
  return sorted.slice(0, limit);
}

function buildHeader(projectInfo, score, findings) {
  const techStack = escapeMdInline(projectInfo.techStack?.join(', ') || 'Unknown');
  const frameworks = escapeMdInline(projectInfo.frameworks?.join(', ') || 'None detected');
  const date = new Date().toISOString();

  return `# CSReview Security Audit Report

> **Project**: ${escapeMdInline(projectInfo.name)}
> **Type**: ${escapeMdInline(projectInfo.projectType || 'Unknown')}
> **Tech Stack**: ${techStack}
> **Frameworks**: ${frameworks}
> **Date**: ${date}
> **Security Score**: ${score}/100
> **Total Findings**: ${findings.length}`;
}

function buildExecutiveSummary(findings, score) {
  const counts = countBySeverity(findings);
  const topFixes = getTopPriorityFixes(findings, 5);
  const riskAssessment = getRiskAssessment(findings, score);

  const topFixesList =
    topFixes.length > 0
      ? topFixes
          .map(
            (f, i) => `${i + 1}. **${escapeMdInline(f.name)}** (${f.severity}) - ${mdCodeSpan(`${f.file}:${f.line}`)}`,
          )
          .join('\n')
      : 'No findings to prioritize.';

  return `## Executive Summary

| Severity | Count | Weight |
|----------|-------|--------|
| CRITICAL | ${counts.CRITICAL} | ${counts.CRITICAL * SEVERITY_WEIGHTS.CRITICAL} pts |
| HIGH | ${counts.HIGH} | ${counts.HIGH * SEVERITY_WEIGHTS.HIGH} pts |
| MEDIUM | ${counts.MEDIUM} | ${counts.MEDIUM * SEVERITY_WEIGHTS.MEDIUM} pts |
| LOW | ${counts.LOW} | ${counts.LOW * SEVERITY_WEIGHTS.LOW} pts |
| INFO | ${counts.INFO} | 0 pts |

### Risk Assessment

${riskAssessment}

### Top 5 Priority Fixes

${topFixesList}`;
}

function buildFindingsIndex(findings) {
  const sorted = sortBySeverity(findings);
  const rows = sorted
    .map(
      (f) =>
        `| ${escapeMdInline(f.id)} | ${f.severity} | ${escapeMdInline(f.category)} | ${escapeMdInline(f.cwe || 'N/A')} | ${mdCodeSpan(f.file)} | ${f.line} | ${escapeMdInline(f.name)} | ${escapeMdInline(f.confidence || 'N/A')} |`,
    )
    .join('\n');

  return `## Findings Index

| ID | Severity | Category | CWE | File | Line | Name | Confidence |
|----|----------|----------|-----|------|------|------|------------|
${rows}`;
}

function buildDetailedFindings(findings) {
  const sorted = sortBySeverity(findings);

  const sections = sorted.map((f) => {
    const lang = getLanguageFromExtension(f.file);
    const cweLink = f.cwe ? `[${escapeMdInline(f.cwe)}](${getCweUrl(f.cwe)})` : 'N/A';
    const owaspCode = f.owasp || OWASP_CATEGORY_MAP[f.category] || '';
    const owaspLink = owaspCode ? `[${escapeMdInline(owaspCode)}](${getOwaspUrl(owaspCode)})` : 'N/A';
    const vibeRiskText = f.vibeRisk ? 'Yes' : 'No';
    const complianceText = escapeMdInline(f.compliance || 'None specified');
    const exploitationText = escapeMdInline(f.exploitation || 'No potential exploitation path provided.');
    const references =
      f.references && f.references.length > 0
        ? f.references
            .map((r) => `- ${escapeMdInline(typeof r === 'string' ? r : r?.url || r?.advisory || '')}`)
            .join('\n')
        : `- ${getCweUrl(f.cwe)}`;

    return `---

### [${escapeMdInline(f.id)}] ${escapeMdInline(f.name)}

**Severity**: ${f.severity}
**Category**: ${escapeMdInline(f.category)}
**CWE**: ${cweLink}
**OWASP**: ${owaspLink}
**Confidence**: ${escapeMdInline(f.confidence || 'N/A')}
**Vibe Coding Risk**: ${vibeRiskText}
**Compliance**: ${complianceText}

#### Location

- **File**: ${mdCodeSpan(f.file)}
- **Line**: ${f.line}

#### Description

${escapeMdInline(f.description)}

#### Vulnerable Code

${fencedCode(f.vulnerableCode || 'No code snippet available.', lang)}

#### Potential Exploitation Path (theoretical)

Static-analysis hypothesis only; not a validated or executed exploit.

${exploitationText}

#### Recommended Fix

${fencedCode(f.fix || 'No fix recommendation provided.', lang)}

#### References

${references}

---`;
  });

  return `## Detailed Findings

${sections.join('\n\n')}`;
}

function buildCategoryAnalysis(findings) {
  const groups = groupByCategory(findings);
  const categories = Object.keys(groups).sort();

  if (categories.length === 0) {
    return `## Category Analysis

No findings to categorize.`;
  }

  const sections = categories.map((category) => {
    const catFindings = groups[category];
    const counts = countBySeverity(catFindings);
    const severityBreakdown = Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([sev, count]) => `${count} ${sev}`)
      .join(', ');

    const fileList = [...new Set(catFindings.map((f) => f.file))];
    const filesAffected = fileList.map((f) => mdCodeSpan(f)).join(', ');

    return `### ${escapeMdInline(category)}

**Total Findings**: ${catFindings.length}
**Severity Breakdown**: ${severityBreakdown}
**Files Affected**: ${filesAffected}

${catFindings.map((f) => `- **${escapeMdInline(f.id)}** (${f.severity}): ${escapeMdInline(f.name)} in ${mdCodeSpan(`${f.file}:${f.line}`)}`).join('\n')}`;
  });

  return `## Category Analysis

${sections.join('\n\n')}`;
}

function buildComplianceMapping(findings) {
  const owaspMap = {};
  const gdprFindings = [];
  const lgpdFindings = [];

  for (const f of findings) {
    const owaspCode = f.owasp || OWASP_CATEGORY_MAP[f.category] || '';
    if (owaspCode) {
      if (!owaspMap[owaspCode]) owaspMap[owaspCode] = [];
      owaspMap[owaspCode].push(f.id);
    }

    const compliance = (f.compliance || '').toUpperCase();
    if (compliance.includes('GDPR') || compliance.includes('DATA PROTECTION') || compliance.includes('PERSONAL DATA')) {
      gdprFindings.push(f);
    }
    if (compliance.includes('LGPD') || compliance.includes('DADOS PESSOAIS')) {
      lgpdFindings.push(f);
    }
  }

  const hasDataExposure = findings.some(
    (f) =>
      f.category === 'Sensitive Data Exposure' ||
      f.category === 'Cryptographic Failures' ||
      f.category === 'Data Leakage' ||
      (f.compliance || '').toLowerCase().includes('data'),
  );

  const owaspRows =
    Object.keys(owaspMap).length > 0
      ? Object.entries(owaspMap)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([code, ids]) => `| ${escapeMdInline(code)} | FAIL | ${ids.map(escapeMdInline).join(', ')} |`)
          .join('\n')
      : '| - | PASS | No findings mapped |';

  const gdprRows =
    gdprFindings.length > 0
      ? gdprFindings.map((f) => `| Art.32 | ${f.severity} | ${escapeMdInline(f.id)} |`).join('\n')
      : hasDataExposure
        ? '| Art.32 | MEDIUM | General risk |'
        : '| Art.32 | PASS | No findings mapped |';

  const lgpdRows =
    lgpdFindings.length > 0
      ? lgpdFindings.map((f) => `| Art.46 | ${f.severity} | ${escapeMdInline(f.id)} |`).join('\n')
      : hasDataExposure
        ? '| Art.46 | MEDIUM | General risk |'
        : '| Art.46 | PASS | No findings mapped |';

  return `## Compliance Impact

> Indicative correlation derived from CWE/category mappings, not an audited compliance verification.

### OWASP ASVS

| Requirement | Status | Findings |
|-------------|--------|----------|
${owaspRows}

### GDPR

| Article | Impact | Findings |
|---------|--------|----------|
${gdprRows}

### LGPD

| Article | Impact | Findings |
|---------|--------|----------|
${lgpdRows}`;
}

function estimateEffort(finding) {
  const severity = finding.severity;
  const category = finding.category || '';
  if (severity === 'CRITICAL' && (category.includes('Injection') || category.includes('XSS'))) return 'Medium';
  if (severity === 'CRITICAL') return 'High';
  if (severity === 'HIGH') return 'Medium';
  if (severity === 'MEDIUM') return 'Low';
  return 'Low';
}

function getImpactSummary(finding) {
  const impacts = {
    CRITICAL: 'Remote code execution, full system compromise, or data breach',
    HIGH: 'Significant security risk, potential for data exposure or privilege escalation',
    MEDIUM: 'Moderate risk, could be chained with other vulnerabilities',
    LOW: 'Minor security concern, limited direct impact',
    INFO: 'Informational, best practice recommendation',
  };
  return impacts[finding.severity] || 'Security improvement recommended';
}

function getFixSummary(finding) {
  if (!fixAvailable(finding)) return 'Review and apply appropriate remediation';
  const fix = finding.fix;
  if (fix.length <= 80) return escapeMdInline(fix);
  return escapeMdInline(fix.split('\n')[0].substring(0, 80) + '...');
}

function fixAvailable(finding) {
  return finding.fix && finding.fix.trim().length > 0;
}

function buildPriorityLine(f, i) {
  return `${i + 1}. **${escapeMdInline(f.id)}** - ${escapeMdInline(f.name)} in ${mdCodeSpan(`${f.file}:${f.line}`)}
   - Impact: ${getImpactSummary(f)}
   - Effort: ${estimateEffort(f)}
   - Fix: ${getFixSummary(f)}`;
}

function buildFixPriorityOrder(findings) {
  const grouped = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL'),
    HIGH: findings.filter((f) => f.severity === 'HIGH'),
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM'),
    LOW: findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFO'),
  };

  const sections = [];

  if (grouped.CRITICAL.length > 0) {
    sections.push(`### Immediate (CRITICAL)

${grouped.CRITICAL.map(buildPriorityLine).join('\n')}`);
  }

  if (grouped.HIGH.length > 0) {
    sections.push(`### Short-term (HIGH)

${grouped.HIGH.map(buildPriorityLine).join('\n')}`);
  }

  if (grouped.MEDIUM.length > 0) {
    sections.push(`### Medium-term (MEDIUM)

${grouped.MEDIUM.map(buildPriorityLine).join('\n')}`);
  }

  if (grouped.LOW.length > 0) {
    sections.push(`### Low Priority (LOW/INFO)

${grouped.LOW.map(buildPriorityLine).join('\n')}`);
  }

  if (sections.length === 0) {
    return `## Fix Priority Order

No findings to remediate.`;
  }

  return `## Fix Priority Order

${sections.join('\n\n')}`;
}

function buildAgentInstructions(findings) {
  const sorted = sortBySeverity(findings);

  if (sorted.length === 0) {
    return `## Remediation Guidance

> **READ-ONLY REPORT**: No vulnerabilities were found. CSReview did not modify the audited project.`;
  }

  const guidance = sorted.map((f) => {
    const lang = getLanguageFromExtension(f.file);
    const hasFix = fixAvailable(f);

    const beforeBlock = f.vulnerableCode ? fencedCode(f.vulnerableCode, lang) : 'No vulnerable code snippet available.';

    const afterBlock = hasFix
      ? fencedCode(f.fix, 'text')
      : 'No remediation hint available. Manual security review required.';

    return `### Finding ${escapeMdInline(f.id)}: ${escapeMdInline(f.name)}

**File**: ${mdCodeSpan(f.file)}
**Line**: ${f.line}
**Severity**: ${f.severity}
**Action**: Review the vulnerable code and validate the remediation approach against the project context, framework, schema, and tests before making any code change.

**Evidence**:

${beforeBlock}

**Recommended Remediation Approach**:

${afterBlock}`;
  });

  return `## Remediation Guidance

> **READ-ONLY REPORT**: CSReview never modifies, deletes, moves, or creates source code in the audited project. The guidance below is evidence for a human developer or coding agent to review. Apply changes only after understanding the application context, data model, framework rules, and regression risk.

${guidance.join('\n\n')}`;
}

function buildToolMetadata(toolResults) {
  if (!toolResults) {
    return '- **External Tools**: Not reported';
  }

  const semgrep = toolResults.semgrep || {};
  const packageAudit = toolResults.packageAudit || toolResults.npmAudit || {};
  const osvScanner = toolResults.osvScanner || {};
  const semgrepStatus = semgrep.available
    ? `available (${escapeMdInline(semgrep.version || 'version unknown')}), ${semgrep.rawCount || semgrep.findings?.length || 0} findings`
    : `not available${semgrep.error ? ` (${escapeMdInline(semgrep.error)})` : ''}`;
  const packageAuditLabel = escapeMdInline(packageAudit.tool || 'package audit');
  const packageAuditStatus = packageAudit.available
    ? `${packageAuditLabel} available (${escapeMdInline(packageAudit.version || 'version unknown')}), ${packageAudit.rawCount || packageAudit.findings?.length || 0} findings`
    : `not run${packageAudit.reason ? ` (${escapeMdInline(packageAudit.reason)})` : packageAudit.error ? ` (${escapeMdInline(packageAudit.error)})` : ''}`;
  const osvScannerStatus = osvScanner.available
    ? `available (${escapeMdInline(osvScanner.version || 'version unknown')}), ${osvScanner.rawCount || osvScanner.findings?.length || 0} findings`
    : `not available${osvScanner.error ? ` (${escapeMdInline(osvScanner.error)})` : ''}`;
  const semgrepInstall = semgrep.available
    ? ''
    : '\n- **Install Semgrep**: `pipx install semgrep`, `uv tool install semgrep`, or `brew install semgrep`, then verify with `semgrep --version`';
  const osvInstall = osvScanner.available
    ? ''
    : '\n- **Install OSV-Scanner**: `winget install Google.OSVScanner`, `brew install osv-scanner`, or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, then verify with `osv-scanner --version`';

  return `- **Analysis Mode**: ${escapeMdInline(toolResults.mode || 'Agent-Only')}
- **Semgrep Required**: Yes
- **Semgrep Status**: ${semgrepStatus}
- **Package Audit Status**: ${packageAuditStatus}
- **OSV-Scanner Status**: ${osvScannerStatus}${semgrepInstall}${osvInstall}`;
}

function buildScanMetadata(projectInfo, findings, startTime, metadata = {}) {
  const durationMs = Number.isFinite(Number(metadata.durationMs))
    ? Number(metadata.durationMs)
    : Date.now() - Number(metadata.analysisStartTime || startTime);
  const duration = (durationMs / 1000).toFixed(2);
  const scannerVersion = metadata.packageVersion || readPackageVersion();
  const confidenceBreakdown = { CONFIRMED: 0, 'TOOL-ONLY': 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    const c = String(f.confidence || 'MEDIUM').toUpperCase();
    if (confidenceBreakdown[c] !== undefined) confidenceBreakdown[c]++;
  }
  const origin = originBreakdown(findings);
  const originText =
    origin.rows.length > 0 ? origin.rows.map((r) => `${escapeMdInline(r.label)} ${r.count}`).join(', ') : 'none';

  const filesCount = projectInfo.files?.length || 0;
  const configCount = projectInfo.configFiles?.length || 0;

  return `## Scan Metadata

- **Scanner**: CSReview v${escapeMdInline(scannerVersion)}
- **Files Scanned**: ${filesCount}
- **Config Files**: ${configCount}
${buildToolMetadata(metadata.toolResults)}
- **Confidence Breakdown**: ${confidenceBreakdown.CONFIRMED} CONFIRMED, ${confidenceBreakdown['TOOL-ONLY']} TOOL-ONLY, ${confidenceBreakdown.HIGH} HIGH, ${confidenceBreakdown.MEDIUM} MEDIUM, ${confidenceBreakdown.LOW} LOW
- **Findings by origin** (trust corroborated first): ${origin.confirmed} CONFIRMED (tool+detector), ${originText}
- **Duration**: ${duration}s`;
}

export function generateMarkdownReport(projectInfo, findings, outputPath, metadata = {}) {
  console.log('Generating Markdown report...');

  const startTime = Date.now();
  const safeFindings = Array.isArray(findings) ? findings : [];
  const score = calculateSecurityScore(safeFindings, projectInfo);

  const sections = [
    buildHeader(projectInfo, score, safeFindings),
    buildExecutiveSummary(safeFindings, score),
    buildFindingsIndex(safeFindings),
    buildDetailedFindings(safeFindings),
    buildCategoryAnalysis(safeFindings),
    buildComplianceMapping(safeFindings),
    buildFixPriorityOrder(safeFindings),
    buildAgentInstructions(safeFindings),
    buildScanMetadata(projectInfo, safeFindings, startTime, metadata),
  ];

  const report = sections.join('\n\n');

  fs.writeFileSync(outputPath, report, 'utf8');
  console.log(`Markdown report saved to ${outputPath}`);
  return outputPath;
}
