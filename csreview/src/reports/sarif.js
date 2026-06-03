// @ts-check
import fs from 'fs';

/**
 * SARIF 2.1.0 exporter for CSReview findings.
 *
 * SARIF is the interchange format consumed by GitHub code scanning, Azure
 * DevOps, and most CI security dashboards. This reporter is intentionally
 * read-only and never embeds raw `vulnerableCode` (which may contain secrets);
 * it emits name + description + remediation hint only.
 */

const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };

/** GitHub code-scanning `security-severity` is a 0.0-10.0 numeric string. */
const SECURITY_SEVERITY = { CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.0', LOW: '3.0', INFO: '1.0' };

function normalizeSeverity(severity) {
  const upper = String(severity || '').toUpperCase();
  return SARIF_LEVEL[upper] ? upper : 'MEDIUM';
}

function sarifLevel(severity) {
  return SARIF_LEVEL[normalizeSeverity(severity)] || 'warning';
}

function securitySeverity(severity) {
  return SECURITY_SEVERITY[normalizeSeverity(severity)] || '5.0';
}

function canonicalCwe(cwe) {
  const match = String(cwe || '').match(/CWE-\d+/i);
  return match ? match[0].toUpperCase() : '';
}

function cweUrl(cwe) {
  const match = String(cwe || '').match(/CWE-(\d+)/i);
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : undefined;
}

function toUri(file) {
  return String(file || 'unknown')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '');
}

function readPackageVersion() {
  try {
    const packageJson = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
    return packageJson.version || '0.0.1';
  } catch {
    return '0.0.1';
  }
}

/**
 * Stable identifier used to group results into SARIF rules. Prefers the
 * canonical CWE, then the category, so the same class of issue shares a rule.
 *
 * @param {Record<string, unknown>} finding
 */
function ruleIdFor(finding) {
  const cwe = canonicalCwe(finding?.cwe);
  if (cwe) return cwe;
  const category = String(finding?.category || '').trim();
  if (category) return category.replace(/\s+/g, '-');
  return 'csreview-finding';
}

/**
 * Result message. Never includes the raw code snippet to avoid leaking secrets
 * into the SARIF artifact (which is frequently uploaded to CI dashboards).
 *
 * @param {Record<string, any>} finding
 */
function messageText(finding) {
  const parts = [String(finding?.name || 'Security finding')];
  if (finding?.description) parts.push(String(finding.description));
  if (finding?.fix) parts.push(`Remediation: ${String(finding.fix).split('\n')[0]}`);
  return parts.join(' — ');
}

/**
 * Stable per-finding fingerprint so code-scanning can track a result across
 * runs even if line numbers shift slightly.
 *
 * @param {Record<string, any>} finding
 */
function partialFingerprint(finding) {
  const file = toUri(finding?.file).toLowerCase();
  const cwe = canonicalCwe(finding?.cwe) || String(finding?.category || '').toLowerCase();
  const name = String(finding?.name || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
  return `${file}:${cwe}:${name}`;
}

/**
 * Build a SARIF 2.1.0 log object from canonical findings.
 *
 * @param {object} [_projectInfo] reserved for parity with the HTML/Markdown reporters
 * @param {Array<Record<string, any>>} [findings]
 * @param {{packageVersion?: string}} [metadata]
 * @returns {object}
 */
export function buildSarifLog(_projectInfo = {}, findings = [], metadata = {}) {
  const safeFindings = (Array.isArray(findings) ? findings : []).filter(Boolean);
  const rules = new Map();

  const results = safeFindings.map((finding) => {
    const ruleId = ruleIdFor(finding);
    if (!rules.has(ruleId)) {
      const helpUri = cweUrl(finding?.cwe);
      rules.set(ruleId, {
        id: ruleId,
        name: String(finding?.category || ruleId).replace(/[^A-Za-z0-9]/g, '') || 'Finding',
        shortDescription: { text: String(finding?.category || ruleId) },
        ...(helpUri ? { helpUri } : {}),
        properties: {
          'security-severity': securitySeverity(finding?.severity),
          tags: ['security', ...(finding?.owasp ? [String(finding.owasp)] : [])],
        },
      });
    }

    return {
      ruleId,
      level: sarifLevel(finding?.severity),
      message: { text: messageText(finding) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: toUri(finding?.file) },
            region: { startLine: Math.max(1, Number(finding?.line) || 1) },
          },
        },
      ],
      partialFingerprints: { csreviewFingerprint: partialFingerprint(finding) },
      properties: {
        severity: normalizeSeverity(finding?.severity),
        confidence: String(finding?.confidence || 'N/A'),
        ...(canonicalCwe(finding?.cwe) ? { cwe: canonicalCwe(finding?.cwe) } : {}),
        vibeRisk: Boolean(finding?.vibeRisk),
        source: String(finding?.source || 'csreview-detector'),
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CSReview',
            informationUri: 'https://github.com/decksoftware/csreview',
            version: metadata.packageVersion || readPackageVersion(),
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}

/**
 * Write a SARIF 2.1.0 report to disk.
 *
 * @param {object} projectInfo
 * @param {Array<Record<string, any>>} findings
 * @param {string} outputPath
 * @param {{packageVersion?: string}} [metadata]
 * @returns {string}
 */
export function generateSarifReport(projectInfo, findings, outputPath, metadata = {}) {
  console.log('Generating SARIF report...');
  const log = buildSarifLog(projectInfo, findings, metadata);
  fs.writeFileSync(outputPath, JSON.stringify(log, null, 2), 'utf8');
  console.log(`SARIF report saved to ${outputPath}`);
  return outputPath;
}
