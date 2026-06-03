// @ts-check
export const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

// Confidence dampening for the density term. A confirmed/tool-reported finding
// counts at full weight; low-confidence heuristics contribute less so a noisy
// heuristic does not tank the score as hard as a corroborated issue. Findings
// without a confidence field default to full weight (legacy behavior).
export const CONFIDENCE_FACTORS = {
  CONFIRMED: 1.0,
  'TOOL-ONLY': 1.0,
  HIGH: 1.0,
  MEDIUM: 0.7,
  LOW: 0.4,
};

const DENSITY_MULTIPLIER = 5;

function normalizeFilePath(filePath) {
  return String(filePath || '')
    .trim()
    .replace(/\\/g, '/');
}

export function getAuditedFileSet(projectInfo = {}, findings = []) {
  const files = new Set();
  for (const filePath of [
    ...(projectInfo.files || []),
    ...(projectInfo.configFiles || []),
    ...(projectInfo.depFiles || []),
    ...(projectInfo.baasFiles || []),
    ...(findings || []).map((finding) => finding?.file),
  ]) {
    const normalized = normalizeFilePath(filePath);
    if (normalized) {
      files.add(normalized);
    }
  }
  return files;
}

export function getSeverityWeight(severity) {
  return SEVERITY_WEIGHTS[severity] || 0;
}

/**
 * Confidence multiplier for the density term. Unknown/missing confidence keeps
 * the legacy full weight so existing behavior (and tests) are preserved.
 *
 * @param {string} [confidence]
 * @returns {number}
 */
export function getConfidenceFactor(confidence) {
  const key = String(confidence || '').toUpperCase();
  if (key in CONFIDENCE_FACTORS) {
    return CONFIDENCE_FACTORS[key];
  }
  return 1.0;
}

/**
 * Compute a 0-100 security score.
 *
 * Model: confidence-weighted severity density across audited files, then a hard
 * severity cap so the presence of a higher-severity finding can never be hidden
 * by a large file count (e.g. any CRITICAL caps the score at 49). The cap is
 * deliberately severity-based (not confidence-based): for a security tool, a
 * potential critical should pull the score down even if only heuristically
 * detected. Confidence only refines the sub-cap density term.
 *
 * @param {Array<{severity?: string, confidence?: string, file?: string}>} [findings]
 * @param {object} [projectInfo]
 * @returns {number}
 */
export function calculateSecurityScore(findings = [], projectInfo = {}) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  if (safeFindings.length === 0) {
    return 100;
  }

  const weightedTotal = safeFindings.reduce(
    (sum, finding) => sum + getSeverityWeight(finding?.severity) * getConfidenceFactor(finding?.confidence),
    0,
  );
  const fileCount = getAuditedFileSet(projectInfo, safeFindings).size || 1;
  const density = weightedTotal / fileCount;
  const rawScore = 100 - density * DENSITY_MULTIPLIER;
  const severities = new Set(safeFindings.map((finding) => finding?.severity));
  const severityCap = severities.has('CRITICAL')
    ? 49
    : severities.has('HIGH')
      ? 74
      : severities.has('MEDIUM')
        ? 89
        : severities.has('LOW')
          ? 97
          : 100;

  return Math.max(0, Math.min(severityCap, Math.round(rawScore)));
}
