// @ts-check
export const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

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

export function calculateSecurityScore(findings = [], projectInfo = {}) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  if (safeFindings.length === 0) {
    return 100;
  }

  const totalWeight = safeFindings.reduce((sum, finding) => sum + getSeverityWeight(finding?.severity), 0);
  const fileCount = getAuditedFileSet(projectInfo, safeFindings).size || 1;
  const density = totalWeight / fileCount;
  const rawScore = 100 - density * 5;
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
