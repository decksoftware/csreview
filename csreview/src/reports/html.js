// @ts-check
import fs from 'fs';
import { calculateSecurityScore } from '../score.js';

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
  INFO: '#64748b',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function safeToken(str, fallback = 'item') {
  const raw = String(str || '').toLowerCase();
  let token = '';
  let lastWasHyphen = false;

  for (const char of raw) {
    const code = char.charCodeAt(0);
    const safe = (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || char === '_' || char === '-';
    if (safe) {
      token += char;
      lastWasHyphen = false;
    } else if (token && !lastWasHyphen) {
      token += '-';
      lastWasHyphen = true;
    }
  }

  while (token.startsWith('-')) token = token.slice(1);
  while (token.endsWith('-')) token = token.slice(0, -1);
  return token || fallback;
}

function safeJsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003C')
    .replace(/>/g, '\\u003E')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function renderCweMeta(cwe) {
  if (!cwe) {
    return '<span class="meta-value">N/A</span>';
  }
  const normalized = String(cwe);
  const cweId = normalized.replace('CWE-', '');
  if (!/^CWE-\d+$/i.test(normalized)) {
    return `<span class="meta-value">${escapeHtml(normalized)}</span>`;
  }
  return `<span class="meta-value"><a href="https://cwe.mitre.org/data/definitions/${escapeHtml(cweId)}.html" target="_blank" rel="noopener noreferrer">${escapeHtml(normalized)}</a></span>`;
}

function getSeverityColor(severity) {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO;
}

function getCategoryIcon(category) {
  const icons = {
    Injection: '💉',
    XSS: '🕸️',
    Authentication: '🔐',
    Authorization: '🛡️',
    Cryptography: '🔒',
    Configuration: '⚙️',
    Dependencies: '📦',
    Secrets: '🗝️',
    Logging: '📋',
    Session: '🎫',
    'Input Validation': '✅',
    CORS: '🌐',
    'File Upload': '📁',
    Serialization: '🧩',
    SSRF: '🔄',
    Deserialization: '📥',
    'Path Traversal': '📂',
    'Command Injection': '⌨️',
    'SQL Injection': '🗃️',
    'Information Disclosure': '👁️',
    'Denial of Service': '🚫',
    'Race Condition': '🏁',
    'Business Logic': '🧠',
    'API Security': '🔌',
    'Data Exposure': '📊',
    'Code Quality': '📝',
    'Error Handling': '⚠️',
    'Privilege Escalation': '⬆️',
  };
  return icons[category] || '🔍';
}

function getScoreColor(score) {
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#dc2626';
}

function getScoreLabel(score) {
  if (score >= 80) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 40) return 'Poor';
  return 'Critical';
}

function highlightCode(code) {
  const keywords = [
    'const',
    'let',
    'var',
    'function',
    'return',
    'if',
    'else',
    'for',
    'while',
    'class',
    'import',
    'export',
    'from',
    'async',
    'await',
    'try',
    'catch',
    'throw',
    'new',
    'this',
    'typeof',
    'instanceof',
    'switch',
    'case',
    'break',
    'default',
    'true',
    'false',
    'null',
    'undefined',
    'require',
    'module',
    'exports',
    'console',
    'process',
    'yield',
    'extends',
    'super',
    'static',
    'get',
    'set',
    'of',
    'in',
    'do',
    'delete',
    'void',
    'public',
    'private',
    'protected',
    'interface',
    'type',
    'enum',
    'implements',
    'abstract',
    'readonly',
    'declare',
    'namespace',
    'package',
    'with',
    'debugger',
    'finally',
  ];
  const builtins = [
    'console',
    'JSON',
    'Math',
    'Object',
    'Array',
    'String',
    'Number',
    'Boolean',
    'Date',
    'RegExp',
    'Error',
    'Map',
    'Set',
    'Promise',
    'Symbol',
    'Proxy',
    'Reflect',
    'parseInt',
    'parseFloat',
    'isNaN',
    'isFinite',
    'encodeURI',
    'decodeURI',
    'setTimeout',
    'setInterval',
    'clearTimeout',
    'clearInterval',
    'fetch',
    'URL',
    'Buffer',
    'require',
    'process',
    '__dirname',
    '__filename',
    'module',
    'exports',
  ];
  const safePattern = /&amp;|&lt;|&gt;|&quot;|&#039;/g;
  const safeEntities = [];
  let processed = code.replace(safePattern, (match) => {
    safeEntities.push(match);
    return `\x00SAFE${safeEntities.length - 1}\x00`;
  });
  processed = processed
    .replace(/(["'`])(?:(?!\1|\\).|\\.)*\1/g, '<span class="hl-string">$&</span>')
    .replace(/\b(\d+\.?\d*)\b/g, '<span class="hl-number">$1</span>')
    .replace(/(\/\/.*?)(?=\n|$)/g, '<span class="hl-comment">$1</span>')
    .replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="hl-comment">$1</span>')
    .replace(/#(.*?)(?=\n|$)/g, '<span class="hl-comment">#$1</span>');
  const kwRegex = new RegExp('\\b(' + keywords.join('|') + ')\\b', 'g');
  processed = processed.replace(kwRegex, (match) => {
    if (/<span/.test(match)) return match;
    return '<span class="hl-keyword">' + match + '</span>';
  });
  const biRegex = new RegExp('\\b(' + builtins.join('|') + ')\\b', 'g');
  processed = processed.replace(biRegex, (match) => {
    if (/<span/.test(match)) return match;
    return '<span class="hl-builtin">' + match + '</span>';
  });
  processed = processed.replace(/\x00SAFE(\d+)\x00/g, (_, idx) => safeEntities[parseInt(idx)]);
  return processed;
}

function buildConicGradient(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return 'conic-gradient(#e2e8f0 0deg 360deg)';
  const segments = [];
  let currentDeg = 0;
  for (const sev of SEVERITY_ORDER) {
    if (counts[sev] > 0) {
      const deg = (counts[sev] / total) * 360;
      segments.push(`${getSeverityColor(sev)} ${currentDeg}deg ${currentDeg + deg}deg`);
      currentDeg += deg;
    }
  }
  return `conic-gradient(${segments.join(', ')})`;
}

function buildCategoryData(findings) {
  const cats = {};
  for (const f of findings) {
    cats[f.category] = (cats[f.category] || 0) + 1;
  }
  return Object.entries(cats).sort((a, b) => b[1] - a[1]);
}

function buildFileData(findings) {
  const files = {};
  for (const f of findings) {
    const name = f.file.split(/[/\\]/).pop();
    files[name] = (files[name] || 0) + 1;
  }
  return Object.entries(files)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
}

export function generateHtmlReport(projectInfo, findings, outputPath, metadata = {}) {
  console.log('Generating HTML report...');
  const score = calculateSecurityScore(findings, projectInfo);
  const scoreColor = getScoreColor(score);
  const scoreLabel = getScoreLabel(score);
  const counts = {};
  for (const sev of SEVERITY_ORDER) {
    counts[sev] = findings.filter((f) => f.severity === sev).length;
  }
  const categories = [...new Set(findings.map((f) => f.category))].sort();
  const categoryData = buildCategoryData(findings);
  const fileData = buildFileData(findings);
  const maxCatCount = categoryData.length > 0 ? categoryData[0][1] : 1;
  const maxFileCount = fileData.length > 0 ? fileData[0][1] : 1;
  const conicGradient = buildConicGradient(counts);
  const totalFindings = findings.length;
  const uniqueFiles = new Set(findings.map((f) => f.file)).size;
  const vibeRiskCount = findings.filter((f) => f.vibeRisk).length;
  const now = new Date().toISOString().split('T')[0];
  const toolMode = metadata.toolResults?.mode || 'Agent-Only';
  const semgrep = metadata.toolResults?.semgrep || {};
  const packageAudit = metadata.toolResults?.packageAudit || metadata.toolResults?.npmAudit || {};
  const osvScanner = metadata.toolResults?.osvScanner || {};
  const assuranceNote =
    totalFindings === 0
      ? '<p><strong>Assurance note:</strong> No findings were identified by this run. This does not prove the application is secure; it means CSReview and the available external tools did not detect reportable issues in the analyzed scope.</p>'
      : '';
  const semgrepText = semgrep.available
    ? `Semgrep ${escapeHtml(semgrep.version || '')} (${semgrep.rawCount || semgrep.findings?.length || 0} findings)`
    : `Semgrep unavailable${semgrep.error ? `: ${escapeHtml(semgrep.error)}` : ''}. Install with pipx install semgrep, uv tool install semgrep, or brew install semgrep.`;
  const packageAuditLabel = packageAudit.tool || 'package audit';
  const packageAuditText = packageAudit.available
    ? `${escapeHtml(packageAuditLabel)} ${escapeHtml(packageAudit.version || '')} (${packageAudit.rawCount || packageAudit.findings?.length || 0} findings)`
    : `package audit not run${packageAudit.reason ? `: ${escapeHtml(packageAudit.reason)}` : packageAudit.error ? `: ${escapeHtml(packageAudit.error)}` : ''}.`;
  const osvScannerText = osvScanner.available
    ? `OSV-Scanner ${escapeHtml(osvScanner.version || '')} (${osvScanner.rawCount || osvScanner.findings?.length || 0} findings)`
    : `OSV-Scanner unavailable${osvScanner.error ? `: ${escapeHtml(osvScanner.error)}` : ''}. Install with winget install Google.OSVScanner, brew install osv-scanner, or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest.`;

  const findingsHtml = findings
    .map((f) => {
      const color = getSeverityColor(f.severity);
      const icon = getCategoryIcon(f.category);
      const safeId = safeToken(f.id, 'finding');
      const safeSeverity = safeToken(f.severity, 'info').toUpperCase();
      const safeConfidence = safeToken(f.confidence || 'medium', 'medium');
      const filePath = String(f.file || 'unknown');
      const vibeBadge = f.vibeRisk
        ? `<span class="vibe-badge" title="Vibe Coding Risk">⚡ Vibe Coding Risk</span>`
        : '';
      const refs = (f.references || [])
        .map((r) => {
          if (typeof r === 'string') {
            return `<a href="${escapeHtml(r)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r)}</a>`;
          }
          return '';
        })
        .join('\n');
      const highlightedVuln = highlightCode(escapeHtml(f.vulnerableCode || ''));
      const highlightedFix = highlightCode(escapeHtml(f.fix || ''));

      return `
    <article class="finding-card" data-severity="${escapeHtml(safeSeverity)}" data-category="${escapeHtml(f.category)}" data-file="${escapeHtml(filePath)}" id="finding-${escapeHtml(safeId)}">
      <div class="finding-header" onclick="toggleFinding(this)">
        <div class="finding-header-left">
          <span class="finding-id">${escapeHtml(f.id)}</span>
          <span class="severity-badge" style="background:${color}">${escapeHtml(f.severity)}</span>
          <span class="finding-name">${escapeHtml(f.name)}</span>
          ${vibeBadge}
        </div>
        <div class="finding-header-right">
          <span class="finding-location">${escapeHtml(filePath.split(/[/\\]/).pop())}:${f.line}</span>
          <span class="chevron">▶</span>
        </div>
      </div>
      <div class="finding-body">
        <div class="finding-detail">
          <div class="detail-section">
            <h3>Description</h3>
            <p>${escapeHtml(f.description)}</p>
          </div>
          <div class="detail-meta">
            <div class="meta-item"><span class="meta-label">Category</span><span class="meta-value">${icon} ${escapeHtml(f.category)}</span></div>
            <div class="meta-item"><span class="meta-label">CWE</span>${renderCweMeta(f.cwe)}</div>
            <div class="meta-item"><span class="meta-label">OWASP</span><span class="meta-value">${escapeHtml(f.owasp)}</span></div>
            <div class="meta-item"><span class="meta-label">Confidence</span><span class="meta-value confidence-${safeConfidence}">${escapeHtml(f.confidence || 'MEDIUM')}</span></div>
            <div class="meta-item"><span class="meta-label">Compliance</span><span class="meta-value">${escapeHtml(f.compliance || 'N/A')}</span></div>
          </div>
          <div class="detail-section">
            <h3>Vulnerable Code</h3>
            <div class="code-block"><pre><code>${highlightedVuln}</code></pre></div>
          </div>
          <div class="detail-section">
            <h3>Potential Exploitation Path (theoretical)</h3>
            <p><strong>Static-analysis hypothesis:</strong> ${escapeHtml(f.exploitation || 'No potential exploitation path provided.')} This is not a validated or executed exploit.</p>
          </div>
          <div class="detail-section">
            <h3>Recommended Fix</h3>
            <div class="code-block"><pre><code>${highlightedFix}</code></pre></div>
          </div>
          ${refs ? `<div class="detail-section"><h3>References</h3><div class="references-list">${refs}</div></div>` : ''}
        </div>
      </div>
    </article>`;
    })
    .join('\n');

  const severityCardsHtml = SEVERITY_ORDER.map(
    (sev) => `
    <div class="stat-card" style="border-left: 4px solid ${getSeverityColor(sev)}" onclick="filterBySeverity('${sev}')">
      <div class="stat-count" style="color: ${getSeverityColor(sev)}">${counts[sev]}</div>
      <div class="stat-label">${sev}</div>
    </div>`,
  ).join('');

  const severityFiltersHtml = SEVERITY_ORDER.map(
    (sev) => `
    <label class="filter-checkbox">
      <input type="checkbox" value="${sev}" checked onchange="applyFilters()">
      <span class="checkbox-label">
        <span class="dot" style="background:${getSeverityColor(sev)}"></span>
        ${sev}
        <span class="filter-count">${counts[sev]}</span>
      </span>
    </label>`,
  ).join('');

  const categoryFiltersHtml = categories
    .map(
      (cat) => `
    <label class="filter-checkbox">
      <input type="checkbox" value="${escapeHtml(cat)}" checked onchange="applyFilters()">
      <span class="checkbox-label">${getCategoryIcon(cat)} ${escapeHtml(cat)}</span>
    </label>`,
    )
    .join('');

  const catBarHtml = categoryData
    .map(
      ([cat, count]) => `
    <div class="bar-row">
      <span class="bar-label">${getCategoryIcon(cat)} ${escapeHtml(cat)}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(count / maxCatCount) * 100}%; background:#3b82f6"></div>
      </div>
      <span class="bar-value">${count}</span>
    </div>`,
    )
    .join('');

  const fileBarHtml = fileData
    .map(
      ([file, count]) => `
    <div class="bar-row">
      <span class="bar-label" title="${escapeHtml(file)}">${escapeHtml(file)}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(count / maxFileCount) * 100}%; background:#8b5cf6"></div>
      </div>
      <span class="bar-value">${count}</span>
    </div>`,
    )
    .join('');

  const techStackHtml = (projectInfo.techStack || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('');
  const frameworksHtml = (projectInfo.frameworks || [])
    .map((f) => `<span class="tag tag-framework">${escapeHtml(f)}</span>`)
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report - ${escapeHtml(projectInfo.name)}</title>
<style>
:root {
  --sidebar-width: 260px;
  --header-height: 56px;
  --color-bg: #f8fafc;
  --color-surface: #ffffff;
  --color-text: #1e293b;
  --color-text-secondary: #64748b;
  --color-border: #e2e8f0;
  --color-border-light: #f1f5f9;
  --color-code-bg: #1e293b;
  --color-code-text: #e2e8f0;
  --color-primary: #3b82f6;
  --color-primary-hover: #2563eb;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.05);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.08), 0 4px 6px -4px rgba(0,0,0,0.04);
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --severity-critical: #dc2626;
  --severity-high: #ea580c;
  --severity-medium: #ca8a04;
  --severity-low: #2563eb;
  --severity-info: #64748b;
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #0f172a;
    --color-surface: #1e293b;
    --color-text: #e2e8f0;
    --color-text-secondary: #94a3b8;
    --color-border: #334155;
    --color-border-light: #1e293b;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
    --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.3), 0 2px 4px -2px rgba(0,0,0,0.2);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.4), 0 4px 6px -4px rgba(0,0,0,0.3);
  }
}

*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  scroll-behavior: smooth;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', Arial, sans-serif;
  background: var(--color-bg);
  color: var(--color-text);
  line-height: 1.6;
  min-height: 100vh;
}

a {
  color: var(--color-primary);
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}

.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  width: var(--sidebar-width);
  height: 100vh;
  background: var(--color-surface);
  border-right: 1px solid var(--color-border);
  overflow-y: auto;
  z-index: 100;
  display: flex;
  flex-direction: column;
  transition: transform 0.3s ease;
}

.sidebar-header {
  padding: 20px;
  border-bottom: 1px solid var(--color-border);
}

.sidebar-header h2 {
  font-size: 1.1rem;
  font-weight: 700;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.sidebar-header .project-type {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
}

.sidebar-nav {
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-border);
}

.sidebar-nav a {
  display: block;
  padding: 6px 10px;
  border-radius: var(--radius-sm);
  color: var(--color-text);
  font-size: 0.88rem;
  font-weight: 500;
  transition: background 0.15s;
}
.sidebar-nav a:hover {
  background: var(--color-border-light);
  text-decoration: none;
}

.sidebar-section {
  padding: 14px 16px;
  border-bottom: 1px solid var(--color-border);
}

.sidebar-section-title {
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--color-text-secondary);
  margin-bottom: 10px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  cursor: pointer;
  user-select: none;
}

.sidebar-section-title .toggle-icon {
  font-size: 0.65rem;
  transition: transform 0.2s;
}
.sidebar-section-title.collapsed .toggle-icon {
  transform: rotate(-90deg);
}
.sidebar-section-content {
  overflow: hidden;
  transition: max-height 0.3s ease;
}
.sidebar-section-content.collapsed {
  max-height: 0 !important;
}

.filter-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  cursor: pointer;
  font-size: 0.85rem;
}
.filter-checkbox input[type="checkbox"] {
  accent-color: var(--color-primary);
  width: 15px;
  height: 15px;
}
.checkbox-label {
  display: flex;
  align-items: center;
  gap: 6px;
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.filter-count {
  margin-left: auto;
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  background: var(--color-border-light);
  padding: 1px 6px;
  border-radius: 8px;
}

.filter-search {
  width: 100%;
  padding: 7px 10px;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  background: var(--color-bg);
  color: var(--color-text);
  font-size: 0.85rem;
  outline: none;
  transition: border-color 0.2s;
}
.filter-search:focus {
  border-color: var(--color-primary);
}

.sidebar-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tag {
  display: inline-block;
  padding: 2px 8px;
  background: var(--color-border-light);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--color-text-secondary);
}
.tag-framework {
  background: #eff6ff;
  border-color: #bfdbfe;
  color: #1d4ed8;
}
@media (prefers-color-scheme: dark) {
  .tag-framework {
    background: #1e3a5f;
    border-color: #2563eb;
    color: #93c5fd;
  }
}

.sidebar-footer {
  margin-top: auto;
  padding: 16px;
  border-top: 1px solid var(--color-border);
}

.btn-export {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  width: 100%;
  padding: 10px;
  background: var(--color-primary);
  color: #fff;
  border: none;
  border-radius: var(--radius-sm);
  font-size: 0.88rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s;
}
.btn-export:hover {
  background: var(--color-primary-hover);
}

.main-content {
  margin-left: var(--sidebar-width);
  min-height: 100vh;
}

.sticky-header {
  position: sticky;
  top: 0;
  z-index: 50;
  background: var(--color-surface);
  border-bottom: 1px solid var(--color-border);
  padding: 10px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: var(--header-height);
  box-shadow: var(--shadow-sm);
}

.sticky-header h1 {
  font-size: 1.15rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 0.85rem;
  color: var(--color-text-secondary);
}

.finding-counter {
  background: var(--color-border-light);
  padding: 4px 12px;
  border-radius: 12px;
  font-weight: 600;
  font-size: 0.85rem;
}

.menu-toggle {
  display: none;
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--color-text);
  padding: 4px;
}

.content-body {
  padding: 32px;
  max-width: 1400px;
}

.section {
  margin-bottom: 48px;
}

.section-title {
  font-size: 1.35rem;
  font-weight: 700;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.score-area {
  display: flex;
  gap: 40px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 40px;
}

.score-gauge {
  position: relative;
  width: 180px;
  height: 180px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.score-gauge-inner {
  position: absolute;
  width: 140px;
  height: 140px;
  border-radius: 50%;
  background: var(--color-surface);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: var(--shadow-md);
}

.score-number {
  font-size: 2.5rem;
  font-weight: 800;
  line-height: 1;
}

.score-suffix {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
  font-weight: 500;
}

.score-label {
  font-size: 0.95rem;
  font-weight: 700;
  margin-top: 2px;
}

.score-details {
  flex: 1;
  min-width: 280px;
}

.score-details h2 {
  font-size: 1.5rem;
  margin-bottom: 8px;
}

.score-details p {
  color: var(--color-text-secondary);
  font-size: 0.95rem;
  margin-bottom: 16px;
}

.score-metrics {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}

.score-metric {
  text-align: center;
}

.score-metric-value {
  font-size: 1.4rem;
  font-weight: 700;
}

.score-metric-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 16px;
  margin-bottom: 40px;
}

.stat-card {
  background: var(--color-surface);
  padding: 20px;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  text-align: center;
  cursor: pointer;
  transition: transform 0.15s, box-shadow 0.15s;
}
.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.stat-count {
  font-size: 2rem;
  font-weight: 800;
  line-height: 1.2;
}

.stat-label {
  font-size: 0.82rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-secondary);
  margin-top: 4px;
}

.charts-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin-bottom: 40px;
}

.chart-card {
  background: var(--color-surface);
  padding: 24px;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
}

.chart-card h3 {
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 20px;
}

.donut-chart {
  display: flex;
  align-items: center;
  gap: 32px;
}

.donut {
  width: 160px;
  height: 160px;
  border-radius: 50%;
  position: relative;
  flex-shrink: 0;
}

.donut-hole {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 90px;
  height: 90px;
  border-radius: 50%;
  background: var(--color-surface);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  font-weight: 800;
}

.donut-legend {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.85rem;
}

.legend-dot {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  flex-shrink: 0;
}

.legend-count {
  font-weight: 700;
  margin-left: auto;
  min-width: 24px;
  text-align: right;
}

.bar-chart {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.bar-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.bar-label {
  font-size: 0.82rem;
  font-weight: 500;
  width: 140px;
  flex-shrink: 0;
  text-align: right;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.bar-track {
  flex: 1;
  height: 20px;
  background: var(--color-border-light);
  border-radius: 4px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.6s ease;
  min-width: 2px;
}

.bar-value {
  font-size: 0.82rem;
  font-weight: 700;
  width: 30px;
  text-align: right;
  flex-shrink: 0;
}

.chart-card-wide {
  grid-column: 1 / -1;
}

.finding-card {
  background: var(--color-surface);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  margin-bottom: 12px;
  overflow: hidden;
  border: 1px solid var(--color-border);
  transition: box-shadow 0.2s;
}
.finding-card:hover {
  box-shadow: var(--shadow-lg);
}

.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  cursor: pointer;
  user-select: none;
  gap: 12px;
  transition: background 0.15s;
}
.finding-header:hover {
  background: var(--color-border-light);
}

.finding-header-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  min-width: 0;
}

.finding-header-right {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.finding-id {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.8rem;
  font-weight: 700;
  color: var(--color-text-secondary);
  background: var(--color-border-light);
  padding: 2px 8px;
  border-radius: 4px;
}

.severity-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #fff;
  white-space: nowrap;
}

.finding-name {
  font-weight: 600;
  font-size: 0.95rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.vibe-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  background: #fef3c7;
  color: #92400e;
  border: 1px solid #fde68a;
  border-radius: 10px;
  font-size: 0.72rem;
  font-weight: 700;
  white-space: nowrap;
}
@media (prefers-color-scheme: dark) {
  .vibe-badge {
    background: #451a03;
    color: #fbbf24;
    border-color: #78350f;
  }
}

.finding-location {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.8rem;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.chevron {
  font-size: 0.7rem;
  color: var(--color-text-secondary);
  transition: transform 0.25s ease;
}
.finding-card.expanded .chevron {
  transform: rotate(90deg);
}

.finding-body {
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.4s ease;
}
.finding-card.expanded .finding-body {
  max-height: 5000px;
}

.finding-detail {
  padding: 0 20px 24px;
  border-top: 1px solid var(--color-border);
}

.detail-section {
  margin-top: 20px;
}

.detail-section h3 {
  font-size: 0.85rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-secondary);
  margin-bottom: 8px;
}

.detail-section p {
  font-size: 0.92rem;
  line-height: 1.7;
}

.detail-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-top: 20px;
  padding: 16px;
  background: var(--color-bg);
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border);
}

.meta-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.meta-label {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-secondary);
}

.meta-value {
  font-size: 0.88rem;
  font-weight: 600;
}

.confidence-high { color: #16a34a; }
.confidence-medium { color: #ca8a04; }
.confidence-low { color: #dc2626; }

.code-block {
  background: var(--color-code-bg);
  border-radius: var(--radius-sm);
  overflow: hidden;
  border: 1px solid #334155;
}

.code-block pre {
  margin: 0;
  padding: 16px;
  overflow-x: auto;
  font-size: 0.85rem;
  line-height: 1.7;
}

.code-block code {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  color: var(--color-code-text);
}

.hl-keyword { color: #c084fc; font-weight: 600; }
.hl-string { color: #86efac; }
.hl-number { color: #fbbf24; }
.hl-comment { color: #64748b; font-style: italic; }
.hl-builtin { color: #67e8f9; }

.references-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.references-list a {
  font-size: 0.88rem;
  word-break: break-all;
}

.no-findings {
  text-align: center;
  padding: 60px 20px;
  color: var(--color-text-secondary);
}
.no-findings .icon {
  font-size: 3rem;
  margin-bottom: 12px;
}
.no-findings h3 {
  font-size: 1.2rem;
  margin-bottom: 6px;
  color: var(--color-text);
}

.sidebar-overlay {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.4);
  z-index: 99;
}

@media (max-width: 1024px) {
  .sidebar {
    transform: translateX(-100%);
  }
  .sidebar.open {
    transform: translateX(0);
  }
  .sidebar-overlay.open {
    display: block;
  }
  .main-content {
    margin-left: 0;
  }
  .menu-toggle {
    display: block;
  }
  .charts-grid {
    grid-template-columns: 1fr;
  }
  .stats-grid {
    grid-template-columns: repeat(3, 1fr);
  }
  .content-body {
    padding: 20px;
  }
}

@media (max-width: 640px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .score-area {
    flex-direction: column;
    align-items: flex-start;
  }
  .finding-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .finding-header-right {
    width: 100%;
    justify-content: space-between;
  }
  .donut-chart {
    flex-direction: column;
    align-items: flex-start;
  }
  .bar-label {
    width: 100px;
  }
  .detail-meta {
    grid-template-columns: 1fr 1fr;
  }
  .sticky-header h1 {
    font-size: 1rem;
  }
}

@media print {
  .sidebar, .menu-toggle, .sidebar-overlay, .sticky-header, .btn-export {
    display: none !important;
  }
  .main-content {
    margin-left: 0 !important;
  }
  .finding-card {
    break-inside: avoid;
  }
  .finding-body {
    max-height: none !important;
  }
  .finding-card .chevron {
    display: none;
  }
}
</style>
</head>
<body>

<aside class="sidebar" id="sidebar">
  <div class="sidebar-header">
    <h2>🛡️ ${escapeHtml(projectInfo.name)}</h2>
    <div class="project-type">${escapeHtml(projectInfo.projectType || 'Application')}</div>
  </div>

  <nav class="sidebar-nav">
    <a href="#overview">Overview</a>
    <a href="#findings-section">Findings</a>
    <a href="#categories-section">Categories</a>
    <a href="#compliance-section">Compliance</a>
    <a href="#statistics-section">Statistics</a>
  </nav>

  <div class="sidebar-section">
    <div class="sidebar-section-title" onclick="toggleSection(this)">
      Severity Filters <span class="toggle-icon">▼</span>
    </div>
    <div class="sidebar-section-content" id="severity-filters">
      ${severityFiltersHtml}
    </div>
  </div>

  <div class="sidebar-section">
    <div class="sidebar-section-title" onclick="toggleSection(this)">
      Category Filters <span class="toggle-icon">▼</span>
    </div>
    <div class="sidebar-section-content" id="category-filters">
      ${categoryFiltersHtml}
    </div>
  </div>

  <div class="sidebar-section">
    <div class="sidebar-section-title" onclick="toggleSection(this)">
      File Search <span class="toggle-icon">▼</span>
    </div>
    <div class="sidebar-section-content" id="file-search-section">
      <input type="text" class="filter-search" id="file-search" placeholder="Search by file name..." oninput="applyFilters()">
    </div>
  </div>

  <div class="sidebar-section">
    <div class="sidebar-section-title" onclick="toggleSection(this)">
      Project Info <span class="toggle-icon">▼</span>
    </div>
    <div class="sidebar-section-content" id="project-info-section">
      ${techStackHtml ? `<div style="margin-bottom:10px"><div style="font-size:0.75rem;font-weight:700;color:var(--color-text-secondary);margin-bottom:6px">Tech Stack</div><div class="sidebar-tags">${techStackHtml}</div></div>` : ''}
      ${frameworksHtml ? `<div><div style="font-size:0.75rem;font-weight:700;color:var(--color-text-secondary);margin-bottom:6px">Frameworks</div><div class="sidebar-tags">${frameworksHtml}</div></div>` : ''}
    </div>
  </div>

  <div class="sidebar-footer">
    <button class="btn-export" onclick="exportJSON()">📥 Export JSON</button>
  </div>
</aside>

<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>

<main class="main-content">
  <header class="sticky-header">
    <div style="display:flex;align-items:center;gap:12px">
      <button class="menu-toggle" id="menu-toggle" onclick="toggleSidebar()">☰</button>
      <h1>🛡️ Security Audit Report</h1>
    </div>
    <div class="header-right">
      <span class="finding-counter" id="finding-counter">${totalFindings} / ${totalFindings} findings</span>
      <span>${now}</span>
    </div>
  </header>

  <div class="content-body">

    <section id="overview" class="section">
      <div class="score-area">
        <div class="score-gauge" style="background: ${conicGradient}">
          <div class="score-gauge-inner">
            <span class="score-number" style="color:${scoreColor}">${score}</span>
            <span class="score-suffix">/ 100</span>
            <span class="score-label" style="color:${scoreColor}">${scoreLabel}</span>
          </div>
        </div>
        <div class="score-details">
          <h2>Security Score</h2>
          <p>Assessment for <strong>${escapeHtml(projectInfo.name)}</strong> generated on ${now}. This score considers finding severity weighted against project file density for a fair evaluation.</p>
          ${assuranceNote}
          <div class="score-metrics">
            <div class="score-metric">
              <div class="score-metric-value">${totalFindings}</div>
              <div class="score-metric-label">Findings</div>
            </div>
            <div class="score-metric">
              <div class="score-metric-value">${uniqueFiles}</div>
              <div class="score-metric-label">Files Affected</div>
            </div>
            <div class="score-metric">
              <div class="score-metric-value">${categories.length}</div>
              <div class="score-metric-label">Categories</div>
            </div>
            <div class="score-metric">
              <div class="score-metric-value">${vibeRiskCount}</div>
              <div class="score-metric-label">Vibe Risks</div>
            </div>
            <div class="score-metric">
              <div class="score-metric-value">${escapeHtml(toolMode)}</div>
              <div class="score-metric-label">Mode</div>
            </div>
          </div>
          <p><strong>Semgrep:</strong> ${semgrepText}</p>
          <p><strong>Dependency scanners:</strong> ${packageAuditText} ${osvScannerText}</p>
          <p>CSReview remains read-only for audited source code and only writes report artifacts.</p>
        </div>
      </div>

      <div class="stats-grid">
        ${severityCardsHtml}
      </div>
    </section>

    <section id="findings-section" class="section">
      <h2 class="section-title">🔍 Findings</h2>
      <div id="findings-list">
        ${
          totalFindings === 0
            ? `
        <div class="no-findings">
          <div class="icon">✅</div>
          <h3>No Findings</h3>
          <p>No security issues were identified in this audit.</p>
        </div>`
            : findingsHtml
        }
      </div>
    </section>

    <section id="categories-section" class="section">
      <h2 class="section-title">📂 Category Breakdown</h2>
      <div class="charts-grid">
        <div class="chart-card">
          <h3>Distribution by Category</h3>
          <div class="bar-chart">
            ${catBarHtml || '<p style="color:var(--color-text-secondary)">No data available.</p>'}
          </div>
        </div>
        <div class="chart-card">
          <h3>Severity Distribution</h3>
          <div class="donut-chart">
            <div class="donut" style="background: ${conicGradient}">
              <div class="donut-hole">${totalFindings}</div>
            </div>
            <div class="donut-legend">
              ${SEVERITY_ORDER.map(
                (sev) => `
              <div class="legend-item">
                <span class="legend-dot" style="background:${getSeverityColor(sev)}"></span>
                <span>${sev}</span>
                <span class="legend-count">${counts[sev]}</span>
              </div>`,
              ).join('')}
            </div>
          </div>
        </div>
      </div>
    </section>

    <section id="compliance-section" class="section">
      <h2 class="section-title">📋 Compliance Mapping</h2>
      <div class="chart-card">
        <div class="detail-meta" style="background:var(--color-surface)">
          ${SEVERITY_ORDER.map((sev) => {
            const sevFindings = findings.filter((f) => f.severity === sev);
            const complianceTags = [...new Set(sevFindings.map((f) => f.compliance).filter(Boolean))];
            return complianceTags
              .map(
                (tag) => `
            <div class="meta-item">
              <span class="meta-label">${sev}</span>
              <span class="meta-value">${escapeHtml(tag)}</span>
            </div>`,
              )
              .join('');
          }).join('')}
          ${findings.filter((f) => f.compliance).length === 0 ? '<p style="color:var(--color-text-secondary)">No compliance data available.</p>' : ''}
        </div>
      </div>
    </section>

    <section id="statistics-section" class="section">
      <h2 class="section-title">📊 Statistics</h2>
      <div class="charts-grid">
        <div class="chart-card chart-card-wide">
          <h3>Top 10 Files by Findings</h3>
          <div class="bar-chart">
            ${fileBarHtml || '<p style="color:var(--color-text-secondary)">No data available.</p>'}
          </div>
        </div>
      </div>
    </section>

  </div>
</main>

<script>
const projectData = ${safeJsonForScript(projectInfo)};
const findingsData = ${safeJsonForScript(findings)};
const reportScore = ${score};

function toggleFinding(header) {
  const card = header.closest('.finding-card');
  card.classList.toggle('expanded');
}

function toggleSection(titleEl) {
  titleEl.classList.toggle('collapsed');
  const content = titleEl.nextElementSibling;
  content.classList.toggle('collapsed');
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}

function filterBySeverity(sev) {
  const checkboxes = document.querySelectorAll('#severity-filters input[type="checkbox"]');
  const allChecked = Array.from(checkboxes).every(cb => cb.checked);
  checkboxes.forEach(cb => {
    if (allChecked) {
      cb.checked = cb.value === sev;
    } else {
      cb.checked = true;
    }
  });
  applyFilters();
  document.getElementById('findings-section').scrollIntoView({ behavior: 'smooth' });
}

function applyFilters() {
  const severityChecked = Array.from(document.querySelectorAll('#severity-filters input:checked')).map(cb => cb.value);
  const categoryChecked = Array.from(document.querySelectorAll('#category-filters input:checked')).map(cb => cb.value);
  const fileSearch = (document.getElementById('file-search').value || '').toLowerCase().trim();
  const cards = document.querySelectorAll('.finding-card');
  let visible = 0;
  cards.forEach(card => {
    const sev = card.dataset.severity;
    const cat = card.dataset.category;
    const file = (card.dataset.file || '').toLowerCase();
    const matchSev = severityChecked.includes(sev);
    const matchCat = categoryChecked.includes(cat);
    const matchFile = !fileSearch || file.includes(fileSearch);
    if (matchSev && matchCat && matchFile) {
      card.style.display = '';
      visible++;
    } else {
      card.style.display = 'none';
    }
  });
  document.getElementById('finding-counter').textContent = visible + ' / ' + cards.length + ' findings';
}

function exportJSON() {
  const data = {
    projectInfo: projectData,
    findings: findingsData,
    score: reportScore,
    generatedAt: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-report-' + (projectData.name || 'project').replace(/[^a-zA-Z0-9]/g, '-') + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeSidebar();
});
</script>

</body>
</html>`;

  fs.writeFileSync(outputPath, html, 'utf8');
  console.log(`HTML report saved to ${outputPath}`);
  return outputPath;
}
