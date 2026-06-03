// @ts-check
import fs from 'fs';
import path from 'path';
import { normalizeLocalPath, safeResolveInside } from './pathSafety.js';

// Node's URL parser returns the bracketed form for IPv6 loopback (e.g. new URL('http://[::1]').hostname === '[::1]').
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const PREFLIGHT_ENV_FILES = ['.env', '.env.local', '.env.development'];
const SECURITY_HEADERS = [
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
];

function sanitizeAgentName(agentName) {
  const raw = String(agentName || 'codex')
    .trim()
    .toLowerCase();
  const normalized = raw
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return normalized || 'codex';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function validateTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || ''));
  } catch {
    throw new Error('Local DAST target must be a valid http://localhost or http://127.0.0.1 URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Local DAST target must use http or https.');
  }
  if (!LOCAL_HOSTS.has(parsed.hostname)) {
    throw new Error('Local DAST may target only localhost or 127.0.0.1.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Local DAST target URL must not include credentials.');
  }
  return parsed;
}

function isLocalUrl(rawUrl, baseUrl = 'http://localhost') {
  try {
    const parsed = new URL(rawUrl, baseUrl);
    return LOCAL_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
}

function extractUrls(text) {
  return String(text || '').match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi) || [];
}

function extractAssignedHost(line) {
  const match = String(line || '').match(
    /^\s*[A-Z0-9_]*(?:HOST|URL|URI|ENDPOINT|BASE)[A-Z0-9_]*\s*=\s*["']?([^"'\s#]+)["']?/i,
  );
  if (!match) return null;
  const value = match[1].trim();
  if (!value || value.includes('://')) return null;
  if (value === 'localhost' || value === '127.0.0.1') return null;
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/i.test(value)) return value.split(':')[0];
  return null;
}

// Pre-flight is advisory, not blocking: a real dev .env almost always references external
// hosts (DB, auth, storage). Blocking on that would make Phase 9 unusable. The hard guards
// are elsewhere: the target must be localhost/127.0.0.1 (validateTargetUrl) and responses
// must not redirect to external hosts (assertNoExternalRedirect). Here we only WARN.
function runEnvPreflight(rootDir) {
  const scanned = [];
  const warnings = [];
  for (const envFile of PREFLIGHT_ENV_FILES) {
    const envPath = safeResolveInside(rootDir, envFile);
    if (!envPath || !fs.existsSync(envPath)) continue;
    scanned.push(envFile);
    const content = fs.readFileSync(envPath, 'utf8');

    for (const url of extractUrls(content)) {
      if (!isLocalUrl(url)) {
        warnings.push({ file: envFile, host: new URL(url).hostname });
      }
    }

    for (const line of content.split(/\r?\n/)) {
      const assignedHost = extractAssignedHost(line);
      if (assignedHost) {
        warnings.push({ file: envFile, host: assignedHost });
      }
    }
  }
  return { scanned, warnings };
}

function headersToObject(headers) {
  const result = {};
  if (!headers) return result;
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      result[String(key).toLowerCase()] = String(value);
    });
    return result;
  }
  for (const [key, value] of Object.entries(headers)) {
    result[String(key).toLowerCase()] = String(value);
  }
  return result;
}

function responseText(status, headers) {
  const lines = [`HTTP ${status}`];
  for (const [key, value] of Object.entries(headers).sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`${key}: ${value}`);
  }
  return lines.join('\n');
}

function assertNoExternalRedirect(targetUrl, response, headers) {
  if (response.status < 300 || response.status > 399) return;
  const location = headers.location;
  if (location && !isLocalUrl(location, targetUrl.href)) {
    throw new Error(
      `abort Phase 9: local target redirected to external host ${new URL(location, targetUrl.href).hostname}.`,
    );
  }
}

async function fetchHead(fetchImpl, targetUrl, extraHeaders = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetchImpl(targetUrl.href, {
      method: 'HEAD',
      redirect: 'manual',
      headers: extraHeaders,
      signal: controller.signal,
    });
    const headers = headersToObject(response.headers);
    assertNoExternalRedirect(targetUrl, response, headers);
    return { status: response.status, headers };
  } finally {
    clearTimeout(timeout);
  }
}

function buildSecurityHeaderResult(targetUrl, response) {
  const missing = SECURITY_HEADERS.filter((header) => !response.headers[header]);
  const status = missing.length > 0 ? 'DAST-SUSPECTED' : 'DAST-CLEAN';
  return {
    id: 'DAST-HEADERS-1',
    status,
    severity: missing.length > 0 ? 'LOW' : 'INFO',
    name: missing.length > 0 ? 'Missing recommended security headers' : 'Recommended security headers present',
    category: 'Dynamic Analysis (DAST)',
    target: targetUrl.href,
    command: `curl -s -I --max-redirs 0 ${targetUrl.href}`,
    response: responseText(response.status, response.headers),
    description:
      missing.length > 0
        ? `The local response is missing these recommended headers: ${missing.join(', ')}.`
        : 'The local response included the checked browser security headers.',
    recommendation:
      missing.length > 0
        ? 'Review framework middleware/header configuration before release. HSTS may be intentionally absent for plain localhost development.'
        : 'Keep header middleware covered by integration tests.',
  };
}

function buildCorsResult(targetUrl, response) {
  const origin = response.headers['access-control-allow-origin'] || '';
  const risky = origin === '*' || origin.toLowerCase() === 'https://evil.com';
  return {
    id: 'DAST-CORS-1',
    status: risky ? 'DAST-SUSPECTED' : 'DAST-CLEAN',
    severity: risky ? 'MEDIUM' : 'INFO',
    name: risky ? 'Permissive CORS response to untrusted origin' : 'No permissive CORS response observed',
    category: 'Dynamic Analysis (DAST)',
    target: targetUrl.href,
    command: `curl -s -I --max-redirs 0 -H "Origin: https://evil.com" ${targetUrl.href}`,
    response: responseText(response.status, response.headers),
    description: risky
      ? `The local server returned access-control-allow-origin: ${origin} for an untrusted Origin header.`
      : 'The local server did not expose a permissive Access-Control-Allow-Origin response for the untrusted origin probe.',
    recommendation: risky
      ? 'Restrict CORS to explicit trusted origins and validate credentials behavior.'
      : 'Keep CORS policy explicit and environment-specific.',
  };
}

function buildMarkdownReport(projectName, targetUrl, envFiles, results) {
  const rows = results
    .map((result) => `| ${result.id} | ${result.status} | ${result.severity} | ${result.name} |`)
    .join('\n');
  const details = results
    .map(
      (result) => `### ${result.id}: ${result.name}

- **Status**: ${result.status}
- **Severity**: ${result.severity}
- **Target**: ${result.target}
- **Description**: ${result.description}
- **Recommendation**: ${result.recommendation}

#### Exact command

\`\`\`bash
${result.command}
\`\`\`

#### Response received

\`\`\`http
${result.response}
\`\`\``,
    )
    .join('\n\n');

  return `# Dynamic Analysis (DAST) - Local Complementary Report

> **Project**: ${projectName}
> **Target**: ${targetUrl.href}
> **Scope**: Explicitly confirmed localhost/127.0.0.1 only
> **Pre-flight env files scanned**: ${envFiles.length > 0 ? envFiles.join(', ') : 'none found'}

This complementary report sends real HTTP requests only to the confirmed local development server. It does not replace the static CSReview SAST/SCA report and must never be used against external, staging, or production systems.

## Results

| ID | Status | Severity | Name |
|----|--------|----------|------|
${rows}

## Detailed Dynamic Findings

${details}
`;
}

function buildHtmlReport(projectName, targetUrl, envFiles, results) {
  const cards = results
    .map(
      (result) => `<article class="card ${escapeHtml(result.status.toLowerCase())}">
  <h2>${escapeHtml(result.id)}: ${escapeHtml(result.name)}</h2>
  <p><strong>Status:</strong> ${escapeHtml(result.status)} | <strong>Severity:</strong> ${escapeHtml(result.severity)}</p>
  <p><strong>Target:</strong> ${escapeHtml(result.target)}</p>
  <p>${escapeHtml(result.description)}</p>
  <p><strong>Recommendation:</strong> ${escapeHtml(result.recommendation)}</p>
  <h3>Exact command</h3>
  <pre><code>${escapeHtml(result.command)}</code></pre>
  <h3>Response received</h3>
  <pre><code>${escapeHtml(result.response)}</code></pre>
</article>`,
    )
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dynamic Analysis (DAST) - Local Complementary Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #172033; }
main { max-width: 1040px; margin: 0 auto; }
.card { background: #fff; border: 1px solid #dbe3ef; border-left: 5px solid #64748b; border-radius: 8px; padding: 18px; margin: 16px 0; }
.dast-suspected { border-left-color: #ca8a04; }
.dast-clean { border-left-color: #16a34a; }
pre { overflow: auto; background: #111827; color: #e5e7eb; padding: 14px; border-radius: 6px; }
.scope { background: #eef6ff; border: 1px solid #bfdbfe; padding: 12px; border-radius: 8px; }
</style>
</head>
<body>
<main>
<h1>Dynamic Analysis (DAST) - Local Complementary Report</h1>
<section class="scope">
<p><strong>Project:</strong> ${escapeHtml(projectName)}</p>
<p><strong>Target:</strong> ${escapeHtml(targetUrl.href)}</p>
<p><strong>Pre-flight env files scanned:</strong> ${escapeHtml(envFiles.length > 0 ? envFiles.join(', ') : 'none found')}</p>
<p>This report sends real HTTP requests only to the explicitly confirmed local development server. It must never be used against external, staging, or production systems.</p>
</section>
${cards}
</main>
</body>
</html>`;
}

function buildEnvWarningResult(targetUrl, warning, index) {
  return {
    id: `DAST-ENV-${index + 1}`,
    status: 'DAST-SUSPECTED',
    severity: 'LOW',
    name: 'Local .env references an external host',
    category: 'Dynamic Analysis (DAST)',
    target: targetUrl.href,
    command: `grep -iE "host|url|uri|endpoint" ${warning.file}`,
    response: `${warning.file} references ${warning.host}`,
    description: `${warning.file} references external host ${warning.host}. Phase 9 still probes only the confirmed local target and never follows redirects to external hosts, but verify your local app does not proxy DAST traffic to this host during the test.`,
    recommendation:
      'Use a local test database/copy and local service stubs so the app under test does not reach external/production endpoints while you run the probe.',
  };
}

export async function runLocalDast(rootDir, options = {}) {
  if (options.confirmed !== true) {
    throw new Error('Local DAST requires explicit confirmation because it sends real HTTP requests.');
  }

  const absRoot = normalizeLocalPath(rootDir);
  const targetUrl = validateTargetUrl(options.targetUrl);
  const { scanned: envFiles, warnings: envWarnings } = runEnvPreflight(absRoot);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('Local DAST requires a fetch implementation available in Node.js >=18.');
  }

  const reportsRoot = safeResolveInside(absRoot, 'csreview-reports');
  const outputDir = options.outputDir ? normalizeLocalPath(options.outputDir) : reportsRoot;
  const relativeOutput = path.relative(reportsRoot, outputDir);
  if (!reportsRoot || relativeOutput.startsWith('..') || path.isAbsolute(relativeOutput)) {
    throw new Error('Local DAST may write reports only inside csreview-reports/.');
  }
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const baseResponse = await fetchHead(fetchImpl, targetUrl);
  const corsResponse = await fetchHead(fetchImpl, targetUrl, { Origin: 'https://evil.com' });
  const results = [buildSecurityHeaderResult(targetUrl, baseResponse), buildCorsResult(targetUrl, corsResponse)];
  for (const warning of envWarnings) {
    results.push(buildEnvWarningResult(targetUrl, warning, results.length));
  }

  const packageJsonPath = safeResolveInside(absRoot, 'package.json');
  const projectName =
    packageJsonPath && fs.existsSync(packageJsonPath)
      ? JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')).name || path.basename(absRoot)
      : path.basename(absRoot);
  const agentName = sanitizeAgentName(options.agentName || process.env.CSREVIEW_AGENT_NAME || 'codex');
  const htmlPath = safeResolveInside(outputDir, `${agentName}_local-dast-report.html`);
  const mdPath = safeResolveInside(outputDir, `${agentName}_local-dast-findings.md`);
  if (!htmlPath || !mdPath) {
    throw new Error('Unable to resolve local DAST report output paths safely.');
  }

  fs.writeFileSync(mdPath, buildMarkdownReport(projectName, targetUrl, envFiles, results), 'utf8');
  fs.writeFileSync(htmlPath, buildHtmlReport(projectName, targetUrl, envFiles, results), 'utf8');

  return {
    target: targetUrl.href,
    envFiles,
    envWarnings,
    results,
    reports: {
      html: htmlPath,
      markdown: mdPath,
    },
  };
}
