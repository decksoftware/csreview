import { relative } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync } from 'fs';
import { scanProject } from './scanner.js';
import { detectVulnerabilities } from './detector.js';
import { generateHtmlReport } from './reports/html.js';
import { generateMarkdownReport } from './reports/markdown.js';
import { calculateSecurityScore } from './score.js';
import { normalizeLocalPath, safeResolveInside } from './pathSafety.js';

const execFileAsync = promisify(execFile);
const WINDOWS_CMD_EXE = 'C:\\Windows\\System32\\cmd.exe';
const TOOL_COMMANDS = new Set(['semgrep', 'npm', 'osv-scanner', 'python3', 'python']);

function executable(command) {
  if (!TOOL_COMMANDS.has(command)) {
    throw new Error(`Unsupported external tool: ${command}`);
  }
  if (process.platform === 'win32' && ['npm', 'npx', 'yarn', 'pnpm'].includes(command)) {
    return `${command}.cmd`;
  }
  return command;
}

function execTool(command, args, options = {}) {
  const commandPath = executable(command);
  const needsShell = process.platform === 'win32' && commandPath.endsWith('.cmd');
  if (needsShell) {
    return execFileAsync(WINDOWS_CMD_EXE, ['/d', '/s', '/c', commandPath, ...args], options);
  }
  return execFileAsync(commandPath, args, options);
}

const LANG_MAP = {
  'js': 'javascript', 'mjs': 'javascript', 'cjs': 'javascript',
  'ts': 'typescript', 'tsx': 'typescript', 'jsx': 'javascript',
  'py': 'python',
  'java': 'java',
  'kt': 'kotlin',
  'go': 'go',
  'rs': 'rust',
  'php': 'php',
  'rb': 'ruby',
  'cs': 'csharp',
  'swift': 'swift',
  'dart': 'dart',
  'c': 'c',
  'h': 'c',
  'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp',
  'pas': 'delphi', 'dpr': 'delphi', 'dpk': 'delphi', 'lpr': 'delphi', 'pp': 'delphi',
  'vue': 'vue',
  'svelte': 'svelte',
  'sh': 'bash', 'bash': 'bash',
  'sql': 'sql',
  'graphql': 'graphql', 'gql': 'graphql',
  'html': 'html', 'htm': 'html',
  'xml': 'xml',
  'json': 'json',
  'yaml': 'yaml', 'yml': 'yaml',
  'toml': 'toml',
  'env': 'env',
  'tf': 'terraform', 'tfvars': 'terraform',
  'lua': 'lua',
  'r': 'r', 'R': 'r',
  'scala': 'scala',
  'groovy': 'groovy',
  'ex': 'elixir', 'exs': 'elixir',
  'erl': 'erlang',
  'hs': 'haskell',
  'dart': 'dart',
  'zig': 'zig',
  'nim': 'nim',
  'v': 'v',
  'sol': 'solidity',
};

function getLanguage(filePath) {
  const ext = filePath.includes('.') ? filePath.split('.').pop().toLowerCase() : '';
  return LANG_MAP[ext] || 'unknown';
}

function enrichFiles(filePaths) {
  return filePaths.map(fp => ({
    path: fp,
    language: getLanguage(fp),
  }));
}

function uniqueAuditFiles(projectInfo) {
  return [
    ...(projectInfo.files || []),
    ...(projectInfo.configFiles || []),
    ...(projectInfo.baasFiles || []),
  ].filter((filePath, index, all) => filePath && all.indexOf(filePath) === index);
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function sanitizeAgentName(agentName) {
  const raw = String(agentName || 'codex').trim().toLowerCase();
  let normalized = '';
  let lastWasGeneratedHyphen = false;

  for (const char of raw) {
    const code = char.charCodeAt(0);
    const isSafeAscii =
      (code >= 97 && code <= 122) ||
      (code >= 48 && code <= 57) ||
      char === '_' ||
      char === '-';

    if (isSafeAscii) {
      normalized += char;
      lastWasGeneratedHyphen = false;
    } else if (normalized && !lastWasGeneratedHyphen) {
      normalized += '-';
      lastWasGeneratedHyphen = true;
    }
  }

  let start = 0;
  let end = normalized.length;
  while (start < end && normalized[start] === '-') start += 1;
  while (end > start && normalized[end - 1] === '-') end -= 1;

  return normalized.slice(start, end) || 'codex';
}

function createSkippedToolResult(reason) {
  return {
    mode: 'Agent-Only',
    semgrep: {
      available: false,
      required: true,
      skipped: true,
      reason,
      findings: [],
    },
    npmAudit: {
      available: false,
      required: false,
      skipped: true,
      reason,
      findings: [],
    },
    osvScanner: {
      available: false,
      required: false,
      skipped: true,
      reason,
      findings: [],
    },
  };
}

function normalizeSeverity(severity) {
  const upper = String(severity || '').toUpperCase();
  if (upper === 'CRITICAL') return 'CRITICAL';
  if (upper === 'HIGH') return 'HIGH';
  if (upper === 'MEDIUM' || upper === 'MODERATE') return 'MEDIUM';
  if (upper === 'LOW') return 'LOW';
  return 'INFO';
}

const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const CONFIDENCE_RANK = { CONFIRMED: 5, 'TOOL-ONLY': 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function normalizeKeyPart(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\\/g, '/')
    .replace(/\s+/g, ' ');
}

function canonicalCwe(cwe) {
  const match = String(cwe || '').match(/CWE-\d+/i);
  return match ? match[0].toUpperCase() : '';
}

function findingSource(finding) {
  return finding?.source || 'csreview-detector';
}

function findingDedupKey(finding) {
  const file = normalizeKeyPart(finding?.file);
  const line = Number.isFinite(Number(finding?.line)) ? Number(finding.line) : 1;
  const cwe = canonicalCwe(finding?.cwe);
  if (cwe) {
    return `${file}:${line}:${cwe}`;
  }
  return [
    file,
    line,
    normalizeKeyPart(finding?.category),
    normalizeKeyPart(finding?.name),
  ].join(':');
}

function rankSeverity(severity) {
  return SEVERITY_RANK[normalizeSeverity(severity)] || 0;
}

function rankConfidence(confidence) {
  return CONFIDENCE_RANK[String(confidence || '').toUpperCase()] || 0;
}

function mergeReferences(left = [], right = []) {
  return [...new Set([
    ...(Array.isArray(left) ? left : []),
    ...(Array.isArray(right) ? right : []),
  ].filter(Boolean))];
}

function shouldReplaceFinding(current, incoming) {
  const severityDelta = rankSeverity(incoming?.severity) - rankSeverity(current?.severity);
  if (severityDelta !== 0) {
    return severityDelta > 0;
  }
  const confidenceDelta = rankConfidence(incoming?.confidence) - rankConfidence(current?.confidence);
  if (confidenceDelta !== 0) {
    return confidenceDelta > 0;
  }
  return findingSource(incoming) !== 'csreview-detector' && findingSource(current) === 'csreview-detector';
}

function mergeFindings(current, incoming) {
  const sources = new Set([
    ...(current.sources || [findingSource(current)]),
    ...(incoming.sources || [findingSource(incoming)]),
  ]);
  const primary = shouldReplaceFinding(current, incoming) ? incoming : current;
  const secondary = primary === incoming ? current : incoming;
  const hasToolAndDetector = sources.has('csreview-detector') && [...sources].some(source => source !== 'csreview-detector');

  return {
    ...primary,
    description: primary.description || secondary.description,
    vulnerableCode: primary.vulnerableCode || secondary.vulnerableCode,
    fix: primary.fix || secondary.fix,
    exploitation: primary.exploitation || secondary.exploitation,
    references: mergeReferences(primary.references, secondary.references),
    confidence: hasToolAndDetector ? 'CONFIRMED' : primary.confidence,
    source: primary.source || secondary.source,
    sources: [...sources].sort(),
    duplicateCount: (current.duplicateCount || 1) + 1,
  };
}

export function deduplicateFindings(findings = []) {
  const byKey = new Map();
  for (const finding of findings || []) {
    if (!finding) continue;
    const key = findingDedupKey(finding);
    if (!byKey.has(key)) {
      byKey.set(key, {
        ...finding,
        sources: [findingSource(finding)],
        duplicateCount: 1,
      });
      continue;
    }
    byKey.set(key, mergeFindings(byKey.get(key), finding));
  }
  return [...byKey.values()].sort((left, right) => {
    const severityDelta = rankSeverity(right.severity) - rankSeverity(left.severity);
    if (severityDelta !== 0) return severityDelta;
    return Number(left.line || 0) - Number(right.line || 0);
  });
}

function normalizeSemgrepSeverity(severity) {
  if (severity === 'ERROR') return 'HIGH';
  if (severity === 'WARNING') return 'MEDIUM';
  return 'LOW';
}

function normalizeSemgrepFinding(result, index) {
  const cwe = result.extra?.metadata?.cwe?.[0]?.match(/CWE-\d+/)?.[0] || 'N/A';
  return {
    id: `SEMGREP_${index + 1}`,
    severity: normalizeSemgrepSeverity(result.extra?.severity),
    category: result.extra?.metadata?.vulnerability_class?.[0] || 'Semgrep',
    name: result.extra?.message || result.check_id,
    description: result.extra?.message || 'Semgrep finding.',
    file: result.path,
    line: result.start?.line || 1,
    vulnerableCode: result.extra?.lines || 'Semgrep did not include a code snippet.',
    cwe,
    owasp: result.extra?.metadata?.owasp?.[0] || 'N/A',
    vibeRisk: false,
    compliance: cwe !== 'N/A' ? 'Semgrep mapped finding' : '',
    fix: 'Review the Semgrep finding and apply the remediation recommended by the referenced rule.',
    confidence: 'TOOL-ONLY',
    exploitation: 'See the Semgrep rule metadata and references for exploitation context.',
    references: [
      result.extra?.metadata?.source,
      result.extra?.metadata?.shortlink,
      ...(result.extra?.metadata?.references || []),
    ].filter(Boolean),
    source: 'semgrep',
  };
}

function firstAuditAdvisory(vulnerability) {
  return (vulnerability.via || []).find(item => item && typeof item === 'object') || {};
}

function formatNpmFix(vulnerability) {
  const fix = vulnerability.fixAvailable;
  if (!fix) {
    return `Review ${vulnerability.name}; npm audit did not report a direct safe upgrade. Validate impact and choose a context-aware dependency update or mitigation.`;
  }
  if (fix === true) {
    return `Review ${vulnerability.name}; npm audit reports a fix is available. Inspect the dependency tree and apply the smallest compatible update manually.`;
  }
  const version = fix.version ? ` to ${fix.version}` : '';
  const major = fix.isSemVerMajor ? ' This may be a breaking major upgrade and must be validated against tests.' : '';
  return `Review ${vulnerability.name} and update${version} if compatible.${major}`;
}

export function normalizeNpmAuditFindings(auditJson = {}) {
  const vulnerabilities = auditJson.vulnerabilities || {};
  return Object.values(vulnerabilities).map((vulnerability, index) => {
    const advisory = firstAuditAdvisory(vulnerability);
    const cwe = Array.isArray(advisory.cwe) ? advisory.cwe[0] : 'N/A';
    const references = [advisory.url].filter(Boolean);
    const nodes = Array.isArray(vulnerability.nodes) ? vulnerability.nodes.join(', ') : 'dependency tree';
    const directness = vulnerability.isDirect ? 'direct' : 'transitive';

    return {
      id: `NPM_AUDIT_${index + 1}`,
      severity: normalizeSeverity(vulnerability.severity),
      category: 'Dependency Vulnerability',
      name: `npm audit: ${vulnerability.name}`,
      description: advisory.title || `${vulnerability.name} has a known vulnerability in npm audit.`,
      file: 'package-lock.json',
      line: 1,
      vulnerableCode: `${vulnerability.name} ${vulnerability.range || ''} (${directness}); affected nodes: ${nodes}`.trim(),
      cwe,
      owasp: 'A06:2021 - Vulnerable and Outdated Components',
      vibeRisk: false,
      compliance: 'Known vulnerable dependency reported by npm audit',
      fix: formatNpmFix(vulnerability),
      confidence: 'TOOL-ONLY',
      exploitation: 'A vulnerable dependency can be exploited when application code reaches the affected package or when package lifecycle behavior is abused.',
      references,
      source: 'npm-audit',
    };
  });
}

function getOsvSeverity(vulnerability) {
  return normalizeSeverity(vulnerability.database_specific?.severity || vulnerability.severity?.[0]?.type);
}

function getOsvFixedVersions(vulnerability) {
  const fixed = [];
  for (const affected of vulnerability.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) fixed.push(event.fixed);
      }
    }
  }
  return [...new Set(fixed)];
}

function normalizeSourcePath(sourcePath, rootDir) {
  if (!sourcePath) return 'dependency manifest';
  const rel = relative(rootDir, sourcePath);
  return rel && !rel.startsWith('..') ? rel.replace(/\\/g, '/') : sourcePath.replace(/\\/g, '/');
}

export function normalizeOsvScannerFindings(osvJson = {}, rootDir = process.cwd()) {
  const findings = [];
  for (const result of osvJson.results || []) {
    const sourcePath = normalizeSourcePath(result.source?.path, rootDir);
    for (const pkg of result.packages || []) {
      const pkgInfo = pkg.package || {};
      for (const vulnerability of pkg.vulnerabilities || []) {
        const fixedVersions = getOsvFixedVersions(vulnerability);
        const fix = fixedVersions.length > 0
          ? `Review ${pkgInfo.name} and update to ${fixedVersions.join(' or ')} or later when compatible with the project.`
          : `Review ${pkgInfo.name}; OSV did not report a fixed version, so evaluate compensating controls, replacement, or removal.`;

        findings.push({
          id: `OSV_${findings.length + 1}`,
          severity: getOsvSeverity(vulnerability),
          category: 'Dependency Vulnerability',
          name: `OSV: ${pkgInfo.name || 'package'} ${vulnerability.id || ''}`.trim(),
          description: vulnerability.summary || vulnerability.details || 'OSV-Scanner reported a vulnerable dependency.',
          file: sourcePath,
          line: 1,
          vulnerableCode: `${pkgInfo.ecosystem || 'package'}:${pkgInfo.name || 'unknown'}@${pkgInfo.version || 'unknown'} from ${sourcePath}`,
          cwe: Array.isArray(vulnerability.aliases)
            ? vulnerability.aliases.find(alias => /^CWE-\d+$/i.test(alias)) || 'N/A'
            : 'N/A',
          owasp: 'A06:2021 - Vulnerable and Outdated Components',
          vibeRisk: false,
          compliance: 'Known vulnerable dependency reported by OSV-Scanner',
          fix,
          confidence: 'TOOL-ONLY',
          exploitation: 'A vulnerable dependency can become exploitable when reachable from application code, build scripts, package lifecycle hooks, or deployment artifacts.',
          references: [
            vulnerability.id ? `https://osv.dev/${vulnerability.id}` : null,
            ...(vulnerability.references || []).map(ref => ref.url),
          ].filter(Boolean),
          source: 'osv-scanner',
        });
      }
    }
  }
  return findings;
}

async function runSemgrep(rootDir) {
  try {
    const versionResult = await execTool('semgrep', ['--version'], { timeout: 30000 });
    const scanResult = await execTool(
      'semgrep',
      [
        '--config',
        'auto',
        '--json',
        '--quiet',
        '--exclude',
        'node_modules',
        '--exclude',
        'csreview-reports',
        '--exclude',
        'security-report.html',
        '--exclude',
        'security-findings.md',
        rootDir,
      ],
      {
        cwd: rootDir,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024,
      },
    );
    const parsed = JSON.parse(scanResult.stdout || '{}');
    return {
      available: true,
      required: true,
      version: versionResult.stdout.trim(),
      error: null,
      findings: Array.isArray(parsed.results) ? parsed.results.map(normalizeSemgrepFinding) : [],
      rawCount: Array.isArray(parsed.results) ? parsed.results.length : 0,
    };
  } catch (err) {
    return {
      available: false,
      required: true,
      version: null,
      error: err.code === 'ENOENT' ? 'semgrep not found in PATH' : err.message,
      findings: [],
      rawCount: 0,
    };
  }
}

async function runNpmAudit(rootDir) {
  const packageJsonPath = safeResolveInside(rootDir, 'package.json');
  if (!packageJsonPath || !existsSync(packageJsonPath)) {
    return {
      available: false,
      required: false,
      skipped: true,
      reason: 'package.json not found at project root',
      findings: [],
      rawCount: 0,
    };
  }

  try {
    const versionResult = await execTool('npm', ['--version'], { timeout: 30000 });
    let stdout = '';
    try {
      const auditResult = await execTool('npm', ['audit', '--json'], {
        cwd: rootDir,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024,
      });
      stdout = auditResult.stdout;
    } catch (err) {
      stdout = err.stdout || '';
      if (!stdout) throw err;
    }
    const parsed = JSON.parse(stdout || '{}');
    const findings = normalizeNpmAuditFindings(parsed);
    return {
      available: true,
      required: false,
      version: versionResult.stdout.trim(),
      error: null,
      findings,
      rawCount: findings.length,
    };
  } catch (err) {
    return {
      available: false,
      required: false,
      version: null,
      error: err.code === 'ENOENT' ? 'npm not found in PATH' : err.message,
      findings: [],
      rawCount: 0,
    };
  }
}

async function runOsvScanner(rootDir) {
  try {
    const versionResult = await execTool('osv-scanner', ['--version'], { timeout: 30000 });
    let stdout = '';
    try {
      const scanResult = await execTool('osv-scanner', ['scan', '--format', 'json', rootDir], {
        cwd: rootDir,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024,
      });
      stdout = scanResult.stdout;
    } catch (err) {
      stdout = err.stdout || '';
      if (!stdout) throw err;
    }
    const parsed = JSON.parse(stdout || '{}');
    const findings = normalizeOsvScannerFindings(parsed, rootDir);
    return {
      available: true,
      required: false,
      version: versionResult.stdout.trim(),
      error: null,
      findings,
      rawCount: findings.length,
    };
  } catch (err) {
    return {
      available: false,
      required: false,
      version: null,
      error: err.code === 'ENOENT' ? 'osv-scanner not found in PATH' : err.message,
      findings: [],
      rawCount: 0,
    };
  }
}

async function checkToolVersion(command, args = ['--version']) {
  try {
    const result = await execTool(command, args, { timeout: 30000 });
    return {
      available: true,
      version: result.stdout.trim() || result.stderr.trim() || 'version unknown',
      error: null,
    };
  } catch (err) {
    return {
      available: false,
      version: null,
      error: err.code === 'ENOENT' ? `${command} not found in PATH` : err.message,
    };
  }
}

export async function checkExternalTools(rootDir = process.cwd()) {
  const packageJsonPath = safeResolveInside(rootDir, 'package.json');
  const hasPackageJson = Boolean(packageJsonPath && existsSync(packageJsonPath));
  const checks = await Promise.all([
    checkToolVersion('semgrep'),
    checkToolVersion('npm'),
    checkToolVersion('osv-scanner'),
  ]);
  return {
    semgrep: { ...checks[0], required: true },
    npmAudit: {
      ...checks[1],
      required: false,
      skipped: !hasPackageJson,
      reason: hasPackageJson ? null : 'package.json not found at project root',
    },
    osvScanner: { ...checks[2], required: false },
  };
}

async function runSecurityTools(rootDir, options) {
  if (options.runTools === false) {
    return createSkippedToolResult('Tool execution disabled by caller.');
  }

  const [semgrep, npmAudit, osvScanner] = await Promise.all([
    runSemgrep(rootDir),
    runNpmAudit(rootDir),
    runOsvScanner(rootDir),
  ]);
  const hasAnyTool = semgrep.available || npmAudit.available || osvScanner.available;
  return {
    mode: hasAnyTool ? 'Hybrid' : 'Agent-Only',
    semgrep,
    npmAudit,
    osvScanner,
  };
}

export async function runAnalysis(rootDir, options = {}) {
  const startTime = Date.now();
  const absRoot = normalizeLocalPath(rootDir);
  const outputDir = options.outputDir
    ? normalizeLocalPath(options.outputDir)
    : safeResolveInside(absRoot, 'csreview-reports');
  const agentName = sanitizeAgentName(options.agentName || process.env.CSREVIEW_AGENT_NAME || 'codex');

  const projectInfo = await scanProject(absRoot);

  const enrichedFiles = enrichFiles(uniqueAuditFiles(projectInfo));

  const detectorInput = {
    ...projectInfo,
    files: enrichedFiles,
  };

  const toolResults = await runSecurityTools(absRoot, options);
  const findings = deduplicateFindings([
    ...detectVulnerabilities(detectorInput),
    ...toolResults.semgrep.findings,
    ...toolResults.npmAudit.findings,
    ...toolResults.osvScanner.findings,
  ]);

  const score = calculateSecurityScore(findings, projectInfo);

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const htmlPath = safeResolveInside(outputDir, `${agentName}_security-report.html`);
  const mdPath = safeResolveInside(outputDir, `${agentName}_security-findings.md`);
  if (!htmlPath || !mdPath) {
    throw new Error('Unable to resolve report output paths safely.');
  }

  generateHtmlReport(projectInfo, findings, htmlPath, { toolResults });
  generateMarkdownReport(projectInfo, findings, mdPath, { toolResults });

  const duration = Date.now() - startTime;

  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (severityCounts[f.severity] !== undefined) {
      severityCounts[f.severity]++;
    }
  }

  return {
    project: projectInfo.name,
    root: absRoot,
    score,
    totalFindings: findings.length,
    severityCounts,
    filesScanned: projectInfo.files.length,
    configFiles: projectInfo.configFiles.length,
    depFiles: projectInfo.depFiles.length,
    baasFiles: projectInfo.baasFiles.length,
    frameworks: projectInfo.frameworks,
    projectType: projectInfo.projectType,
    techStack: projectInfo.techStack,
    reports: { html: htmlPath, markdown: mdPath },
    toolResults,
    duration: formatDuration(duration),
    findings,
  };
}
