import { relative, resolve } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync } from 'fs';
import { scanProject } from './scanner.js';
import { detectVulnerabilities } from './detector.js';
import { generateHtmlReport } from './reports/html.js';
import { generateMarkdownReport } from './reports/markdown.js';

const execFileAsync = promisify(execFile);

function executable(command) {
  if (process.platform === 'win32' && ['npm', 'npx', 'yarn', 'pnpm'].includes(command)) {
    return `${command}.cmd`;
  }
  return command;
}

function execTool(command, args, options = {}) {
  const commandPath = executable(command);
  const needsShell = process.platform === 'win32' && commandPath.endsWith('.cmd');
  if (needsShell) {
    return execFileAsync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', commandPath, ...args], options);
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

function calculateDensityScore(findings, fileCount) {
  if (!fileCount) return 100;
  let penalty = 0;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') penalty += 20;
    else if (f.severity === 'HIGH') penalty += 10;
    else if (f.severity === 'MEDIUM') penalty += 5;
    else if (f.severity === 'LOW') penalty += 2;
    else if (f.severity === 'INFO') penalty += 1;
  }
  const density = penalty / fileCount;
  const raw = 100 - (density * 10);
  return Math.max(0, Math.min(100, Math.round(raw)));
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function sanitizeAgentName(agentName) {
  return String(agentName || 'codex')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'codex';
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
  if (!existsSync(resolve(rootDir, 'package.json'))) {
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
      skipped: !existsSync(resolve(rootDir, 'package.json')),
      reason: existsSync(resolve(rootDir, 'package.json')) ? null : 'package.json not found at project root',
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
  const absRoot = resolve(rootDir);
  const outputDir = options.outputDir || resolve(absRoot, 'csreview-reports');
  const agentName = sanitizeAgentName(options.agentName || process.env.CSREVIEW_AGENT_NAME || 'codex');

  const projectInfo = await scanProject(absRoot);

  const enrichedFiles = enrichFiles(uniqueAuditFiles(projectInfo));

  const detectorInput = {
    ...projectInfo,
    files: enrichedFiles,
  };

  const toolResults = await runSecurityTools(absRoot, options);
  const findings = [
    ...detectVulnerabilities(detectorInput),
    ...toolResults.semgrep.findings,
    ...toolResults.npmAudit.findings,
    ...toolResults.osvScanner.findings,
  ];

  const score = calculateDensityScore(findings, projectInfo.files.length);

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const htmlPath = resolve(outputDir, `${agentName}_security-report.html`);
  const mdPath = resolve(outputDir, `${agentName}_security-findings.md`);

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
