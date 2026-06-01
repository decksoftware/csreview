import { resolve } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync } from 'fs';
import { scanProject } from './scanner.js';
import { detectVulnerabilities } from './detector.js';
import { generateHtmlReport } from './reports/html.js';
import { generateMarkdownReport } from './reports/markdown.js';

const execFileAsync = promisify(execFile);

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
  };
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

async function runSemgrep(rootDir) {
  try {
    const versionResult = await execFileAsync('semgrep', ['--version'], { timeout: 30000 });
    const scanResult = await execFileAsync(
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

async function runSecurityTools(rootDir, options) {
  if (options.runTools === false) {
    return createSkippedToolResult('Tool execution disabled by caller.');
  }

  const semgrep = await runSemgrep(rootDir);
  return {
    mode: semgrep.available ? 'Hybrid' : 'Agent-Only',
    semgrep,
  };
}

export async function runAnalysis(rootDir, options = {}) {
  const startTime = Date.now();
  const absRoot = resolve(rootDir);
  const outputDir = options.outputDir || resolve(absRoot, 'csreview-reports');

  const projectInfo = await scanProject(absRoot);

  const enrichedFiles = enrichFiles(projectInfo.files);

  const detectorInput = {
    ...projectInfo,
    files: enrichedFiles,
  };

  const toolResults = await runSecurityTools(absRoot, options);
  const findings = [
    ...detectVulnerabilities(detectorInput),
    ...toolResults.semgrep.findings,
  ];

  const score = calculateDensityScore(findings, projectInfo.files.length);

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const htmlPath = resolve(outputDir, 'csreview-report.html');
  const mdPath = resolve(outputDir, 'csreview-report.md');

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
