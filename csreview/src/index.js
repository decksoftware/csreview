// @ts-check
import { relative } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'fs';
import { scanProject } from './scanner.js';
import { detectVulnerabilities } from './detector.js';
import { generateHtmlReport } from './reports/html.js';
import { generateMarkdownReport } from './reports/markdown.js';
import { generateSarifReport } from './reports/sarif.js';
import { calculateSecurityScore } from './score.js';
import { normalizeLocalPath, safeResolveInside } from './pathSafety.js';
import {
  loadIgnore,
  applyIgnore,
  compileIgnorePatterns,
  DEFAULT_IGNORE_PATTERNS,
  DEFAULT_IGNORE_DIRS,
} from './ignore.js';
import { loadBaseline, applyBaseline, writeBaseline } from './baseline.js';

/**
 * Canonical finding object exchanged by the deterministic engine, tool
 * normalizers, subagent partials, Markdown report, HTML report, and JSON export.
 *
 * @typedef {object} Finding
 * @property {string} [id]
 * @property {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'|string} severity
 * @property {string} category
 * @property {string} name
 * @property {string} [description]
 * @property {string} file
 * @property {number} line
 * @property {string} [vulnerableCode]
 * @property {string} [cwe]
 * @property {string} [owasp]
 * @property {string} [fix]
 * @property {'DAST-CONFIRMED'|'DAST-SUSPECTED'|'DAST-CLEAN'|'CONFIRMED'|'HIGH'|'MEDIUM'|'LOW'|string} confidence
 * @property {string} [exploitation]
 * @property {string[]|Array<{url?: string, advisory?: string}>} [references]
 * @property {string} [source]
 * @property {boolean} [vibeRisk]
 * @property {string} [compliance]
 * @property {string[]} [sources]
 * @property {number} [duplicateCount]
 */

/**
 * @typedef {object} ToolRunResult
 * @property {boolean} available
 * @property {boolean} [required]
 * @property {string} [version]
 * @property {string} [error]
 * @property {string} [reason]
 * @property {boolean} [skipped]
 * @property {number} [rawCount]
 * @property {Finding[]} [findings]
 * @property {string} [tool]
 * @property {string} [manager]
 * @property {string} [lockfile]
 */

/**
 * @typedef {object} ToolResults
 * @property {string} mode
 * @property {ToolRunResult} semgrep
 * @property {ToolRunResult} packageAudit
 * @property {ToolRunResult} npmAudit
 * @property {ToolRunResult} osvScanner
 */

const execFileAsync = promisify(execFile);

// `--version` and other quick tool probes should return near-instantly; cap them
// so a misbehaving tool (e.g. Semgrep's hanging version check) can never block a
// scan or the doctor.
const VERSION_CHECK_TIMEOUT_MS = 10000;
const WINDOWS_CMD_EXE = 'C:\\Windows\\System32\\cmd.exe';
const TOOL_COMMANDS = new Set(['semgrep', 'npm', 'pnpm', 'bun', 'osv-scanner', 'python3', 'python']);
const WINDOWS_CMD_META_CHARS = /[\r\n&|^<>"%]/;

function executable(command) {
  if (!TOOL_COMMANDS.has(command)) {
    throw new Error(`Unsupported external tool: ${command}`);
  }
  if (process.platform === 'win32' && ['npm', 'npx', 'yarn', 'pnpm'].includes(command)) {
    return `${command}.cmd`;
  }
  return command;
}

/**
 * Build exec options for a tool, disabling Semgrep's update/version "phone home"
 * check — it can hang the process (notably on Linux, where `semgrep --version`
 * prints the version and then blocks on the check). Forced off for every semgrep
 * invocation unless the user set SEMGREP_ENABLE_VERSION_CHECK explicitly. No-op
 * for other tools (returns the options object unchanged).
 *
 * @param {string} command
 * @param {import('child_process').ExecFileOptions} [options]
 * @param {NodeJS.ProcessEnv} [baseEnv]
 * @returns {import('child_process').ExecFileOptions}
 */
export function withToolEnv(command, options = {}, baseEnv = process.env) {
  if (command !== 'semgrep') return options;
  return {
    ...options,
    // `'0'` first so it is the default, but baseEnv (an explicit user setting)
    // overrides it, and a caller-provided options.env wins last.
    env: { SEMGREP_ENABLE_VERSION_CHECK: '0', ...baseEnv, ...(options.env || {}) },
  };
}

/**
 * Execute an allowlisted external tool without a shell except for Windows npm-style
 * .cmd shims, which require cmd.exe and are guarded against shell metacharacters.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {import('child_process').ExecFileOptions} [options]
 * @returns {Promise<{stdout: string, stderr: string}>}
 */
function execTool(command, args, options = {}) {
  const commandPath = executable(command);
  const needsShell = process.platform === 'win32' && commandPath.endsWith('.cmd');
  validateWindowsCmdArgs(commandPath, args);
  const execOptions = withToolEnv(command, options);
  if (needsShell) {
    // Invariant: .cmd tools execute through cmd.exe on Windows, so user-controlled
    // values such as rootDir, targets, agentName, and paths must never be passed
    // in args for .cmd commands. User input belongs in cwd or direct non-.cmd tools.
    return /** @type {Promise<{stdout: string, stderr: string}>} */ (
      execFileAsync(WINDOWS_CMD_EXE, ['/d', '/s', '/c', commandPath, ...args], execOptions)
    );
  }
  return /** @type {Promise<{stdout: string, stderr: string}>} */ (execFileAsync(commandPath, args, execOptions));
}

/**
 * Reject arguments that would be unsafe if routed through cmd.exe for Windows
 * .cmd shims. Direct execFile tools on Linux/macOS and non-.cmd tools are unchanged.
 *
 * @param {string} commandPath
 * @param {string[]} args
 * @param {NodeJS.Platform} [platform]
 */
export function validateWindowsCmdArgs(commandPath, args, platform = process.platform) {
  if (platform !== 'win32' || !String(commandPath).endsWith('.cmd')) {
    return;
  }

  const unsafeIndex = (args || []).findIndex((arg) => WINDOWS_CMD_META_CHARS.test(String(arg)));
  if (unsafeIndex !== -1) {
    throw new Error(`Unsafe argument for Windows cmd-backed tool ${commandPath} at index ${unsafeIndex}`);
  }
}

const LANG_MAP = {
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  jsx: 'javascript',
  py: 'python',
  java: 'java',
  kt: 'kotlin',
  go: 'go',
  rs: 'rust',
  php: 'php',
  rb: 'ruby',
  cs: 'csharp',
  swift: 'swift',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  cc: 'cpp',
  cxx: 'cpp',
  hpp: 'cpp',
  pas: 'delphi',
  dpr: 'delphi',
  dpk: 'delphi',
  lpr: 'delphi',
  pp: 'delphi',
  vue: 'vue',
  svelte: 'svelte',
  sh: 'bash',
  bash: 'bash',
  sql: 'sql',
  graphql: 'graphql',
  gql: 'graphql',
  html: 'html',
  htm: 'html',
  xml: 'xml',
  json: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'toml',
  env: 'env',
  tf: 'terraform',
  tfvars: 'terraform',
  lua: 'lua',
  r: 'r',
  R: 'r',
  scala: 'scala',
  groovy: 'groovy',
  ex: 'elixir',
  exs: 'elixir',
  erl: 'erlang',
  hs: 'haskell',
  dart: 'dart',
  zig: 'zig',
  nim: 'nim',
  v: 'v',
  sol: 'solidity',
};

function getLanguage(filePath) {
  const ext = filePath.includes('.') ? filePath.split('.').pop().toLowerCase() : '';
  return LANG_MAP[ext] || 'unknown';
}

function enrichFiles(projectInfo) {
  const configSet = new Set(projectInfo.configFiles || []);
  const baasSet = new Set(projectInfo.baasFiles || []);
  return uniqueAuditFiles(projectInfo).map((fp) => ({
    path: fp,
    language: getLanguage(fp),
    kind: baasSet.has(fp) ? 'baas' : configSet.has(fp) ? 'config' : 'source',
  }));
}

function uniqueAuditFiles(projectInfo) {
  return [...(projectInfo.files || []), ...(projectInfo.configFiles || []), ...(projectInfo.baasFiles || [])].filter(
    (filePath, index, all) => filePath && all.indexOf(filePath) === index,
  );
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function sanitizeAgentName(agentName) {
  const raw = String(agentName || 'codex')
    .trim()
    .toLowerCase();
  let normalized = '';
  let lastWasGeneratedHyphen = false;

  for (const char of raw) {
    const code = char.charCodeAt(0);
    const isSafeAscii = (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || char === '_' || char === '-';

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

function toolErrorMessage(command, err) {
  if (err?.code === 'ENOENT') {
    return `${command} not found in PATH`;
  }
  if (err?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' || /maxBuffer/i.test(err?.message || '')) {
    return `${command} output exceeded maxBuffer; rerun with a narrower scope or inspect the tool output directly`;
  }
  return err?.message || `${command} failed`;
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
    packageAudit: {
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
const PARTIAL_REQUIRED_FIELDS = [
  'severity',
  'category',
  'name',
  'description',
  'file',
  'line',
  'cwe',
  'fix',
  'confidence',
  'source',
];
const PARTIAL_TOOL_FIELDS = ['toolExecutions', 'toolRuns', 'toolsExecuted', 'executedTools'];
const WHOLE_TREE_TOOL_NAMES = new Set(['semgrep', 'npm audit', 'pnpm audit', 'bun audit', 'osv-scanner', 'trivy']);

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
  return [file, line, normalizeKeyPart(finding?.category), normalizeKeyPart(finding?.name)].join(':');
}

function rankSeverity(severity) {
  return SEVERITY_RANK[normalizeSeverity(severity)] || 0;
}

function rankConfidence(confidence) {
  return CONFIDENCE_RANK[String(confidence || '').toUpperCase()] || 0;
}

function mergeReferences(left = [], right = []) {
  return [...new Set([...(Array.isArray(left) ? left : []), ...(Array.isArray(right) ? right : [])].filter(Boolean))];
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
  const hasToolAndDetector =
    sources.has('csreview-detector') && [...sources].some((source) => source !== 'csreview-detector');

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

/**
 * Collapse duplicate findings by file, line, and CWE/rule while preserving
 * cross-source evidence for confidence promotion.
 *
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
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

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeToolName(entry) {
  const raw = typeof entry === 'string' ? entry : entry?.name || entry?.tool || entry?.command || entry?.id || '';
  const value = String(raw).trim().toLowerCase();
  if (!value) return '';
  if (value === 'npm' || value === 'npm audit' || value.includes('npm audit')) return 'npm audit';
  if (value === 'pnpm' || value === 'pnpm audit' || value.includes('pnpm audit')) return 'pnpm audit';
  if (value === 'bun' || value === 'bun audit' || value.includes('bun audit')) return 'bun audit';
  if (value === 'osv' || value === 'osv scanner' || value === 'osv-scanner' || value.includes('osv-scanner'))
    return 'osv-scanner';
  if (value.includes('semgrep')) return 'semgrep';
  if (value.includes('trivy')) return 'trivy';
  return value.split(/\s+/)[0];
}

function extractToolExecutions(payload) {
  const values = [];
  for (const field of PARTIAL_TOOL_FIELDS) {
    if (Array.isArray(payload?.[field])) values.push(...payload[field]);
    if (Array.isArray(payload?.metadata?.[field])) values.push(...payload.metadata[field]);
  }
  return values.map(normalizeToolName).filter(Boolean);
}

function extractPartialFindings(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.findings)) return payload.findings;
  if (Array.isArray(payload?.partialFindings)) return payload.partialFindings;
  return null;
}

function isSubagentSource(value) {
  return /^subagent:[a-z0-9][a-z0-9_-]*$/i.test(String(value || ''));
}

function hasSubagentEvidence(finding) {
  if (isSubagentSource(finding?.source)) return true;
  return Array.isArray(finding?.sources) && finding.sources.some(isSubagentSource);
}

function validatePartialFinding(finding, fileName, index) {
  const errors = [];
  const location = `${fileName} finding #${index + 1}`;
  if (!isPlainObject(finding)) {
    return [`${location} must be an object using the canonical finding schema.`];
  }
  for (const field of PARTIAL_REQUIRED_FIELDS) {
    if (finding[field] === undefined || finding[field] === null || finding[field] === '') {
      errors.push(`${location} is missing required field "${field}".`);
    }
  }
  if (!Number.isFinite(Number(finding.line)) || Number(finding.line) < 1) {
    errors.push(`${location} field "line" must be a positive number.`);
  }
  if (!isSubagentSource(finding.source)) {
    errors.push(`${location} must set source: "subagent:<domain>".`);
  }
  return errors;
}

function readSubagentPartials(outputDir) {
  const result = {
    status: 'skipped',
    partialFiles: [],
    partialFindings: [],
    toolExecutions: [],
    errors: [],
    warnings: [],
  };
  const partialsDir = safeResolveInside(outputDir, '.partials');
  if (!partialsDir || !existsSync(partialsDir)) {
    return result;
  }
  result.status = 'empty';
  try {
    if (!statSync(partialsDir).isDirectory()) {
      result.errors.push('Partial reconciliation failed: .partials exists but is not a directory.');
      result.status = 'failed';
      return result;
    }
    const fileNames = readdirSync(partialsDir)
      .filter((name) => name.toLowerCase().endsWith('.json'))
      .sort();
    if (fileNames.length === 0) {
      return result;
    }
    result.status = 'found';
    for (const fileName of fileNames) {
      if (!/^[a-z0-9][a-z0-9_-]*\.json$/i.test(fileName)) {
        result.errors.push(`Partial file ${fileName} must match <subagent>.json with letters, numbers, "_" or "-".`);
        continue;
      }
      const partialPath = safeResolveInside(partialsDir, fileName);
      if (!partialPath) {
        result.errors.push(`Partial file ${fileName} could not be resolved safely.`);
        continue;
      }
      let payload;
      try {
        payload = JSON.parse(readFileSync(partialPath, 'utf8'));
      } catch (err) {
        result.errors.push(`Partial file ${fileName} is not valid JSON: ${err.message}`);
        continue;
      }
      result.partialFiles.push(partialPath);
      result.toolExecutions.push(...extractToolExecutions(payload));
      const findings = extractPartialFindings(payload);
      if (!findings) {
        result.errors.push(`Partial file ${fileName} must contain a findings array.`);
        continue;
      }
      findings.forEach((finding, index) => {
        const errors = validatePartialFinding(finding, fileName, index);
        if (errors.length > 0) {
          result.errors.push(...errors);
          return;
        }
        result.partialFindings.push(finding);
      });
    }
  } catch (err) {
    result.errors.push(`Partial reconciliation failed while reading .partials: ${err.message}`);
  }
  return result;
}

/**
 * Validate and reconcile subagent partial JSON files against the final report.
 *
 * @param {string} outputDir
 * @param {Finding[]} finalFindings
 * @param {{strict?: boolean}} [options]
 */
export function reconcilePartials(outputDir, finalFindings = [], options = {}) {
  const absOutputDir = normalizeLocalPath(outputDir);
  const result = {
    ...readSubagentPartials(absOutputDir),
    ok: true,
    partialFindingCount: 0,
    dedupedPartialFindingCount: 0,
    finalSubagentFindingCount: 0,
    duplicateToolExecutions: {},
  };

  if (result.status === 'skipped' || result.status === 'empty') {
    return result;
  }

  const dedupedPartialFindings = deduplicateFindings(result.partialFindings);
  result.partialFindingCount = result.partialFindings.length;
  result.dedupedPartialFindingCount = dedupedPartialFindings.length;
  result.finalSubagentFindingCount = (finalFindings || []).filter(hasSubagentEvidence).length;

  if (result.dedupedPartialFindingCount !== result.finalSubagentFindingCount) {
    result.errors.push(
      `Final subagent finding count (${result.finalSubagentFindingCount}) does not match deduplicated partial count (${result.dedupedPartialFindingCount}).`,
    );
  }

  const toolCounts = new Map();
  for (const toolName of result.toolExecutions) {
    if (!WHOLE_TREE_TOOL_NAMES.has(toolName)) continue;
    toolCounts.set(toolName, (toolCounts.get(toolName) || 0) + 1);
  }
  for (const [toolName, count] of toolCounts.entries()) {
    if (count > 1) {
      result.duplicateToolExecutions[toolName] = count;
      result.errors.push(
        `${toolName} appears executed ${count} times in subagent partial metadata; whole-tree tools must run once in Phase 0/1.`,
      );
    }
  }

  result.ok = result.errors.length === 0;
  result.status = result.ok ? 'ok' : 'failed';
  if (!result.ok && options.strict) {
    throw new Error(`Partial reconciliation failed: ${result.errors.join(' ')}`);
  }
  return result;
}

function normalizeSemgrepSeverity(extra) {
  const severity = extra?.severity;
  const impact = String(extra?.metadata?.impact || '').toUpperCase();
  if (severity === 'ERROR') return impact === 'HIGH' ? 'CRITICAL' : 'HIGH';
  if (severity === 'WARNING') return 'MEDIUM';
  return 'LOW';
}

export function normalizeSemgrepFinding(result, index) {
  const cwe = result.extra?.metadata?.cwe?.[0]?.match(/CWE-\d+/)?.[0] || 'N/A';
  return {
    id: `SEMGREP_${index + 1}`,
    severity: normalizeSemgrepSeverity(result.extra),
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
  return (vulnerability.via || []).find((item) => item && typeof item === 'object') || {};
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

function splitReferenceLines(value) {
  return String(value || '')
    .split(/\r?\n/)
    .map((line) => line.replace(/^-\s*/, '').trim())
    .filter((line) => /^https?:\/\//i.test(line));
}

/**
 * Normalize npm audit JSON into canonical dependency findings.
 *
 * @param {object} auditJson
 * @returns {Finding[]}
 */
export function normalizeNpmAuditFindings(auditJson = {}) {
  if (!isPlainObject(auditJson)) return [];
  const vulnerabilities = isPlainObject(auditJson.vulnerabilities) ? auditJson.vulnerabilities : {};
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
      vulnerableCode:
        `${vulnerability.name} ${vulnerability.range || ''} (${directness}); affected nodes: ${nodes}`.trim(),
      cwe,
      owasp: 'A06:2021 - Vulnerable and Outdated Components',
      vibeRisk: false,
      compliance: 'Known vulnerable dependency reported by npm audit',
      fix: formatNpmFix(vulnerability),
      confidence: 'TOOL-ONLY',
      exploitation:
        'A vulnerable dependency can be exploited when application code reaches the affected package or when package lifecycle behavior is abused.',
      references,
      source: 'npm-audit',
    };
  });
}

/**
 * Normalize `bun audit --json` output (npm-audit-compatible schema) into
 * canonical dependency findings.
 *
 * @param {object} auditJson
 * @param {string} [lockfile]
 * @returns {Finding[]}
 */
export function normalizeBunAuditFindings(auditJson = {}, lockfile = 'bun.lock') {
  return normalizeNpmAuditFindings(auditJson).map((finding, index) => ({
    ...finding,
    id: `BUN_AUDIT_${index + 1}`,
    name: finding.name.replace(/^npm audit:/, 'bun audit:'),
    file: lockfile,
    compliance: 'Known vulnerable dependency reported by bun audit',
    source: 'bun-audit',
  }));
}

function formatPnpmFix(advisory) {
  if (advisory.recommendation) {
    return `Review ${advisory.module_name}; ${advisory.recommendation}. Validate the update against the project lockfile and tests before applying it.`;
  }
  if (advisory.patched_versions && advisory.patched_versions !== '<0.0.0') {
    return `Review ${advisory.module_name} and update to a version matching ${advisory.patched_versions} when compatible with the project.`;
  }
  return `Review ${advisory.module_name}; pnpm audit did not report a direct safe upgrade. Validate impact and choose a context-aware dependency update or mitigation.`;
}

/**
 * Normalize pnpm audit JSON into canonical dependency findings.
 *
 * @param {object} auditJson
 * @returns {Finding[]}
 */
export function normalizePnpmAuditFindings(auditJson = {}) {
  if (!isPlainObject(auditJson)) return [];
  const advisories = isPlainObject(auditJson.advisories) ? auditJson.advisories : {};
  return Object.values(advisories).map((advisory, index) => {
    const firstFinding = Array.isArray(advisory.findings) ? advisory.findings[0] || {} : {};
    const paths = Array.isArray(firstFinding.paths) ? firstFinding.paths.join(', ') : 'dependency tree';
    const cwe = Array.isArray(advisory.cwe) ? advisory.cwe[0] : 'N/A';
    const references = [advisory.url, ...splitReferenceLines(advisory.references)].filter(Boolean);

    return {
      id: `PNPM_AUDIT_${index + 1}`,
      severity: normalizeSeverity(advisory.severity),
      category: 'Dependency Vulnerability',
      name: `pnpm audit: ${advisory.module_name || 'package'}`,
      description:
        advisory.title || advisory.overview || `${advisory.module_name} has a known vulnerability in pnpm audit.`,
      file: 'pnpm-lock.yaml',
      line: 1,
      vulnerableCode:
        `${advisory.module_name || 'package'} ${firstFinding.version || advisory.vulnerable_versions || ''}; affected paths: ${paths}`.trim(),
      cwe,
      owasp: 'A06:2021 - Vulnerable and Outdated Components',
      vibeRisk: false,
      compliance: 'Known vulnerable dependency reported by pnpm audit',
      fix: formatPnpmFix(advisory),
      confidence: 'TOOL-ONLY',
      exploitation:
        'A vulnerable dependency can be exploited when application code reaches the affected package or when package lifecycle behavior is abused.',
      references: [...new Set(references)],
      source: 'pnpm-audit',
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

/**
 * Normalize OSV-Scanner JSON into canonical dependency findings.
 *
 * @param {object} osvJson
 * @param {string} rootDir
 * @returns {Finding[]}
 */
export function normalizeOsvScannerFindings(osvJson = {}, rootDir = process.cwd()) {
  const findings = [];
  if (!isPlainObject(osvJson) || !Array.isArray(osvJson.results)) return findings;
  for (const result of osvJson.results) {
    const sourcePath = normalizeSourcePath(result.source?.path, rootDir);
    for (const pkg of result.packages || []) {
      const pkgInfo = pkg.package || {};
      for (const vulnerability of pkg.vulnerabilities || []) {
        const fixedVersions = getOsvFixedVersions(vulnerability);
        const fix =
          fixedVersions.length > 0
            ? `Review ${pkgInfo.name} and update to ${fixedVersions.join(' or ')} or later when compatible with the project.`
            : `Review ${pkgInfo.name}; OSV did not report a fixed version, so evaluate compensating controls, replacement, or removal.`;

        findings.push({
          id: `OSV_${findings.length + 1}`,
          severity: getOsvSeverity(vulnerability),
          category: 'Dependency Vulnerability',
          name: `OSV: ${pkgInfo.name || 'package'} ${vulnerability.id || ''}`.trim(),
          description:
            vulnerability.summary || vulnerability.details || 'OSV-Scanner reported a vulnerable dependency.',
          file: sourcePath,
          line: 1,
          vulnerableCode: `${pkgInfo.ecosystem || 'package'}:${pkgInfo.name || 'unknown'}@${pkgInfo.version || 'unknown'} from ${sourcePath}`,
          cwe: Array.isArray(vulnerability.aliases)
            ? vulnerability.aliases.find((alias) => /^CWE-\d+$/i.test(alias)) || 'N/A'
            : 'N/A',
          owasp: 'A06:2021 - Vulnerable and Outdated Components',
          vibeRisk: false,
          compliance: 'Known vulnerable dependency reported by OSV-Scanner',
          fix,
          confidence: 'TOOL-ONLY',
          exploitation:
            'A vulnerable dependency can become exploitable when reachable from application code, build scripts, package lifecycle hooks, or deployment artifacts.',
          references: [
            vulnerability.id ? `https://osv.dev/${vulnerability.id}` : null,
            ...(vulnerability.references || []).map((ref) => ref.url),
          ].filter(Boolean),
          source: 'osv-scanner',
        });
      }
    }
  }
  return findings;
}

/**
 * Build Semgrep `--exclude <dir>` argument pairs from the canonical ignore-dir
 * list so Semgrep skips the SAME build outputs / vendored dirs as the heuristic
 * detector. Without this Semgrep scanned `.output`, `dist`, `.nuxt`, etc. and
 * produced critical false positives from compiled bundles (e.g. prototype
 * pollution in `_nitro.mjs`).
 *
 * @param {string[]} [dirs]
 * @returns {string[]}
 */
export function semgrepExcludeArgs(dirs = DEFAULT_IGNORE_DIRS) {
  return dirs.flatMap((dir) => ['--exclude', dir]);
}

async function runSemgrep(rootDir) {
  try {
    const versionResult = await execTool('semgrep', ['--version'], { timeout: VERSION_CHECK_TIMEOUT_MS });
    const scanResult = await execTool(
      'semgrep',
      ['--config', 'auto', '--json', '--quiet', ...semgrepExcludeArgs(), rootDir],
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
      error: toolErrorMessage('semgrep', err),
      findings: [],
      rawCount: 0,
    };
  }
}

export function detectNodeAuditStrategy(rootDir) {
  const packageJsonPath = safeResolveInside(rootDir, 'package.json');
  if (!packageJsonPath || !existsSync(packageJsonPath)) {
    return {
      skipped: true,
      reason: 'package.json not found at project root',
    };
  }

  const lockfiles = {
    pnpm: 'pnpm-lock.yaml',
    npm: 'package-lock.json',
    shrinkwrap: 'npm-shrinkwrap.json',
    yarn: 'yarn.lock',
  };
  const hasLockfile = (name) => {
    const lockPath = safeResolveInside(rootDir, name);
    return Boolean(lockPath && existsSync(lockPath));
  };

  if (hasLockfile(lockfiles.pnpm)) {
    return {
      command: 'pnpm',
      args: ['audit', '--json'],
      versionArgs: ['--version'],
      label: 'pnpm audit',
      manager: 'pnpm',
      lockfile: lockfiles.pnpm,
      source: 'pnpm-audit',
    };
  }

  if (hasLockfile(lockfiles.npm)) {
    return {
      command: 'npm',
      args: ['audit', '--json'],
      versionArgs: ['--version'],
      label: 'npm audit',
      manager: 'npm',
      lockfile: lockfiles.npm,
      source: 'npm-audit',
    };
  }

  if (hasLockfile(lockfiles.shrinkwrap)) {
    return {
      command: 'npm',
      args: ['audit', '--json'],
      versionArgs: ['--version'],
      label: 'npm audit',
      manager: 'npm',
      lockfile: lockfiles.shrinkwrap,
      source: 'npm-audit',
    };
  }

  if (hasLockfile('bun.lockb') || hasLockfile('bun.lock')) {
    return {
      command: 'bun',
      args: ['audit', '--json'],
      versionArgs: ['--version'],
      label: 'bun audit',
      manager: 'bun',
      lockfile: hasLockfile('bun.lockb') ? 'bun.lockb' : 'bun.lock',
      source: 'bun-audit',
    };
  }

  if (hasLockfile(lockfiles.yarn)) {
    return {
      skipped: true,
      manager: 'yarn',
      lockfile: lockfiles.yarn,
      reason:
        'yarn.lock detected; yarn audit JSON is not engine-orchestrated yet. OSV-Scanner covers this lockfile when available.',
    };
  }

  return {
    command: 'npm',
    args: ['audit', '--json'],
    versionArgs: ['--version'],
    label: 'npm audit',
    manager: 'npm',
    lockfile: 'package.json',
    source: 'npm-audit',
  };
}

async function runPackageAudit(rootDir) {
  const strategy = detectNodeAuditStrategy(rootDir);
  if (strategy.skipped) {
    return {
      available: false,
      required: false,
      skipped: true,
      reason: strategy.reason,
      tool: strategy.label || 'package audit',
      manager: strategy.manager,
      lockfile: strategy.lockfile,
      findings: [],
      rawCount: 0,
    };
  }

  try {
    const versionResult = await execTool(strategy.command, strategy.versionArgs, { timeout: 30000 });
    let stdout = '';
    try {
      const auditResult = await execTool(strategy.command, strategy.args, {
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
    let findings;
    if (strategy.source === 'pnpm-audit') {
      findings = normalizePnpmAuditFindings(parsed);
    } else if (strategy.source === 'bun-audit') {
      findings = normalizeBunAuditFindings(parsed, strategy.lockfile);
    } else {
      findings = normalizeNpmAuditFindings(parsed);
    }
    return {
      available: true,
      required: false,
      tool: strategy.label,
      manager: strategy.manager,
      lockfile: strategy.lockfile,
      version: versionResult.stdout.trim(),
      error: null,
      findings,
      rawCount: findings.length,
    };
  } catch (err) {
    return {
      available: false,
      required: false,
      tool: strategy.label,
      manager: strategy.manager,
      lockfile: strategy.lockfile,
      version: null,
      error: toolErrorMessage(strategy.label || strategy.command, err),
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
      error: toolErrorMessage('osv-scanner', err),
      findings: [],
      rawCount: 0,
    };
  }
}

async function checkToolVersion(command, args = ['--version']) {
  try {
    const result = await execTool(command, args, { timeout: VERSION_CHECK_TIMEOUT_MS });
    return {
      available: true,
      version: result.stdout.trim() || result.stderr.trim() || 'version unknown',
      error: null,
    };
  } catch (err) {
    return {
      available: false,
      version: null,
      error: toolErrorMessage(command, err),
    };
  }
}

export async function checkExternalTools(rootDir = process.cwd()) {
  const packageStrategy = detectNodeAuditStrategy(rootDir);
  const packageAuditCheck = packageStrategy.skipped
    ? {
        available: false,
        version: null,
        error: null,
        skipped: true,
        reason: packageStrategy.reason,
        tool: packageStrategy.label || 'package audit',
        manager: packageStrategy.manager,
        lockfile: packageStrategy.lockfile,
      }
    : {
        ...(await checkToolVersion(packageStrategy.command, packageStrategy.versionArgs)),
        skipped: false,
        reason: null,
        tool: packageStrategy.label,
        manager: packageStrategy.manager,
        lockfile: packageStrategy.lockfile,
      };
  const checks = await Promise.all([checkToolVersion('semgrep'), checkToolVersion('osv-scanner')]);
  return {
    semgrep: { ...checks[0], required: true },
    packageAudit: { ...packageAuditCheck, required: false },
    npmAudit: { ...packageAuditCheck, required: false },
    osvScanner: { ...checks[1], required: false },
  };
}

/**
 * Run engine-orchestrated external tools once and return their normalized output.
 *
 * @param {string} rootDir
 * @param {{runTools?: boolean}} options
 * @returns {Promise<ToolResults>}
 */
async function runSecurityTools(rootDir, options) {
  if (options.runTools === false) {
    return createSkippedToolResult('Tool execution disabled by caller.');
  }

  const [semgrep, packageAudit, osvScanner] = await Promise.all([
    runSemgrep(rootDir),
    runPackageAudit(rootDir),
    runOsvScanner(rootDir),
  ]);
  return {
    mode: classifyToolMode({ semgrep, packageAudit, npmAudit: packageAudit, osvScanner }),
    semgrep,
    packageAudit,
    npmAudit: packageAudit,
    osvScanner,
  };
}

/**
 * Classify confidence mode from availability of engine-orchestrated tools.
 *
 * @param {Partial<ToolResults>} toolResults
 */
export function classifyToolMode(toolResults = {}) {
  const relevantTools = [toolResults.semgrep, toolResults.osvScanner];

  const packageAudit = toolResults.packageAudit || toolResults.npmAudit;
  if (!packageAudit?.skipped) {
    relevantTools.push(packageAudit);
  }

  const concreteTools = relevantTools.filter(Boolean);
  const availableCount = concreteTools.filter((tool) => tool.available).length;
  if (availableCount === 0) {
    return 'Agent-Only';
  }
  if (availableCount === concreteTools.length) {
    return 'Self-Hosted';
  }
  return 'Hybrid';
}

/**
 * Run a full CSReview static analysis and write reports.
 *
 * @param {string} rootDir
 * @param {{outputDir?: string, agentName?: string, runTools?: boolean, strictPartials?: boolean, htmlReportPath?: string, markdownReportPath?: string, baselinePath?: string, updateBaselinePath?: string, gatherSecurityTools?: (projectInfo: object, rootDir: string) => Promise<{findings?: Array<object>, results?: Array<object>}>}} [options]
 */
export async function runAnalysis(rootDir, options = {}) {
  const startTime = Date.now();
  const absRoot = normalizeLocalPath(rootDir);
  const outputDir = options.outputDir
    ? normalizeLocalPath(options.outputDir)
    : safeResolveInside(absRoot, 'csreview-reports');
  const agentName = sanitizeAgentName(options.agentName || process.env.CSREVIEW_AGENT_NAME || 'codex');

  const projectInfo = await scanProject(absRoot);

  const enrichedFiles = enrichFiles(projectInfo);

  const detectorInput = {
    ...projectInfo,
    files: enrichedFiles,
  };

  const toolResults = await runSecurityTools(absRoot, options);

  // Opt-in, engine-orchestrated stack-native security tools (Gitleaks/Bandit/
  // gosec/Trivy). The CLI composes the real gatherer (provision + run) behind
  // --provision-tools; when absent, this is a no-op so the default scan is
  // unchanged. Fail-open: the suite can never break a scan.
  let securityToolFindings = [];
  let securityToolResults = [];
  if (typeof options.gatherSecurityTools === 'function') {
    try {
      const gathered = await options.gatherSecurityTools(projectInfo, absRoot);
      if (gathered) {
        securityToolFindings = Array.isArray(gathered.findings) ? gathered.findings : [];
        securityToolResults = Array.isArray(gathered.results) ? gathered.results : [];
      }
    } catch {
      // never let the optional security-tools suite break a scan
    }
  }

  const partialScan = readSubagentPartials(outputDir);
  const findings = deduplicateFindings([
    ...detectVulnerabilities(detectorInput),
    ...toolResults.semgrep.findings,
    ...toolResults.packageAudit.findings,
    ...toolResults.osvScanner.findings,
    ...securityToolFindings,
    ...partialScan.partialFindings,
  ]);
  const partialReconciliation = reconcilePartials(outputDir, findings, {
    strict: Boolean(options.strictPartials),
  });

  // Report-level suppression: built-in defaults + .csreview-ignore (path globs)
  // then --baseline (known-finding fingerprints). All read-only and only filter
  // the reported set; subagent reconciliation above runs on the full deduped set.
  //
  // The built-in DEFAULT_IGNORE_PATTERNS (generated caches, vendored deps) are
  // layered FIRST, then the user's .csreview-ignore (last-match-wins, so a
  // project can `!`-re-include a default). This is what scopes the external
  // security tools' findings to first-party source, exactly like the detector —
  // those tools scan the raw tree and otherwise flood the report with secrets
  // from generated caches (e.g. a Chrome profile under .dart_tool/).
  const ignore = loadIgnore(absRoot);
  const ignoreCompiled = compileIgnorePatterns([...DEFAULT_IGNORE_PATTERNS, ...ignore.patterns]);
  const ignoreResult = applyIgnore(findings, ignoreCompiled);
  let reportFindings = ignoreResult.kept;

  // Attribute ignore-suppressed findings back to their originating external tool
  // so the CLI can report an honest "raw vs filtered as generated/cache" count.
  // The join is finding.source === result.tool (locked by a normalizer contract
  // test). Counts are post-dedup: if a finding was reported by multiple tools
  // and deduped to one entry, only the surviving source is counted (rawCount,
  // captured pre-dedup, is unaffected).
  if (securityToolResults.length > 0 && ignoreResult.suppressed.length > 0) {
    /** @type {Record<string, number>} */
    const suppressedBySource = {};
    for (const f of ignoreResult.suppressed) {
      const src = f && f.source;
      if (src) suppressedBySource[src] = (suppressedBySource[src] || 0) + 1;
    }
    securityToolResults = securityToolResults.map((r) =>
      suppressedBySource[r.tool] ? { ...r, suppressed: suppressedBySource[r.tool] } : r,
    );
  }

  /** @type {{applied: boolean, baselinedCount: number, written: string|null}} */
  const baselineInfo = { applied: false, baselinedCount: 0, written: null };
  if (options.updateBaselinePath) {
    const target = normalizeLocalPath(options.updateBaselinePath);
    writeBaseline(target, reportFindings);
    baselineInfo.written = target;
  } else if (options.baselinePath) {
    const baselineSet = loadBaseline(normalizeLocalPath(options.baselinePath));
    const baselineApplied = applyBaseline(reportFindings, baselineSet);
    baselineInfo.applied = true;
    baselineInfo.baselinedCount = baselineApplied.baselined.length;
    reportFindings = baselineApplied.newFindings;
  }

  const score = calculateSecurityScore(reportFindings, projectInfo);

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const htmlPath = safeResolveInside(outputDir, `${agentName}_security-report.html`);
  const mdPath = safeResolveInside(outputDir, `${agentName}_security-findings.md`);
  const sarifPath = safeResolveInside(outputDir, `${agentName}_security.sarif`);
  if (!htmlPath || !mdPath || !sarifPath) {
    throw new Error('Unable to resolve report output paths safely.');
  }

  generateHtmlReport(projectInfo, reportFindings, htmlPath, { toolResults, partialReconciliation });
  generateMarkdownReport(projectInfo, reportFindings, mdPath, {
    toolResults,
    partialReconciliation,
    analysisStartTime: startTime,
  });
  generateSarifReport(projectInfo, reportFindings, sarifPath);

  const duration = Date.now() - startTime;

  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of reportFindings) {
    if (severityCounts[f.severity] !== undefined) {
      severityCounts[f.severity]++;
    }
  }

  return {
    project: projectInfo.name,
    root: absRoot,
    score,
    totalFindings: reportFindings.length,
    suppressedByIgnore: ignoreResult.suppressed.length,
    baseline: baselineInfo,
    severityCounts,
    filesScanned: projectInfo.files.length,
    configFiles: projectInfo.configFiles.length,
    depFiles: projectInfo.depFiles.length,
    baasFiles: projectInfo.baasFiles.length,
    frameworks: projectInfo.frameworks,
    projectType: projectInfo.projectType,
    techStack: projectInfo.techStack,
    reports: { html: htmlPath, markdown: mdPath, sarif: sarifPath },
    toolResults,
    securityTools: securityToolResults,
    partialReconciliation,
    duration: formatDuration(duration),
    findings: reportFindings,
  };
}
