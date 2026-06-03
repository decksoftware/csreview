#!/usr/bin/env node
// @ts-check
import { resolve, dirname } from 'path';
import { existsSync, readFileSync } from 'fs';
import chalk from 'chalk';
import { checkExternalTools, runAnalysis } from './index.js';
import { runLocalDast } from './localDast.js';
import { DEFAULT_BASELINE_FILE } from './baseline.js';
import { scanProject } from './scanner.js';
import { generateDumpGuide, sanitizeAgentName } from './dumpGuide.js';
import { checkForUpdate } from './updateCheck.js';
import { checkToolFreshness } from './toolFreshness.js';
import { makeSecurityToolGatherer } from './provisionRuntime.js';

const args = process.argv.slice(2);

/** Read the installed CSReview version from package.json (best-effort). */
function readCurrentVersion() {
  try {
    return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version || null;
  } catch {
    return null;
  }
}

/**
 * Pre-flight self-update check (READ-ONLY, FAIL-OPEN): advise if a newer
 * CSReview exists in the official repo. Never applies an update; the agent/user
 * reviews the change before updating. Skipped with --no-update-check.
 */
async function runUpdatePreflight() {
  if (args.includes('--no-update-check')) return;
  try {
    const result = await checkForUpdate(readCurrentVersion(), { timeoutMs: 4000 });
    if (result.checked && result.updateAvailable) {
      console.log(
        chalk.yellow(
          `\n  Update available: CSReview ${result.latest} (installed ${result.current || 'unknown'}). ` +
            `Review changes before updating — source: ${result.source}. Use --no-update-check to skip.`,
        ),
      );
    }
  } catch {
    // fail-open: never block a scan on the update check
  }
}

/**
 * Pre-flight tool-freshness check (READ-ONLY, FAIL-OPEN): for tools that are
 * installed, compare against the latest official release. Never auto-upgrades.
 */
async function runToolFreshness(tools) {
  const installed = {
    semgrep: tools.semgrep?.version,
    'osv-scanner': tools.osvScanner?.version,
    npm:
      (tools.packageAudit || tools.npmAudit)?.manager === 'npm'
        ? (tools.packageAudit || tools.npmAudit)?.version
        : null,
  };
  try {
    const freshness = await checkToolFreshness(installed, { timeoutMs: 4000 });
    if (freshness.length === 0) return;
    console.log(chalk.bold('\n  Tool freshness:\n'));
    for (const tool of freshness) {
      const label =
        tool.status === 'outdated'
          ? chalk.yellow(`outdated (latest ${tool.latest})`)
          : tool.status === 'current'
            ? chalk.green('current')
            : chalk.gray('unknown');
      console.log(`  ${tool.name.padEnd(12)} ${tool.installed || '?'} - ${label}`);
      if (tool.status === 'outdated') console.log(chalk.gray(`    update: ${tool.update}`));
    }
  } catch {
    // fail-open
  }
}

if (args.includes('--doctor')) {
  const targetArg = args.find((arg) => !arg.startsWith('-'));
  const targetDir = resolve(targetArg || '.');
  const tools = await checkExternalTools(targetDir);

  console.log(chalk.bold.cyan('\n  CSReview Tool Doctor\n'));
  console.log(`  Target: ${targetDir}\n`);

  /** @type {Array<[string, {available: boolean, version?: string, reason?: string, error?: string}, string]>} */
  const rows = [
    ['Semgrep', tools.semgrep, 'required'],
    ['Package audit', tools.packageAudit || tools.npmAudit, 'recommended for Node.js'],
    ['OSV-Scanner', tools.osvScanner, 'recommended'],
  ];

  for (const [name, result, requirement] of rows) {
    const status = result.available ? chalk.green('available') : chalk.red('missing');
    const detail = result.available ? result.version : result.reason || result.error || 'not found';
    console.log(`  ${name.padEnd(12)} ${status} (${requirement}) - ${detail}`);
  }

  if (!args.includes('--no-tool-check')) {
    await runToolFreshness(tools);
  }

  console.log('\n  Install Semgrep with: pipx install semgrep');
  console.log('  Install OSV-Scanner with: winget install Google.OSVScanner\n');
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  console.log(`
${chalk.bold.cyan('CSReview')} - Development-time local workspace security alignment for AI coding agents

${chalk.bold('USAGE:')}
  csreview <target-directory> [options]
  csreview --doctor [target-directory]

${chalk.bold('OPTIONS:')}
  --output, -o <dir>    Output directory for reports (default: <target>/csreview-reports/)
  --agent-name <name>   Prefix report files with the coding agent name (default: codex)
  --local-dast-url <url> Run complementary local-only DAST against localhost/127.0.0.1
  --confirm-local-dast  Required confirmation flag for --local-dast-url
  --strict-partials     Fail when csreview-reports/.partials/ does not reconcile
  --baseline <file>     Suppress findings already recorded in a baseline JSON file
  --update-baseline     Write/refresh the baseline file from this run (with --baseline or default .csreview-baseline.json)
  --dump-guide          Also generate a read-only per-backend local DB dump guide (auto with --local-dast-url)
  --provision-tools     Opt-in: run stack-native security tools (Gitleaks/Trivy/Bandit/gosec) and, if missing, download them from OFFICIAL sources (SHA-256 verified) into an isolated, gitignored .csreview/bin/. Higher fidelity, fewer false positives.
  --no-update-check     Skip the pre-flight CSReview self-update check
  --doctor              Check external security tools (and their freshness) without scanning source code
  --help, -h            Show this help message

${chalk.bold('EXAMPLES:')}
  csreview .
  csreview /path/to/project
  csreview . --output ./security-reports
  csreview . --agent-name claude
  csreview . --local-dast-url http://localhost:3000 --confirm-local-dast
  csreview --doctor .

${chalk.bold('OUTPUT:')}
  Generates three reports in the output directory:
  - <agent>_security-report.html    - Human-readable HTML report with charts and navigation
  - <agent>_security-findings.md    - Machine-parseable Markdown for AI coding agents
  - <agent>_security.sarif          - SARIF 2.1.0 for CI / GitHub code scanning

  A .csreview-ignore file at the project root (gitignore-style globs) suppresses
  findings for matching paths. It is read-only and never modifies your project.

  With --local-dast-url, also generates complementary local dynamic reports:
  - <agent>_local-dast-report.html
  - <agent>_local-dast-findings.md

${chalk.bold('SECURITY TOOLS:')}
  CSReview is read-only for audited source code. It writes reports only.
  Required baseline:
  - Semgrep      - Advanced multi-language SAST (pipx install semgrep)

  Recommended complements:
  - npm/pnpm audit - Node.js dependency vulnerability scanning selected from lockfiles
  - OSV-Scanner  - Multi-ecosystem dependency vulnerability scanning
  `);
  process.exit(0);
}

const targetDir = resolve(args[0]);
let outputDir = null;
let agentName = process.env.CSREVIEW_AGENT_NAME || 'codex';
let localDastUrl = null;
const strictPartials = args.includes('--strict-partials');

const outputIdx = args.findIndex((a) => a === '--output' || a === '-o');
if (outputIdx !== -1 && args[outputIdx + 1]) {
  outputDir = resolve(args[outputIdx + 1]);
}

const agentNameIdx = args.findIndex((a) => a === '--agent-name');
if (agentNameIdx !== -1 && args[agentNameIdx + 1]) {
  agentName = args[agentNameIdx + 1];
}

const localDastIdx = args.findIndex((a) => a === '--local-dast-url');
if (localDastIdx !== -1 && args[localDastIdx + 1]) {
  localDastUrl = args[localDastIdx + 1];
}
const localDastConfirmed = args.includes('--confirm-local-dast');

let baselinePath = null;
const baselineIdx = args.findIndex((a) => a === '--baseline');
if (baselineIdx !== -1 && args[baselineIdx + 1] && !args[baselineIdx + 1].startsWith('-')) {
  baselinePath = resolve(args[baselineIdx + 1]);
}
const updateBaseline = args.includes('--update-baseline');
const updateBaselinePath = updateBaseline ? baselinePath || resolve(targetDir, DEFAULT_BASELINE_FILE) : null;

const provisionTools = args.includes('--provision-tools');

if (!existsSync(targetDir)) {
  console.error(chalk.red(`\n  Error: Directory not found: ${targetDir}\n`));
  process.exit(1);
}

console.log(chalk.bold.cyan('\n  CSReview - Security Audit\n'));
console.log(chalk.gray(`  Target:  ${targetDir}`));
console.log(chalk.gray(`  Output:  ${outputDir || resolve(targetDir, 'csreview-reports')}`));
console.log(chalk.gray(`  Started: ${new Date().toISOString()}\n`));

await runUpdatePreflight();

// Opt-in, user-informed security-tool provisioning. CSReview only downloads when
// you pass --provision-tools; here it tells you exactly what it will install and
// from where, then runs the tools from an isolated, gitignored .csreview/bin/.
let securityToolGatherer;
if (provisionTools) {
  console.log(chalk.bold('  Security tooling (opt-in provisioning enabled)\n'));
  console.log(chalk.yellow('  CSReview will use stack-native security tools and, if missing, DOWNLOAD them'));
  console.log(chalk.yellow('  from their OFFICIAL release pages, verify SHA-256 checksums, and run them from an'));
  console.log(chalk.yellow('  isolated, gitignored .csreview/bin/ (never globally, never as project deps).'));
  console.log(chalk.gray('  Auto-installed if missing (official release + SHA-256): Gitleaks, Trivy, gosec.'));
  console.log(chalk.gray('  Used only if already installed: Bandit (pip install bandit).'));
  console.log(
    chalk.gray(
      '  Sources: github.com/gitleaks/gitleaks · github.com/aquasecurity/trivy · github.com/securego/gosec.\n',
    ),
  );
  securityToolGatherer = makeSecurityToolGatherer({
    rootDir: targetDir,
    provision: true,
    log: (m) => console.log(chalk.gray(`    ${m}`)),
  });
}

try {
  const result = await runAnalysis(targetDir, {
    outputDir,
    agentName,
    strictPartials,
    baselinePath,
    updateBaselinePath,
    gatherSecurityTools: securityToolGatherer,
  });

  console.log(chalk.bold('\n  ----------------------------------------\n'));
  console.log(chalk.bold('  Scan Complete\n'));

  const scoreColor = result.score >= 80 ? chalk.green : result.score >= 50 ? chalk.yellow : chalk.red;
  console.log(`  Security Score: ${scoreColor.bold(result.score + '/100')}`);
  console.log(`  Files Scanned:  ${result.filesScanned}`);
  console.log(`  Analysis Mode:  ${result.toolResults?.mode || 'Agent-Only'}`);

  if (result.toolResults?.semgrep?.available) {
    console.log(
      `  Semgrep:        ${result.toolResults.semgrep.version} (${result.toolResults.semgrep.rawCount} findings)`,
    );
  } else {
    console.log(
      `  Semgrep:        REQUIRED but unavailable (${result.toolResults?.semgrep?.error || result.toolResults?.semgrep?.reason || 'not run'})`,
    );
  }

  const packageAudit = result.toolResults?.packageAudit || result.toolResults?.npmAudit;
  if (packageAudit?.available) {
    const packageAuditLabel = packageAudit.tool || 'package audit';
    console.log(`  Package audit:  ${packageAuditLabel} ${packageAudit.version} (${packageAudit.rawCount} findings)`);
  } else if (packageAudit?.reason) {
    console.log(`  Package audit:  skipped (${packageAudit.reason})`);
  }

  if (result.toolResults?.osvScanner?.available) {
    console.log(
      `  OSV-Scanner:    ${result.toolResults.osvScanner.version} (${result.toolResults.osvScanner.rawCount} findings)`,
    );
  } else if (result.toolResults?.osvScanner?.error) {
    console.log(`  OSV-Scanner:    recommended but unavailable (${result.toolResults.osvScanner.error})`);
  }

  if (Array.isArray(result.securityTools) && result.securityTools.length > 0) {
    console.log(chalk.bold('\n  Stack-native security tools:'));
    for (const t of result.securityTools) {
      if (t.available) {
        console.log(
          `    ${String(t.tool).padEnd(10)} ${chalk.green('ran')} (${t.source}${t.provisioned ? ', provisioned' : ''}, ${t.rawCount || 0} findings)`,
        );
      } else {
        console.log(
          `    ${String(t.tool).padEnd(10)} ${chalk.gray('skipped')}${t.reason ? chalk.gray(` (${t.reason})`) : ''}`,
        );
      }
    }
  }

  if (result.partialReconciliation?.status && !['skipped', 'empty'].includes(result.partialReconciliation.status)) {
    const reconciliationLabel = result.partialReconciliation.ok ? chalk.green('OK') : chalk.red.bold('FAILED');
    console.log(
      `  Partials:       ${reconciliationLabel} (${result.partialReconciliation.partialFindingCount} partial findings)`,
    );
    for (const error of result.partialReconciliation.errors || []) {
      console.log(chalk.red(`    - ${error}`));
    }
  }

  console.log(`  Duration:       ${result.duration}\n`);

  if (result.totalFindings > 0) {
    console.log(chalk.bold('  Findings:\n'));
    const { severityCounts } = result;
    if (severityCounts.CRITICAL > 0) console.log(`    ${chalk.red.bold('CRITICAL')}  ${severityCounts.CRITICAL}`);
    if (severityCounts.HIGH > 0) console.log(`    ${chalk.red('HIGH')}      ${severityCounts.HIGH}`);
    if (severityCounts.MEDIUM > 0) console.log(`    ${chalk.yellow('MEDIUM')}    ${severityCounts.MEDIUM}`);
    if (severityCounts.LOW > 0) console.log(`    ${chalk.blue('LOW')}       ${severityCounts.LOW}`);
    if (severityCounts.INFO > 0) console.log(`    ${chalk.gray('INFO')}      ${severityCounts.INFO}`);
    console.log(`\n    ${chalk.bold('Total:')}     ${result.totalFindings}`);
  } else {
    console.log(chalk.green.bold('  No vulnerabilities detected.\n'));
  }

  if (result.frameworks.length > 0) {
    console.log(`\n  ${chalk.bold('Frameworks:')}  ${result.frameworks.join(', ')}`);
  }
  if (result.projectType !== 'unknown') {
    console.log(`  ${chalk.bold('Project Type:')} ${result.projectType}`);
  }

  if (result.suppressedByIgnore > 0) {
    console.log(`\n  ${chalk.gray(`Suppressed by .csreview-ignore: ${result.suppressedByIgnore}`)}`);
  }
  if (result.baseline?.applied) {
    console.log(`  ${chalk.gray(`Baselined (known) findings hidden: ${result.baseline.baselinedCount}`)}`);
  }
  if (result.baseline?.written) {
    console.log(`  ${chalk.green(`Baseline written: ${result.baseline.written}`)}`);
  }

  console.log(chalk.bold('\n  Reports:\n'));
  console.log(`    ${chalk.cyan('HTML')}  ${result.reports.html}`);
  console.log(`    ${chalk.cyan('MD')}    ${result.reports.markdown}`);
  console.log(`    ${chalk.cyan('SARIF')} ${result.reports.sarif}`);

  // Phase 9 helper: a read-only per-backend "safe local dump" guide so the user
  // can prepare an isolated local copy before any optional local DAST.
  const wantDumpGuide = args.includes('--dump-guide') || Boolean(localDastUrl);
  if (wantDumpGuide) {
    try {
      const projectInfo = await scanProject(targetDir);
      const guidePath = resolve(dirname(result.reports.html), `${sanitizeAgentName(agentName)}_db-dump-guide.html`);
      const guide = generateDumpGuide(projectInfo, guidePath);
      console.log(`    ${chalk.cyan('GUIDE')} ${guidePath}`);
      if (guide.detected.length > 0) {
        console.log(chalk.gray(`    DB backends detected: ${guide.detected.join(', ')}`));
      }
    } catch (guideErr) {
      console.log(chalk.gray(`    (db-dump-guide skipped: ${guideErr.message})`));
    }
  }

  if (localDastUrl) {
    console.log(chalk.bold('\n  Running Local DAST Complement\n'));
    console.log(chalk.yellow('  Local test environment only. Never use this against production.'));
    console.log(
      chalk.yellow(
        '  If this test uses a database copy, keep it deliberate, local, secure, and sanitized/minimized where needed.',
      ),
    );
    console.log(chalk.gray('  Purpose: White Hat Hacker-style analysis and remediation of security flaws.\n'));
    const localDast = await runLocalDast(targetDir, {
      targetUrl: localDastUrl,
      confirmed: localDastConfirmed,
      agentName,
      runId: new Date().toISOString(),
      outputDir: resolve(targetDir, 'csreview-reports'),
    });
    const suspected = localDast.results.filter((item) => item.status === 'DAST-SUSPECTED').length;
    const clean = localDast.results.filter((item) => item.status === 'DAST-CLEAN').length;
    console.log(`  Target:         ${localDast.target}`);
    if (localDast.runId) console.log(`  Run ID:         ${localDast.runId}`);
    console.log(`  DAST-SUSPECTED: ${suspected}`);
    console.log(`  DAST-CLEAN:     ${clean}`);
    console.log(chalk.bold('\n  Local DAST Reports:\n'));
    console.log(`    ${chalk.cyan('HTML')}  ${localDast.reports.html}`);
    console.log(`    ${chalk.cyan('MD')}    ${localDast.reports.markdown}`);
    if (localDast.reports.historyMarkdown) {
      console.log(chalk.gray(`    history: ${localDast.reports.historyMarkdown}`));
    }
  } else {
    console.log(chalk.gray('\n  After remediating findings, you may run optional local-only DAST:'));
    console.log(
      chalk.gray(
        `  csreview ${targetDir} --local-dast-url http://localhost:3000 --confirm-local-dast --agent-name ${agentName}`,
      ),
    );
  }

  console.log('');
} catch (err) {
  console.error(chalk.red(`\n  Fatal Error: ${err.message}\n`));
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
}
