#!/usr/bin/env node
// @ts-check
import { resolve } from 'path';
import { existsSync } from 'fs';
import chalk from 'chalk';
import { checkExternalTools, runAnalysis } from './index.js';
import { runLocalDast } from './localDast.js';

const args = process.argv.slice(2);

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
  --doctor              Check external security tools without scanning source code
  --help, -h            Show this help message

${chalk.bold('EXAMPLES:')}
  csreview .
  csreview /path/to/project
  csreview . --output ./security-reports
  csreview . --agent-name claude
  csreview . --local-dast-url http://localhost:3000 --confirm-local-dast
  csreview --doctor .

${chalk.bold('OUTPUT:')}
  Generates two reports in the output directory:
  - <agent>_security-report.html    - Human-readable HTML report with charts and navigation
  - <agent>_security-findings.md    - Machine-parseable Markdown for AI coding agents

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

if (!existsSync(targetDir)) {
  console.error(chalk.red(`\n  Error: Directory not found: ${targetDir}\n`));
  process.exit(1);
}

console.log(chalk.bold.cyan('\n  CSReview - Security Audit\n'));
console.log(chalk.gray(`  Target:  ${targetDir}`));
console.log(chalk.gray(`  Output:  ${outputDir || resolve(targetDir, 'csreview-reports')}`));
console.log(chalk.gray(`  Started: ${new Date().toISOString()}\n`));

try {
  const result = await runAnalysis(targetDir, { outputDir, agentName, strictPartials });

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

  console.log(chalk.bold('\n  Reports:\n'));
  console.log(`    ${chalk.cyan('HTML')}  ${result.reports.html}`);
  console.log(`    ${chalk.cyan('MD')}    ${result.reports.markdown}`);

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
      outputDir: resolve(targetDir, 'csreview-reports'),
    });
    const suspected = localDast.results.filter((item) => item.status === 'DAST-SUSPECTED').length;
    const clean = localDast.results.filter((item) => item.status === 'DAST-CLEAN').length;
    console.log(`  Target:         ${localDast.target}`);
    console.log(`  DAST-SUSPECTED: ${suspected}`);
    console.log(`  DAST-CLEAN:     ${clean}`);
    console.log(chalk.bold('\n  Local DAST Reports:\n'));
    console.log(`    ${chalk.cyan('HTML')}  ${localDast.reports.html}`);
    console.log(`    ${chalk.cyan('MD')}    ${localDast.reports.markdown}`);
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
