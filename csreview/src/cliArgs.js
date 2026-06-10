// @ts-check
import { parseArgs } from 'util';

/**
 * Strict CLI argument parsing.
 *
 * The CLI is a security gate, so a mistyped flag must be a hard error — the
 * previous hand-rolled `findIndex` parsing silently ignored unknown flags,
 * meaning `--basline known.json` ran a full scan WITHOUT the baseline and
 * reported success. `node:util` parseArgs in strict mode turns that into an
 * immediate, explanatory failure.
 */

const CLI_OPTIONS = /** @type {const} */ ({
  output: { type: 'string', short: 'o' },
  'agent-name': { type: 'string' },
  'local-dast-url': { type: 'string' },
  'confirm-local-dast': { type: 'boolean', default: false },
  'strict-partials': { type: 'boolean', default: false },
  baseline: { type: 'string' },
  'update-baseline': { type: 'boolean', default: false },
  'dump-guide': { type: 'boolean', default: false },
  'provision-tools': { type: 'boolean', default: false },
  'fail-on': { type: 'string' },
  'tool-timeout': { type: 'string' },
  'semgrep-config': { type: 'string' },
  'no-update-check': { type: 'boolean', default: false },
  'no-tool-check': { type: 'boolean', default: false },
  doctor: { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
  version: { type: 'boolean', short: 'v', default: false },
});

/** Severities accepted by `--fail-on` (INFO is never a CI gate). */
export const FAIL_ON_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

/**
 * Validate and normalize a `--fail-on` value. Null/undefined means "no gate".
 *
 * @param {string} [value]
 * @returns {string|null}
 */
export function normalizeFailOn(value) {
  if (value === undefined || value === null || value === '') return null;
  const upper = String(value).trim().toUpperCase();
  if (!FAIL_ON_SEVERITIES.includes(upper)) {
    throw new Error(`--fail-on must be one of: ${FAIL_ON_SEVERITIES.join(', ').toLowerCase()} (got "${value}")`);
  }
  return upper;
}

/**
 * Count findings at or above the gate severity.
 *
 * @param {Record<string, number>} severityCounts
 * @param {string} failOn normalized severity (see {@link normalizeFailOn})
 * @returns {number}
 */
export function countFindingsAtOrAbove(severityCounts, failOn) {
  const threshold = SEVERITY_RANK[failOn];
  if (!threshold) return 0;
  let total = 0;
  for (const [severity, count] of Object.entries(severityCounts || {})) {
    if ((SEVERITY_RANK[severity] || 0) >= threshold) {
      total += Number(count) || 0;
    }
  }
  return total;
}

/**
 * Validate and normalize a `--tool-timeout` value (seconds) into milliseconds.
 *
 * @param {string} [value]
 * @returns {number|null}
 */
export function normalizeToolTimeout(value) {
  if (value === undefined || value === null || value === '') return null;
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error(`--tool-timeout must be a positive number of seconds (got "${value}")`);
  }
  return Math.round(seconds * 1000);
}

/**
 * Parse raw argv (without the node/script prefix) into a flat options object.
 * Throws with a human-readable message on unknown flags, missing option
 * values, or invalid `--fail-on` / `--tool-timeout` values.
 *
 * @param {string[]} argv
 */
export function parseCliArgs(argv) {
  const parsed = parseArgs({
    args: argv,
    options: /** @type {any} */ (CLI_OPTIONS),
    allowPositionals: true,
    strict: true,
  });
  const values = /** @type {Record<string, string|boolean|undefined>} */ (parsed.values);
  const positionals = parsed.positionals;

  /** @param {string|boolean|undefined} value @returns {string|null} */
  const asString = (value) => (typeof value === 'string' && value !== '' ? value : null);

  return {
    targetArg: positionals[0] || null,
    output: asString(values.output),
    agentName: asString(values['agent-name']),
    localDastUrl: asString(values['local-dast-url']),
    confirmLocalDast: Boolean(values['confirm-local-dast']),
    strictPartials: Boolean(values['strict-partials']),
    baseline: asString(values.baseline),
    updateBaseline: Boolean(values['update-baseline']),
    dumpGuide: Boolean(values['dump-guide']),
    provisionTools: Boolean(values['provision-tools']),
    failOn: normalizeFailOn(asString(values['fail-on']) ?? undefined),
    toolTimeoutMs: normalizeToolTimeout(asString(values['tool-timeout']) ?? undefined),
    semgrepConfig: asString(values['semgrep-config']),
    noUpdateCheck: Boolean(values['no-update-check']),
    noToolCheck: Boolean(values['no-tool-check']),
    doctor: Boolean(values.doctor),
    help: Boolean(values.help),
    version: Boolean(values.version),
  };
}
