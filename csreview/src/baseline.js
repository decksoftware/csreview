// @ts-check
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

/**
 * `--baseline` support.
 *
 * A baseline is a JSON file of finding fingerprints that are already known and
 * accepted. On later runs, baselined findings are suppressed so CI only fails
 * on NEW findings. Fingerprints are intentionally line-independent so they
 * survive code shifting up/down. This module is read-only with respect to the
 * audited project; the only file it writes is the baseline file the user
 * explicitly asked for via --update-baseline.
 */

const BASELINE_VERSION = 1;
const DEFAULT_BASELINE_FILE = '.csreview-baseline.json';

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

/**
 * Stable, line-independent fingerprint for a finding. Two findings of the same
 * class in the same file collapse to one baseline entry on purpose: baselining
 * a class of issue in a file accepts that class in that file.
 *
 * @param {Record<string, any>} finding
 * @returns {string}
 */
export function fingerprintFinding(finding) {
  const file = normalizeKeyPart(finding?.file);
  const cwe = canonicalCwe(finding?.cwe);
  const category = normalizeKeyPart(finding?.category);
  const name = normalizeKeyPart(finding?.name);
  return [file, cwe || category, name].join('|');
}

/**
 * Read a baseline file into a Set of fingerprints (fail-open: returns an empty
 * Set when the file is absent or invalid, so a first run with --baseline simply
 * treats every finding as new).
 *
 * @param {string} filePath
 * @returns {Set<string>}
 */
export function loadBaseline(filePath) {
  try {
    if (!filePath || !existsSync(filePath)) {
      return new Set();
    }
    const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
    const list = Array.isArray(parsed) ? parsed : parsed?.fingerprints;
    if (!Array.isArray(list)) return new Set();
    return new Set(list.map((value) => String(value)));
  } catch {
    return new Set();
  }
}

/**
 * Partition findings into new vs baselined.
 *
 * @param {Array<Record<string, any>>} findings
 * @param {Set<string>} baselineSet
 * @returns {{newFindings: Array<object>, baselined: Array<object>}}
 */
export function applyBaseline(findings = [], baselineSet = new Set()) {
  const newFindings = [];
  const baselined = [];
  for (const finding of findings || []) {
    if (finding && baselineSet.has(fingerprintFinding(finding))) {
      baselined.push(finding);
    } else {
      newFindings.push(finding);
    }
  }
  return { newFindings, baselined };
}

/**
 * Serialize findings into a baseline document. Deterministic (no timestamp) so
 * regenerating an unchanged project produces an identical file.
 *
 * @param {Array<Record<string, any>>} findings
 * @returns {{version: number, tool: string, fingerprints: string[], entries: Array<object>}}
 */
export function serializeBaseline(findings = []) {
  const byFingerprint = new Map();
  for (const finding of findings || []) {
    if (!finding) continue;
    const fingerprint = fingerprintFinding(finding);
    if (!byFingerprint.has(fingerprint)) {
      byFingerprint.set(fingerprint, {
        fingerprint,
        severity: finding.severity || 'INFO',
        file: String(finding.file || ''),
        name: String(finding.name || ''),
      });
    }
  }
  const entries = [...byFingerprint.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  return {
    version: BASELINE_VERSION,
    tool: 'csreview',
    fingerprints: entries.map((entry) => entry.fingerprint),
    entries,
  };
}

/**
 * Write a baseline file for the given findings, creating parent dirs as needed.
 *
 * @param {string} filePath
 * @param {Array<Record<string, any>>} findings
 * @returns {string}
 */
export function writeBaseline(filePath, findings = []) {
  // INVARIANT: filePath must originate from a trusted source (the user's
  // --baseline/--update-baseline argv), never from audited project content.
  // This is the only function in CSReview that writes outside csreview-reports/,
  // so a caller that sourced the path from scanned files would enable an
  // arbitrary file write. Do not wire untrusted input here.
  const dir = dirname(filePath);
  if (dir && !existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(filePath, `${JSON.stringify(serializeBaseline(findings), null, 2)}\n`, 'utf8');
  return filePath;
}

export { BASELINE_VERSION, DEFAULT_BASELINE_FILE };
