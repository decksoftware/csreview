// @ts-check
// Aggregate findings by their originating tool/source so a report makes the
// corroboration story explicit: a finding seen by BOTH a tool and the heuristic
// detector is CONFIRMED and should be trusted first; detector-only heuristics are
// lower confidence. This separates "what Semgrep/OSV/audit/Gitleaks found" from
// "what the internal detector guessed", which is exactly the triage signal users
// asked for.

const SOURCE_LABELS = {
  'csreview-detector': 'CSReview detector (heuristic)',
  semgrep: 'Semgrep',
  'osv-scanner': 'OSV-Scanner',
  'npm-audit': 'npm audit',
  'pnpm-audit': 'pnpm audit',
  'bun-audit': 'bun audit',
  gitleaks: 'Gitleaks',
  trivy: 'Trivy',
  bandit: 'Bandit',
  gosec: 'gosec',
};

const SUBAGENT_PREFIX = 'subagent:';

/**
 * Human-friendly label for an internal source id.
 * @param {string} source
 * @returns {string}
 */
export function labelForSource(source) {
  const s = String(source || 'csreview-detector');
  if (s.startsWith(SUBAGENT_PREFIX)) return `Subagent: ${s.slice(SUBAGENT_PREFIX.length)}`;
  return SOURCE_LABELS[s] || s;
}

/**
 * Count findings per originating source. A finding corroborated by more than one
 * source counts once under each; `confirmed` counts findings a tool and the
 * detector (or any two sources) agree on.
 *
 * @param {Array<{source?: string, sources?: string[], confidence?: string}>} [findings]
 * @returns {{confirmed: number, total: number, rows: Array<{source: string, label: string, count: number}>}}
 */
export function originBreakdown(findings = []) {
  const list = Array.isArray(findings) ? findings : [];
  const counts = new Map();
  let confirmed = 0;
  for (const finding of list) {
    const raw =
      Array.isArray(finding?.sources) && finding.sources.length
        ? finding.sources
        : [finding?.source || 'csreview-detector'];
    const unique = [...new Set(raw.map((s) => String(s)))];
    if (String(finding?.confidence).toUpperCase() === 'CONFIRMED' || unique.length > 1) {
      confirmed += 1;
    }
    for (const source of unique) {
      counts.set(source, (counts.get(source) || 0) + 1);
    }
  }
  const rows = [...counts.entries()]
    .map(([source, count]) => ({ source, label: labelForSource(source), count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  return { confirmed, total: list.length, rows };
}
