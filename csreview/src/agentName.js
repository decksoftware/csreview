// @ts-check

/**
 * Canonical agent-name sanitizer for report file prefixes
 * (`<agent>_security-report.html`, `<agent>_local-dast-report.html`,
 * `<agent>_db-dump-guide.html`).
 *
 * This is the single source of truth: it used to exist as three separate
 * copies (index.js, localDast.js, dumpGuide.js), and any drift between them
 * would scatter one agent's reports across different file prefixes.
 *
 * @param {string} [agentName]
 * @returns {string} lowercase `[a-z0-9_-]` name, never empty (falls back to "codex")
 */
export function sanitizeAgentName(agentName) {
  const normalized = String(agentName || 'codex')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return normalized || 'codex';
}
