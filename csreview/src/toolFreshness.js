// @ts-check
// Pre-flight (READ-ONLY, FAIL-OPEN): for each EXTERNAL scanner available on the system,
// compare the installed version against the latest official release and note the advisory-DB
// freshness mode. It only informs/recommends — it NEVER auto-upgrades system tools (that is
// invasive and requires the user's consent). Network lookups fail-open (offline => 'unknown').
import { compareVersions } from './updateCheck.js';

const DEFAULT_TIMEOUT_MS = 8000;

// dbMode: how the tool gets vulnerability/rule data.
//   online      -> queries a live service each run (always fresh)
//   local-db    -> caches a DB locally; should refresh before scanning
//   bundled     -> rules ship inside the binary; update the binary to get new rules
export const TOOL_REGISTRY = [
  {
    name: 'semgrep',
    latest: { type: 'pypi', id: 'semgrep' },
    update: 'pipx upgrade semgrep (or: uv tool upgrade semgrep / brew upgrade semgrep)',
    dbMode: 'online',
  },
  {
    name: 'osv-scanner',
    latest: { type: 'github', id: 'google/osv-scanner' },
    update:
      'winget upgrade Google.OSVScanner / brew upgrade osv-scanner / go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest',
    dbMode: 'online',
  },
  { name: 'npm', latest: { type: 'npm', id: 'npm' }, update: 'npm install -g npm', dbMode: 'online' },
  {
    name: 'trivy',
    latest: { type: 'github', id: 'aquasecurity/trivy' },
    update: 'brew upgrade trivy / winget upgrade AquaSecurity.Trivy',
    dbMode: 'local-db',
  },
  {
    name: 'gitleaks',
    latest: { type: 'github', id: 'gitleaks/gitleaks' },
    update: 'brew upgrade gitleaks / winget upgrade gitleaks.gitleaks',
    dbMode: 'bundled',
  },
  {
    name: 'cargo-audit',
    latest: { type: 'crates', id: 'cargo-audit' },
    update: 'cargo install cargo-audit --force',
    dbMode: 'online',
  },
  { name: 'pip-audit', latest: { type: 'pypi', id: 'pip-audit' }, update: 'pipx upgrade pip-audit', dbMode: 'online' },
  { name: 'bandit', latest: { type: 'pypi', id: 'bandit' }, update: 'pipx upgrade bandit', dbMode: 'bundled' },
  { name: 'checkov', latest: { type: 'pypi', id: 'checkov' }, update: 'pipx upgrade checkov', dbMode: 'bundled' },
];

/** Extract the first dotted version number from a tool's --version output. */
export function parseVersion(text) {
  const match = String(text || '').match(/\d+\.\d+(?:\.\d+)?/);
  return match ? match[0] : null;
}

async function fetchJson(fetchImpl, url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'csreview-tool-freshness' },
      signal: controller.signal,
    });
    if (!res || !res.ok) throw new Error(`HTTP ${res ? res.status : 'no-response'}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/** Resolve the latest published version for a tool from its official registry. Returns null on failure. */
export async function fetchLatestVersion(tool, fetchImpl, timeoutMs) {
  try {
    if (tool.latest.type === 'pypi') {
      const data = await fetchJson(fetchImpl, `https://pypi.org/pypi/${tool.latest.id}/json`, timeoutMs);
      return data?.info?.version || null;
    }
    if (tool.latest.type === 'github') {
      const data = await fetchJson(
        fetchImpl,
        `https://api.github.com/repos/${tool.latest.id}/releases/latest`,
        timeoutMs,
      );
      return String(data?.tag_name || '').replace(/^v/i, '') || null;
    }
    if (tool.latest.type === 'crates') {
      const data = await fetchJson(fetchImpl, `https://crates.io/api/v1/crates/${tool.latest.id}`, timeoutMs);
      return data?.crate?.max_stable_version || data?.crate?.newest_version || null;
    }
    if (tool.latest.type === 'npm') {
      const data = await fetchJson(fetchImpl, `https://registry.npmjs.org/${tool.latest.id}/latest`, timeoutMs);
      return data?.version || null;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * For each AVAILABLE tool (present in `installed`), compare installed vs latest and report freshness.
 * @param {Record<string, string|null|undefined>} installed  map of toolName -> installed version string (raw --version output ok)
 * @param {{fetchImpl?: Function, timeoutMs?: number}} [options]
 * @returns {Promise<Array<{name:string, installed:string|null, latest:string|null, status:'current'|'outdated'|'unknown', update:string, dbMode:string, dbNote:string}>>}
 */
export async function checkToolFreshness(installed = {}, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const results = [];

  for (const tool of TOOL_REGISTRY) {
    const raw = installed[tool.name];
    if (!raw) continue; // only report tools that are actually available
    const installedVersion = parseVersion(raw);

    let latest = null;
    if (typeof fetchImpl === 'function') {
      latest = await fetchLatestVersion(tool, fetchImpl, options.timeoutMs);
    }

    /** @type {'current' | 'outdated' | 'unknown'} */
    let status = 'unknown';
    if (latest && installedVersion) {
      status = compareVersions(latest, installedVersion) > 0 ? 'outdated' : 'current';
    }

    const dbNote =
      tool.dbMode === 'online'
        ? 'Advisory/rule data is fetched live each run (run online for fresh data).'
        : tool.dbMode === 'local-db'
          ? 'Refresh the local vulnerability DB before scanning (e.g., Trivy auto-updates online; offline runs may be stale).'
          : 'Detection rules ship inside the binary — update the binary to get newer rules.';

    results.push({
      name: tool.name,
      installed: installedVersion,
      latest,
      status,
      update: tool.update,
      dbMode: tool.dbMode,
      dbNote,
    });
  }

  return results;
}
