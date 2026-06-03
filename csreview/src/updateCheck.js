// @ts-check
// Pre-flight (READ-ONLY, FAIL-OPEN): check whether a newer CSReview version exists in the
// OFFICIAL repo, fetch a change summary, and surface red flags so the coding agent can
// review the update for safety BEFORE recommending it. This module never applies an update
// and never executes anything — it only fetches public metadata over HTTPS from the pinned repo.

const DEFAULT_REPO = 'decksoftware/csreview';
const DEFAULT_BRANCH = 'main';
const DEFAULT_TIMEOUT_MS = 8000;

/** Compare two dotted versions. Returns 1 if a>b, -1 if a<b, 0 if equal. Pre-release suffixes ignored. */
export function compareVersions(a, b) {
  const parse = (v) =>
    String(v || '')
      .replace(/^v/i, '')
      .split('-')[0]
      .split('.')
      .map((n) => parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

async function fetchWithTimeout(fetchImpl, url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || DEFAULT_TIMEOUT_MS);
  try {
    return await fetchImpl(url, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'csreview-update-check' },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchText(fetchImpl, url, timeoutMs) {
  const res = await fetchWithTimeout(fetchImpl, url, timeoutMs);
  if (!res || !res.ok) throw new Error(`HTTP ${res ? res.status : 'no-response'}`);
  return res.text();
}

async function fetchJson(fetchImpl, url, timeoutMs) {
  const res = await fetchWithTimeout(fetchImpl, url, timeoutMs);
  if (!res || !res.ok) throw new Error(`HTTP ${res ? res.status : 'no-response'}`);
  return res.json();
}

/**
 * Compare the installed version against the official repo's latest (package.json + latest release tag).
 * Never throws: on any failure returns { checked: false, error }.
 * @param {string} currentVersion
 * @param {{fetchImpl?: Function, repo?: string, branch?: string, timeoutMs?: number}} [options]
 */
export async function checkForUpdate(currentVersion, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const repo = options.repo || DEFAULT_REPO;
  const branch = options.branch || DEFAULT_BRANCH;
  const base = {
    current: currentVersion || null,
    latest: null,
    source: null,
    updateAvailable: false,
    checked: false,
    error: null,
  };

  if (typeof fetchImpl !== 'function') {
    return { ...base, error: 'no fetch implementation (offline or Node < 18)' };
  }

  // Pin the request host by refusing a repo/branch that is not a plain
  // owner/name + ref. Defaults are already pinned and the CLI never passes user
  // input, but this prevents a malformed value from redirecting the request.
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || !/^[\w./-]+$/.test(branch)) {
    return { ...base, error: 'invalid repo/branch (refusing to build request URL)' };
  }

  let remoteVersion = null;
  let source = null;

  try {
    const pkgText = await fetchText(
      fetchImpl,
      `https://raw.githubusercontent.com/${repo}/${branch}/csreview/package.json`,
      options.timeoutMs,
    );
    const version = JSON.parse(pkgText).version;
    if (version) {
      remoteVersion = version;
      source = `${repo}@${branch}/csreview/package.json`;
    }
  } catch {
    // fall through to release tag
  }

  try {
    const release = await fetchJson(
      fetchImpl,
      `https://api.github.com/repos/${repo}/releases/latest`,
      options.timeoutMs,
    );
    const tag = String(release.tag_name || '').replace(/^v/i, '');
    if (tag && (!remoteVersion || compareVersions(tag, remoteVersion) > 0)) {
      remoteVersion = tag;
      source = `${repo} release ${release.tag_name}`;
    }
  } catch {
    // releases may not exist; package.json version is enough
  }

  if (!remoteVersion) {
    return { ...base, error: 'could not determine latest version' };
  }

  return {
    current: currentVersion || null,
    latest: remoteVersion,
    source,
    updateAvailable: currentVersion ? compareVersions(remoteVersion, currentVersion) > 0 : true,
    checked: true,
    error: null,
  };
}

/**
 * Fetch recent commit titles from the official repo as a lightweight changelog for agent review.
 * Never throws: returns [] on failure.
 */
export async function fetchRecentChanges(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const repo = options.repo || DEFAULT_REPO;
  if (typeof fetchImpl !== 'function') return [];
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return [];
  try {
    const commits = await fetchJson(
      fetchImpl,
      `https://api.github.com/repos/${repo}/commits?per_page=${options.limit || 15}`,
      options.timeoutMs,
    );
    return (Array.isArray(commits) ? commits : []).map((c) => ({
      sha: String(c.sha || '').slice(0, 7),
      message: String(c.commit?.message || '').split('\n')[0],
    }));
  } catch {
    return [];
  }
}

const RED_FLAGS = [
  {
    id: 'dynamic-exec',
    re: /\beval\s*\(|new\s+Function\s*\(/,
    note: 'dynamic code execution (eval/Function) introduced',
  },
  {
    id: 'process-exec',
    re: /child_process|execSync|spawnSync|\bexecFile\b|\bspawn\s*\(/,
    note: 'process/shell execution introduced',
  },
  {
    id: 'new-network',
    re: /\bfetch\s*\(|https?\.request|net\.connect|new\s+WebSocket|axios|node-fetch/,
    note: 'new outbound network call',
  },
  {
    id: 'obfuscation',
    re: /atob\s*\(|Buffer\.from\([^)]*['"]base64['"]\)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,
    note: 'possible obfuscated/base64 payload',
  },
  {
    id: 'dependency-change',
    re: /"(?:dependencies|devDependencies)"\s*:/,
    note: 'dependency manifest changed (supply-chain review needed)',
  },
  {
    id: 'safeguard-touch',
    re: /redact|pathSafety|LOCAL_HOSTS|confirmed\s*!==\s*true|allow_force_pushes/,
    note: 'touches a safeguard (redaction/local-only/path-safety) — review carefully',
  },
];

/** Heuristic red-flag scan over a provided diff/text. Pure function; the agent supplies the diff. */
export function scanTextForRedFlags(text = '') {
  const source = String(text || '');
  return RED_FLAGS.filter((flag) => flag.re.test(source)).map((flag) => ({ id: flag.id, note: flag.note }));
}
