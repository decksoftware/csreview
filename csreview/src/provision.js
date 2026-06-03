// @ts-check
import { createHash } from 'node:crypto';

/**
 * Opt-in, isolated, integrity-verified provisioning of external security tools.
 *
 * SECURITY MODEL (this is the highest-risk capability in CSReview — designed so
 * it can never become an attack vector):
 *  - OPT-IN: nothing is downloaded unless the caller passes `provision: true`
 *    (the CLI gates this behind --provision-tools + informed consent).
 *  - PINNED OFFICIAL HOSTS ONLY: every download URL must pass assertOfficialUrl
 *    (HTTPS + an allow-listed official host). URLs are derived only from a tool's
 *    pinned official repo via the releases API — never from user input.
 *  - INTEGRITY: the artifact's SHA-256 is verified against the vendor-published
 *    checksums file BEFORE it is extracted, made executable, or run.
 *  - ISOLATED: binaries are cached under the caller-provided cache dir
 *    (e.g. <project>/.csreview/bin, gitignored). Never the global system, never
 *    sudo, never the user's package.json.
 *  - FAIL-OPEN: PATH -> cache -> (opt-in) download+verify -> isolated install ->
 *    "unavailable" (lower confidence). It never throws out of ensureTool except
 *    for a verification/security failure, which is reported, not executed.
 *
 * All network/filesystem/exec operations are INJECTED so unit tests are
 * deterministic and never hit the network.
 */

/** Official hosts CSReview may download tool artifacts from. */
export const ALLOWED_DOWNLOAD_HOSTS = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com', // GitHub release-asset redirect target
  'release-assets.githubusercontent.com',
  'codeload.github.com',
  'api.github.com',
]);

/**
 * Throw unless `url` is HTTPS on an allow-listed official host. This is the
 * SSRF / supply-chain pin for all provisioning downloads.
 *
 * @param {string} url
 * @returns {URL}
 */
export function assertOfficialUrl(url) {
  let parsed;
  try {
    parsed = new URL(String(url));
  } catch {
    throw new Error(`Provisioning refused: not a valid URL (${url}).`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`Provisioning refused: non-HTTPS download (${parsed.protocol}).`);
  }
  if (!ALLOWED_DOWNLOAD_HOSTS.has(parsed.hostname)) {
    throw new Error(`Provisioning refused: non-official host "${parsed.hostname}".`);
  }
  return parsed;
}

/**
 * Pinned registry of provisionable tools. Each maps to its OFFICIAL GitHub repo
 * plus how to recognize its release asset and checksums file. No URLs are stored
 * literally; they are resolved from the pinned repo via the releases API at run
 * time (and every resolved URL is re-checked with assertOfficialUrl).
 */
export const TOOL_REGISTRY = {
  gitleaks: {
    name: 'gitleaks',
    bin: 'gitleaks',
    repo: 'gitleaks/gitleaks',
    purpose: 'secret scanning (corroborates the regex secret detector)',
    versionArgs: ['version'],
  },
  gosec: {
    name: 'gosec',
    bin: 'gosec',
    repo: 'securego/gosec',
    purpose: 'Go security checker (AST)',
    versionArgs: ['--version'],
  },
  trivy: {
    name: 'trivy',
    bin: 'trivy',
    repo: 'aquasecurity/trivy',
    purpose: 'IaC / container / filesystem misconfig + vuln scanner',
    versionArgs: ['--version'],
  },
  bandit: {
    name: 'bandit',
    bin: 'bandit',
    repo: 'PyCQA/bandit',
    purpose: 'Python security checker (AST)',
    versionArgs: ['--version'],
    // PyPI-distributed, not a single GitHub-release binary, so it is NOT
    // auto-downloaded via the archive cascade — used only if already on PATH.
    pathOnly: true,
    installHint: 'pip install bandit (or pipx install bandit)',
  },
};

/**
 * Normalize Node's platform/arch into the synonym tokens used across vendor
 * release asset names (each token set is matched case-insensitively).
 *
 * @param {NodeJS.Platform} [platform]
 * @param {string} [arch]
 */
export function platformTokens(platform = process.platform, arch = process.arch) {
  const os =
    platform === 'win32' ? ['windows', 'win'] : platform === 'darwin' ? ['darwin', 'macos', 'osx', 'mac'] : ['linux'];
  const cpu =
    arch === 'arm64' ? ['arm64', 'aarch64'] : arch === 'x64' ? ['x64', 'amd64', 'x86_64', '64bit', '64-bit'] : [arch];
  return { os, cpu, isWindows: platform === 'win32' };
}

const ARCHIVE_EXT = /\.(?:tar\.gz|tgz|zip)$/i;

function nameMatchesPlatform(name, tokens) {
  const lower = String(name || '').toLowerCase();
  const osOk = tokens.os.some((t) => lower.includes(t));
  const cpuOk = tokens.cpu.some((t) => lower.includes(t));
  return osOk && cpuOk;
}

/**
 * Pick the release asset matching this platform (an archive containing the
 * binary). `assets` is the GitHub release `assets` array ({name, browser_download_url}).
 *
 * @param {Array<{name?: string, browser_download_url?: string}>} assets
 * @param {ReturnType<typeof platformTokens>} tokens
 * @returns {{name: string, browser_download_url: string} | null}
 */
export function pickReleaseAsset(assets = [], tokens) {
  const candidates = (assets || []).filter(
    (a) => a && ARCHIVE_EXT.test(a.name || '') && nameMatchesPlatform(a.name, tokens),
  );
  // Prefer .tar.gz on unix, .zip on windows, but accept either.
  const preferred = candidates.find((a) =>
    tokens.isWindows ? /\.zip$/i.test(a.name) : /\.(?:tar\.gz|tgz)$/i.test(a.name),
  );
  const chosen = preferred || candidates[0] || null;
  return chosen ? { name: String(chosen.name), browser_download_url: String(chosen.browser_download_url) } : null;
}

/**
 * Pick the checksums asset from a release (e.g. "gitleaks_8.x_checksums.txt").
 *
 * @param {Array<{name?: string, browser_download_url?: string}>} assets
 */
export function pickChecksumsAsset(assets = []) {
  const chosen =
    (assets || []).find((a) => a && /checksums?(?:\.txt)?$/i.test(a.name || '') && /\.txt$/i.test(a.name || '')) ||
    (assets || []).find((a) => a && /checksums?/i.test(a.name || ''));
  return chosen ? { name: String(chosen.name), browser_download_url: String(chosen.browser_download_url) } : null;
}

/**
 * SHA-256 hex digest of a buffer.
 *
 * @param {Buffer|Uint8Array|string} data
 */
export function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Parse a `<sha256>  <filename>` checksums listing and return the digest for
 * `assetName` (lower-cased hex), or null if absent.
 *
 * @param {string} text
 * @param {string} assetName
 */
export function parseChecksums(text, assetName) {
  const base = String(assetName || '')
    .split('/')
    .pop();
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.trim().match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (m && m[2].trim().split('/').pop() === base) {
      return m[1].toLowerCase();
    }
  }
  return null;
}

/**
 * Verify a downloaded artifact against an expected SHA-256. Returns true only on
 * an exact match. Never throws.
 *
 * @param {Buffer|Uint8Array|string} data
 * @param {string} expectedHex
 */
export function verifyChecksum(data, expectedHex) {
  if (!expectedHex || !/^[a-fA-F0-9]{64}$/.test(String(expectedHex))) return false;
  return sha256(data) === String(expectedHex).toLowerCase();
}

/**
 * @typedef {object} EnsureToolResult
 * @property {string} tool
 * @property {boolean} available
 * @property {string|null} path        resolved executable path (or bin name on PATH)
 * @property {'path'|'cache'|'provisioned'|'none'} source
 * @property {string} [version]
 * @property {string} [reason]         why it is unavailable / what degraded
 * @property {boolean} [provisioned]   true if newly downloaded this run
 */

/**
 * Resolve a tool through the fail-open cascade. ALL effects are injected via
 * `io` so this is deterministic and offline-safe in tests.
 *
 * io = {
 *   onPath(bin): {version}|null,            // tool already on PATH
 *   cacheLookup(bin): {path,version}|null,  // previously provisioned copy
 *   fetchLatestRelease(repo): {tag, assets},// official releases API (assets pre-validated by caller or here)
 *   download(url): Promise<Buffer|string>,  // bytes for assets, text for checksums
 *   install({buffer, assetName, bin}): {path,version}, // extract+chmod into the isolated cache, returns path
 * }
 *
 * @param {string} toolKey
 * @param {{provision?: boolean, platform?: ReturnType<typeof platformTokens>, io: any}} opts
 * @returns {Promise<EnsureToolResult>}
 */
export async function ensureTool(toolKey, opts = /** @type {any} */ ({})) {
  const spec = TOOL_REGISTRY[toolKey];
  const io = opts.io || {};
  const base = { tool: toolKey, available: false, path: null, source: /** @type {const} */ ('none') };
  if (!spec) return { ...base, reason: `unknown tool "${toolKey}"` };

  try {
    // 1) Already on PATH (probe may be async at runtime; awaiting a sync mock is a no-op).
    const onPath = io.onPath && (await io.onPath(spec.bin));
    if (onPath) {
      return { ...base, available: true, path: spec.bin, source: 'path', version: onPath.version };
    }
    // 2) Previously provisioned in the isolated cache.
    const cached = io.cacheLookup && (await io.cacheLookup(spec.bin));
    if (cached) {
      return { ...base, available: true, path: cached.path, source: 'cache', version: cached.version };
    }
    // 2b) PATH-only tools (e.g. pip-distributed bandit) are used only if already
    // installed; CSReview never auto-downloads them via the archive cascade.
    if (spec.pathOnly) {
      return { ...base, reason: `not on PATH; install with: ${spec.installHint || 'see tool docs'}` };
    }
    // 3) Opt-in download from the pinned official repo, verified.
    if (!opts.provision) {
      return { ...base, reason: `not installed; run with --provision-tools to fetch ${spec.name} from ${spec.repo}` };
    }
    const tokens = opts.platform || platformTokens();
    const release = await io.fetchLatestRelease(spec.repo);
    if (!release || !Array.isArray(release.assets)) {
      return { ...base, reason: `could not resolve a release for ${spec.repo}` };
    }
    const asset = pickReleaseAsset(release.assets, tokens);
    const checksums = pickChecksumsAsset(release.assets);
    if (!asset) return { ...base, reason: `no release asset for this platform from ${spec.repo}` };
    if (!checksums)
      return { ...base, reason: `no checksums file published for ${spec.repo} (refusing unverified download)` };

    assertOfficialUrl(asset.browser_download_url);
    assertOfficialUrl(checksums.browser_download_url);

    const checksumsText = await io.download(checksums.browser_download_url);
    const expected = parseChecksums(String(checksumsText), asset.name);
    if (!expected) return { ...base, reason: `no checksum entry for ${asset.name} (refusing unverified download)` };

    const buffer = await io.download(asset.browser_download_url);
    if (!verifyChecksum(buffer, expected)) {
      return { ...base, reason: `SHA-256 mismatch for ${asset.name} (download rejected, not executed)` };
    }

    const installed = io.install({ buffer, assetName: asset.name, bin: spec.bin });
    return {
      ...base,
      available: true,
      path: installed.path,
      source: 'provisioned',
      provisioned: true,
      version: installed.version || release.tag,
    };
  } catch (err) {
    // Fail-open: provisioning problems degrade to "unavailable", never crash.
    return { ...base, reason: `provisioning failed: ${err && err.message ? err.message : String(err)}` };
  }
}
