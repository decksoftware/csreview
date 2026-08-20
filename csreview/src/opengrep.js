// @ts-check
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { assertOfficialUrl } from './provision.js';
import { downloadBuffer } from './provisionRuntime.js';

export const OPENGREP_VERSION = '1.26.0';
const OPENGREP_RELEASE_BASE = `https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}`;
const OPENGREP_MAX_BYTES = 100 * 1024 * 1024;
const VERSION_TIMEOUT_MS = 10000;
const DEFAULT_TOOL_TIMEOUT_MS = 120000;
const DEFAULT_MAX_BUFFER = 20 * 1024 * 1024;
const execFileAsync = promisify(execFile);

export const OPENGREP_ARTIFACTS = Object.freeze([
  artifact(
    'win32',
    'x64',
    null,
    'opengrep_windows_x86.exe',
    '4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3',
  ),
  artifact(
    'linux',
    'x64',
    'glibc',
    'opengrep_manylinux_x86',
    '40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26',
  ),
  artifact(
    'linux',
    'arm64',
    'glibc',
    'opengrep_manylinux_aarch64',
    '3042a3b1aa98fa93407b9d66a45ab1f179b5b367e76965f56afdbd2c038fb1fa',
  ),
  artifact(
    'linux',
    'x64',
    'musl',
    'opengrep_musllinux_x86',
    '18aeca114221e2816ec26e1a731f1a2583408c8e4578cd868cd2d47c12fd29f8',
  ),
  artifact(
    'linux',
    'arm64',
    'musl',
    'opengrep_musllinux_aarch64',
    'd4e20ac57b6f9bb32c2b0ffc0501b8c6acb92ecee60f11f1cd72db9b11647857',
  ),
  artifact(
    'darwin',
    'x64',
    null,
    'opengrep_osx_x86',
    '36c00a2b6eeb45796275e69cb8f74ef27c42724a1b3c98f6c8d861bad7a8529d',
  ),
  artifact(
    'darwin',
    'arm64',
    null,
    'opengrep_osx_arm64',
    '513ff8491f7254c9a672cf8421136a537eb53b2a8af748568bd697acdc59eefe',
  ),
]);

export function detectLinuxLibc(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'linux') return null;
  let reportHeader = options.reportHeader;
  if (reportHeader === undefined) {
    try {
      const report = /** @type {{header?: {glibcVersionRuntime?: string}}} */ (process.report?.getReport?.());
      reportHeader = report?.header;
    } catch {
      reportHeader = null;
    }
  }
  return reportHeader?.glibcVersionRuntime ? 'glibc' : 'musl';
}

function artifact(platform, arch, libc, filename, sha256) {
  return Object.freeze({
    platform,
    arch,
    libc,
    filename,
    sha256,
    sourceUrl: `${OPENGREP_RELEASE_BASE}/${filename}`,
    maxBytes: OPENGREP_MAX_BYTES,
  });
}

export function selectOpenGrepArtifact(options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const libc = platform === 'linux' ? options.libc || detectLinuxLibc({ ...options, platform }) : null;
  return (
    OPENGREP_ARTIFACTS.find((entry) => entry.platform === platform && entry.arch === arch && entry.libc === libc) ||
    null
  );
}

export function getPrivateToolCacheRoot(options = {}) {
  const platform = options.platform || process.platform;
  const env = options.env || process.env;
  const homeDir = options.homeDir || os.homedir();
  if (platform === 'win32') {
    const localAppData = path.win32.isAbsolute(env.LOCALAPPDATA || '')
      ? env.LOCALAPPDATA
      : path.join(homeDir, 'AppData', 'Local');
    return path.resolve(localAppData, 'CSReview', 'tools');
  }
  const base = path.posix.isAbsolute(env.XDG_CACHE_HOME || '') ? env.XDG_CACHE_HOME : path.join(homeDir, '.cache');
  return path.resolve(base, 'csreview', 'tools');
}

function isInside(candidate, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function resolveThroughExistingAncestor(candidate) {
  let ancestor = path.resolve(candidate);
  const missing = [];
  while (!existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    missing.unshift(path.basename(ancestor));
    ancestor = parent;
  }
  const canonicalAncestor = existsSync(ancestor) ? realpathSync(ancestor) : ancestor;
  return path.resolve(canonicalAncestor, ...missing);
}

export function validatePrivateCacheBoundary(cacheRoot, targetRoot) {
  const canonicalCache = resolveThroughExistingAncestor(cacheRoot);
  const canonicalTarget = resolveThroughExistingAncestor(targetRoot);
  if (isInside(canonicalCache, canonicalTarget) || isInside(canonicalTarget, canonicalCache)) {
    throw new Error('OpenGrep private cache must not overlap the audited target.');
  }
  return { cacheRoot: canonicalCache, targetRoot: canonicalTarget };
}

function hashFile(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

function minimalToolEnv(source = process.env, runtimeDir = null) {
  const env = {};
  for (const name of [
    'PATH',
    'SystemRoot',
    'WINDIR',
    'TEMP',
    'TMP',
    'HOME',
    'USERPROFILE',
    'LOCALAPPDATA',
    'APPDATA',
    'HOMEDRIVE',
    'HOMEPATH',
    'PATHEXT',
    'ComSpec',
    'LANG',
    'LC_ALL',
  ]) {
    if (source[name]) env[name] = source[name];
  }
  env.LANG ||= 'C';
  env.LC_ALL ||= 'C';
  env.OPENGREP_ENABLE_VERSION_CHECK = '0';
  if (runtimeDir) {
    env.OPENGREEP_LOG_FILE = path.join(runtimeDir, 'opengrep.log');
    env.OPENGREP_VERSION_CACHE_PATH = path.join(runtimeDir, 'version-cache');
    env.XDG_CONFIG_HOME = runtimeDir;
  }
  return env;
}

function createRuntimeEnv(source, cacheRoot, targetRoot) {
  const boundary = validatePrivateCacheBoundary(cacheRoot, targetRoot);
  const runtimeDir = path.join(boundary.cacheRoot, 'runtime');
  mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  return minimalToolEnv(source, runtimeDir);
}

export function findExecutableOnPath(bin = 'opengrep', env = process.env, platform = process.platform) {
  const pathValue = String(env.PATH || '');
  if (!pathValue) return null;
  const extensions = platform === 'win32' ? String(env.PATHEXT || '.EXE;.CMD;.BAT').split(';') : [''];
  const names = platform === 'win32' ? extensions.map((ext) => `${bin}${ext.toLowerCase()}`) : [bin];
  for (const segment of pathValue.split(path.delimiter).filter(Boolean)) {
    for (const name of names) {
      const candidate = path.resolve(segment, name);
      try {
        const stat = lstatSync(candidate);
        if (stat.isFile() && !stat.isSymbolicLink()) return candidate;
      } catch {
        // Continue searching PATH entries.
      }
    }
  }
  return null;
}

function parseVersion(value) {
  return String(value || '').match(/\d+\.\d+\.\d+/)?.[0] || null;
}

function validateManifest(manifest, artifactSpec, binaryPath, options) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return false;
  const requiredStrings = ['tool', 'version', 'platform', 'arch', 'sourceUrl', 'sha256', 'installedAt'];
  if (requiredStrings.some((key) => typeof manifest[key] !== 'string' || !manifest[key])) return false;
  if (!Number.isSafeInteger(manifest.size) || manifest.size <= 0) return false;
  return (
    manifest.tool === 'opengrep' &&
    manifest.version === OPENGREP_VERSION &&
    manifest.platform === (options.platform || process.platform) &&
    manifest.arch === (options.arch || process.arch) &&
    manifest.sourceUrl === artifactSpec.sourceUrl &&
    manifest.sha256 === artifactSpec.sha256 &&
    manifest.size === lstatSync(binaryPath).size &&
    !Number.isNaN(Date.parse(manifest.installedAt))
  );
}

export async function validateTrustedOpenGrep(binaryPath, options = {}) {
  let targetRoot;
  let cacheRoot;
  try {
    const boundary = validatePrivateCacheBoundary(
      options.cacheRoot || getPrivateToolCacheRoot(options),
      options.targetRoot || process.cwd(),
    );
    targetRoot = boundary.targetRoot;
    cacheRoot = boundary.cacheRoot;
  } catch (error) {
    return { available: false, reason: error?.message || String(error) };
  }
  const artifactSpec = options.artifact || selectOpenGrepArtifact(options);
  if (!artifactSpec) return { available: false, reason: 'OpenGrep 1.26.0 has no approved artifact for this platform.' };
  try {
    const stat = lstatSync(binaryPath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return { available: false, reason: 'OpenGrep executable is not a regular non-symlink file.' };
    }
    const resolved = realpathSync(binaryPath);
    if (isInside(resolved, targetRoot)) {
      return { available: false, reason: 'OpenGrep executable is inside the audited target and will not be executed.' };
    }
    if (options.requireManifest !== false && !isInside(resolved, cacheRoot)) {
      return { available: false, reason: 'OpenGrep cache entry escaped the private cache root.' };
    }
    if (stat.size > artifactSpec.maxBytes) {
      return { available: false, reason: 'OpenGrep executable exceeds the approved size ceiling.' };
    }
    const digest = hashFile(resolved);
    if (digest !== artifactSpec.sha256) {
      return { available: false, reason: 'OpenGrep executable SHA-256 does not match the approved artifact.' };
    }
    if (options.requireManifest !== false) {
      const manifestPath = path.join(path.dirname(resolved), 'manifest.json');
      const manifestStat = lstatSync(manifestPath);
      if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) {
        return { available: false, reason: 'OpenGrep cache manifest is not a regular non-symlink file.' };
      }
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (!validateManifest(manifest, artifactSpec, resolved, options)) {
        return { available: false, reason: 'OpenGrep cache manifest failed validation.' };
      }
    }
    const execImpl = options.execImpl || execFileAsync;
    const result = await execImpl(resolved, ['--version'], {
      timeout: VERSION_TIMEOUT_MS,
      windowsHide: true,
      env: createRuntimeEnv(options.env || process.env, cacheRoot, targetRoot),
    });
    const version = parseVersion(result.stdout || result.stderr);
    if (version !== OPENGREP_VERSION) {
      return { available: false, reason: `OpenGrep version ${version || 'unknown'} is not approved.` };
    }
    return { available: true, path: resolved, version, sha256: digest };
  } catch (error) {
    return { available: false, reason: `OpenGrep validation failed: ${error?.message || String(error)}` };
  }
}

export function validateOpenGrepConfig(value, options = {}) {
  if (value === undefined || value === null || value === '') return null;
  const raw = String(value).trim();
  const localPath = path.resolve(options.cwd || process.cwd(), raw);
  const isRemote = /^(?:https?|git|ssh):/i.test(raw) || raw === 'auto';
  if (isRemote || !existsSync(localPath)) {
    throw new Error('--opengrep-config must resolve to an existing local file or directory.');
  }
  const stat = lstatSync(localPath);
  if ((!stat.isFile() && !stat.isDirectory()) || stat.isSymbolicLink()) {
    throw new Error('--opengrep-config must resolve to an existing local file or directory.');
  }
  return realpathSync(localPath);
}

export function openGrepExcludeArgs(dirs = []) {
  return dirs.flatMap((dir) => ['--exclude', String(dir)]);
}

export function buildOpenGrepArgs(targetRoot, options = {}) {
  const rulepackPath = path.resolve(options.rulepackPath || fileURLToPath(new URL('../rules', import.meta.url)));
  const args = ['scan', '--config', rulepackPath];
  if (options.configPath) args.push('--config', path.resolve(options.configPath));
  args.push('--json', '--quiet', '--disable-version-check', ...openGrepExcludeArgs(options.excludes || []));
  args.push(path.resolve(targetRoot));
  return args;
}

function normalizeSeverity(extra) {
  const severity = String(extra?.severity || '').toUpperCase();
  const impact = String(extra?.metadata?.impact || '').toUpperCase();
  if (severity === 'ERROR') return impact === 'HIGH' ? 'CRITICAL' : 'HIGH';
  if (severity === 'WARNING') return 'MEDIUM';
  return 'LOW';
}

export function normalizeOpenGrepFinding(result, index) {
  const metadata = result?.extra?.metadata || {};
  const cweValues = Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe];
  const cwe =
    cweValues
      .filter(Boolean)
      .join(' ')
      .match(/CWE-\d+/i)?.[0]
      ?.toUpperCase() || 'N/A';
  const references = [
    metadata.source,
    metadata.shortlink,
    ...(Array.isArray(metadata.references) ? metadata.references : []),
  ].filter(Boolean);
  return {
    id: `OPENGREP_${index + 1}`,
    severity: normalizeSeverity(result?.extra),
    category: metadata.vulnerability_class?.[0] || 'OpenGrep',
    name: result?.extra?.message || result?.check_id || 'OpenGrep finding',
    description: result?.extra?.message || 'OpenGrep finding.',
    file: result?.path || 'unknown',
    line: result?.start?.line || 1,
    vulnerableCode: result?.extra?.lines || 'OpenGrep did not include a code snippet.',
    cwe,
    owasp: metadata.owasp?.[0] || 'N/A',
    vibeRisk: false,
    compliance: cwe !== 'N/A' ? 'OpenGrep mapped finding' : '',
    fix: 'Review the OpenGrep finding and apply the remediation recommended by the referenced rule.',
    confidence: 'TOOL-ONLY',
    exploitation: 'See the OpenGrep rule metadata and references for exploitation context.',
    references,
    source: 'opengrep',
  };
}

export async function resolveOpenGrep(options = {}) {
  const targetRoot = path.resolve(options.targetRoot || process.cwd());
  const cacheRoot = path.resolve(options.cacheRoot || getPrivateToolCacheRoot(options));
  const artifactSpec = options.artifact || selectOpenGrepArtifact(options);
  const legacyDir = path.join(targetRoot, '.csreview', 'bin');
  const legacyCacheIgnored =
    existsSync(path.join(legacyDir, 'opengrep')) || existsSync(path.join(legacyDir, 'opengrep.exe'));
  if (!artifactSpec) {
    return {
      available: false,
      path: null,
      source: 'none',
      reason: 'No approved OpenGrep artifact for this platform.',
      legacyCacheIgnored,
    };
  }

  const onPath = findExecutableOnPath('opengrep', options.env || process.env, options.platform || process.platform);
  if (onPath) {
    const validated = await validateTrustedOpenGrep(onPath, {
      ...options,
      targetRoot,
      cacheRoot,
      artifact: artifactSpec,
      requireManifest: false,
    });
    if (validated.available) return { ...validated, source: 'path', legacyCacheIgnored };
  }

  const binaryName = artifactSpec.platform === 'win32' ? 'opengrep.exe' : 'opengrep';
  const cachedPath = path.join(cacheRoot, 'opengrep', OPENGREP_VERSION, artifactSpec.sha256, binaryName);
  if (existsSync(cachedPath)) {
    const validated = await validateTrustedOpenGrep(cachedPath, {
      ...options,
      targetRoot,
      cacheRoot,
      artifact: artifactSpec,
      requireManifest: true,
    });
    if (validated.available) return { ...validated, source: 'cache', legacyCacheIgnored };
  }

  if (options.provision) {
    const provisioned = await provisionOpenGrep({ ...options, targetRoot, cacheRoot, artifact: artifactSpec });
    return { ...provisioned, legacyCacheIgnored };
  }

  return {
    available: false,
    path: null,
    source: 'none',
    reason: 'OpenGrep is not installed; run with --provision-tools to fetch the approved artifact.',
    legacyCacheIgnored,
  };
}

export async function provisionOpenGrep(options = {}) {
  let targetRoot;
  let cacheRoot;
  try {
    const boundary = validatePrivateCacheBoundary(
      options.cacheRoot || getPrivateToolCacheRoot(options),
      options.targetRoot || process.cwd(),
    );
    targetRoot = boundary.targetRoot;
    cacheRoot = boundary.cacheRoot;
  } catch (error) {
    return { available: false, path: null, source: 'none', reason: error?.message || String(error) };
  }
  const artifactSpec = options.artifact || selectOpenGrepArtifact(options);
  if (!artifactSpec) {
    return { available: false, path: null, source: 'none', reason: 'No approved OpenGrep artifact for this platform.' };
  }

  let tempDir = null;
  try {
    assertOfficialUrl(artifactSpec.sourceUrl);
    const bytes = Buffer.from(
      options.download
        ? await options.download(artifactSpec.sourceUrl, { maxBytes: artifactSpec.maxBytes })
        : await downloadBuffer(artifactSpec.sourceUrl, globalThis.fetch, { maxBytes: artifactSpec.maxBytes }),
    );
    if (bytes.length <= 0 || bytes.length > artifactSpec.maxBytes) {
      return {
        available: false,
        path: null,
        source: 'none',
        reason: 'OpenGrep artifact exceeded the approved size ceiling.',
      };
    }
    const firstDigest = createHash('sha256').update(bytes).digest('hex');
    if (firstDigest !== artifactSpec.sha256) {
      return {
        available: false,
        path: null,
        source: 'none',
        reason: 'OpenGrep artifact SHA-256 mismatch; download rejected.',
      };
    }

    const finalDir = path.join(cacheRoot, 'opengrep', OPENGREP_VERSION, artifactSpec.sha256);
    const binaryName = artifactSpec.platform === 'win32' ? 'opengrep.exe' : 'opengrep';
    const finalPath = path.join(finalDir, binaryName);
    const manifestPath = path.join(finalDir, 'manifest.json');
    if (existsSync(finalDir)) {
      const existing = await validateTrustedOpenGrep(finalPath, {
        ...options,
        targetRoot,
        cacheRoot,
        artifact: artifactSpec,
        requireManifest: true,
      });
      if (existing.available) return { ...existing, source: 'cache', manifestPath };
      return {
        available: false,
        path: null,
        source: 'none',
        reason: 'Existing OpenGrep cache entry failed validation and was not overwritten.',
      };
    }

    mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
    tempDir = mkdtempSync(path.join(cacheRoot, '.opengrep-'));
    const tempBinary = path.join(tempDir, binaryName);
    writeFileSync(tempBinary, bytes, { flag: 'wx', mode: 0o600 });
    if (hashFile(tempBinary) !== artifactSpec.sha256) {
      return { available: false, path: null, source: 'none', reason: 'OpenGrep artifact changed while staging.' };
    }
    const installedAt = (options.now ? options.now() : new Date()).toISOString();
    const manifest = {
      tool: 'opengrep',
      version: OPENGREP_VERSION,
      platform: options.platform || process.platform,
      arch: options.arch || process.arch,
      sourceUrl: artifactSpec.sourceUrl,
      sha256: artifactSpec.sha256,
      size: bytes.length,
      installedAt,
    };
    writeFileSync(path.join(tempDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, {
      flag: 'wx',
      mode: 0o600,
    });

    mkdirSync(path.dirname(finalDir), { recursive: true, mode: 0o700 });
    renameSync(tempDir, finalDir);
    tempDir = null;
    if (hashFile(finalPath) !== artifactSpec.sha256) {
      return {
        available: false,
        path: null,
        source: 'none',
        reason: 'OpenGrep artifact changed after atomic installation.',
      };
    }
    chmodSync(finalPath, 0o700);
    const validated = await validateTrustedOpenGrep(finalPath, {
      ...options,
      targetRoot,
      cacheRoot,
      artifact: artifactSpec,
      requireManifest: true,
    });
    if (!validated.available) return { ...validated, path: null, source: 'none' };
    return { ...validated, source: 'provisioned', manifestPath };
  } catch (error) {
    return {
      available: false,
      path: null,
      source: 'none',
      reason: `OpenGrep provisioning failed: ${error?.message || String(error)}`,
    };
  } finally {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  }
}

export async function runOpenGrep(targetRoot, options = {}) {
  const configPath = validateOpenGrepConfig(options.configPath, { cwd: targetRoot });
  const resolved = await resolveOpenGrep({ ...options, targetRoot });
  if (!resolved.available) {
    return {
      ...resolved,
      required: true,
      findings: [],
      rawCount: 0,
      error: resolved.reason,
      diagnostic: 'unavailable',
      complete: false,
      ruleErrorCount: 0,
      skippedCount: 0,
      skippedReasons: [],
    };
  }
  const args = buildOpenGrepArgs(targetRoot, {
    rulepackPath: options.rulepackPath,
    configPath,
    excludes: options.excludes,
  });
  const execImpl = options.execImpl || execFileAsync;
  try {
    const cacheRoot = path.resolve(options.cacheRoot || getPrivateToolCacheRoot(options));
    const result = await execImpl(resolved.path, args, {
      cwd: path.resolve(targetRoot),
      timeout: options.timeoutMs || DEFAULT_TOOL_TIMEOUT_MS,
      maxBuffer: DEFAULT_MAX_BUFFER,
      windowsHide: true,
      env: createRuntimeEnv(options.env || process.env, cacheRoot, targetRoot),
    });
    let parsed;
    try {
      parsed = JSON.parse(result.stdout || '{}');
    } catch {
      return {
        ...resolved,
        available: false,
        required: true,
        findings: [],
        rawCount: 0,
        error: 'OpenGrep returned malformed JSON.',
        diagnostic: 'malformed-json',
        complete: false,
        ruleErrorCount: 0,
        skippedCount: 0,
        skippedReasons: [],
      };
    }
    const raw = Array.isArray(parsed.results) ? parsed.results : [];
    const diagnostics = summarizeOpenGrepDiagnostics(parsed);
    return {
      ...resolved,
      available: diagnostics.diagnostic !== 'rule-errors',
      required: true,
      findings: raw.map(normalizeOpenGrepFinding),
      rawCount: raw.length,
      error:
        diagnostics.diagnostic === 'rule-errors'
          ? `OpenGrep reported ${diagnostics.ruleErrorCount} scan error(s); primary SAST is incomplete.`
          : null,
      ...diagnostics,
    };
  } catch (error) {
    const timedOut = Boolean(error?.killed || error?.signal === 'SIGTERM' || error?.code === 'ETIMEDOUT');
    return {
      ...resolved,
      available: false,
      required: true,
      findings: [],
      rawCount: 0,
      error: timedOut
        ? `OpenGrep timed out after ${options.timeoutMs || DEFAULT_TOOL_TIMEOUT_MS}ms.`
        : `OpenGrep failed: ${error?.message || String(error)}`,
      diagnostic: timedOut ? 'timeout' : 'execution-error',
      complete: false,
      ruleErrorCount: 0,
      skippedCount: 0,
      skippedReasons: [],
    };
  }
}

export function classifyOpenGrepDiagnostic(parsed = {}) {
  return summarizeOpenGrepDiagnostics(parsed).diagnostic;
}

export function summarizeOpenGrepDiagnostics(parsed = {}) {
  const errors = Array.isArray(parsed.errors) ? parsed.errors : [];
  const skipped = Array.isArray(parsed.paths?.skipped) ? parsed.paths.skipped : [];
  const diagnostic = errors.length > 0 ? 'rule-errors' : skipped.length > 0 ? 'partial-skips' : 'complete';
  return {
    diagnostic,
    complete: diagnostic === 'complete',
    ruleErrorCount: errors.length,
    skippedCount: skipped.length,
    skippedReasons: skipped.slice(0, 10).map((entry) => {
      if (typeof entry === 'string') return entry;
      return String(entry?.reason || entry?.path || entry?.details || 'unspecified skip');
    }),
  };
}
