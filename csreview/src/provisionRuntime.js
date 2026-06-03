// @ts-check
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  existsSync,
  mkdirSync,
  writeFileSync,
  chmodSync,
  readdirSync,
  lstatSync,
  copyFileSync,
  rmSync,
  mkdtempSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { assertOfficialUrl, ensureTool, platformTokens, TOOL_REGISTRY } from './provision.js';
import { runSecurityTool, selectSecurityTools, gatherSecurityToolFindings } from './securityTools.js';

const execFileAsync = promisify(execFile);

/**
 * Probe a tool already on PATH. Returns {version} or null. Never throws.
 * @param {string} bin
 * @param {string[]} versionArgs
 * @param {(file: string, args: string[], opts?: object) => Promise<{stdout: string, stderr?: string}>} [execImpl]
 */
export async function probeOnPath(bin, versionArgs, execImpl = execFileAsync) {
  try {
    const { stdout, stderr } = await execImpl(bin, versionArgs, { timeout: 15000 });
    const out = String(stdout || stderr || '').trim();
    const m = out.match(/\d+\.\d+(?:\.\d+)?/);
    return { version: m ? m[0] : 'unknown' };
  } catch {
    return null;
  }
}

/**
 * Look for a previously provisioned binary in the isolated cache dir.
 * @param {string} cacheDir
 * @param {string} bin
 * @param {(p: string) => boolean} [existsImpl]
 */
export function cacheLookup(cacheDir, bin, existsImpl = existsSync) {
  for (const candidate of [path.join(cacheDir, bin), path.join(cacheDir, `${bin}.exe`)]) {
    if (existsImpl(candidate)) return { path: candidate, version: 'cached' };
  }
  return null;
}

/**
 * Resolve the latest release of a pinned repo via the official GitHub API.
 * Returns {tag, assets:[{name, browser_download_url}]}. Never throws (returns
 * null on failure → caller degrades).
 * @param {string} repo  owner/name
 * @param {typeof fetch} [fetchImpl]
 * @param {number} [timeoutMs]
 */
export async function fetchLatestRelease(repo, fetchImpl = globalThis.fetch, timeoutMs = 15000) {
  if (typeof fetchImpl !== 'function') return null;
  const url = `https://api.github.com/repos/${repo}/releases/latest`;
  assertOfficialUrl(url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'csreview-provision' },
      signal: controller.signal,
    });
    if (!res || !res.ok) return null;
    const data = /** @type {any} */ (await res.json());
    return {
      tag: String(data.tag_name || ''),
      assets: (Array.isArray(data.assets) ? data.assets : []).map((a) => ({
        name: String(a.name || ''),
        browser_download_url: String(a.browser_download_url || ''),
      })),
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Hard ceiling on a single artifact download (defense against oversized responses). */
export const MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024;

function headerValue(res, name) {
  try {
    if (res && res.headers && typeof res.headers.get === 'function') return res.headers.get(name);
    if (res && res.headers) return res.headers[name];
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * Fetch following redirects MANUALLY, re-asserting the official-host pin on EVERY
 * hop (a 3xx from an official host to an arbitrary host would otherwise defeat
 * the pin). Bounded redirect count.
 * @param {string} url
 * @param {typeof fetch} fetchImpl
 * @param {number} [maxHops]
 */
async function fetchOfficialFollowing(url, fetchImpl, maxHops = 5) {
  let current = String(url);
  for (let hop = 0; hop <= maxHops; hop += 1) {
    assertOfficialUrl(current); // re-assert at every hop, including redirects
    const res = await fetchImpl(current, { headers: { 'User-Agent': 'csreview-provision' }, redirect: 'manual' });
    const status = res && res.status;
    if (status && status >= 300 && status < 400) {
      const location = headerValue(res, 'location');
      if (!location) throw new Error('redirect without a Location header');
      current = new URL(location, current).href;
      continue;
    }
    return res;
  }
  throw new Error('too many redirects');
}

/**
 * Download an artifact (binary) from a pinned official URL. The official-host pin
 * is enforced on the initial URL and on every redirect hop; the size is capped.
 * @param {string} url
 * @param {typeof fetch} [fetchImpl]
 */
export async function downloadBuffer(url, fetchImpl = globalThis.fetch) {
  const res = await fetchOfficialFollowing(url, fetchImpl);
  if (!res || !res.ok) throw new Error(`download failed: HTTP ${res ? res.status : 'no-response'}`);
  const declared = Number(headerValue(res, 'content-length') || 0);
  if (declared && declared > MAX_DOWNLOAD_BYTES) throw new Error(`artifact too large (${declared} bytes)`);
  const buffer = Buffer.from(await res.arrayBuffer());
  if (buffer.length > MAX_DOWNLOAD_BYTES) throw new Error(`artifact too large (${buffer.length} bytes)`);
  return buffer;
}

/**
 * Download text (checksums file) from a pinned official URL (redirect-safe, capped).
 * @param {string} url
 * @param {typeof fetch} [fetchImpl]
 */
export async function downloadText(url, fetchImpl = globalThis.fetch) {
  const res = await fetchOfficialFollowing(url, fetchImpl);
  if (!res || !res.ok) throw new Error(`download failed: HTTP ${res ? res.status : 'no-response'}`);
  const text = await res.text();
  if (text.length > 8 * 1024 * 1024) throw new Error('checksums file too large');
  return text;
}

/**
 * Default archive extractor. Uses ONLY pure-argv invocations (execFile, no shell,
 * no string interpolation): `tar` for .tar.gz/.tgz everywhere; on Windows `tar`
 * (bsdtar, shipped since Win10) also extracts .zip; elsewhere `unzip`. This
 * avoids any command-injection sink on the extraction path.
 */
async function defaultExtract(archivePath, destDir, execImpl = execFileAsync) {
  if (/\.(?:tar\.gz|tgz)$/i.test(archivePath)) {
    await execImpl('tar', ['-xzf', archivePath, '-C', destDir], { timeout: 60000 });
  } else if (/\.zip$/i.test(archivePath)) {
    if (process.platform === 'win32') {
      await execImpl('tar', ['-xf', archivePath, '-C', destDir], { timeout: 60000 });
    } else {
      await execImpl('unzip', ['-o', archivePath, '-d', destDir], { timeout: 60000 });
    }
  } else {
    throw new Error(`unsupported archive type: ${path.basename(archivePath)}`);
  }
}

function findBinary(dir, bin) {
  const wanted = new Set([bin, `${bin}.exe`]);
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    for (const entry of readdirSync(cur)) {
      const full = path.join(cur, entry);
      let st;
      try {
        st = lstatSync(full); // N3: lstat (not stat) so we never follow a symlinked member
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue; // never copy a symlinked archive member out
      if (st.isDirectory()) stack.push(full);
      else if (wanted.has(entry)) return full;
    }
  }
  return null;
}

/**
 * Extract a verified archive buffer into the isolated cache and return the bin
 * path. The buffer MUST already be checksum-verified by ensureTool. Writes only
 * under cacheDir + a temp dir; never the audited source.
 *
 * @param {{buffer: Buffer, assetName: string, bin: string, cacheDir: string, extractImpl?: Function}} args
 */
export function installFromArchive({ buffer, assetName, bin, cacheDir, extractImpl = defaultExtract }) {
  mkdirSync(cacheDir, { recursive: true });
  // N4: make the audited project's .csreview/ gitignored so provisioning never
  // pollutes the user's VCS (the cache lives at <project>/.csreview/bin).
  try {
    const giPath = path.join(path.dirname(cacheDir), '.gitignore');
    if (!existsSync(giPath)) writeFileSync(giPath, '*\n');
  } catch {
    /* best effort */
  }
  // N2: unpredictable temp dir (avoids TOCTOU pre-create/symlink on shared hosts).
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'csreview-prov-'));
  // H1: path.basename strips BOTH `/` and `\` separators (the old split('/') let a
  // Windows asset name like `..\..\evil.zip` escape tmp). Then assert the archive
  // path stays inside tmp — a release asset name must never write outside the box.
  const safeName = path.basename(String(assetName || '')) || 'artifact';
  const archivePath = path.join(tmp, safeName);
  if (!path.resolve(archivePath).startsWith(path.resolve(tmp) + path.sep)) {
    throw new Error(`refusing unsafe archive path for asset "${assetName}"`);
  }
  writeFileSync(archivePath, buffer);
  // extractImpl is async by default; callers that need the path should await
  // via installFromArchiveAsync. Kept sync-friendly for injected tests.
  return { archivePath, tmp, cacheDir, bin, extractImpl };
}

/**
 * Async variant that actually extracts and places the binary.
 * @param {{buffer: Buffer, assetName: string, bin: string, cacheDir: string, extractImpl?: Function}} args
 * @returns {Promise<{path: string, version?: string}>}
 */
export async function installFromArchiveAsync(args) {
  const { archivePath, tmp, cacheDir, bin, extractImpl } = installFromArchive(args);
  try {
    await extractImpl(archivePath, tmp);
    const found = findBinary(tmp, bin);
    if (!found) throw new Error(`binary "${bin}" not found in extracted archive`);
    const target = path.join(cacheDir, path.basename(found));
    copyFileSync(found, target);
    if (process.platform !== 'win32') {
      try {
        chmodSync(target, 0o755);
      } catch {
        /* best effort */
      }
    }
    return { path: target };
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

/**
 * Build the injected io for ensureTool using real network/fs/exec (or injected
 * impls for tests).
 * @param {string} rootDir
 * @param {{fetchImpl?: any, execImpl?: any, extractImpl?: any}} [impls]
 */
export function makeRealIo(rootDir, impls = {}) {
  const cacheDir = path.join(rootDir, '.csreview', 'bin');
  const fetchImpl = impls.fetchImpl || globalThis.fetch;
  const execImpl = impls.execImpl || execFileAsync;
  return {
    onPath: (bin) => {
      const spec = Object.values(TOOL_REGISTRY).find((t) => t.bin === bin);
      return probeOnPath(bin, (spec && spec.versionArgs) || ['--version'], execImpl);
    },
    cacheLookup: (bin) => cacheLookup(cacheDir, bin),
    fetchLatestRelease: (repo) => fetchLatestRelease(repo, fetchImpl),
    download: (url) => (/checksums?/i.test(url) ? downloadText(url, fetchImpl) : downloadBuffer(url, fetchImpl)),
    install: ({ buffer, assetName, bin }) =>
      installFromArchiveAsync({ buffer, assetName, bin, cacheDir, extractImpl: impls.extractImpl }),
  };
}

/**
 * Compose the gatherSecurityTools function runAnalysis expects, using real
 * provisioning + execution (or injected impls for tests). Opt-in: only downloads
 * when `provision` is true.
 *
 * @param {{rootDir: string, provision?: boolean, impls?: object, log?: (msg: string) => void}} opts
 * @returns {(projectInfo: object, absRoot: string) => Promise<{findings: Array<object>, results: Array<object>}>}
 */
export function makeSecurityToolGatherer(opts) {
  const impls = opts.impls || {};
  const execImpl = /** @type {any} */ (impls).execImpl || execFileAsync;
  return async (projectInfo, absRoot) => {
    const rootDir = absRoot || opts.rootDir;
    const io = makeRealIo(rootDir, impls);
    const candidates = selectSecurityTools(projectInfo);
    const ensure = async (toolKey) => {
      const res = await ensureTool(toolKey, { provision: Boolean(opts.provision), platform: platformTokens(), io });
      if (opts.log && res && res.provisioned) opts.log(`provisioned ${toolKey} (${res.source})`);
      if (opts.log && res && !res.available && res.reason) opts.log(`${toolKey}: ${res.reason}`);
      return res;
    };
    const run = (toolKey, toolPath) =>
      runSecurityTool(toolKey, {
        rootDir,
        toolPath,
        exec: (file, argv) =>
          execImpl(file, argv, { cwd: rootDir, timeout: 180000, maxBuffer: 32 * 1024 * 1024 }).then((r) => ({
            stdout: r.stdout || '',
          })),
      });
    return gatherSecurityToolFindings({ candidates, ensure, run });
  };
}
