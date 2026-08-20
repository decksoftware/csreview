# OpenGrep Primary SAST Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every active Semgrep integration with a reproducible, offline OpenGrep 1.26.0 primary SAST engine and make the CLI, reports, package, documentation, and CI tell the same truth.

**Architecture:** A focused `src/opengrep.js` module owns the approved artifact table, private-cache validation/provisioning, local-config validation, argument construction, execution, diagnostics, and finding normalization. `src/index.js` consumes that adapter through an injectable runner, while the existing package-audit and OSV paths remain unchanged. A small CSReview-owned MIT rulepack ships in `rules/`; all public surfaces use the `opengrep` result key and `--opengrep-config` without a Semgrep compatibility alias.

**Tech Stack:** Node.js ESM (Node >=18), `node:test`, OpenGrep 1.26.0 JSON output, YAML rulepack, GitHub Actions.

## Global Constraints

- OpenGrep version is exactly `1.26.0`; only the platform artifacts and SHA-256 digests in `2026-08-12-opengrep-supply-chain-design.md` are trusted.
- Default rules are local and bundled; `auto`, registry identifiers, URLs, autofix, local builds, and untrusted validators are forbidden.
- Downloads require `--provision-tools`, official allowlisted HTTPS hosts, bounded responses, manual redirect validation, and digest verification.
- The cache is outside the audited target and uses `<tool>/<version>/<sha256>/`; target-local `.csreview/bin` is ignored.
- No compatibility alias, option, source id, install instruction, supported-tool claim, report label, or workflow for Semgrep remains in active source, tests, package metadata, user documentation, or workflows.
- All process execution uses absolute paths and `execFile` without a shell; OpenGrep receives a minimal environment and bounded timeout/output buffers.

---

### Task 1: OpenGrep artifact policy and private cache

**Files:**
- Create: `csreview/src/opengrep.js`
- Create: `csreview/test/opengrep.test.js`
- Modify: `csreview/src/provisionRuntime.js`

**Interfaces:**
- Produces: `OPENGREP_VERSION`, `OPENGREP_ARTIFACTS`, `getPrivateToolCacheRoot(options)`, `selectOpenGrepArtifact(options)`, `findExecutableOnPath(bin, env)`, `validateTrustedOpenGrep(path, options)`, `provisionOpenGrep(options)`, and `resolveOpenGrep(options)`.
- Consumes: `assertOfficialUrl()` from `src/provision.js` and the redirect-safe bounded download helper exported from `src/provisionRuntime.js`.
- `resolveOpenGrep()` returns `{available, path, version, source, reason, legacyCacheIgnored}` and never returns a path inside `targetRoot`.

- [ ] **Step 1: Write failing private-cache and artifact tests**

```js
test('selectOpenGrepArtifact returns the approved Windows x64 digest', () => {
  assert.equal(selectOpenGrepArtifact({ platform: 'win32', arch: 'x64' }).sha256,
    '4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3');
});

test('resolveOpenGrep ignores target-local legacy binaries', async () => {
  const result = await resolveOpenGrep({ targetRoot, provision: false, env: { PATH: '' }, cacheRoot });
  assert.equal(result.available, false);
  assert.equal(result.legacyCacheIgnored, true);
});

test('validateTrustedOpenGrep rejects symlinks, paths inside target, invalid manifests, and changed hashes', async () => {
  for (const fixture of [symlinkFixture, insideTargetFixture, badManifestFixture, changedBinaryFixture]) {
    const result = await validateTrustedOpenGrep(fixture.path, fixture.options);
    assert.equal(result.available, false);
  }
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `node --test test/opengrep.test.js`

Expected: FAIL because `src/opengrep.js` does not exist.

- [ ] **Step 3: Implement the artifact table and cache validation**

Implement the seven approved platform entries, platform/libc selection, private cache root resolution, PATH traversal without a shell, `lstat`/`realpath` containment checks, manifest schema validation, version parsing, and pre-execution SHA-256 recomputation. Export `fetchOfficialFollowing` from `provisionRuntime.js` so OpenGrep provisioning reuses the existing redirect allowlist.

- [ ] **Step 4: Add failing provisioning tests**

```js
test('provisionOpenGrep installs atomically only after both hash checks', async () => {
  const result = await provisionOpenGrep({ targetRoot, cacheRoot, artifact, download: fakeDownload });
  assert.equal(result.available, true);
  assert.equal(result.source, 'provisioned');
  assert.equal(JSON.parse(readFileSync(result.manifestPath, 'utf8')).sha256, artifact.sha256);
});

test('provisionOpenGrep refuses wrong hashes and non-official redirects', async () => {
  assert.equal((await provisionOpenGrep({ ...base, download: wrongBytes })).available, false);
  await assert.rejects(() => fetchOfficialFollowing(redirectingUrl, hostileFetch), /non-official host/i);
});
```

- [ ] **Step 5: Verify RED, implement opt-in atomic provisioning, then verify GREEN**

Run RED and GREEN: `node --test test/opengrep.test.js`

The minimal implementation writes into a private temporary directory, enforces the artifact size ceiling, hashes before and after the atomic move, writes a strict JSON manifest, and applies executable permissions only after final validation.

- [ ] **Step 6: Commit the cache boundary**

```text
git add csreview/src/opengrep.js csreview/src/provisionRuntime.js csreview/test/opengrep.test.js
git commit -m "feat: add trusted OpenGrep artifact cache"
```

### Task 2: Offline adapter and CSReview rulepack

**Files:**
- Modify: `csreview/src/opengrep.js`
- Modify: `csreview/test/opengrep.test.js`
- Create: `csreview/rules/csreview.yml`
- Create: `csreview/rules/manifest.json`
- Create: `csreview/rules/NOTICE.md`
- Create: `csreview/rules/LICENSES/MIT.txt`
- Create: `csreview/test/fixtures/opengrep/positive/javascript-eval.js`
- Create: `csreview/test/fixtures/opengrep/negative/javascript-eval.js`
- Create: `csreview/test/fixtures/opengrep/positive/python-pickle.py`
- Create: `csreview/test/fixtures/opengrep/negative/python-pickle.py`

**Interfaces:**
- Produces: `validateOpenGrepConfig(value, options)`, `openGrepExcludeArgs(dirs)`, `buildOpenGrepArgs(targetRoot, options)`, `normalizeOpenGrepFinding(result, index)`, and `runOpenGrep(targetRoot, options)`.
- `runOpenGrep()` returns `{available, required: true, version, error, diagnostic, findings, rawCount, source}`.

- [ ] **Step 1: Write failing adapter contract tests**

```js
test('buildOpenGrepArgs is offline, version-check-free, and uses bundled rules', () => {
  const args = buildOpenGrepArgs('/target', { rulepackPath: '/package/rules' });
  assert.deepEqual(args.slice(0, 6), ['scan', '--config', '/package/rules', '--json', '--quiet', '--disable-version-check']);
  assert.ok(!args.includes('auto'));
});

test('validateOpenGrepConfig rejects URLs, auto, and registry identifiers before execution', () => {
  for (const value of ['auto', 'p/security-audit', 'https://example.test/rules.yml']) {
    assert.throws(() => validateOpenGrepConfig(value, { cwd: fixtureRoot }), /local file or directory/i);
  }
});

test('normalizeOpenGrepFinding emits opengrep source and stable ids', () => {
  const finding = normalizeOpenGrepFinding(openGrepJson.results[0], 0);
  assert.equal(finding.source, 'opengrep');
  assert.match(finding.id, /^OPENGREP_/);
});
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `node --test test/opengrep.test.js`

Expected: FAIL because the adapter exports are missing.

- [ ] **Step 3: Implement local config validation, args, diagnostics, and normalization**

Use the bundled rule directory by default; append a second `--config` only for an existing local file/directory. Execute the absolute validated binary with `execFile`, `cwd: targetRoot`, a minimal `PATH`/locale environment, the configured timeout, and a 20 MiB output cap. Classify timeout, malformed JSON, nonzero exit, rule errors, and partial skips separately.

- [ ] **Step 4: Add the original MIT rulepack and fixture assertions**

Create stable rules `csreview.javascript.security.eval-detected` and `csreview.python.security.pickle-loads` with positive/negative fixtures. Record them as CSReview-native MIT rules in `manifest.json`, including source/transformed SHA-256 hashes. Add an integration test that normalizes representative OpenGrep JSON and a scriptable validation command that runs `opengrep scan --validate --config rules/csreview.yml` when `CSREVIEW_OPENGREP_BIN` is provided.

- [ ] **Step 5: Verify adapter and rulepack GREEN**

Run: `node --test test/opengrep.test.js`

Run with trusted development binary: `$env:CSREVIEW_OPENGREP_BIN='<verified-path>'; node --test test/opengrep.test.js`

- [ ] **Step 6: Commit the adapter and rulepack**

```text
git add csreview/src/opengrep.js csreview/rules csreview/test/opengrep.test.js csreview/test/fixtures/opengrep
git commit -m "feat: add offline OpenGrep adapter and rules"
```

### Task 3: Engine and CLI integration without compatibility aliases

**Files:**
- Modify: `csreview/src/index.js`
- Modify: `csreview/src/cliArgs.js`
- Modify: `csreview/src/cli.js`
- Modify: `csreview/test/analysis.test.js`
- Modify: `csreview/test/cli-args.test.js`
- Replace: `csreview/test/tool-env.test.js` with OpenGrep argument/config tests in `csreview/test/opengrep.test.js`

**Interfaces:**
- `parseCliArgs()` produces `opengrepConfig` and rejects `--semgrep-config` as unknown.
- `runAnalysis()` accepts `opengrepConfig`, `provisionTools`, and optional `runOpenGrepImpl` for deterministic tests.
- `ToolResults` exposes `opengrep`; `semgrep` is absent.

- [ ] **Step 1: Change tests first to the public OpenGrep contract**

```js
test('parseCliArgs exposes only --opengrep-config', () => {
  assert.equal(parseCliArgs(['.', '--opengrep-config', './rules']).opengrepConfig, './rules');
  assert.throws(() => parseCliArgs(['.', '--semgrep-config', './rules']), /Unknown option/);
});

test('runAnalysis consumes OpenGrep findings as the required primary SAST source', async () => {
  const result = await runAnalysis(root, { runOpenGrepImpl: fakeOpenGrep });
  assert.equal(result.toolResults.opengrep.available, true);
  assert.equal(result.findings[0].source, 'opengrep');
  assert.equal('semgrep' in result.toolResults, false);
});
```

- [ ] **Step 2: Run CLI/analysis tests and verify RED**

Run: `node --test test/cli-args.test.js test/analysis.test.js`

- [ ] **Step 3: Integrate the adapter and remove old Semgrep code**

Delete `withToolEnv`, `semgrepExcludeArgs`, `buildSemgrepArgs`, `normalizeSemgrepFinding`, and `runSemgrep` from `index.js`. Import `runOpenGrep`, use `opengrep` in mode classification, deduplication, partial whole-tree tool names, doctor output, scan summary, options, and CLI help. Pass `provisionTools` into OpenGrep resolution; retain current opt-in stack-native gatherer behavior.

- [ ] **Step 4: Verify GREEN and commit**

Run: `node --test test/cli-args.test.js test/analysis.test.js test/opengrep.test.js`

```text
git add csreview/src/index.js csreview/src/cli.js csreview/src/cliArgs.js csreview/test
git commit -m "feat: make OpenGrep the primary SAST engine"
```

### Task 4: Reports, metadata, and freshness

**Files:**
- Modify: `csreview/src/reports/html.js`
- Modify: `csreview/src/reports/markdown.js`
- Modify: `csreview/src/reports/summary.js`
- Modify: `csreview/src/toolFreshness.js`
- Modify: `csreview/test/reports.test.js`
- Modify: `csreview/test/summary.test.js`
- Modify: `csreview/test/preflight.test.js`
- Modify: `csreview/package.json`
- Modify: `csreview/package-lock.json`
- Create: `csreview/LICENSE`

**Interfaces:**
- Reports read `toolResults.opengrep`, label source `opengrep` as `OpenGrep`, and give `--provision-tools` remediation.
- Package metadata declares OpenGrep 1.26.0 as the required external tool and includes `rules/`, `LICENSE`, and notices in the tarball.

- [ ] **Step 1: Update report/package tests first and verify RED**

Assert `OpenGrep 1.26.0`, `source: opengrep`, required tool metadata, `rules/` in package files, and absence of a `semgrep` keyword/tool entry.

Run: `node --test test/reports.test.js test/summary.test.js test/preflight.test.js test/analysis.test.js`

- [ ] **Step 2: Implement report and metadata changes**

Replace report labels/status/install guidance, origin labels, freshness lookup (`github: opengrep/opengrep`, bundled rule data), and package keywords/tool metadata. Copy the repository MIT license into the package and update the lockfile deterministically with `npm install --package-lock-only --ignore-scripts`.

- [ ] **Step 3: Verify GREEN and package contents**

Run: `node --test test/reports.test.js test/summary.test.js test/preflight.test.js test/analysis.test.js`

Run: `npm pack --dry-run`

- [ ] **Step 4: Commit reports and distribution metadata**

```text
git add csreview/src/reports csreview/src/toolFreshness.js csreview/test csreview/package.json csreview/package-lock.json csreview/LICENSE
git commit -m "docs: expose OpenGrep in reports and package metadata"
```

### Task 5: CI supply chain and user documentation

**Files:**
- Modify: `.github/workflows/ci.yml`
- Delete: `.github/workflows/semgrep.yml`
- Create: `.github/workflows/opengrep.yml`
- Modify: `README.md`
- Modify: `csreview/SKILL.md`
- Modify: `csreview/reference/tooling.md`
- Modify: `csreview/reference/reports.md`
- Modify: `csreview/reference/subagents.md`
- Modify: `csreview/docs/security-first-provisioning-design.md`
- Modify: `csreview/test/analysis.test.js`

**Interfaces:**
- CI downloads the pinned Linux x64 OpenGrep 1.26.0 artifact, verifies `40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26`, validates the bundled rulepack, fails on scanner failure, and uploads SARIF only from a successful run.
- README's mirrored SKILL block remains byte-equivalent to `csreview/SKILL.md`.

- [ ] **Step 1: Add the failing repository-wide migration assertion**

```js
test('active product surfaces contain no Semgrep integration after migration', () => {
  const active = readActiveProductFilesExcludingImmutableSpecsAndAttribution();
  assert.doesNotMatch(active, /semgrep/i);
  assert.match(active, /opengrep/i);
});
```

- [ ] **Step 2: Run the assertion and verify RED**

Run: `node --test test/analysis.test.js`

- [ ] **Step 3: Replace workflows and documentation**

Use full commit SHAs for `actions/checkout`, `actions/setup-node`, and `github/codeql-action/upload-sarif`. Rename the workflow/job/artifact to OpenGrep, remove `continue-on-error`, use the bundled rules, and verify the binary digest before scanning. Update all active docs to OpenGrep, its offline rulepack, private cache, `--opengrep-config`, and opt-in provisioning. Regenerate the README mirror from the final `SKILL.md` content exactly.

- [ ] **Step 4: Verify migration assertion and docs contracts GREEN**

Run: `node --test test/analysis.test.js`

Run: `rg -n -i "semgrep" README.md csreview/src csreview/test csreview/SKILL.md csreview/reference csreview/package.json .github/workflows`

Expected: no matches.

- [ ] **Step 5: Commit CI and documentation**

```text
git add .github/workflows README.md csreview/SKILL.md csreview/reference csreview/docs csreview/test/analysis.test.js
git commit -m "ci: replace Semgrep with pinned OpenGrep"
```

### Task 6: End-to-end verification and main integration

**Files:**
- Review only: all files changed by Tasks 1-5

**Interfaces:**
- Produces a clean verified commit series ready for `main`.

- [ ] **Step 1: Run the complete verification suite**

Run: `npm test`

Run: `npm run lint`

Run: `npm run typecheck`

Run: `npm pack --dry-run`

Run: `git diff --check main...HEAD`

- [ ] **Step 2: Validate the trusted local OpenGrep artifact and rulepack**

Compute SHA-256 before execution and require the Windows x64 approved digest. Then run `opengrep scan --validate --config rules/csreview.yml` and scan the positive/negative fixtures with network unavailable.

- [ ] **Step 3: Audit requirements line by line**

Confirm: no target-local execution; no remote configs; no auto registry; cache containment and manifest checks; correct public CLI; OpenGrep in reports; rulepack and notices in tarball; pinned CI; zero active Semgrep references.

- [ ] **Step 4: Integrate and push**

Fast-forward or merge the verified feature branch into `main`, confirm `HEAD == origin/main` after `git push origin main`, and leave unrelated untracked `graphify-out/` content untouched.
