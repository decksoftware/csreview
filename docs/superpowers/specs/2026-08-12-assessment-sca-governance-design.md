# Assessment, Recursive SCA, Baseline, and Ignore Design

**Status:** Approved

**Date:** 2026-08-12

## Purpose

Prevent incomplete tool coverage from appearing clean, cover monorepo dependencies recursively, and ensure suppression does not erase known risk or create a denial-of-service path.

## Assessment contract

Every run returns an assessment object:

```js
{
  status: 'COMPLETE' | 'PARTIAL' | 'FAILED',
  requiredTools: [],
  missingTools: [],
  failedTools: [],
  coverage: [],
  diagnostics: []
}
```

Tool relevance is derived from the discovered project:

- OpenGrep is always required.
- OSV-Scanner is required when supported dependency manifests or lockfiles are discovered.
- Every discovered Node lockfile creates an applicable package-audit requirement.
- Optional Gitleaks, Trivy, gosec, and Bandit affect status only when explicitly named by `--require-tools`.

`COMPLETE` means every applicable required tool completed, returned parseable output, and covered its planned scope. Zero findings is meaningful only in this state.

`PARTIAL` means the core produced reports but at least one required tool was missing, timed out, failed, returned invalid output, skipped planned work, or exceeded a safety limit. A partial report states what was observed but does not display a security score as authoritative.

`FAILED` means project discovery, canonical finding validation, assessment construction, or report persistence failed such that no trustworthy assessment artifact can be produced.

The return value uses `score: null` unless status is `COMPLETE`. It may expose clearly labeled observed counts, but the HTML/Markdown headline reads “Not rated — coverage incomplete” for `PARTIAL` and “Assessment failed” for `FAILED`.

## CLI gates

`--require-tools <comma-separated>` accepts `opengrep`, `osv-scanner`, `package-audit`, `gitleaks`, `trivy`, `gosec`, and `bandit`. Unknown names are hard errors.

An explicitly required tool that is not applicable to the discovered stack is an unmet requirement with a `not_applicable` diagnostic. This prevents a misspelled or inappropriate CI policy from appearing satisfied without executing anything.

- A normal local run writes and displays a partial report without claiming success.
- `--fail-on <severity>` fails when the threshold is reached or the assessment is not `COMPLETE`.
- `--require-tools` fails when any named tool is unavailable or failed, independent of finding count.
- Reports are written before a finding or coverage gate changes the exit status.
- CLI output never prints “No vulnerabilities detected” for a partial run. It prints “No reportable findings observed in the completed checks; assessment incomplete.”

All nonfatal gates preserve exit code `1` for compatibility. Fatal exceptions also exit `1`; the fatal message and, when report persistence is still possible, the assessment artifact distinguish the cause.

## Recursive SCA plan

`src/sca.js` builds an immutable audit plan from discovered dependency files. Each unique lockfile is associated with its nearest manifest, manager, working directory, and workspace coverage. Shared monorepo lockfiles are executed once; independent nested lockfiles are executed separately.

Supported Node plans are:

- `package-lock.json` or `npm-shrinkwrap.json` -> `npm audit --json` in that lockfile directory;
- `pnpm-lock.yaml` -> `pnpm audit --json` in that lockfile directory;
- `bun.lock` or `bun.lockb` -> `bun audit --json` in that lockfile directory.

All planned audits run with bounded concurrency, independent timeout/output limits, minimal environment, and per-plan results. One failed workspace makes the aggregate package-audit coverage partial; successful workspace findings remain available. The aggregate preserves `plans`, `completed`, `failed`, `rawCount`, and normalized findings instead of presenting a single root-only tool result.

OSV runs `osv-scanner scan -r --format json <target>`. Its result records recursive coverage. The normalizer reads `database_specific.cwe_ids`, aliases, advisory references, affected package paths, and ecosystem metadata.

`src/cvss.js` parses supported CVSS v3.0/v3.1 vectors and classifies their base score using the published thresholds. A numeric database severity is preferred when authoritative. The string `CVSS_V3` is never treated as a severity. Unsupported vectors remain `INFO` with a diagnostic rather than being guessed.

Npm audit emits one canonical finding per advisory. Multiple `via` advisories for the same package remain independently attributable and may later correlate.

## Risk views and baseline v2

Risk is calculated twice only for `COMPLETE` assessments:

- `totalRiskScore` uses all canonical, non-generated findings, including accepted/baselined debt;
- `newRiskScore` uses findings not matched by the baseline and supports change gates.

The report headline is total risk. Baseline use cannot improve it; the report separately shows new findings and accepted debt.

Baseline v2 entries contain a SHA-256 fingerprint over canonical path, rule/advisory identity or vulnerability class, symbol/sink, and context hash. Line numbers are display metadata rather than identity so a harmless line shift does not invalidate an entry. Two occurrences of the same class in one file produce different fingerprints.

Snapshot entries written by `--update-baseline` include version, creation time, source assessment status, and canonical evidence metadata. A baseline can be updated only from a `COMPLETE` assessment. Formal exception entries additionally require reason, author, and expiry. Expired exceptions return to the new-finding set.

Baseline v1 is readable for migration. A legacy fingerprint suppresses a current finding only when it maps unambiguously to exactly one occurrence. Ambiguous legacy matches suppress nothing and emit a migration warning.

## Safe and governed ignore matching

Dynamic regular expressions are replaced by a bounded glob matcher with deterministic `O(pattern length * path length)` behavior for `*`, `**`, `?`, directory rules, negation, and last-match-wins. Limits are 256 project patterns, 256 characters per pattern, and 4096 characters per normalized path. Invalid or excess project entries are ignored with diagnostics rather than blocking the scan.

Built-in generated/cache exclusions remain engine policy and cannot be negated by the audited project. Project `.csreview-ignore` entries are separate suppressions and their source, count, and matched findings are reported.

Local runs apply project ignores. In CI, project-owned ignore rules require `--allow-project-ignore`; otherwise they are reported but not applied. An explicitly supplied `--ignore-file <path>` is accepted when it resolves outside the audited target, enabling centrally governed CI policy.

Security debt should normally use baseline v2 exceptions rather than broad path ignores.

## Verification

- A repository with only `apps/a/package-lock.json` produces an npm audit plan.
- Independent nested npm, pnpm, and bun locks all run in their own directories; a shared lock runs once.
- One failed plan yields `PARTIAL` while retaining successful findings and coverage diagnostics.
- OSV receives `scan -r` and maps CVSS vectors and `database_specific.cwe_ids` correctly.
- Multiple npm `via` advisories are not discarded.
- Missing OpenGrep, applicable OSV, or an applicable package audit prevents `COMPLETE`.
- `--fail-on` cannot pass an incomplete assessment with zero findings.
- A baseline cannot be written from a partial run; known debt remains in total risk.
- Two same-class occurrences in one file have distinct v2 fingerprints; line shifts retain identity.
- An ambiguous v1 baseline suppresses nothing.
- The adversarial `*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b` glob completes within a deterministic small bound.
- Project ignore is inert in CI without explicit opt-in.
