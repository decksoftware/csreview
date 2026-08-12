# Finding Integrity and Reporting Design

**Status:** Approved

**Date:** 2026-08-12

## Purpose

Make the canonical finding set a trusted security boundary. No scanner, partial file, repository content, or subagent may forge derived evidence, leak secrets, create an unsafe report link, or promote an unrelated finding to `CONFIRMED`.

## Canonical ingress boundary

All detector, OpenGrep, SCA, stack-native tool, and subagent output passes through `src/findingPolicy.js` before deduplication:

```js
normalizeFinding(raw, { rootDir, source, ingress })
// -> { ok, finding, errors, warnings }
```

Adapters provide `source`; incoming objects cannot choose trusted provenance. The boundary accepts only documented raw fields and constructs all derived fields itself.

The canonical finding includes:

- stable `id`, `source`, and optional `ruleId` or `advisoryId`;
- `name`, `category`, `severity`, `confidence`, and `description`;
- root-relative POSIX `file` and integer `line >= 1`;
- canonical CWE values;
- remediation and evidence text within documented size limits;
- normalized references;
- derived `contextHash`, `evidenceId`, and semantic attributes when available.

Severity is normalized to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`; known aliases such as `MODERATE` map to `MEDIUM`; unknown values are rejected. Confidence is normalized to the documented set. Partials may use only `subagent:<domain>` provenance and heuristic `HIGH`, `MEDIUM`, or `LOW` confidence.

Fields such as `sources`, `evidence`, `duplicateCount`, `correlationId`, and `CONFIRMED` are always stripped from raw input and derived internally. A partial that attempts to set trusted fields is rejected in strict mode and excluded with a visible diagnostic otherwise.

Absolute paths inside the target become root-relative paths. Traversal, drive changes, UNC escapes, and absolute paths outside the target are rejected. Path comparison is case-normalized only on case-insensitive platforms while report display preserves a stable project-relative form.

## Central redaction

`src/redaction.js` provides the single secret scrubber used by every adapter, the final finding boundary, DAST evidence, and report exporters. It covers provider keys, bearer/basic authorization, cookies/session identifiers, private keys, connection strings with credentials, passwords with symbols, common cloud tokens, and high-entropy assignments.

All string fields are scrubbed before persistence, including `vulnerableCode`, descriptions, exploitation text, fixes, references, tool diagnostics, commands, URLs, and embedded JSON. The redactor preserves enough type and suffix information for remediation but never the complete secret.

Report generators remain defensive: they escape their output context and never accept an unsanitized finding. SARIF continues to omit source snippets by default.

## Safe references

`safeReference(value)` parses references. Only `http:` and `https:` receive clickable links. Credentials are removed and sensitive query values and fragments are redacted. `javascript:`, `data:`, `file:`, invalid values, and arbitrary strings render as escaped text without `href`.

CWE links are constructed only from validated numeric CWE identifiers. OWASP links are selected from an explicit year/category table; an unknown mapping links only to the official generic landing page.

## Evidence deduplication and correlation

`src/correlation.js` separates exact duplication from semantic corroboration:

```js
deduplicateEvidence(findings)
correlateFindings(findings)
```

An exact evidence identity is based on source family, rule/advisory ID, canonical path, context hash, and relevant symbol or sink. Duplicate emissions from the same engine collapse without increasing trust.

Correlation uses canonical path, vulnerability class, sink/symbol, rule family, and context hash. Line number is location evidence, not sufficient identity. Two different XSS mechanisms on the same line and CWE remain separate.

`CONFIRMED` requires at least two independent source families describing the same semantic issue. A subagent paraphrasing an OpenGrep result is not automatically independent. The output stores the individual evidence records and derives sorted `sources`; it never infers confirmation merely from `sources.length > 1`.

## Honest compliance correlation

Reports replace compliance verdicts with correlations:

```js
{
  framework: 'OWASP_TOP10_2021' | 'ASVS_5.0.0' | 'GDPR' | 'LGPD',
  control: '...',
  status: 'RELATED' | 'NOT_EVALUATED',
  basis: 'CWE correlation'
}
```

OWASP Top 10 and ASVS are separate sections. An observed mapping is `RELATED`; absence of a finding is `NOT_EVALUATED`, never `PASS`. GDPR and LGPD entries appear only when an explicit maintained map supports the relationship. Every report states that this is indicative evidence, not an audited legal or compliance assessment.

## Integration point

`runAnalysis()` becomes orchestration only:

1. collect raw outputs;
2. normalize and sanitize every item;
3. deduplicate exact evidence;
4. correlate semantic evidence;
5. apply ignore and baseline policies;
6. compute assessment and risk views;
7. generate reports from canonical data only.

Malformed optional findings produce visible source diagnostics. A failure of the canonicalization boundary itself is a core failure and produces assessment status `FAILED` rather than silently dropping the entire source.

## Verification

- Lowercase severity is normalized; an unknown enum is rejected.
- Absolute and relative forms of the same in-target path correlate; traversal and out-of-root paths do not enter reports.
- A partial containing forged `sources`, `CONFIRMED`, or detector provenance cannot raise confidence.
- Same-line/same-CWE findings with different rules or sinks remain distinct.
- Equivalent evidence from two independent source families becomes `CONFIRMED`.
- Representative API keys, bearer tokens, cookies, connection strings, and symbol-heavy passwords are absent from HTML, Markdown, SARIF, embedded JSON, and CLI diagnostics.
- Unsafe URI schemes never become clickable.
- Reports contain no compliance `PASS` or `FAIL` verdict and keep Top 10 separate from ASVS.

