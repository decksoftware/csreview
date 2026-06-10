# CSReview Reference - What the Engine Reports Actually Contain

The engine writes every report deterministically. The agent never handcrafts
report files and never invents metrics that the engine does not compute. In
particular there is **no** "ASVS coverage %", "SLSA level", or per-article
compliance PASS/FAIL anywhere in the generated reports — see
`reference/compliance-frameworks.md` for what compliance correlation means.

## HTML report (`<agent>_security-report.html`)

For human review, generated in a self-contained file: executive summary with
the 0-100 score (severity-capped: any CRITICAL caps it at 49, any HIGH at 74),
severity and category charts, findings-by-origin breakdown (which tool reported
what, corroborated findings first), tool execution status (which engine tools
ran, versions, raw counts), filterable finding cards (severity, category, file
search), per-finding metadata (CWE link, OWASP category, confidence, compliance
correlation, vibe-risk flag, redacted evidence snippet, theoretical
exploitation hypothesis, remediation guidance, references), and an "Export as
JSON" button. Secrets are redacted before rendering; all dynamic content is
HTML-escaped.

## Markdown report (`<agent>_security-findings.md`)

For coding agents (always English). Actual sections emitted by the engine:

1. **Executive Summary** — score, totals by severity, mode, tool status
2. **Findings Index** — table of every finding with file:line
3. **Detailed Findings** — full canonical finding objects
4. **Category Analysis** — counts and highlights per category
5. **Compliance Impact** — CWE-correlated framework references (indicative)
6. **Fix Priority Order** — Immediate (CRITICAL) → Short-term (HIGH) →
   Medium-term (MEDIUM) → Low Priority (LOW/INFO)
7. **Remediation Guidance** — per-finding guidance, never an exact patch to
   apply blindly
8. **Scan Metadata** — timestamps, file counts, tool versions, suppression and
   baseline counts

## SARIF report (`<agent>_security.sarif`)

SARIF 2.1.0 for CI and GitHub code scanning. It never embeds raw vulnerable
code, so secrets are not leaked into uploaded artifacts. Pair it with
`--fail-on <severity>` to gate merges.

## Canonical finding schema

Exchanged by the detector, tool normalizers, subagent partials, and all report
generators:

```json
{
  "id": "SQL_INJECTION_src-auth-ts_45",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "Injection",
  "name": "...",
  "description": "...",
  "file": "src/auth.ts",
  "line": 45,
  "vulnerableCode": "redacted/snippet",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "fix": "...",
  "confidence": "CONFIRMED|TOOL-ONLY|HIGH|MEDIUM|LOW",
  "exploitation": "theoretical hypothesis, never a validated exploit",
  "references": ["https://..."],
  "source": "csreview-detector|semgrep|npm-audit|pnpm-audit|bun-audit|osv-scanner|gitleaks|trivy|gosec|bandit|subagent:<domain>",
  "vibeRisk": false,
  "compliance": "OWASP ASVS V5.3, GDPR Art.32 (CWE correlation)"
}
```

Confidence semantics: `CONFIRMED` = corroborated by more than one independent
source (e.g. detector + Semgrep at the same file:line:CWE); `TOOL-ONLY` = one
external tool; `HIGH|MEDIUM|LOW` = heuristic detector confidence. Findings in
test/fixture/example paths are downgraded to LOW instead of hidden.
