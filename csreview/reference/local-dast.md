# CSReview Reference - Phase 9 Optional Local DAST

Full protocol for the optional, post-remediation, local-only dynamic
complement. The core rules and the required user-facing confirmation prompt
live in SKILL.md; this file holds the operational detail.

## What the built-in probe actually does

`csreview <dir> --local-dast-url <url> --confirm-local-dast` performs a
conservative, non-mutating HTTP check against the confirmed loopback target:
reachability, browser security headers (Content-Security-Policy,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy),
and CORS behavior against a hostile origin. It is **not** a penetration test,
it never follows redirects, and it aborts immediately if a response points to
an external host.

## Engine guards (enforced in code, not just documented)

- Target hostname must be `localhost`, `127.0.0.1`, or `[::1]`; anything else
  is rejected before any request.
- `--confirm-local-dast` is required; without it the run stops with the
  confirmation instructions.
- Redirects are not followed (`redirect: manual`); an external `Location`
  aborts the phase.
- Reports are written only inside `csreview-reports/`.
- An advisory pre-flight scans `.env`, `.env.local`, and `.env.development` for
  external hosts and surfaces them as `DAST-SUSPECTED` so you can verify the
  local app does not proxy probe traffic outward. It is advisory because real
  development env files almost always reference external services.

## Status labels (honest semantics)

- `DAST-SUSPECTED` — anomalous local response that requires human review.
- `DAST-CLEAN` — the checked condition passed for the local target.
- `DAST-CONFIRMED` — **reserved label, never produced by the built-in probe.**
  It may only appear when a dedicated local DAST tool (run separately by the
  agent, e.g. OWASP ZAP or Nikto against the same confirmed loopback target,
  after the same pre-flight and confirmation) dynamically reproduced an issue
  with clear evidence. If no such tool ran, no finding may carry this label.

## Outputs

- `csreview-reports/<agent>_local-dast-report.html`
- `csreview-reports/<agent>_local-dast-findings.md`
- With a run ID: timestamped history copies
  (`<agent>_local-dast-report-<runId>.html` / `...-findings-<runId>.md`) so
  re-running after remediation never overwrites prior evidence.
- `<agent>_db-dump-guide.html` — a read-only, per-backend guide for preparing
  an isolated local database copy BEFORE any database-level testing (schema-only
  dumps, synthetic users, zero real PII; never dump production).

## Hard limits

Never probe external IPs, domains, staging, or production. Never use
destructive payloads or DELETE. Do not send mutating POST/PUT/PATCH unless the
user provided an explicit local test endpoint allowlist and confirmed the data
mutation risk. If the test uses a database copy, it must be deliberately
created, stored securely, and sanitized or minimized where needed.
