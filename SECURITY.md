# Security Policy

CSReview is a white-hat, development-time security tool. We take the security of
the tool itself — and of the reports it generates — seriously.

## Supported Versions

Only the latest commit on the `main` branch is supported. Please update before
reporting an issue.

| Version              | Supported |
| -------------------- | --------- |
| `main` (latest)      | ✅        |
| older commits / forks| ❌        |

## Reporting a Vulnerability

**Please do not open public Issues or Pull Requests for security vulnerabilities.**

Report privately through GitHub's **Private Vulnerability Reporting**:

1. Open the [Security tab](https://github.com/decksoftware/csreview/security) of this repository.
2. Click **"Report a vulnerability"**.
3. Include the affected files/lines, the impact, and a reproduction if possible.

You can expect an initial acknowledgement within **5 business days**. Validated
issues are fixed on `main` and credited, unless you prefer to remain anonymous.

## Scope

**In scope**
- The CSReview skill code (`csreview/src/**`) and the CLI.
- Security weaknesses in the **generated reports** — e.g., script injection into the
  HTML report, or secret/credential leakage in the Markdown report.
- The skill instructions (`SKILL.md`) where they could steer a coding agent into
  unsafe behavior.

**Out of scope**
- Findings that CSReview reports about *your own* audited code — that is the tool
  working as intended, not a vulnerability in CSReview.
- Vulnerabilities in third-party scanners (Semgrep, OSV-Scanner, npm audit, etc.) —
  please report those to their respective upstream projects.
- Social engineering, or anything requiring access to a maintainer's machine.

## Our Commitment

CSReview is **read-only** on audited code and never tests live, deployed, or
production systems. If you find a way it violates that guarantee, treat it as a
high-priority report.
