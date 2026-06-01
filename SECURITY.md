# Security Policy

CSReview is a white-hat, development-time security alignment tool for local
workspaces. We take the security of the tool itself, its instructions, and the
reports it generates seriously.

## Supported Versions

Only the latest commit on the `main` branch is supported. Please update before
reporting an issue.

| Version               | Supported |
| --------------------- | --------- |
| `main` (latest)       | Yes       |
| older commits / forks | No        |

## Reporting a Vulnerability

Do not open public Issues or Pull Requests for security vulnerabilities.

Report privately through GitHub's Private Vulnerability Reporting:

1. Open the [Security tab](https://github.com/decksoftware/csreview/security) of this repository.
2. Click "Report a vulnerability".
3. Include the affected files/lines, impact, local reproduction steps, and relevant static evidence.

Avoid including real secrets, tokens, private customer data, or exploit output.
Redact sensitive values before sharing evidence.

You can expect an initial acknowledgement within 5 business days. Validated
issues are fixed on `main` and credited, unless you prefer to remain anonymous.

## Scope

In scope:

- The CSReview skill code (`csreview/src/**`) and CLI.
- Security weaknesses in generated reports, such as script injection into the
  HTML report or credential leakage in the Markdown report.
- Skill instructions (`SKILL.md`) that could steer a coding agent into unsafe
  behavior.
- Static-analysis behavior that violates the documented local-only, read-only
  scope.

Out of scope:

- Findings that CSReview reports about your own audited code. That is the tool
  working as intended, not a vulnerability in CSReview.
- Vulnerabilities in third-party scanners such as Semgrep, OSV-Scanner, npm
  audit, CodeQL, or similar tools. Report those to their upstream projects.
- Social engineering or anything requiring access to a maintainer's machine.
- Testing, probing, or calling live systems, production services, external
  application endpoints, or user data while reporting an issue here.

## Our Commitment

CSReview is read-only on audited code and never tests live, deployed, or
production systems. If you find a way it violates that guarantee, treat it as a
high-priority report.
