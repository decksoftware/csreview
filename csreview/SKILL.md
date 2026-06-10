---
name: "csreview"
description: "Development-time local workspace security alignment for codebases. Generates HTML report for humans and MD report for agents. Invoke when user requests security review, code audit, vulnerability scan, or pentest-style static analysis."
---

# CSReview - Code Security Review

## What CSReview Is

CSReview performs development-time security alignment for the local workspace a developer is actively building. It applies a penetration tester's adversarial mindset to the project's local source, configuration, dependencies, and infrastructure files (static SAST + SCA). It does NOT perform live penetration testing against running, deployed, or production systems.

It is two things working together, and the agent must keep them straight:

1. **A deterministic engine** (the `csreview` CLI). It discovers the workspace, runs and parses the external security tools, applies its own heuristic detector, deduplicates evidence across sources (promoting corroborated findings to `CONFIRMED`), scores the result, and writes ALL report files. The engine is the single writer of reports.
2. **An agent methodology** (this document + `reference/`). The agent runs the engine, then adds what tools cannot: contextual review of flagged code, framework research, remediation planning, and honest communication of confidence and limits.

CSReview's value is orchestration, corroboration, and evidence — it complements Semgrep and the other scanners; it does not replace them. Its built-in regex detector is a complementary net (secrets, misconfigurations, BaaS rules, common injection shapes), not a taint-tracking SAST.

## Scope

- **IN SCOPE**: the local development workspace/project, including all local source code, configuration, `.env` files, infrastructure-as-code, and BaaS rule files. Local SAST/SCA tools such as Semgrep, npm/pnpm package audit, OSV-Scanner, and framework-native scanners may be run against that local code only. Optional Phase 9 Local DAST is in scope only after remediation work, only with explicit user confirmation, and only against `localhost`, `127.0.0.1`, or the IPv6 loopback `[::1]`.
- **GOAL**: improve the SECURITY and EFFICIENCY (cost/performance) of the project under development.
- **OUT OF SCOPE / PROHIBITED**: testing, probing, or calling live, deployed, staging, or production systems; external service endpoints used by the app; unconfirmed dynamic testing; DAST against non-local running targets; modifying audited code; exfiltrating data.
- **Reference documentation research is ALLOWED**: reading OWASP, CWE, CVE/NVD, OSV, vendor advisories, and official framework documentation to ground remediation is allowed. That is reading documentation, not probing a target.

## Ethical Use & Attribution

CSReview is a white-hat security alignment tool (MIT License). Use it for authorized security reviews, local development hardening, education, and remediation. Do not use it to support unauthorized intrusion, exploitation, credential theft, data exfiltration, surveillance, or harm. CSReview is a Deck Software project idealized by Márcio PS, built with assistance and review from AI coding agents including Claude Code, Trae, MiniMax, Qwen, Cascade, Codex, GLM, MiMo, and other reviewer agents.

## Core Rules

These rules appear once, here, and apply everywhere:

1. **READ-ONLY**: CSReview never modifies, deletes, moves, or creates source code in the analyzed project. It identifies problems, locates them precisely, and suggests remediation. Fixes are applied later by the developer or a coding agent with project context. Report files under the output directory and the gitignored `.csreview/` tool cache are audit artifacts, not source modifications.
2. **Global Skill Installation**: CSReview is a global agent skill, loaded from the agent's global skills environment (`~/.codex/skills/csreview`, `~/.agents/skills/csreview`, `~/.trae/skills/csreview`, `~/.claude/skills/csreview`). The agent MUST NOT copy, scaffold, install, update, delete, or move the CSReview skill inside the project being audited (including `<project>/.claude/skills/`, `<project>/AGENTS.md`, `<project>/CLAUDE.md`, `.cursorrules`, `.windsurfrules`) unless the user explicitly asks for project-local installation.
3. **Single writer**: the engine writes the final reports. Subagents (when used) write only partial JSON. The agent never handcrafts report files.
4. **No fabricated metrics**: the engine does not compute ASVS coverage percentages, SLSA levels, or per-article compliance verdicts — so the agent must never state them as scan output. Compliance fields are CWE correlation (indicative), not an audited compliance verification. See `reference/compliance-frameworks.md`.
5. **Never expose secrets in chat**: hardcoded credentials found during a scan are referenced in the reports (redacted) — never echoed in the conversation.
6. **No-Findings Assurance Limit**: zero findings is not proof of security; it only means CSReview and the available tools detected nothing reportable in the analyzed scope. Reports state this; so must the agent.
7. **Honest confidence**: every claim carries its source (engine mode, tool, heuristic confidence). When uncertain, research (see External Research Protocol) or say the uncertainty out loud.

## How to Run the Engine

The CLI is the canonical execution path — never reimplement its phases by hand:

```bash
csreview <target-directory> --agent-name <agent>
csreview --doctor [target-directory]   # tool availability + freshness, no scan
csreview --version
```

Key options (run `csreview --help` for the full list):

| Option | Purpose |
| --- | --- |
| `--agent-name <name>` | Prefix report files with the coding agent name (or set `CSREVIEW_AGENT_NAME`) |
| `--output, -o <dir>` | Output directory (default `<target>/csreview-reports/`) |
| `--fail-on <severity>` | CI gate: exit 1 when findings at or above `critical\|high\|medium\|low` remain |
| `--baseline <file>` / `--update-baseline` | Suppress known findings so CI fails only on NEW ones |
| `--provision-tools` | Opt-in: run Gitleaks/Trivy/gosec/Bandit; missing ones are downloaded from OFFICIAL releases, SHA-256-verified, into gitignored `.csreview/bin/` |
| `--tool-timeout <s>` | Per-tool timeout in seconds (default 120); timeouts are reported as timeouts, not as missing tools |
| `--semgrep-config <ref>` | Use local/explicit Semgrep rules instead of `auto` (offline-friendly; adds `--metrics=off`) |
| `--local-dast-url <url>` + `--confirm-local-dast` | Phase 9 local-only dynamic complement (see below) |
| `--strict-partials` | Fail when subagent partials do not reconcile |
| `--no-update-check` | Skip the read-only, fail-open self-update advisory |

A `.csreview-ignore` file at the project root (gitignore-style globs) suppresses findings for matching paths in the report only. Unknown CLI flags are hard errors by design — a mistyped option aborts instead of silently changing what is audited.

### Engine-Orchestrated Tools

The engine invokes and parses these deterministically; their findings enter deduplication and scoring:

| Tool | Engine behavior |
|------|-----------------|
| Semgrep | **Mandatory baseline attempt** on every run: `semgrep --config auto --json --quiet <path>` (or `--semgrep-config <ref>`). If unavailable or timed out, the run is marked lower confidence with install instructions (`pipx install semgrep`). |
| Node package audit | Selected by lockfile: `pnpm audit --json` for `pnpm-lock.yaml`, `npm audit --json` for npm lockfiles, `bun audit --json` for `bun.lock`/`bun.lockb` |
| OSV-Scanner | `osv-scanner scan --format json <path>` for multi-ecosystem dependency vulnerabilities |
| Gitleaks / Trivy / gosec / Bandit | Only with `--provision-tools` (Bandit only if already installed); results corroborate the detector |
| Built-in detector | Heuristic patterns for secrets (redacted in evidence), config/IaC/BaaS misconfigurations (scoped to config-kind files), and common vulnerability shapes |
| Local DAST | Optional Phase 9 complement via `--local-dast-url`, separate reports |

### Analysis Modes

The engine reports which mode ran; the agent MUST tell the user and what it implies:

- **Mode A: Self-Hosted (RECOMMENDED)** — all relevant engine-orchestrated tools are available; parsed, reproducible findings; highest-confidence engine mode.
- **Mode B: Agent-Only (FALLBACK)** — no engine-orchestrated tool available; regex/static heuristics plus careful agent reading. Lower precision and recall; line-oriented checks miss multiline issues. Mark the run lower confidence and recommend installing Semgrep and OSV-Scanner.
- **Mode C: Hybrid (PARTIAL)** — some tools available; missing ones are disclosed in the report.

### Agent-Recommended Stack-Native Tools

Tools below are recommended for agent-assisted validation when relevant to the detected stack. They are **not parsed by the npm engine**: report their results as supplemental evidence, never silently merged into engine counts. Run a tool only if already available, already configured in the workspace, or provisioned with explicit user opt-in; do not install missing tools into the analyzed project or globally. If a relevant tool is unavailable, record it in the report as a `missing recommended tool` with the install pointer (see `reference/tooling.md` for detection, invocation, and installation commands).

#### Stack-Native Tool Recommendation Matrix

| Detected stack | Prefer read-only commands and scanners |
| --- | --- |
| JavaScript / TypeScript / React / Node | lockfile-selected package audit (engine), configured `eslint`, `eslint-plugin-security`, `eslint-plugin-react`, `eslint-plugin-react-hooks`, `typescript-eslint`, Semgrep |
| .NET / C# / ASP.NET | `dotnet format analyzers --verify-no-changes`, `dotnet list package --include-transitive --vulnerable --format json`, Roslyn analyzers, Semgrep, CodeQL when available |
| Kotlin / Android / JVM | `gradlew lint` or `./gradlew lint`, Android Lint, `detekt`, `ktlint`, Qodana, Gradle dependency checks, OSV-Scanner, Semgrep |
| Go | `go vet ./...`, `govulncheck ./...`, `gosec ./...`, `staticcheck ./...`, `golangci-lint run`, OSV-Scanner, Semgrep |
| Python | `pip-audit`, `bandit -r`, `ruff check`, `safety` when available, OSV-Scanner, Semgrep |
| Java / Spring / Maven / Gradle | Maven/Gradle dependency checks, SpotBugs/FindSecBugs when configured, Checkstyle/PMD when configured, Qodana, OSV-Scanner, Semgrep |
| Rust | `cargo audit`, `cargo deny check`, `cargo clippy --all-targets --all-features`, OSV-Scanner, Semgrep |
| PHP / Laravel / Symfony | `composer audit --format=json`, PHPStan/Psalm when configured, OSV-Scanner, Semgrep |
| Ruby / Rails | `bundle audit`, `brakeman`, RuboCop when configured, OSV-Scanner, Semgrep |
| Flutter / Dart | `dart analyze`, `flutter analyze`, `dart pub outdated --json`, OSV-Scanner, Semgrep |
| IaC / containers / CI | Checkov, Trivy, Hadolint, Dockerfile linting, GitHub Actions linting, Terraform validators, Semgrep |
| BaaS / database rules | Supabase CLI checks when configured, Firebase rules validation when configured, Appwrite/Convex/PocketBase config review, SQL linters when configured, Semgrep |

## External Research Protocol

Do not guess when framework behavior, configuration defaults, security controls, exploitability, dependency advisories, CVE details, or remediation guidance are uncertain. Consult primary or specialized sources before reporting a confident recommendation:

- official framework documentation, release notes, migration guides, and security pages
- vendor security advisory pages for the affected product, cloud service, database, BaaS, or package manager
- OWASP, CWE, CVE/NVD, GitHub Security Advisories, OSV.dev, Snyk advisories, and other specialized application security portals
- official package, API, or SDK documentation for the exact version in use

Include source names and URLs in finding references. Prefer official documentation and vendor advisories over blog posts. If sources disagree or the version cannot be confirmed, mark the finding lower confidence and explain the uncertainty.

## Execution Workflow

1. **Confirm global skill scope** (Core Rule 2) if the task involves installing or updating CSReview itself.
2. **Announce the scan** and run the engine: `csreview <dir> --agent-name <agent>` (plus `--provision-tools` when the user opted in, `--baseline` when one exists). The engine performs tool detection, the tool runs, workspace discovery, heuristic detection, deduplication, scoring, and report generation.
3. **Report the mode** (Self-Hosted / Hybrid / Agent-Only) and which tools ran, were skipped, or timed out — exactly as the engine printed them.
4. **Contextual review pass**: read the Markdown report, then inspect the flagged files and their surroundings using the checklists in `reference/security-checklists.md` (injection, auth, data leakage, BaaS rules, platform-specific surfaces, database security, Firebase cost patterns). Validate or discount engine findings with file-level context; research anything uncertain (External Research Protocol).
5. **Supply-chain and compliance correlation** when the user asked for it: use `reference/compliance-frameworks.md` (SLSA Build L3 (v1.2) checklist, OWASP ASVS 5.0.0 areas, LGPD/GDPR/SOC2/HIPAA/CCPA-CPRA) — correlation and judgment, never fabricated percentages.
6. **Vibe Coding Heuristics**: the engine attaches a `vibeRisk` flag — a static boolean heuristic marking vulnerability patterns that commonly appear in rushed or AI-assisted code. It does not prove AI authorship and is a prioritization hint, nothing more.
7. **Deliver the reports** (Report Handoff Protocol below) and a verbal summary of CRITICAL/HIGH findings, tool-detected vs heuristic-only counts, and disclosed gaps.
8. **Offer next steps**: a prioritized remediation plan, or a coding-agent session to apply selected fixes with project-context validation, then a re-run (optionally `--update-baseline` after triage, `--fail-on high` in CI).
9. **Offer Phase 9** (optional local DAST) only after remediation work.

The default report covers 8 sections: Reconnaissance, Ultra-Deep Security, Database Security, SLSA Build L3 (v1.2) Supply Chain, OWASP ASVS 5.0.0, Compliance mapping (LGPD/GDPR/SOC2/HIPAA/CCPA-CPRA — indicative correlation, not an audited compliance verification), Vibe Coding Protection, and Dual Report Generation. These are report sections, not separate executable engine phases.

## Report Handoff Protocol

After every CSReview run, the agent MUST present two explicit paths:

- **Agent name prefix**: report filenames MUST begin with the coding agent name in lowercase, for example `codex_security-report.html` and `codex_security-findings.md`. Other agents replace `codex` with their own name, such as `claude_security-report.html`. Pass `--agent-name <agent>` or set `CSREVIEW_AGENT_NAME=<agent>`.
- **MUST NOT generate generic report names**: `security-report.html`, `security-findings.md`, `csreview-report.html`, and similar agent-less names are invalid handoff names because they hide which agent produced the analysis.
- **HTML report path**: the absolute path to `csreview-reports/codex_security-report.html` (or configured output). Tell the user this is the file to open in a browser for human reading; if a browser-opening tool is available and the user asked, open it.
- **Markdown report path**: the absolute path to `csreview-reports/codex_security-findings.md`. The coding agent must analyze this file before planning any remediation — never infer findings from the verbal summary alone. For remediation work, read the Markdown report first, then inspect the referenced source files, framework documentation, schemas, tests, and security advisories before proposing changes.
- **SARIF path**: `csreview-reports/codex_security.sarif` for CI / GitHub code scanning ingestion (no raw vulnerable code embedded).

## Finding Semantics

Confidence labels (engine-emitted): `CONFIRMED` (corroborated by independent sources at the same file:line:CWE), `TOOL-ONLY` (one external tool), `HIGH`/`MEDIUM`/`LOW` (heuristic detector confidence; non-source paths such as tests/fixtures are downgraded to LOW). Exploitation text in findings is always a **Potential Exploitation Path (theoretical, unverified)** — a hypothesis derived from static analysis, not a validated or executed exploit. Full report anatomy and the canonical finding schema: `reference/reports.md`.

Severity classification:

| Severity | Criteria | Response |
|----------|----------|----------|
| **CRITICAL** | Direct data breach, RCE, auth bypass, exposed PII/secrets | Immediate fix |
| **HIGH** | Significant vulnerability, exploitable with effort | 24-48h |
| **MEDIUM** | Moderate risk, requires specific conditions | Within a week |
| **LOW** | Minor issue, defense-in-depth | Next sprint |
| **INFO** | Best-practice recommendation | Consider |

## Scatter-Gather Security Subagent Orchestration

When the agent runtime supports subagents and the workspace is large enough to justify the cost, CSReview MAY use a scatter-gather workflow; otherwise fallback to sequential analysis. The flow is: **Phase 0 + Phase 1 sequential gate** (engine run + shared project map) → **compatibility-gated fan-out** (spawn only subagents matching detected stacks) → parallel validation against cached tool output → gather barrier → reduce (`dedup -> ASVS -> compliance -> score -> report`).

### Subagent Orchestration DoD

1. **Single writer**: Subagents MUST NOT write final reports. Each writes only partial findings JSON to `csreview-reports/.partials/<subagent>.json`; the coordinator is the only writer of the final reports.
2. **Canonical finding schema**: every partial finding uses the engine finding object and sets `source: "subagent:<domain>"` — without it the engine cannot correlate evidence or promote to `CONFIRMED`.
3. **Run SAST/SCA tools once**: whole-tree tools (Semgrep, package audit, OSV-Scanner, Trivy) run only in the gate; subagents read cached tool output instead of re-executing them.

**Final check**: CSReview produces one pair of final reports, the final count matches the sum of partial findings after deduplication, and no tool appears executed more than once in the log. The engine enforces this via `partialReconciliation` (`--strict-partials` to fail hard).

### Non-negotiable rules

1. Single writer — partial JSON only; the engine/coordinator writes reports.
2. Canonical schema with `source: "subagent:<domain>"`.
3. Whole-tree tools run once, in the gate.

Full protocol and partial-file contract: `reference/subagents.md`.

## Phase 9: Optional Local DAST Complementary Report

Available only after the user or coding agent has implemented and validated remediations from the static report. It MUST NOT start automatically, and it is a conservative local HTTP probe (reachability, security headers, CORS), NOT a full penetration test.

The required user-facing prompt is: "Static remediation is complete. You can optionally run CSReview Phase 9 Local DAST in a local test environment only. Never use this against production. If the test uses a database copy, make sure the copy was made deliberately, stored in a secure local place, and sanitized or minimized where needed. This resource is for White Hat Hacker-style analysis and remediation of security flaws; it sends real HTTP requests only to localhost/127.0.0.1 and writes a complementary report. Do you want me to run it? (yes/no)"

Phase 9 may proceed only with explicit user confirmation, only for a local test environment, never production, and only against `http(s)://localhost:<port>`, `http(s)://127.0.0.1:<port>`, or `http(s)://[::1]:<port>`. The engine enforces the hard guards: redirects are never followed — if a response points to an external host, abort Phase 9 immediately; reports are written only inside `csreview-reports/` (`csreview-reports/<agent>_local-dast-report.html`, `<agent>_local-dast-findings.md`, plus run-ID history copies and the read-only `<agent>_db-dump-guide.html`).

```bash
csreview . --local-dast-url http://localhost:3000 --confirm-local-dast --agent-name codex
```

Status labels — honest semantics: the built-in probe produces `DAST-SUSPECTED` (anomalous local response requiring human review) and `DAST-CLEAN` (check passed). `DAST-CONFIRMED` is a reserved label for dynamically reproduced evidence from a dedicated local DAST tool the agent ran separately (e.g. OWASP ZAP or Nikto, only when installed, after the same pre-flight and confirmation, against the same confirmed local target) — the built-in probe never emits it. Never probe external hosts, never use destructive payloads or DELETE, and do not send mutating requests without an explicit local allowlist and confirmed data-mutation risk. Full protocol: `reference/local-dast.md`.

## Built-in Code Review Modes

CSReview includes integrated review modes (no extra skills required) — methodology in `reference/review-modes.md`:

```
@csreview                                    -> Full security audit (engine + agent passes)
@csreview review [files]                     -> Standard code review
@csreview adversarial [files]                -> Adversarial (red-team) review
@csreview security-review [files]            -> Security-focused review of changes
@csreview request-review [PR/branch/commit]  -> Review of a change set
@csreview review csreview-reports/codex_security-findings.md  -> Plan remediation from a report (CSReview never edits source)
```

## When to Invoke

- User requests a security review, code audit, vulnerability scan, or pentest-style static analysis
- User asks about exposed secrets, data leakage, SQL injection, XSS, or auth flaws
- Pre-release/deployment review of the local workspace; Supabase/Firebase/Appwrite/BaaS rule review
- Compliance correlation requests (LGPD, GDPR, SOC 2, HIPAA); vibe-coding verification of AI-written code
- Any `@csreview ...` invocation listed above

## Supported Technologies

Frontend (React, Vue, Nuxt, Angular, Svelte, Next.js), mobile (Flutter, Kotlin/Android, Swift/iOS, React Native), backend (Node.js, Python, C#/.NET, Go, Java, PHP, Ruby), systems (C, C++, Rust), desktop (Electron, Tauri), Delphi/Lazarus/Free Pascal, SQL/NoSQL databases, BaaS platforms (Supabase, Firebase, Appwrite, Neon, PocketBase, Convex, and similar), installers/DLLs/binaries, and OS-specific surfaces (macOS, iOS, Linux, Windows). Detection depth varies by stack: language-specific engine rules exist for JavaScript/TypeScript, Python, C#, Go, C/C++, and Delphi; other stacks rely on Semgrep, OSV-Scanner, and the agent checklists in `reference/security-checklists.md`.

### AI Agent Compatibility

| Agent | Integration |
|-------|-------------|
| Claude Code | Global skill via `~/.claude/skills/csreview/SKILL.md` |
| Codex | Global skill via `~/.codex/skills/csreview/SKILL.md` or `~/.agents/skills/csreview/SKILL.md` |
| Trae / SOLO | Global skill via `~/.trae/skills/csreview/SKILL.md` |
| OpenCode / Qwen CLI / Antigravity / Qoder / Cursor / Windsurf / Cline / Copilot CLI / Aider | Compatible via each agent's global rules/instructions mechanism when supported |

Regardless of agent: the HTML report is generated for the user (human review); the MD report is always English for agent consumption; behavior and report formats stay consistent.

## Output

- **Primary**: `csreview-reports/<agent>_security-report.html` — visual report for human review
- **Secondary**: `csreview-reports/<agent>_security-findings.md` — structured English report for remediation planning
- **CI**: `csreview-reports/<agent>_security.sarif` — SARIF 2.1.0 (pair with `--fail-on`)
- **Verbal**: summary of CRITICAL/HIGH findings, mode, and disclosed gaps; JSON export available from the HTML report

## Reference Index

Load these on demand; they are reference material, not standing instructions:

- `reference/security-checklists.md` — contextual review checklists (injection, auth, BaaS, platform-specific, database, Firebase cost)
- `reference/compliance-frameworks.md` — SLSA / ASVS / LGPD / GDPR / SOC 2 / HIPAA / CCPA correlation (and what the engine does NOT compute)
- `reference/tooling.md` — tool detection, read-only invocation forms, installation pointers
- `reference/subagents.md` — scatter-gather protocol detail and partial-file contract
- `reference/local-dast.md` — Phase 9 protocol detail and guard semantics
- `reference/review-modes.md` — the five review-mode methodologies
- `reference/reports.md` — actual report anatomy and the canonical finding schema
