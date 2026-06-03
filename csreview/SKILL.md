---
name: "csreview"
description: "Development-time local workspace security alignment for codebases. Generates HTML report for humans and MD report for agents. Invoke when user requests security review, code audit, vulnerability scan, or pentest-style static analysis."
---

# CSReview - Code Security Review

## Overview

This skill performs development-time security alignment for the local workspace a developer is actively building. It applies a penetration tester's adversarial mindset to the project's local source, configuration, dependencies, and infrastructure files (static SAST + SCA). It does NOT perform live penetration testing against running, deployed, or production systems. It identifies vulnerabilities, data leakage risks, misconfigurations, and security flaws, then generates:

## Scope

- **IN SCOPE**: the local development workspace/project, including all local source code, configuration, `.env` files, infrastructure-as-code, and BaaS rule files. Local SAST/SCA tools such as Semgrep, npm/pnpm package audit, OSV-Scanner, and framework-native scanners may be run against that local code only. Optional Phase 9 Local DAST is in scope only after remediation work, only with explicit user confirmation, and only against `localhost`, `127.0.0.1`, or the IPv6 loopback `[::1]`.
- **GOAL**: improve the SECURITY and EFFICIENCY (cost/performance) of the project under development.
- **OUT OF SCOPE / PROHIBITED**: testing, probing, or calling live, deployed, staging, or production systems; external service endpoints used by the app; unconfirmed dynamic testing; DAST against non-local running targets; modifying audited code; exfiltrating data.
- **Reference documentation research is ALLOWED**: reading OWASP, CWE, CVE/NVD, OSV, vendor advisories, and official framework documentation to ground remediation is allowed. That is reading documentation, not probing a target.

## Ethical Use & Attribution

CSReview is a white-hat security alignment tool. You may copy, fork, adapt, and replicate it under the MIT License, but the project asks that it be used for good: authorized security reviews, local development hardening, education, and remediation work in the spirit of an ethical hacker / White Hat Hacker. Do not use CSReview to support unauthorized intrusion, exploitation, credential theft, data exfiltration, surveillance, or harm.

Credit should be preserved where practical: CSReview is a Deck Software project idealized by Márcio PS, built with assistance, review, and ideas from AI coding agents and tools including Claude Code, Trae, MiniMax, Qwen, Cascade da Windsurf, Codex, GLM 5.1, MiMo V2.5 Pro, and other reviewer agents.

1. **HTML Report** (`csreview-reports/<agent>_security-report.html`) - Visual report for human review with executive summary, charts, and detailed findings
2. **Markdown Report** (`csreview-reports/<agent>_security-findings.md`) - Structured report for humans and coding agents to understand, prioritize, and plan remediations without CSReview modifying the audited code
3. **SARIF Report** (`csreview-reports/<agent>_security.sarif`) - SARIF 2.1.0 for CI pipelines and GitHub code scanning ingestion. It never embeds raw vulnerable code, so secrets are not leaked into the uploaded artifact.

**CSReview is READ-ONLY**: It never modifies, deletes, moves, or creates source code in the analyzed project. It only identifies problems, locates them precisely, and suggests remediation approaches based on the frameworks and technologies in use. The actual fixes are applied later by the human developer or a coding agent after understanding the project context, schema, tests, and regression risk. When encountering unfamiliar frameworks, CSReview researches official documentation and community forums to provide accurate recommendations.

**Global Skill Installation Policy**: CSReview is a global agent skill. It MUST be installed and loaded from the agent's global skills/instructions environment, such as `~/.codex/skills/csreview`, `~/.agents/skills/csreview`, `~/.trae/skills/csreview`, or `~/.claude/skills/csreview`. The agent MUST NOT copy, scaffold, install, update, delete, or move the CSReview skill inside the project being audited, including `<project>/.trae/skills/csreview`, `<project>/.codex/skills/csreview`, `<project>/.agents/skills/csreview`, `<project>/.claude/skills/csreview`, `<project>/AGENTS.md`, `<project>/CLAUDE.md`, `.cursorrules`, or `.windsurfrules`, unless the user explicitly asks for project-local installation. Generated reports may be written to the selected output directory, but those reports are audit artifacts, not a skill installation.

**Semgrep is mandatory as a baseline SAST attempt**: every CSReview run MUST attempt to execute `semgrep --version` and `semgrep --config auto --json --quiet <project_path>` before relying on agent-only analysis. Semgrep is a required external CLI tool, not a normal bundled npm dependency; install it with `pipx install semgrep`, `uv tool install semgrep`, Homebrew, Docker, or the platform package manager. If Semgrep is unavailable, the report MUST state that the run has lower confidence and include installation instructions.

**Dependency SCA complements Semgrep**: when available, the deterministic npm engine orchestrates and parses Node package audit tools selected by lockfile: `npm audit --json` for npm lockfiles, `pnpm audit --json` for `pnpm-lock.yaml`, and `bun audit --json` for `bun.lockb`/`bun.lock` (npm/pnpm take priority when more than one lockfile is present). It also parses `osv-scanner scan --format json <project_path>` for multi-ecosystem lockfile/manifests. These tools complement Semgrep by identifying known vulnerable dependency versions without changing source code or package files. Framework-native lint/scanning tools such as ESLint security plugins, pip-audit, Bandit, Gosec, cargo audit, dotnet vulnerable package checks, Checkov, Hadolint, Trivy, Snyk, and CodeQL are agent-recommended stack-native tools: the agent may run them when relevant and available, but they are not parsed by the npm engine unless explicitly added to the engine-orchestrated tool list.

**Config and BaaS misconfiguration detection**: on files classified as configuration/IaC/BaaS (Firebase/Firestore/Storage rules, SQL migrations, Dockerfiles, Kubernetes/Compose YAML, Terraform, ORM config), CSReview additionally checks for high-signal misconfigurations such as public BaaS rules (`allow ... if true`), disabled Row Level Security, disabled TLS verification, `0.0.0.0/0` network ingress, public object-storage ACLs, privileged/run-as-root containers, world-writable permissions, and unpinned `:latest` base images. These config patterns are scoped to those file kinds and are not run against application source code, to keep false positives low.

**CI integration and noise control**: CSReview also emits a SARIF 2.1.0 report (`<agent>_security.sarif`) for CI pipelines and code-scanning dashboards. A `.csreview-ignore` file at the project root (gitignore-style globs: `**`, `*`, `?`, anchored `/x`, directory `x/`, and `!negation`) suppresses findings for matching paths in the report only — it is read-only and never modifies the project. A baseline of known findings can be recorded with `--update-baseline` and enforced with `--baseline <file>` so CI fails only on NEW findings; baseline fingerprints are line-independent so they survive code shifting.

**Pre-flight checks (read-only, fail-open)**: before a scan CSReview can check whether a newer CSReview version exists in the official repository — this is advisory only, it never auto-updates itself, and the agent/user reviews the change before updating (skip with `--no-update-check`). `--doctor` additionally reports whether the available external scanners are on their latest version, but it never auto-upgrades system tools. These checks only query pinned official hosts over HTTPS (`raw.githubusercontent.com`/`api.github.com` for `decksoftware/csreview`, `pypi.org`, `crates.io`, `registry.npmjs.org`), never block the scan when offline, and never execute fetched content.

**Stack-Native Tool Recommendation Matrix**: after detecting the languages, frameworks, package managers, and lockfiles in the workspace, CSReview MUST select the relevant read-only tools below. Run a tool only if it is already available in the user's environment or already configured in the workspace. Do not install missing tools inside the analyzed project. If a recommended tool is unavailable, record it in the report as a `missing recommended tool` with the exact install/documentation pointer. These tools are agent-recommended unless listed under Engine-Orchestrated Tools.

| Detected stack | Prefer read-only commands and scanners |
| --- | --- |
| JavaScript / TypeScript / React / Node | `npm audit --json` for npm lockfiles, `pnpm audit --json` for `pnpm-lock.yaml`, `npm run lint -- --format json` when configured, `eslint` with project config, `eslint-plugin-security`, `eslint-plugin-react`, `eslint-plugin-react-hooks`, `typescript-eslint`, Semgrep |
| .NET / C# / ASP.NET | `dotnet build --no-restore`, `dotnet format analyzers --verify-no-changes`, `dotnet package list --include-transitive --vulnerable --format json` or `dotnet list package --include-transitive --vulnerable --format json`, .NET Roslyn analyzers (`CAxxxx`, `IDExxxx`), Semgrep, CodeQL/default setup when available |
| Kotlin / Android / JVM | `gradlew lint` or `./gradlew lint`, Android Lint, `detekt`, `ktlint`, Qodana, Gradle dependency vulnerability checks, OSV-Scanner, Semgrep |
| Go | `go vet ./...`, `govulncheck ./...`, `gosec ./...`, `staticcheck ./...`, `golangci-lint run`, OSV-Scanner, Semgrep |
| Python | `pip-audit`, `bandit -r`, `ruff check`, `safety` when available, OSV-Scanner, Semgrep |
| Java / Spring / Maven / Gradle | Maven/Gradle dependency checks, SpotBugs/FindSecBugs when configured, Checkstyle/PMD when configured, Qodana, OSV-Scanner, Semgrep |
| Rust | `cargo audit`, `cargo deny check`, `cargo clippy --all-targets --all-features`, OSV-Scanner, Semgrep |
| PHP / Laravel / Symfony | `composer audit --format=json`, PHPStan/Psalm when configured, Laravel Pint for linting, OSV-Scanner, Semgrep |
| Ruby / Rails | `bundle audit`, `brakeman`, RuboCop when configured, OSV-Scanner, Semgrep |
| Flutter / Dart | `dart analyze`, `flutter analyze`, `dart pub outdated --json`, OSV-Scanner, Semgrep |
| IaC / containers / CI | Checkov, Trivy, Hadolint, Dockerfile linting, GitHub Actions linting, Terraform validators, Semgrep |
| BaaS / database rules | Supabase CLI checks when configured, Firebase rules validation when configured, Appwrite/Convex/PocketBase config review, SQL linters when configured, Semgrep |

**External Research Protocol**: Do not guess when framework behavior, configuration defaults, security controls, exploitability, dependency advisories, CVE details, or remediation guidance are uncertain. The coding agent MUST know how to perform external internet research when necessary and MUST consult primary or specialized sources before reporting a confident recommendation:

- official framework documentation, release notes, migration guides, and security pages
- Vendor security advisory pages for the affected product, cloud service, database, BaaS, or package manager
- OWASP, CWE, CVE/NVD, GitHub Security Advisories, OSV.dev, Snyk advisory pages, and other specialized application security portals
- Official package, API, or SDK documentation for the exact version or major version in use

When external research is used, include source names and URLs in the finding references. Prefer official documentation and vendor advisories over generic blog posts. If sources disagree or the version cannot be confirmed, mark the finding as lower confidence and explain the uncertainty in the report.

**No-Findings Assurance Limit**: A report with zero findings is not proof that the system is secure. It only means CSReview and the available external tools did not detect reportable issues in the analyzed scope. The HTML and Markdown reports MUST state this limitation when no findings are found.

**Report Handoff Protocol**: After every CSReview run, the agent MUST present two explicit paths:

- **Agent name prefix**: report filenames MUST begin with the coding agent name in lowercase, for example `codex_security-report.html` and `codex_security-findings.md`. Other agents must replace `codex` with their own name, such as `claude_security-report.html`.
- **MUST NOT generate generic report names**: `security-report.html`, `security-findings.md`, `_security-report.html`, `_security-findings.md`, `csreview-report.html`, and `csreview-report.md` are invalid handoff names because they hide which agent produced the analysis.
- **CLI identity**: pass `--agent-name <agent>` on CLI runs or set `CSREVIEW_AGENT_NAME=<agent>` before running CSReview. Examples: `csreview . --agent-name codex`, `csreview . --agent-name claude`, `CSREVIEW_AGENT_NAME=qwen csreview .`.
- **HTML report path**: the absolute path to `csreview-reports/codex_security-report.html` or the configured output HTML file. Tell the user this is the file to click/open in a browser for human reading. If the environment has an available browser-opening tool and the user asked to open it, open the HTML report in the browser.
- **Markdown report path**: the absolute path to `csreview-reports/codex_security-findings.md` or the configured output Markdown file. Tell the user and the coding agent that this is the file the coding agent must analyze before planning any remediation.

The coding agent must not infer findings from the verbal summary alone. For remediation work, it must read the Markdown report path first, then inspect the referenced source files, framework documentation, schemas, tests, and security advisories before proposing or applying changes.

**Phase 9: Optional Local DAST Complementary Report**: after the user or coding agent has implemented and validated remediations from the static CSReview report, the agent MUST inform the user that an optional broader local dynamic validation is available. This phase is not part of the default SAST/SCA run and MUST NOT start automatically. It is a conservative local HTTP probe (security headers + CORS checks), NOT a full penetration test; for active probing install and run a dedicated tool such as Nuclei against the confirmed local target.

The required user-facing prompt is: "Static remediation is complete. You can optionally run CSReview Phase 9 Local DAST in a local test environment only. Never use this against production. If the test uses a database copy, make sure the copy was made deliberately, stored in a secure local place, and sanitized or minimized where needed. This resource is for White Hat Hacker-style analysis and remediation of security flaws; it sends real HTTP requests only to localhost/127.0.0.1 and writes a complementary report. Do you want me to run it? (yes/no)"

Phase 9 may proceed only when all of these are true:

- The user gives explicit user confirmation.
- The user understands this is for a local test environment, never production, and that any database copy used for testing must be securely created, stored, and handled.
- The target URL is strictly `http://localhost:<port>`, `https://localhost:<port>`, `http://127.0.0.1:<port>`, `https://127.0.0.1:<port>`, or the IPv6 loopback `http://[::1]:<port>` / `https://[::1]:<port>`.
- The `.env`, `.env.local`, and `.env.development` pre-flight is advisory, not blocking: if an external host is referenced, it is surfaced as a `DAST-SUSPECTED` warning so you verify the local app under test does not proxy probe traffic to that host. A real development `.env` almost always references external services, so this warning by itself does not abort Phase 9; the hard guards below still apply.
- Redirects are not followed. If a response points to an external host, abort Phase 9 immediately. (This is a hard guard enforced in the engine.)
- The complementary reports are written only inside `csreview-reports/` as `csreview-reports/<agent>_local-dast-report.html` and `csreview-reports/<agent>_local-dast-findings.md`. A run ID is embedded in the report and, when provided, time-stamped history copies are also written inside `csreview-reports/` so re-running Phase 9 after remediation does not overwrite the previous run's evidence. A read-only per-backend local database dump guide (`<agent>_db-dump-guide.html`) is also generated to help prepare an isolated local copy before any database-level testing.

The CLI form is:

```bash
csreview . --local-dast-url http://localhost:3000 --confirm-local-dast --agent-name codex
```

Phase 9 output uses dynamic status labels:

- `DAST-CONFIRMED`: dynamically reproduced with clear evidence, normally from a dedicated local DAST tool or an explicitly allowed endpoint test.
- `DAST-SUSPECTED`: anomalous local response that requires human review.
- `DAST-CLEAN`: the checked condition passed for the local target.

Hard limits: never probe external IPs, domains, staging, or production; never follow redirects to external hosts; never write outside `csreview-reports/`; never use destructive payloads; never use DELETE; do not send mutating POST/PUT/PATCH requests unless the user provided an explicit local test endpoint allowlist and confirmed the data mutation risk. The built-in CSReview local DAST mode is conservative and performs non-mutating HTTP checks such as reachability, browser security headers, and CORS behavior. OWASP ZAP or Nikto may be used only when installed, only after the same pre-flight checks and confirmation, and only against the confirmed local target.

The analysis covers 8 default report sections: Reconnaissance, Ultra-Deep Security, Database Security, SLSA Build L3 (v1.2) Supply Chain, OWASP ASVS 5.0.0, Compliance mapping (LGPD/GDPR/SOC2/HIPAA/CCPA-CPRA — indicative correlation, not an audited compliance verification), Vibe Coding Protection, and Dual Report Generation. These are report sections, not separate executable engine phases. Phase 9 is optional, local-only, post-remediation, and produces a complementary report.

CSReview includes built-in **Code Review** capabilities (equivalent to codex:review, codex:adversarial-review, code-review, requesting-code-review, receiving-code-review) - no additional skills or plugins required.

## When to Invoke

- User requests security review or code audit
- User asks for vulnerability scan or pentest analysis
- User wants to check for data leakage or exposed secrets
- User mentions SQL injection, XSS, auth flaws, or security concerns
- Before release or deployment preparation, while reviewing only the local workspace
- User asks to review Supabase, Firebase, Appwrite, Neon, or similar backend security
- User invokes `@csreview` or mentions CSReview
- User wants compliance verification (LGPD, GDPR, SOC 2, HIPAA)
- User built code with AI agents and wants to verify security (vibe coding check)
- User wants database structure security validation (SQL/NoSQL/BaaS)
- User requests code review (`@csreview review [files]`)
- User requests adversarial review (`@csreview adversarial [files]`)
- User requests security-focused review (`@csreview security-review [files]`)
- User wants to review changes in a PR or branch (`@csreview request-review [scope]`)
- User wants a remediation plan from a report (`@csreview review csreview-reports/codex_security-findings.md`)

## Supported Technologies

### Languages & Frameworks
- **Frontend**: React, Vue, Nuxt, Angular, Svelte, Next.js
- **Mobile**: Flutter, Kotlin (Android), Swift (iOS), React Native
- **Backend**: Python, Node.js, C#, Go, Java, PHP, Ruby
- **Systems**: C, C++, Rust
- **Desktop**: Electron, Tauri, native apps
- **.NET Ecosystem**: .NET Framework, .NET Core, .NET 5/6/7/8/9, ASP.NET Core, Blazor, MAUI, WPF, WinForms, Xamarin
- **Delphi/Lazarus**: Delphi (VCL, FMX), Lazarus (LCL), Free Pascal, Object Pascal
- **Go**: Go standard library, Gin, Echo, Fiber, GORM, and Go modules

### Installer & Binary Security
- **DLL Analysis**: DLL hijacking, side-loading, missing ASLR/DEP, unsigned DLLs, export table inspection
- **Installers**: Inno Setup, NSIS, WiX, InstallShield, MSI packages, custom installers
- **Binary Security**: Code signing verification, Authenticode, checksum integrity, obfuscation review
- **Package Formats**: NuGet (.nupkg), Chocolatey, WinGet, DEB, RPM, APK, IPA, DMG

### Databases & Backends
- **SQL**: PostgreSQL, MySQL, MariaDB, SQL Server, Firebird, SQLite, Oracle
- **NoSQL**: MongoDB, Redis, CouchDB, DynamoDB, Cassandra, ArangoDB
- **BaaS**: Supabase, Firebase, Appwrite, AWS Amplify, Nhost, Neon, PocketBase, Convex, PlanetScale, Turso

### Operating Systems
- **macOS**: App Sandbox, Keychain, TCC, plists, XPC, Gatekeeper
- **iOS**: URL schemes, Keychain, jailbreak detection, TLS, ATS, biometrics
- **Linux**: SUID/SGID, cron, systemd, sudoers, containers, kernel modules
- **Windows**: Registry, UAC, COM, DLL hijacking, named pipes, services, ACLs

### AI Agent Compatibility

This skill is designed to work across multiple AI coding agents:

| Agent | Integration Method |
|-------|-------------------|
| **Trae / SOLO** | Global skill via `~/.trae/skills/csreview/SKILL.md` |
| **OpenCode** | Compatible via global agent instructions |
| **Qwen CLI** | Compatible via system prompt injection |
| **Codex** | Global skill via `~/.codex/skills/csreview/SKILL.md` or `~/.agents/skills/csreview/SKILL.md` |
| **Claude Code** | Global skill via `~/.claude/skills/csreview/SKILL.md` |
| **Antigravity** | Compatible via global agent configuration |
| **Qoder** | Compatible via agent configuration |
| **Cursor / Windsurf / Cline** | Compatible via global rules/instructions when supported |
| **GitHub Copilot CLI** | Compatible via global/custom instructions when supported |
| **Aider / Continue / DevChat** | Compatible via global agent conventions when supported |

**Cross-Agent Behavior**: Regardless of which agent invokes this skill, the analysis depth, report format, and vulnerability detection remain consistent. The HTML report is always generated in the user's language; the MD report is always in English for agent consumption.

## Analysis Phases

### Scatter-Gather Security Subagent Orchestration

When the coding-agent runtime supports subagents and the workspace is large enough to justify the extra token/runtime cost, CSReview MAY ask the coding agent to use a scatter-gather workflow. This is an orchestration rule for agent reasoning, not a replacement for the deterministic npm engine.

The dependency graph is:

1. **Phase 0 + Phase 1 sequential gate**: first detect tools, run the engine-orchestrated SAST/SCA tools once, scan the local workspace, and build the shared project map (`techStack`, frameworks, package managers, BaaS files, database files, IaC files, routes, and generated tool JSON).
2. **Compatibility-gated fan-out**: spawn only the subagents that match the map. Examples: do not spawn a Delphi subagent without Pascal/Delphi files; do not spawn a Firebase subagent without Firebase rules/config; do not spawn a Go subagent without Go modules/files.
3. **Parallel validation**: compatible subagents validate candidate findings in their domain by reading the shared map, relevant local files, and cached tool output. They must not rerun heavy SAST/SCA tools across the whole tree.
4. **Gather barrier**: wait for all subagents to finish before ASVS/compliance correlation.
5. **Reduce/correlation**: one coordinator merges all partial findings, then runs `dedup -> ASVS -> compliance -> score -> report` in that order.
6. **Single writer**: Subagents MUST NOT write final reports. They may write only partial JSON to `csreview-reports/.partials/<subagent>.json`. The coordinator is the only writer for `<agent>_security-report.html` and `<agent>_security-findings.md`, and partial files must use the canonical finding schema.

Hard rules:

- If subagents are unavailable, too expensive for the repository size, or not supported by the current agent, fallback to sequential analysis.
- Run SAST/SCA tools once in the gate stage; later subagents consume cached tool output instead of rerunning Semgrep, OSV-Scanner, Node package audit, Trivy, or similar whole-tree scans.
- Every subagent finding must use the canonical finding schema (`id`, `severity`, `category`, `name`, `description`, `file`, `line`, `vulnerableCode`, `cwe`, `owasp`, `fix`, `confidence`, `exploitation`, `references`, `source`). Use `source: "subagent:<domain>"`, for example `source: "subagent:auth"`, so the coordinator can correlate and deduplicate against `csreview-detector`, `semgrep`, `npm-audit`, and `osv-scanner`.
- Subagents do not write final reports and do not modify audited source code.
- The coordinator owns final deduplication. Matching `file:line:CWE` evidence from multiple sources can be promoted to `CONFIRMED`.

#### Subagent Orchestration DoD

1. **Single writer**: Subagents MUST NOT write final reports. Each subagent writes only partial findings JSON to its own scratch file, for example `csreview-reports/.partials/<subagent>.json`. The coordinator is the only writer for `<agent>_security-report.html` and `<agent>_security-findings.md`.
2. **Canonical schema**: every subagent finding uses the engine finding object (`severity`, `category`, `file`, `line`, `cwe`, `confidence`, `fix`, and related fields) and sets `source: "subagent:<domain>"`. Without this, `deduplicateFindings` cannot correlate evidence or promote confidence to `CONFIRMED`.
3. **Tool runs once**: Semgrep, Node package audit, OSV-Scanner, Trivy, and similar whole-tree SAST/SCA tools run only during Phase 0/1. Their JSON output is cached, and subagents read the cache instead of re-executing tools on the tree.
4. **Compatibility-gated fan-out**: spawn a subagent only when Phase 1 detected its stack, framework, or ruleset. Do not spawn technology-specific subagents for absent ecosystems.
5. **Barrier before reduce**: ASVS mapping, compliance mapping, and score calculation run only after all partial findings have returned. The coordinator applies `dedup -> ASVS -> compliance -> score -> report`.

**Final check**: CSReview produces one pair of final reports, the final count matches the sum of partial findings after deduplication, and no tool appears executed more than once in the log.

**Engine enforcement**: when `csreview-reports/.partials/` exists, the npm engine reads canonical partial JSON, merges valid `source: "subagent:<domain>"` findings into the final finding set, exposes `partialReconciliation`, and provides `reconcilePartials(outputDir, finalFindings, { strict: true })` for coordinators that need the run to fail when the DoD does not reconcile.

#### Non-negotiable rules

1. **Single writer**: subagents write partial JSON only; the coordinator writes final reports.
2. **Canonical schema**: subagent findings must use the engine finding object and `source: "subagent:<domain>"`.
3. **Tool runs once**: whole-tree SAST/SCA tools run in Phase 0/1 only; subagents read cached JSON.

### Phase 0: Security Tool Detection & Integration

**This is the FIRST step of every analysis.** CSReview MUST detect which security tools are available on the user's operating system and use them for real file-by-file scanning. When real tools are not available, CSReview falls back to AI-based analysis (which is less thorough).

#### 0.0 Analysis Modes

CSReview operates in three modes. These mode names are based on the deterministic npm engine's orchestrated tools, not on every agent-recommended tool listed in this skill.

**Mode A: Self-Hosted (RECOMMENDED)**
- All relevant engine-orchestrated tools are available locally: Semgrep, OSV-Scanner, and the Node package audit selected by lockfile (`pnpm audit` for `pnpm-lock.yaml`, `npm audit` for npm lockfiles).
- CSReview detects, invokes, parses, deduplicates, and scores these deterministic outputs.
- Findings from parsed tools are reproducible and can become `TOOL-ONLY` or `CONFIRMED` when matching CSReview detector evidence.
- Agent-recommended stack-native tools may still be listed as missing or supplemental; they do not change the engine mode unless their outputs are parsed by the npm engine.
- **This is the highest-confidence CSReview engine mode for local workspace analysis.**

**Mode B: Agent-Only (FALLBACK)**
- No engine-orchestrated tool is available.
- CSReview relies on local scanner metadata plus regex/static heuristics and any careful agent reading of local files.
- **WARNING**: This mode has lower precision and recall. Line-oriented regex checks can miss multiline issues and may report false positives.
- Always clearly mark the run lower confidence and recommend installing Semgrep and OSV-Scanner before relying on the result.

**Mode C: Hybrid (PARTIAL)**
- Some, but not all, relevant engine-orchestrated tools are available.
- CSReview runs available parsed tools and supplements them with detector heuristics and agent review.
- Tool findings are marked `TOOL-ONLY`; detector+tool agreement is deduplicated and promoted to `CONFIRMED`.
- Missing relevant tools must be disclosed in the report.

**The agent MUST inform the user which mode is active and what the implications are.**

#### 0.1 Tool Detection Protocol

At the start of every scan, run detection commands for each tool. Use `RunCommand` or equivalent:

#### 0.1.1 Engine-Orchestrated Tools

These are the tools the npm engine currently invokes and parses deterministically:

| Tool | Engine behavior |
|------|-----------------|
| Semgrep | Runs `semgrep --config auto --json --quiet <project_path>` and parses findings |
| Node package audit | Runs `pnpm audit --json` when `pnpm-lock.yaml` exists, otherwise `npm audit --json` for npm lockfiles, and parses dependency findings |
| OSV-Scanner | Runs `osv-scanner scan --format json <project_path>` and parses dependency findings |
| Local DAST | Optional post-remediation local-only complement via `--local-dast-url`, writing separate reports |

#### 0.1.2 Agent-Recommended Stack-Native Tools

The tools below are recommended for agent-assisted validation when relevant to the detected stack. They are not parsed by the npm engine unless explicitly listed under Engine-Orchestrated Tools, so their results must be reported as supplemental evidence rather than silently merged into engine counts.

**Detection Commands:**
```bash
# Semgrep - Multi-language static analysis (MANDATORY baseline attempt)
semgrep --version
# Required scan when available: semgrep --config auto --json --quiet <project_path>

# OSV-Scanner - Multi-ecosystem dependency vulnerability scanning
osv-scanner --version
# If found: osv-scanner scan --format json <project_path>

# Bandit - Python security linter
bandit --version
# If found: bandit -r <project_path> -f json -ll

# Trivy - Vulnerability scanner (dependencies, containers, IaC)
trivy --version
# If found: trivy fs --format json --output report.json <project_path>

# CodeQL - GitHub's semantic code analysis (if qlpack available)
codeql version
# If found: codeql database create / analyze

# ESLint with security plugins
npx eslint --version 2>/dev/null || eslint --version
# If found: npx eslint --ext .js,.ts,.jsx,.tsx --config .eslintrc.security.json <project_path>

# Snyk - Dependency vulnerability scanning
snyk --version
# If found: snyk test --json > report.json

# SonarQube Scanner
sonar-scanner --version 2>/dev/null
# If found: sonar-scanner -Dsonar.projectKey=... -Dsonar.sources=.

# Safety - Python dependency vulnerability checker
safety --version
# If found: safety check --json

# Gosec - Go security linter
gosec --version
# If found: gosec -fmt json -out report.json ./...

# Grype - Vulnerability scanner for container images and filesystems
grype version
# If found: grype dir:<project_path> -o json

# Hadolint - Dockerfile security linter
hadolint --version
# If found: hadolint Dockerfile --format json

# TFLint - Terraform linter
tflint --version
# If found: tflint --format json

# Checkov - Infrastructure-as-code security
checkov --version
# If found: checkov -d <project_path> -o json

# Brakeman - Ruby on Rails security scanner
brakeman --version
# If found: brakeman --format json -o report.json

# RetireJS - JavaScript library vulnerability scanner
retire --version
# If found: retire --path <project_path> --outputformat json

# OWASP Dependency-Check
dependency-check.sh --version 2>/dev/null || dependency-check --version 2>/dev/null
# If found: dependency-check --project <name> --scan <path> --format JSON

# pip-audit - Python dependency auditing
pip-audit --version
# If found: pip-audit --format json

# cargo-audit - Rust dependency auditing
cargo audit --version
# If found: cargo audit --json

# npm audit (always available with npm)
npm --version
# If found: npm audit --json

# pnpm audit (selected when pnpm-lock.yaml exists)
pnpm --version
# If found: pnpm audit --json

# yarn audit
yarn --version
# If found: yarn audit --json

# dotnet list package --vulnerable (always available with dotnet)
dotnet --version
# If found: dotnet list package --vulnerable --include-transitive
```

#### 0.2 Tool Selection Matrix

After detection, select tools based on detected project languages:

| Language/Framework | Primary Tools | Secondary Tools |
|-------------------|---------------|-----------------|
| **JavaScript/TypeScript** | semgrep, eslint (security), npm audit or pnpm audit selected by lockfile, osv-scanner | snyk, retire |
| **Python** | bandit, safety, pip-audit, osv-scanner | semgrep, snyk |
| **Go** | gosec, govulncheck, trivy, osv-scanner | semgrep |
| **C# / .NET** | dotnet list package --vulnerable, osv-scanner | semgrep, snyk |
| **Java** | semgrep, snyk, OWASP dep-check, osv-scanner | trivy |
| **Ruby** | brakeman, bundler-audit | semgrep |
| **Rust** | cargo audit, osv-scanner | semgrep, trivy |
| **PHP** | semgrep, snyk | psalm (security) |
| **Kotlin/Swift** | semgrep, snyk | trivy |
| **Docker** | hadolint, trivy, grype | checkov |
| **Terraform/IaC** | checkov, tflint, trivy | semgrep |
| **Delphi/Lazarus** | AI-based analysis only | semgrep (if available) |
| **Multi-language** | semgrep, osv-scanner, trivy | snyk, grype |

#### 0.3 Execution Strategy

**When real tools ARE available:**
1. Run all applicable tools in parallel (use `RunCommand` with `blocking: false` for each)
2. Collect JSON output from each tool
3. Parse and normalize findings into unified format
4. Merge with AI-based analysis (Phase 1-7) for comprehensive coverage
5. Deduplicate findings (same file+line+type = same issue)
6. Prioritize: tool findings take precedence over AI-only findings

**When real tools are NOT available:**
1. Inform the user: "No security scanning tools detected. Using AI-based analysis only. For better accuracy, install: [recommended tools for their stack]"
2. Run AI-based analysis (Phase 1-7) with enhanced depth
3. Add a disclaimer to reports: "This report was generated using AI-based analysis only. For production security audits, install and run: semgrep, [language-specific tool]"
4. Still generate both HTML and MD reports, but mark findings with confidence level

**Confidence Levels:**
| Level | Source | Description |
|-------|--------|-------------|
| **CONFIRMED** | Real tool + AI agree | Highest confidence - both tool and AI identified the issue |
| **TOOL-ONLY** | Real tool only | Issue found by tool but not confirmed by AI review |
| **AI-ONLY** | AI analysis only | Issue found by AI but not detected by tools |
| **AI-ESTIMATED** | No tools available | AI-based analysis only, lower confidence |

#### 0.4 Tool Output Normalization

Each tool's output must be normalized into this unified format:

```json
{
  "source": "semgrep|bandit|trivy|snyk|eslint|codeql|gosec|...",
  "id": "unique-finding-id",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "injection|xss|auth|config|dependency|...",
  "file": "relative/path/to/file",
  "line": 42,
  "column": 10,
  "title": "Short description",
  "description": "Detailed description",
  "cwe": "CWE-89",
  "confidence": "CONFIRMED|TOOL-ONLY|AI-ONLY|AI-ESTIMATED",
  "fix": "Suggested fix or remediation",
  "references": ["url1", "url2"],
  "tool_metadata": {
    "rule_id": "semgrep-rule-id",
    "owasp_category": "A03:2021",
    "cve": "CVE-2024-XXXX"
  }
}
```

#### 0.5 Per-Tool Invocation Details

**Semgrep (highest priority - multi-language):**
```bash
# Auto-detect rules from registry
semgrep --config auto --json --quiet --no-git-ignore <project_path>

# With specific rulesets
semgrep --config p/security-audit --config p/secrets --config p/owasp-top-ten --json <project_path>
```

**Bandit (Python-specific):**
```bash
bandit -r <project_path> -f json -ll -i --skip B101
# -ll = medium and high severity only
# --skip B101 = skip assert warnings (too noisy)
```

**Trivy (comprehensive scanner):**
```bash
# Filesystem scan (dependencies + misconfigs)
trivy fs --format json --scanners vuln,misconfig,secret <project_path>

# With severity filter
trivy fs --severity HIGH,CRITICAL --format json <project_path>
```

**OSV-Scanner (multi-ecosystem dependency SCA):**
```bash
osv-scanner scan --format json <project_path>
```
- Parse JSON `results[].packages[].vulnerabilities[]`
- Map findings to OWASP A06: Vulnerable and Outdated Components
- Do not run `osv-scanner fix` or guided remediation during CSReview

**Node package audit (Node.js dependencies):**
```bash
cd <project_path> && npm audit --json   # npm lockfiles
cd <project_path> && pnpm audit --json  # pnpm-lock.yaml
```
- Parse npm `vulnerabilities` and pnpm `advisories`
- Do not run package-manager fix/update commands during CSReview

**Snyk (if authenticated):**
```bash
snyk test --json --severity-threshold=medium
```

**Gosec (Go-specific):**
```bash
gosec -fmt json -out /tmp/gosec-report.json -severity medium ./...
```

**dotnet (C#/.NET dependencies):**
```bash
dotnet list package --vulnerable --include-transitive
```

**cargo audit (Rust):**
```bash
cargo audit --json
```

**pip-audit (Python dependencies):**
```bash
pip-audit --format json --desc
```

**Checkov (IaC security):**
```bash
checkov -d <project_path> -o json --quiet --compact
```

**Hadolint (Dockerfile):**
```bash
hadolint <project_path>/Dockerfile --format json
```

#### 0.6 Installation Recommendations

When tools are missing, provide platform-specific installation instructions:

```bash
# Semgrep (all platforms)
pipx install semgrep
# Alternative: uv tool install semgrep

# OSV-Scanner
# Windows: winget install Google.OSVScanner
# macOS/Linux: brew install osv-scanner
# Go: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# Bandit (Python)
pip install bandit

# Trivy (all platforms)
# Windows: choco install trivy OR scoop install trivy
# macOS: brew install trivy
# Linux: sudo apt-get install trivy OR curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Snyk
npm install -g snyk

# Gosec (Go)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# pip-audit
pip install pip-audit

# cargo audit
cargo install cargo-audit

# Checkov
pip install checkov

# Hadolint
# Windows: choco install hadolint
# macOS: brew install hadolint
# Linux: docker pull hadolint/hadolint

# ESLint Security Plugin
npm install --save-dev eslint-plugin-security eslint-plugin-no-unsanitized
```

### Phase 1: Reconnaissance & Mapping

1. **Project Structure Scan**
   - Identify all languages, frameworks, and dependencies
   - Map entry points, API routes, and data flow paths
   - Locate configuration files (.env, config.*, database.yml, etc.)

2. **Secret Detection**
   - Hardcoded API keys, tokens, passwords
   - Connection strings with credentials
   - Private keys, certificates, secrets in code
   - Environment files committed to version control

3. **External Service Mapping**
   - Supabase: tables, RLS policies, edge functions, storage rules
   - Firebase: database rules, storage rules, auth config
   - Appwrite: collections, permissions, functions
   - AWS/GCP/Azure: IAM roles, S3 buckets, exposed endpoints

### Phase 2: Ultra-Deep Security Analysis

#### 2.1 Injection Vulnerabilities
- **SQL Injection**: Raw queries, string concatenation, ORM misuse
- **NoSQL Injection**: MongoDB query injection, Redis command injection
- **Command Injection**: exec(), system(), subprocess calls with user input
- **LDAP Injection**: Directory service query manipulation
- **XPath Injection**: XML query manipulation
- **Template Injection**: SSTI in Jinja2, Twig, EJS, etc.

#### 2.2 Authentication & Authorization
- **JWT Flaws**: Missing validation, weak secrets, algorithm confusion
- **Session Management**: Insecure cookies, missing HttpOnly/Secure flags
- **RLS Policies**: Missing or bypassable Row Level Security (Supabase)
- **Role-Based Access**: Privilege escalation, missing authorization checks
- **IDOR**: Insecure Direct Object References exposing other users' data
- **OAuth/OpenID**: Misconfigured flows, token leakage, redirect URI flaws

#### 2.3 Data Leakage
- **Log Exposure**: Sensitive data in console.log, logger, error messages
- **Stack Traces**: Full error details exposed to users
- **PII Exposure**: Personal data in API responses without filtering
- **Debug Mode**: Debug endpoints or panels enabled in production
- **Response Headers**: Server version, framework info leakage
- **Cache Exposure**: Sensitive data cached in browser or CDN

#### 2.4 Cross-Site Vulnerabilities
- **XSS**: Reflected, stored, DOM-based (dangerouslySetInnerHTML, v-html)
- **CSRF**: Missing tokens, SameSite cookie misconfiguration
- **CORS**: Overly permissive origins, wildcard Access-Control-Allow-Origin
- **Clickjacking**: Missing X-Frame-Options or CSP frame-ancestors

#### 2.5 Insecure Configurations
- **Security Headers**: Missing CSP, HSTS, X-Content-Type-Options
- **TLS/SSL**: Weak ciphers, missing certificate pinning, HTTP fallback
- **File Uploads**: Missing validation, executable file upload, path traversal
- **Rate Limiting**: Missing brute force protection, API abuse vectors
- **Error Handling**: Verbose errors, information disclosure

#### 2.6 Dependency Vulnerabilities
- **Outdated Packages**: Known CVEs in dependencies
- **Supply Chain**: Suspicious packages, typosquatting, compromised deps
- **License Compliance**: Restrictive licenses in production

#### 2.7 Cloud & Backend Security
- **Supabase**:
  - Missing RLS policies on sensitive tables
  - Overly permissive policies (allow all authenticated)
  - Exposed service role key in client code
  - Storage bucket public access misconfiguration
  - Edge function authentication bypass
- **Firebase**:
  - Database rules allowing read/write to all users
  - Storage rules without authentication checks
  - Exposed API keys with excessive permissions
  - Missing App Check enforcement
- **Appwrite**:
  - Collection permissions too permissive
  - Missing attribute validation
  - Function execution without auth checks

#### 2.8 Platform-Specific Vulnerabilities

**macOS:**
- App Sandbox escape vectors
- Keychain insecure access patterns
- TCC (Transparency, Consent, Control) permission abuse
- Plist misconfigurations exposing sensitive data
- XPC service vulnerabilities
- Gatekeeper bypass vectors
- Insecure file permissions (world-readable/writable)

**iOS:**
- Insecure URL scheme handling
- Keychain data exposure
- Missing jailbreak detection
- TLS certificate validation bypass
- UserDefaults storing sensitive data
- Biometric authentication flaws
- App Transport Security (ATS) disabled
- Screenshot/cache exposure of sensitive screens
- Insecure WKWebView configurations

**Linux:**
- SUID/SGID binary vulnerabilities
- Cron job injection or race conditions
- Insecure systemd service configurations
- File permission escalation vectors
- Sudoers misconfigurations
- Exposed Unix sockets
- Kernel module vulnerabilities
- Container escape vectors (Docker, LXC)
- Insecure mount options

**Windows:**
- Registry key exposure of sensitive data
- UAC bypass vectors
- Insecure COM object configurations
- DLL hijacking vulnerabilities
- Named pipe access control flaws
- Service account privilege escalation
- PowerShell execution policy bypass
- Insecure ACLs on files/directories
- Token impersonation flaws

#### 2.9 Cross-Platform System Vulnerabilities
- **Path Traversal**: File operations with unsanitized paths
- **Symlink Attacks**: Following malicious symlinks
- **Environment Variable Injection**: Untrusted env var manipulation
- **Insecure Temp Files**: Predictable temp file names
- **Race Conditions**: TOCTOU in file/resource access
- **Memory Corruption**: Buffer overflow, use-after-free in native code
- **IPC Insecurity**: Unprotected inter-process communication
- **Credential Storage**: Plaintext passwords, tokens, keys

#### 2.10 .NET / dotnet Security

**ASP.NET Core / Blazor:**
- Missing `[Authorize]` attributes on controllers/pages
- CORS policy set to `AllowAnyOrigin` in production
- Missing anti-forgery tokens (`[ValidateAntiForgeryToken]`)
- Insecure cookie configuration (missing HttpOnly, Secure, SameSite)
- Sensitive data in `appsettings.json` without user secrets or key vault
- Missing rate limiting middleware
- Debug mode enabled in production (`ASPNETCORE_ENVIRONMENT=Development`)
- Missing HTTPS redirection and HSTS
- Insecure Data Protection API key storage
- Missing input validation with `[ValidateInput]` or FluentValidation

**Entity Framework / EF Core:**
- Raw SQL queries with string interpolation (`FromSqlRaw` with unsanitized input)
- Missing parameterization in LINQ-to-SQL dynamic queries
- Lazy loading without `ProxyCreationEnabled` control (N+1 queries)
- Excessive `Include()` chains loading unnecessary related data
- Missing migration rollback scripts
- Connection strings with credentials in plain text
- Missing database connection encryption

**NuGet / Package Security:**
- Packages from untrusted sources
- Missing `nuget.config` source restrictions
- Packages with known vulnerabilities (check against CVE database)
- Transitive dependency vulnerabilities
- Missing lock files (`packages.lock.json`)

**.NET Binary Security:**
- Missing strong naming / signing of assemblies
- `AllowPartiallyTrustedCallers` attribute misuse
- Missing `[SecurityCritical]` / `[SecuritySafeCritical]` boundaries
- Reflection-based type loading from untrusted sources
- BinaryFormatter / SoapFormatter deserialization (known insecure)
- Missing `SecureString` usage for sensitive data in memory

#### 2.11 Delphi / Lazarus Security

**Delphi (VCL / FireMonkey):**
- Hardcoded database credentials in `.dpr` or `.pas` files
- Missing encryption for stored connection strings
- BDE (Borland Database Engine) insecure configurations
- dbExpress / FireDAC connection strings with plaintext passwords
- Insecure file operations (no path validation on user input)
- Missing input validation on TForm controls
- COM automation with late binding (variant-based) without safety checks
- Unsafe pointer operations and untyped `var` parameters
- Missing bounds checking on dynamic arrays and strings (`{$RANGECHECKS ON}`)
- Insecure registry operations (direct Windows Registry access without validation)
- Missing overflow checking (`{$OVERFLOWCHECKS ON}`)

**Lazarus / Free Pascal:**
- Hardcoded credentials in `.lpr` or `.pas` source files
- SQLite databases without encryption (SQLite3 without SEE or sqlcipher)
- Missing parameterized queries in SQLdb components
- Insecure INI file configurations with sensitive data
- Missing TLS for network communications (Indy / Synapse without SSL)
- Form data stored without encryption
- Insecure file permissions on Linux deployments
- Missing `{$MODESWITCH ANSISTRINGS}` causing string handling issues
- Buffer overflows in `Move`, `FillChar`, `GetMem` operations
- Missing exception handling around database operations

**Database Connectivity (Delphi/Lazarus):**
- Firebird/InterBase connection strings with embedded passwords
- Missing SSL/TLS for database connections
- Unencrypted `.fdb` / `.gdb` database files
- IBX / FIBPlus components with default credentials
- Missing `EXECUTE STATEMENT` parameterization in Firebird PSQL
- zeoslib connection pooling misconfigurations

#### 2.12 Go Security

**Web Frameworks (Gin, Echo, Fiber):**
- Missing input validation middleware
- SQL injection via `fmt.Sprintf` in queries instead of parameterized statements
- Missing CSRF protection
- Unbounded file uploads without size/type validation
- Missing rate limiting
- CORS middleware with `AllowAllOrigins: true`
- Missing request body size limits
- Error messages leaking internal state

**Go-Specific Vulnerabilities:**
- `exec.Command` with unsanitized user input
- `os.ReadFile` / `ioutil.ReadFile` with user-controlled paths (path traversal)
- `template.HTML` bypassing auto-escaping
- `unsafe.Pointer` usage and CGo boundary vulnerabilities
- Missing bounds checking in slice operations
- Goroutine leaks (missing context cancellation)
- Race conditions from shared mutable state without `sync.Mutex`
- `json.Unmarshal` into `interface{}` without schema validation
- Missing `context.WithTimeout` for external service calls
- Hardcoded credentials in source code

**Go Modules:**
- `go.sum` integrity verification failures
- Replaced modules (`replace` directive) pointing to untrusted sources
- Missing `go.sum` file in repository
- Modules with known vulnerabilities (`govulncheck`)
- Private module proxy misconfigurations

#### 2.13 Installer & DLL Security

**DLL Security:**
- DLL hijacking: application loads DLL from current directory before system paths
- DLL side-loading: legitimate app loading malicious DLL from same directory
- Missing Address Space Layout Randomization (ASLR) flag
- Missing Data Execution Prevention (DEP) / NX bit flag
- Unsigned DLLs in production deployments
- Export table exposing sensitive functions
- DLL injection vectors (missing process integrity levels)
- Insecure DLL search order (current directory before System32)

**Installer Security (Inno Setup / NSIS / WiX / MSI):**
- Custom actions running with elevated privileges
- Missing digital signature on installer executable
- Insecure file permissions set during installation
- Hardcoded credentials in installer scripts
- Missing uninstall cleanup (leftover sensitive files/registry keys)
- Insecure temporary directory usage during installation
- Missing integrity checks on extracted files
- Pre-install validation missing (disk space, prerequisites)
- Insecure custom protocol handlers registered during install
- MSI custom actions with `Impersonate="no"` (running as SYSTEM)

**Binary & Executable Security:**
- Missing Authenticode / code signing
- Missing checksum verification for downloaded updates
- Insecure auto-update mechanism (HTTP instead of HTTPS, no signature verification)
- Debug symbols included in release builds
- PDB files deployed to production
- Sensitive strings embedded in binary (use string search analysis)
- Missing compiler security flags (`/GS` buffer security check, `/DYNAMICBASE`, `/NXCOMPAT`)
- Insecure compiler optimizations that remove security checks

#### 2.14 Logic & Business Flaws
- **Race Conditions**: Concurrent request exploitation
- **TOCTOU**: Time-of-check to time-of-use vulnerabilities
- **Business Logic Bypass**: Skipping payment, validation bypass
- **Mass Assignment**: Unfiltered model updates from user input
- **Insecure Deserialization**: Pickle, YAML, JSON parsing flaws

### Phase 3: Database Security Analysis

Deep analysis of database structures, configurations, and access patterns across SQL, NoSQL, and BaaS platforms.

#### 3.1 SQL Database Security

**Structure Analysis:**
- Schema design flaws enabling data leakage
- Missing foreign key constraints allowing orphaned/inconsistent data
- Overly permissive column types (VARCHAR(MAX) for sensitive fields)
- Missing audit columns (created_at, updated_at, created_by)
- Lack of soft delete patterns for compliance data

**Query Security:**
- Dynamic SQL construction with string concatenation
- Stored procedures with SQL injection vectors
- Missing parameterized queries in ORM raw query usage
- Overly broad SELECT statements (SELECT * instead of column selection)
- Missing LIMIT/OFFSET on unbounded queries enabling data exfiltration
- Cursor-based attacks on large result sets

**Access Control:**
- Database users with excessive privileges (DBA for app connections)
- Missing row-level security policies
- Default database credentials unchanged
- Database accessible from public networks
- Missing connection encryption (TLS/SSL)
- Connection string hardcoded or in version control

**Platform-Specific SQL Checks:**
- **PostgreSQL**: RLS policies, pg_hba.conf, superuser roles, extension security (pg_crypto vs plaintext), search_path injection
- **MySQL/MariaDB**: GRANT privileges, LOAD DATA INFILE, secure-file-priv, binary log exposure
- **SQL Server**: xp_cmdshell enabled, TRUSTWORTHY database property, dynamic SQL in stored procedures
- **Firebird**: SYSDBA default password, UDF library security, role-based access
- **SQLite**: File permissions, encryption at rest (SEE/sqlcipher), journal mode security
- **Oracle**: TNS listener security, default accounts, privilege escalation via PL/SQL

#### 3.2 NoSQL Database Security

**MongoDB:**
- Authentication disabled (default in older versions)
- Bind address set to 0.0.0.0 (public access)
- Missing field-level encryption for PII
- NoSQL injection via operator injection ($gt, $ne, $regex)
- Aggregation pipeline injection
- Missing schema validation allowing arbitrary document structure
- GridFS exposed without access control
- Missing audit logging

**Redis:**
- No authentication (requirepass not set)
- BIND set to 0.0.0.0
- Dangerous commands enabled (FLUSHALL, CONFIG, DEBUG, EVAL)
- Lua script injection
- Missing rename-command for sensitive operations
- Unencrypted connections (no TLS)
- Keyspace exposure via INFO/KEYS commands

**CouchDB:**
- Admin party mode (no authentication)
- Missing validate_doc_update functions
- Overly permissive _security objects
- CORS misconfiguration
- Futon admin panel exposed

**DynamoDB:**
- Overly permissive IAM policies
- Missing encryption at rest
- No point-in-time recovery enabled
- Missing VPC endpoint for private access
- Scan operations without pagination limits

**Cassandra:**
- Authenticator set to AllowAllAuthenticator
- Missing encryption (server-to-server, client-to-server)
- Overly broad permissions grants
- Missing audit logging

#### 3.3 BaaS Platform Security

**Supabase:**
- Missing RLS policies on tables with sensitive data
- RLS policies with `true` condition (allow all)
- Service role key exposed in client-side code
- Edge functions without authentication
- Storage buckets with public access for sensitive files
- Realtime subscriptions without authorization checks
- Missing database webhooks validation
- Exposed PostgREST configuration
- Missing rate limiting on API endpoints

**Firebase/Firestore:**
- Database rules allowing unauthenticated read/write
- Firestore rules without proper `request.auth` checks
- Storage rules without file type/size validation
- Missing App Check enforcement
- API key exposed with overly permissive restrictions
- Cloud Functions without authentication
- Missing security rules for subcollections
- Realtime Database rules too permissive

**Firebase Cost & Performance Security:**

*Rule-Based Cost Detection:*
- Firestore rules with `allow read, write: if true;` (unlimited reads/writes = cost explosion)
- Firestore rules with `allow read: if request.auth != null;` (any authenticated user can read ALL documents)
- Realtime Database rules with `.read: true` or `.write: true` at root level
- Storage rules allowing unlimited file uploads without size/type restrictions
- Missing `request.resource.size` limits in Firestore create/update rules
- Rules that allow listing entire collections without filters (`allow list` without `request.query.limit`)

*Query Cost Analysis:*
- `getDocs(collection(db, "collection"))` without pagination (reads entire collection)
- `getDocs(query(collection(db, "collection")))` without `.limit()` clause
- Missing cursor-based pagination (`startAfter`, `startAt`, `endBefore`, `endAt`)
- Realtime Database `ref.once('value')` on root or large nodes
- Excessive snapshot listeners (`onSnapshot`) without proper unsubscribe
- Multiple concurrent `getDoc()` calls instead of batched reads or `getAll()`
- `getDocs()` inside loops (N+1 query pattern in Firestore)
- Missing field selection (reading entire documents when only few fields needed)
- Collection group queries without security rules covering all subcollections

*Cloud Functions Cost Triggers:*
- Firestore `onWrite`/`onCreate` triggers on high-write collections (each trigger = function invocation cost)
- Storage `onArchive`/`onDelete` triggers without event filtering
- HTTP functions without rate limiting (vulnerable to DDoS = cost spike)
- Scheduled functions running too frequently without purpose
- Functions with excessive memory allocation (always using 2GB when 256MB suffices)
- Missing `minInstances: 0` (keeping instances alive when not needed)
- `onRequest` functions without timeout configuration
- Functions that perform unnecessary reads before writes
- Recursive trigger patterns (function writes to same collection that triggers it)

*Realtime Database Cost Patterns:*
- Deep listeners on root node (`ref.on('value')` at `/`)
- Missing `.indexOn` rules causing full database scans for queries
- Large JSON structures stored as single nodes instead of distributed paths
- Missing disconnect handlers leaving stale data
- Excessive `ref.set()` calls instead of batched `ref.update()`
- Not using `ref.once()` when real-time updates aren't needed

*Storage Cost Patterns:*
- Missing file compression before upload (uploading uncompressed images/videos)
- No upload size limits enforced client-side AND server-side
- Missing file cleanup on account/document deletion
- Using `uploadBytes` instead of `uploadBytesResumable` for large files (memory spikes)
- Missing Firebase App Check for Storage (unauthorized uploads = cost)
- Not using CDN caching headers for public files (repeated downloads = cost)
- Missing lifecycle rules for old/deleted files

*Firestore Index Cost:*
- Missing composite indexes causing query failures or full scans
- Over-indexing (indexes on fields rarely queried = unnecessary write cost)
- Single-field index exemptions not configured for high-write fields
- Array-contains queries on large arrays (index size bloat)

*Connection & Instance Cost:*
- Excessive simultaneous Realtime Database connections (free tier: 100, paid: billed per connection)
- Firestore listeners not properly cleaned up on component unmount
- Missing offline persistence configuration causing reconnection storms
- Multiple Firebase app instances initialized unnecessarily
- Not using `firebase-admin` batch operations for bulk writes (individual writes = more cost)
- Missing connection pooling for server-side Firebase Admin SDK

*Cost Estimation Patterns:*
- Estimate monthly read/write/delete costs based on code patterns
- Identify potential infinite loops in Firestore triggers
- Detect patterns where a single user action triggers N database operations
- Flag unbounded queries that could read millions of documents
- Calculate projected storage growth without cleanup policies
- Identify missing budget alerts and spending limits configuration

**Appwrite:**
- Collection permissions set to `any` (public)
- Missing attribute-level validation
- Function execution without authentication
- Storage bucket permissions too broad
- Missing webhook signature validation
- API key scope too permissive

**Neon (Serverless Postgres):**
- Connection string with credentials in code
- Missing SSL/TLS enforcement
- Branch-based access not restricted
- Pooler connection security
- Missing RLS policies (same as PostgreSQL)
- API key exposure

**PocketBase:**
- Default admin credentials unchanged
- Collection rules too permissive
- Missing field encryption for sensitive data
- File upload rules without validation
- API rate limiting not configured

**Convex:**
- Missing authentication in functions
- Overly broad document access rules
- Missing validation on mutations
- Sensitive data in function arguments (logged)
- Missing row-level security patterns

### Phase 4: SLSA Build L3 (v1.2) Supply Chain Security

Assess supply chain integrity against SLSA (Supply-chain Levels for Software Artifacts) framework.

#### 4.1 Source Integrity
- **Version Control**: Signed commits verification, branch protection rules
- **Code Review**: Required reviews for merges, CODEOWNERS file present
- **Access Control**: Repository permissions audit, 2FA enforcement
- **Provenance**: Source location verifiable, build instructions documented

#### 4.2 Build Integrity
- **Build Pipeline**: Automated CI/CD, reproducible builds, hermetic builds
- **Build Service**: Hosted build service (not developer machine), isolated environments
- **Build Provenance**: Signed build attestations, SLSA provenance generation
- **Artifact Signing**: Artifacts signed with Sigstore/cosign/GPG
- **Container Security**: Base image verification, no root user, minimal layers

#### 4.3 Dependency Security
- **Lock Files**: package-lock.json, yarn.lock, Pipfile.lock, Cargo.lock present and committed
- **Pinning**: Dependencies pinned to exact versions (not ranges)
- **Verification**: Dependency integrity hashes verified
- **SBOM**: Software Bill of Materials generated and maintained
- **Vulnerability Scanning**: Automated dependency vulnerability scanning configured
- **Typosquatting**: Check for suspicious package names
- **License Audit**: All dependency licenses compatible with project license

#### 4.4 Deployment Security
- **Environment Separation**: Clear separation between dev/staging/production
- **Secret Management**: Secrets in vault/manager, not in code or env files
- **Access Deployment**: Deployment access restricted and audited
- **Rollback Capability**: Ability to rollback deployments securely
- **Infrastructure as Code**: IaC templates audited for misconfigurations

### Phase 5: OWASP ASVS Verification

Systematic verification against OWASP Application Security Verification Standard (ASVS) 5.0.0 (stable since 2025-05-30). Reference requirements with the version, e.g. `v5.0.0-1.2.5`.

#### V1: Architecture, Design and Threat Modeling
- Threat model documented and up-to-date
- Security architecture documented
- Trusted/untrusted boundary identification
- Security controls for each component

#### V2: Authentication
- Password requirements (length, complexity, breach database check)
- Multi-factor authentication implementation
- Credential storage (bcrypt, scrypt, Argon2 - never MD5/SHA1)
- Session fixation prevention
- Account lockout mechanisms
- Credential recovery security

#### V3: Session Management
- Session ID generation (cryptographically random)
- Session lifecycle (timeout, invalidation)
- Cookie security flags (HttpOnly, Secure, SameSite)
- Session binding to user attributes
- Concurrent session control

#### V4: Access Control
- Default deny principle
- Function-level access control
- Data-level access control
- JWT access control verification
- OAuth scope validation

#### V5: Validation, Sanitization and Encoding
- Input validation on all entry points
- Output encoding for context (HTML, JS, URL, SQL)
- Serialization security
- HTTP request smuggling prevention
- Mass assignment protection

#### V6: Stored Cryptography
- Cryptographic key management
- Encryption algorithms (AES-256, RSA-2048+, never DES/RC4)
- Random number generation (CSPRNG)
- Key rotation procedures
- Certificate validation

#### V7: Error Handling and Logging
- Error messages don't reveal sensitive info
- Security event logging (auth failures, access violations)
- Log integrity protection
- PII in logs (must be redacted)
- Log injection prevention

#### V8: Data Protection
- Sensitive data identification and classification
- Data at rest encryption
- Data in transit encryption (TLS 1.2+)
- PII minimization
- Data retention and deletion policies

#### V9: Communication Security
- TLS configuration (cipher suites, protocols)
- Certificate validation and pinning
- HTTP Strict Transport Security (HSTS)
- DNS security (DNSSEC, CAA records)

#### V10: Malicious Code
- No backdoors or hidden functionality
- No time bombs or logic bombs
- Anti-tampering mechanisms
- Code obfuscation review (if applicable)

#### V11: Business Logic
- Business logic flow validation
- Feature abuse prevention
- Automated threat protection (CAPTCHA, rate limiting)
- File upload validation and scanning

#### V12: Files and Resources
- File upload restrictions (type, size, content)
- File execution prevention
- Path traversal protection
- File inclusion vulnerability prevention

#### V13: API and Web Service
- API authentication and authorization
- API rate limiting and throttling
- GraphQL introspection disabled in production
- REST API input validation
- WebSocket security

#### V14: Configuration
- Secure build and deployment configuration
- Unnecessary features/ports/services disabled
- Security headers properly configured
- Error handling configuration
- Production debug mode disabled

### Phase 6: Regulatory Compliance Analysis

#### 6.1 LGPD (Lei Geral de Proteção de Dados - Brazil)
- **Data Inventory**: Personal data mapping and classification
- **Legal Basis**: Processing legal basis documented (consent, legitimate interest, etc.)
- **Consent Management**: Granular consent collection, withdrawal mechanism
- **Data Subject Rights**: Access, correction, deletion, portability endpoints
- **DPO Contact**: Data Protection Officer contact information published
- **Cross-Border Transfer**: International data transfer safeguards
- **Breach Notification**: Incident response plan with 72h notification to ANPD
- **Privacy by Design**: Default privacy settings, data minimization
- **Third-Party Processing**: Data processing agreements with processors

#### 6.2 GDPR (General Data Protection Regulation - EU)
- All LGPD checks apply, plus:
- **Data Protection Impact Assessment (DPIA)**: For high-risk processing
- **Records of Processing Activities (ROPA)**: Documented and maintained
- **Right to be Forgotten**: Automated data deletion capability
- **Data Portability**: Machine-readable export (JSON/CSV)
- **Consent Records**: Timestamped consent with version tracking
- **EU Representative**: Non-EU companies with EU representative appointed
- **Standard Contractual Clauses**: For international transfers

#### 6.3 SOC 2 Type II
- **Security**: Access controls, logical/physical security
- **Availability**: SLA monitoring, incident management, disaster recovery
- **Processing Integrity**: Input validation, error handling, quality assurance
- **Confidentiality**: Data classification, encryption, access restrictions
- **Privacy**: Collection, use, retention, disclosure, disposal practices
- **Continuous Monitoring**: Automated compliance checks, audit logging
- **Change Management**: Documented change procedures, approval workflows

#### 6.4 HIPAA (Health Insurance Portability and Accountability Act - US)
- **PHI Identification**: Protected Health Information mapped in codebase
- **Access Controls**: Role-based access to PHI, minimum necessary standard
- **Audit Logging**: All PHI access logged with user, timestamp, action
- **Encryption**: PHI encrypted at rest (AES-256) and in transit (TLS 1.2+)
- **Business Associate Agreements**: BAA with all third-party services handling PHI
- **Breach Notification**: HIPAA-specific breach notification procedures
- **De-identification**: Safe Harbor or Expert Determination methods
- **Integrity Controls**: PHI tampering detection and prevention

#### 6.5 CCPA/CPRA (California Consumer Privacy Act / Privacy Rights Act)
- **Consumer Rights**: Right to know, delete, opt-out, correct, limit use
- **Sale/Sharing Disclosure**: "Do Not Sell" mechanism if applicable
- **Sensitive Personal Information**: SPI collection with opt-in consent
- **Service Provider Agreements**: CCPA-compliant contracts with processors
- **Data Minimization**: Collection limited to stated purposes
- **Retention Schedules**: Documented retention periods per data category

### Phase 7: Vibe Coding Heuristics

Specific heuristic analysis for vulnerability patterns commonly seen in AI-assisted code. CSReview does not prove AI authorship and does not perform deterministic authorship attribution. In the npm engine, `vibeRisk` is a static boolean heuristic attached to selected vulnerability patterns so the report can prioritize issues that commonly appear in rushed agent-generated code.

#### 7.1 AI-Generated Code Patterns to Detect

**Authentication & Authorization Bypass:**
- Placeholder authentication (if(true) { next(); })
- Missing middleware on protected routes
- Client-side-only authentication checks
- Hardcoded bypass flags (DEBUG=true, SKIP_AUTH=true)
- JWT verification disabled or using 'none' algorithm
- Missing token expiration checks

**Data Exposure Patterns:**
- SELECT * queries exposing all columns including sensitive fields
- API endpoints returning full user objects (including password hashes)
- Missing response filtering/sanitization
- Overly permissive CORS (Access-Control-Allow-Origin: *)
- Database connection strings in client-side code
- API keys in frontend environment variables

**Injection Vulnerabilities (Common in AI Code):**
- String concatenation in SQL queries (AI often generates this pattern)
- Unsanitized user input in shell commands (exec, spawn, system)
- Template literals with user input (JS template injection)
- Raw HTML rendering (dangerouslySetInnerHTML, v-html, innerHTML)
- Eval-like functions with user data (eval, Function, deserialize)

**Configuration Mistakes:**
- Default credentials unchanged (admin/admin, root/root)
- Development settings in production (debug=True, verbose logging)
- Missing security headers
- Permissive file upload (any type, any size)
- SSL/TLS verification disabled (NODE_TLS_REJECT_UNAUTHORIZED=0)
- Environment files committed to git

**Dependency Issues:**
- Outdated or deprecated packages recommended by AI
- Non-existent packages (AI hallucination)
- Packages with known vulnerabilities
- Unnecessary dependencies increasing attack surface
- Mixed package managers (npm + yarn + pnpm)

#### 7.2 AI-Assisted Development Anti-Patterns

**Over-Confidence in Security:**
- "This is secure" comments without actual security measures
- Using crypto.createHash('md5') for passwords (AI often suggests this)
- Claiming code is "production-ready" without security review
- Missing error handling with generic catch-all
- Suggesting security-through-obscurity as primary defense

**Missing Security Thinking:**
- No input validation on user-facing endpoints
- No rate limiting on authentication endpoints
- No logging of security events
- Missing CSRF protection
- No file upload validation
- Missing pagination on list endpoints (DoS vector)

**Copy-Paste Vulnerabilities:**
- Stack Overflow code with known vulnerabilities
- Tutorial code with intentional security gaps
- Outdated security patterns (MD5, DES, RC4)
- Hardcoded example credentials from documentation

#### 7.3 Vibe Coding Heuristic Labels

Each finding may include a "Vibe Risk" flag indicating that the vulnerability matches a pattern often introduced during AI-assisted development. This is a static boolean heuristic in the engine and a prioritization hint for the agent; it does not prove AI authorship.

| Label | Meaning | Limit |
|-------|---------|-------|
| **Vibe Risk: Yes** | Pattern commonly appears in rushed or AI-assisted code | Not authorship evidence |
| **Vibe Risk: No** | Pattern is not tagged as a vibe-coding heuristic | Not proof the code is human-written |

### Phase 8: Report Generation

Generate TWO reports under the selected output directory, normally `<project>/csreview-reports/`. Report files are allowed audit artifacts; they do not mean the CSReview skill was installed inside the project:

---

## Report 1: HTML Report (For Humans)

File: `csreview-reports/<agent>_security-report.html`

### Executive Summary Section
- **Overall Security Score**: 0-100 scale with color coding
- **Severity Distribution**: Pie/bar chart (Critical/High/Medium/Low/Info)
- **Vulnerability Categories**: Bar chart by category
- **Top 5 Critical Findings**: Quick reference cards
- **Risk Assessment**: Overall risk level (Critical/High/Medium/Low)
- **Scan Metadata**: Timestamp, files analyzed, lines scanned

### Technical Findings Section
For each vulnerability found:

```
┌─────────────────────────────────────────────────┐
│ [SEVERITY BADGE] Vulnerability Title            │
├─────────────────────────────────────────────────┤
│ Category: Injection / Auth / Data Leakage / etc │
│ Location: src/file.ts:142                       │
│ CWE: CWE-89 (SQL Injection)                     │
│                                                 │
│ Description:                                    │
│ Detailed explanation of the vulnerability       │
│                                                 │
│ Vulnerable Code:                                │
│ [syntax-highlighted code snippet]               │
│                                                 │
│ Potential Exploitation Path (theoretical, unverified): │
│ Static-analysis hypothesis; not a validated or executed exploit. │
│                                                 │
│ Impact:                                         │
│ What could happen if exploited                  │
│                                                 │
│ Recommended Fix:                                │
│ [syntax-highlighted corrected code]             │
│                                                 │
│ References:                                     │
│ OWASP, CVE links, documentation                 │
└─────────────────────────────────────────────────┘
```

### Report Features
- **Navigation**: Sidebar with anchor links to each finding
- **Filtering**: Filter by severity, category, or status
- **Syntax Highlighting**: Code blocks with language-specific colors
- **Color Coding**: Red=Critical, Orange=High, Yellow=Medium, Blue=Low, Gray=Info
- **Export**: Button to download findings as JSON
- **Print-Friendly**: Optimized CSS for PDF export
- **Responsive**: Works on desktop and mobile

### HTML Template Structure

```html
<!DOCTYPE html>
<html lang="[user-language]">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit Report - [Project Name]</title>
  <style>
    /* Professional styling with: */
    /* - CSS variables for theming */
    /* - Severity color badges */
    /* - Syntax highlighting */
    /* - Responsive grid layout */
    /* - Print media queries */
    /* - Smooth scroll navigation */
  </style>
</head>
<body>
  <header>
    <h1>Security Audit Report</h1>
    <div class="meta">Project: [name] | Date: [timestamp] | Score: [score]/100</div>
  </header>

  <nav class="sidebar">
    <!-- Executive Summary -->
    <!-- Findings by Severity -->
    <!-- Findings by Category -->
  </nav>

  <main>
    <section id="executive-summary">
      <!-- Score gauge -->
      <!-- Severity chart (SVG) -->
      <!-- Category chart (SVG) -->
      <!-- Top 5 critical cards -->
      <!-- SLSA Level indicator -->
      <!-- OWASP ASVS compliance percentage -->
      <!-- Regulatory compliance status (LGPD/GDPR/SOC2/HIPAA/CCPA) -->
      <!-- Vibe Coding Risk indicator -->
    </section>

    <section id="findings">
      <!-- Each finding as a card -->
      <article class="finding critical|high|medium|low|info">
        <header>
          <span class="severity-badge">CRITICAL</span>
          <h2>SQL Injection in User Authentication</h2>
        </header>
        <div class="finding-meta">
          <span>Category: Injection</span>
          <span>Location: src/auth.ts:45</span>
          <span>CWE: CWE-89</span>
          <span>Vibe Risk: Yes</span>
          <span>Compliance: OWASP ASVS V5.3, GDPR Art.32</span>
        </div>
        <div class="finding-content">
          <h3>Description</h3>
          <p>...</p>
          <h3>Vulnerable Code</h3>
          <pre><code class="language-typescript">...</code></pre>
          <h3>Potential Exploitation Path (theoretical, unverified)</h3>
          <p>Static-analysis hypothesis only; not a validated or executed exploit.</p>
          <h3>Impact</h3>
          <p>...</p>
          <h3>Recommended Fix</h3>
          <pre><code class="language-typescript">...</code></pre>
          <h3>References</h3>
          <ul>...</ul>
        </div>
      </article>
    </section>

    <section id="database-security">
      <!-- SQL database findings -->
      <!-- NoSQL database findings -->
      <!-- BaaS platform findings -->
      <!-- Firebase cost & performance findings with cost impact estimates -->
      <!-- .NET / Delphi / Go / Binary security findings -->
    </section>

    <section id="cost-analysis">
      <!-- Firebase/BaaS cost estimation based on code patterns -->
      <!-- Projected monthly spend based on detected patterns -->
      <!-- Cost optimization recommendations -->
      <!-- Unbounded query warnings -->
      <!-- Missing rate limit impact analysis -->
    </section>

    <section id="compliance-matrix">
      <!-- LGPD compliance status per article -->
      <!-- GDPR compliance status per article -->
      <!-- SOC 2 Trust Service Criteria -->
      <!-- HIPAA Safeguards -->
      <!-- CCPA/CPRA requirements -->
    </section>

    <section id="vibe-coding">
      <!-- AI-generated code risk assessment -->
      <!-- Pattern distribution chart -->
      <!-- Recommendations for vibe coding users -->
    </section>

    <section id="platform-specific">
      <!-- .NET / ASP.NET security findings -->
      <!-- Delphi / Lazarus security findings -->
      <!-- Go security findings -->
      <!-- DLL / Installer security findings -->
      <!-- Binary security findings -->
    </section>
  </main>

  <footer>
    <button id="export-json">Export as JSON</button>
    <p>Generated by CSReview - Code Security Review Skill</p>
  </footer>

  <script>
    // Filtering, navigation, export functionality
  </script>
</body>
</html>
```

---

## Report 2: Markdown Report (For AI Agents)

File: `csreview-reports/<agent>_security-findings.md`

This report is structured for humans and AI coding agents to parse, understand, prioritize, and plan remediations. It contains machine-readable findings with exact file locations, vulnerable code evidence, exploitation context, and recommended remediation approaches. It is **not** permission for CSReview to change the audited code. **Always generated in English** regardless of user language.

### Markdown Structure

```markdown
# Security Findings Report

**Project**: [project-name]
**Date**: [YYYY-MM-DD HH:MM:SS]
**Security Score**: [score]/100
**SLSA Level**: [0-3]
**OWASP ASVS Coverage**: [percentage]%
**Total Findings**: [count]
**Critical**: [count] | **High**: [count] | **Medium**: [count] | **Low**: [count] | **Info**: [count]
**Vibe Coding Heuristics**: [Vibe Risk: count] | [Not flagged: count]

---

## Summary Table

| ID | Severity | Category | File | Line | Issue | Vibe Risk | Compliance |
|----|----------|----------|------|------|-------|-----------|------------|
| 001 | CRITICAL | SQL Injection | src/auth.ts | 45 | Raw SQL query with user input | Vibe Risk: Yes | ASVS V5.3, GDPR Art.32 |
| 002 | HIGH | XSS | src/components/UserInput.vue | 12 | Unsanitized v-html binding | Vibe Risk: Yes | ASVS V5.2, LGPD Art.46 |
| ... | ... | ... | ... | ... | ... | ... | ... |

---

## Findings

### Finding #001

**Severity**: CRITICAL
**Category**: SQL Injection
**CWE**: CWE-89
**File**: `src/auth.ts`
**Line**: 45
**Status**: PENDING
**Vibe Risk**: Yes
**Compliance**: OWASP ASVS V5.3, GDPR Art.32, LGPD Art.46, SOC 2 CC6.1

#### Description
Raw SQL query constructed with string concatenation using user-supplied input, allowing SQL injection attacks.

#### Vulnerable Code
```typescript:src/auth.ts:40-50
// Lines 40-50
const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
const result = await db.query(query);
```

#### Potential Exploitation Path (theoretical, unverified)
This is a hypothesis derived from static analysis, not a validated or executed exploit.

1. Attacker submits email: `' OR '1'='1`
2. Query becomes: `SELECT * FROM users WHERE email = '' OR '1'='1' AND password = 'anything'`
3. Authentication bypass achieved

#### Impact
- Full authentication bypass
- Access to any user account
- Potential data exfiltration via UNION-based injection
- LGPD violation: unauthorized access to personal data (Art.46)
- GDPR violation: inadequate security measures (Art.32)

#### Fix Required
Replace raw SQL query with parameterized query:

```typescript:src/auth.ts:40-50
// FIXED: Use parameterized query
const query = 'SELECT * FROM users WHERE email = $1 AND password = $2';
const result = await db.query(query, [email, password]);
```

#### References
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP ASVS V5.3.3: https://owasp.org/www-project-application-security-verification-standard/

---

## Database Security Findings

### SQL Database Issues
| ID | Severity | Database | File | Issue | Recommendation |
|----|----------|----------|------|-------|----------------|
| DB001 | CRITICAL | PostgreSQL | src/db.ts:23 | Missing RLS on users table | Enable RLS with user-scoped policies |

### NoSQL Database Issues
| ID | Severity | Database | File | Issue | Recommendation |
|----|----------|----------|------|-------|----------------|
| DB010 | HIGH | MongoDB | src/models/user.js:15 | NoSQL injection via $gt operator | Use MongoDB driver query builders |

### BaaS Platform Issues
| ID | Severity | Platform | Config | Issue | Recommendation |
|----|----------|----------|--------|-------|----------------|
| BAAS001 | CRITICAL | Supabase | supabase/config.ts:5 | Service role key in client code | Move to server-side environment |

### Firebase Cost & Performance Issues
| ID | Severity | Category | File | Issue | Cost Impact | Recommendation |
|----|----------|----------|------|-------|-------------|----------------|
| COST001 | CRITICAL | Firestore Rules | firestore.rules:12 | `allow read, write: if true;` | Unlimited reads/writes = cost explosion | Restrict to authenticated users with resource-level checks |
| COST002 | HIGH | Query | src/hooks/useUsers.ts:23 | `getDocs(collection(db, "users"))` without pagination | Reads entire collection | Add `.limit()` and cursor-based pagination |
| COST003 | HIGH | Cloud Functions | functions/src/index.ts:45 | `onWrite` trigger on high-write collection | Each write = function invocation cost | Filter events or use batch processing |
| COST004 | MEDIUM | Storage | src/utils/upload.ts:15 | No file size limit before upload | Large files = storage + bandwidth cost | Add client-side + server-side size validation |
| COST005 | MEDIUM | Realtime DB | src/App.tsx:30 | `ref.on('value')` on root node | Downloads entire database on every change | Listen to specific paths only |
| COST006 | LOW | Connections | src/context/Auth.tsx:10 | Multiple `onSnapshot` listeners without cleanup | Billed per connection | Unsubscribe on component unmount |

### .NET / Delphi / Go / Binary Security Issues
| ID | Severity | Category | File | Issue | Recommendation |
|----|----------|----------|------|-------|----------------|
| DOTNET001 | HIGH | ASP.NET | Controllers/AdminController.cs:15 | Missing `[Authorize]` attribute | Add authorization attribute |
| DELPHI001 | CRITICAL | Database | Unit1.pas:45 | Hardcoded Firebird credentials | Use encrypted connection string storage |
| GO001 | HIGH | Web | main.go:67 | SQL injection via `fmt.Sprintf` | Use parameterized queries with `db.Query` |
| DLL001 | MEDIUM | Binary | installer/setup.iss:23 | Missing digital signature | Sign installer with Authenticode certificate |

---

## SLSA Assessment

| Requirement | Status | Details |
|-------------|--------|---------|
| Source Version Control | [PASS/FAIL] | Git with signed commits |
| Branch Protection | [PASS/FAIL] | Required reviews configured |
| Build Provenance | [PASS/FAIL] | SLSA attestations generated |
| Dependency Pinning | [PASS/FAIL] | Lock files present |
| Artifact Signing | [PASS/FAIL] | Sigstore/cosign configured |

**Current SLSA Level**: [0-3]
**Recommendations**: [list of actions to reach SLSA Build L3 (v1.2)]

---

## OWASP ASVS Compliance

| Category | Name | Pass | Fail | N/A | Score |
|----------|------|------|------|-----|-------|
| V1 | Architecture | 5 | 2 | 3 | 71% |
| V2 | Authentication | 8 | 4 | 0 | 67% |
| ... | ... | ... | ... | ... | ... |

**Overall ASVS Score**: [percentage]%

---

## Compliance Matrix

### LGPD
| Article | Requirement | Status | Finding Reference |
|---------|-------------|--------|-------------------|
| Art.46 | Security measures | FAIL | #001, #003 |
| Art.48 | Breach notification | PASS | - |

### GDPR
| Article | Requirement | Status | Finding Reference |
|---------|-------------|--------|-------------------|
| Art.32 | Security of processing | FAIL | #001 |
| Art.25 | Data protection by design | PASS | - |

### SOC 2 Type II
| Criteria | Requirement | Status | Finding Reference |
|----------|-------------|--------|-------------------|
| CC6.1 | Logical access controls | FAIL | #001, #005 |
| CC6.7 | Data transmission | PASS | - |

### HIPAA
| Safeguard | Requirement | Status | Finding Reference |
|-----------|-------------|--------|-------------------|
| 164.312(a) | Access control | FAIL | #002 |
| 164.312(e) | Transmission security | PASS | - |

### CCPA/CPRA
| Section | Requirement | Status | Finding Reference |
|---------|-------------|--------|-------------------|
| 1798.100 | Right to know | FAIL | Missing endpoint |
| 1798.105 | Right to delete | PASS | - |

---

## Vibe Coding Assessment

### Vibe-Risk Findings
Findings matching vulnerability patterns that commonly appear in rushed or AI-assisted code. This does not prove AI authorship.

| ID | Pattern | Heuristic | Recommendation |
|----|---------|-----------|----------------|
| 001 | String concatenation SQL | Vibe Risk: Yes | Replace with parameterized queries |
| 003 | MD5 password hashing | Vibe Risk: Yes | Switch to bcrypt/Argon2 |

### AI-Assisted Code Quality Notes
- **Security Awareness**: [Low/Medium/High]
- **Common AI Anti-Patterns Found**: [count]
- **Recommendation**: [brief guidance for the user]

---

## Fix Priority Order

Apply fixes in this order:

1. **CRITICAL findings first**: Authentication bypass, SQL injection, RCE, exposed secrets
2. **HIGH findings second**: XSS, CSRF, IDOR, missing authorization
3. **MEDIUM findings third**: CORS misconfiguration, insecure headers, rate limiting
4. **LOW findings fourth**: Defense-in-depth improvements, best practices
5. **INFO findings last**: Recommendations, documentation updates

Within each severity, prioritize by:
1. Vibe-risk findings (patterns often repeated in rushed or AI-assisted code)
2. Compliance-critical findings (regulatory violations)
3. Database security issues
4. Supply chain concerns

## Agent Instructions

When fixing these findings (note: CSReview only reports; the coding agent or developer applies fixes):

1. Read the vulnerable file at the specified line numbers
2. Understand the context before applying the fix
3. If the framework is unfamiliar, research official documentation before applying fixes
4. Treat the recommendation as guidance, not a patch; inspect the framework, schema, tests, and surrounding code before changing anything
5. Verify the fix doesn't break existing functionality
6. Mark the finding as FIXED after successful application
7. Run tests to ensure no regressions
8. Commit changes with descriptive message: `fix(security): [brief description of fix]`
9. After all fixes, re-run CSReview to verify remediation
```

---

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| **Critical** | Direct data breach, RCE, auth bypass, exposed PII | Immediate fix required |
| **High** | Significant vulnerability, exploitable with effort | Fix within 24-48h |
| **Medium** | Moderate risk, requires specific conditions | Fix within 1 week |
| **Low** | Minor issue, defense-in-depth improvement | Fix in next sprint |
| **Info** | Best practice recommendation, no direct risk | Consider for improvement |

## Built-in Code Review System

CSReview includes a complete code review system that eliminates the need for external review skills. This system provides 5 integrated review modes:

### Review Mode 1: Standard Code Review (`codex:review` equivalent)

Comprehensive code review covering:

**Code Quality:**
- Code readability and maintainability
- Naming conventions consistency
- Function/method complexity (cyclomatic complexity)
- Dead code detection
- Code duplication identification
- SOLID principles adherence
- DRY principle violations
- Separation of concerns

**Architecture:**
- Design pattern appropriateness
- Module coupling analysis
- Dependency direction violations
- Interface segregation
- Single responsibility violations

**Performance:**
- Algorithm complexity (O(n) analysis)
- Memory leak potential
- Unnecessary object creation
- Database query optimization (N+1 queries)
- Caching opportunities
- Bundle size impact

**Testing:**
- Test coverage gaps
- Missing edge case tests
- Test isolation issues
- Mock overuse detection
- Missing integration tests

**Documentation:**
- Missing JSDoc/docstrings on public APIs
- Outdated comments
- Missing README sections
- Undocumented breaking changes

### Review Mode 2: Adversarial Review (`codex:adversarial-review` equivalent)

Red-team mindset review that actively tries to break the code:

**Attack Vectors:**
- Boundary condition exploitation
- Race condition identification
- Resource exhaustion scenarios
- Error handling bypass attempts
- State corruption possibilities
- Input validation gaps at every boundary

**Failure Modes:**
- What happens when external services are down?
- What happens with malformed input at each layer?
- What happens under extreme load?
- What happens with concurrent modifications?
- What happens when disk/memory is full?

**Edge Cases:**
- Empty/null/undefined inputs
- Maximum size inputs
- Unicode/special characters
- Timezone-sensitive operations
- Floating point precision issues
- Integer overflow scenarios

**Adversarial Questions:**
- "How can I make this code fail?"
- "What's the worst input an attacker could provide?"
- "What assumptions does this code make that could be wrong?"
- "What happens if I remove this check?"
- "Can I bypass this validation?"

### Review Mode 3: Security-Focused Code Review (`code-review` equivalent)

Security-specific review integrated with the main CSReview analysis:

- All Phase 2 (Ultra-Deep Security) checks applied to specific code changes
- All Phase 3 (Database Security) checks for data layer changes
- All Phase 7 (Vibe Coding) pattern detection for AI-generated code
- Security impact assessment of each change
- Threat model updates required for architectural changes

### Review Mode 4: Requesting Code Review (`requesting-code-review` equivalent)

When a developer or coding agent requests a review:

**Review Request Protocol:**
1. Identify the scope of changes (files, functions, modules)
2. Determine review depth (quick scan, standard, deep)
3. Select applicable review modes (quality, adversarial, security)
4. Generate review checklist based on change type
5. Execute review and generate findings
6. Prioritize findings by severity and actionability

**Change-Type Detection:**
- **New feature**: Full review with adversarial testing
- **Bug fix**: Verify fix correctness, check for regression
- **Refactoring**: Verify behavior preservation, check for missed cases
- **Configuration change**: Security impact assessment
- **Dependency update**: Vulnerability and license check
- **Database migration**: Data integrity and rollback assessment

### Review Mode 5: Receiving Code Review (`receiving-code-review` equivalent)

When CSReview findings are received by a coding agent:

**Response Protocol:**
1. Parse findings from the MD report
2. Categorize by severity and type
3. For each finding:
   - Acknowledge the issue
   - Research the fix (if framework is unfamiliar, consult official docs)
   - Propose a solution
   - Apply the fix (coding agent responsibility)
   - Verify the fix doesn't introduce new issues
4. Report back with summary of changes made

**Fix Verification Checklist:**
- [ ] Fix addresses the specific vulnerability
- [ ] Fix doesn't break existing functionality
- [ ] Fix follows framework best practices
- [ ] Fix doesn't introduce new vulnerabilities
- [ ] Fix includes appropriate tests (if applicable)
- [ ] Fix is documented (if behavior changes)

### Integrated Review Workflow

When CSReview is invoked, it can operate in any of these modes:

```
@csreview                                    → Full 8-phase security audit
@csreview review [files]                     → Standard code review (Mode 1)
@csreview adversarial [files]                → Adversarial review (Mode 2)
@csreview security-review [files]            → Security code review (Mode 3)
@csreview request-review [PR/branch/commit]  → Request review of changes (Mode 4)
@csreview review csreview-reports/codex_security-findings.md        → Plan remediation from report without CSReview editing source code
```

## Execution Workflow

When invoked, follow these steps:

1. **Confirm global skill scope**: If the task involves installing or updating CSReview itself, use the agent's global skills directory by default. Do not install CSReview into the analyzed project unless the user explicitly requested project-local installation.
2. **Announce the scan**: Inform user about starting security analysis
3. **Phase 0 - Tool Detection**: Attempt Semgrep first (`semgrep --version`, then `semgrep --config auto --json --quiet <project_path>`). Then attempt read-only dependency scanners (`pnpm audit --json` when `pnpm-lock.yaml` exists, otherwise `npm audit --json` for npm lockfiles, plus `osv-scanner scan --format json <project_path>` when installed). Detect installed framework/security tools (bandit, trivy, snyk, gosec, eslint, codeql, pip-audit, etc.). Report which tools are available and which are missing. Run all available relevant tools against the project. Normalize tool output into unified findings format.
4. **Phase 1 - Recon**: Scan project structure, identify technologies, map attack surface
5. **Phase 2 - Deep Analysis**: Systematically check each vulnerability category (injection, auth, data leakage, XSS, CSRF, config, deps, cloud, .NET, Delphi/Lazarus, Go, DLL/installer, platform-specific, logic flaws)
6. **Phase 3 - Database Security**: Analyze SQL/NoSQL/BaaS database structures, access patterns, Firebase cost/performance, and configurations
7. **Phase 4 - SLSA Build L3 (v1.2)**: Assess supply chain integrity (source, build, dependency, deployment)
8. **Phase 5 - OWASP ASVS**: Systematic verification against V1-V14 categories
9. **Phase 6 - Compliance**: Check LGPD, GDPR, SOC 2, HIPAA, CCPA-CPRA requirements
10. **Phase 7 - Vibe Coding**: Flag static heuristics for vulnerability patterns commonly seen in rushed or AI-assisted code
11. **Progress updates**: Keep user informed of analysis progress throughout
12. **Phase 8 - Report Generation**: Create BOTH reports:
    - `csreview-reports/<agent>_security-report.html` (visual report in user's language for human review)
    - `csreview-reports/<agent>_security-findings.md` (structured report in English for human/coding-agent remediation planning)
13. **Deliver reports**: Provide absolute paths to both generated files:
    - HTML report path for the user to click/open in a browser
    - Markdown report path for the coding agent to analyze before remediation
14. **Summary**: Give brief verbal summary of critical/high findings including tool-detected vs AI-estimated findings, compliance gaps, vibe coding risks, and Firebase cost issues
15. **Offer next step**: Ask whether the user wants a prioritized remediation plan or wants a separate coding agent session to apply selected fixes with project-context validation.

## Important Guidelines

- **READ-ONLY**: CSReview NEVER modifies, deletes, moves, or creates source code in the analyzed project. It only identifies, reports, and suggests remediation approaches.
- **Global Installation Default**: CSReview MUST be installed in the agent's global skill/instruction environment by default. Do not place CSReview skill files in the analyzed project unless the user explicitly requested project-local installation.
- **Tool Detection First**: ALWAYS run Phase 0 (tool detection) before any analysis. The user must know which mode is active.
- **Agent-Only Risk Disclosure**: When operating in Agent-Only mode, the agent MUST explicitly warn the user that findings have lower confidence and that real security tools should be installed for production audits. A less knowledgeable agent may miss critical vulnerabilities or produce incorrect recommendations.
- **Semgrep Required Baseline**: Always attempt to run `semgrep` (universal) and the language-specific primary tool for the project being analyzed. If Semgrep is missing, mark the run lower-confidence and provide installation commands.
- **Dependency SCA Complement**: Run `pnpm audit --json` for Node.js roots with `pnpm-lock.yaml`, otherwise run `npm audit --json` for npm lockfiles. Also run `osv-scanner scan --format json <project_path>` when OSV-Scanner is installed. Never run dependency fix/update commands during CSReview.
- **External Research Required When Uncertain**: If the agent is unsure about framework behavior, safe configuration, version-specific APIs, exploitability, or remediation, it MUST search external sources before making a confident claim. Use official framework documentation first, then vendor security advisories and specialized security sources such as OWASP, CWE, CVE/NVD, GitHub Security Advisories, OSV.dev, and Snyk. Do not guess.
- **All Relevant Files Are Scanned**: All relevant in-scope files are scanned; generated, vendor, minified, and IDE directories (e.g. `dist`, `build`, `vendor`, `bin`, `obj`, `.next`, `node_modules`, `.git`) and the generated reports are excluded. Do not rely on sampling for in-scope source.
- **Never expose secrets in chat**: If you find hardcoded credentials, mention them in the reports only, not in the conversation
- **Be thorough but practical**: Focus on exploitable vulnerabilities, not theoretical edge cases
- **Provide actionable remediation**: Every finding must include concrete remediation guidance, but the fix is applied by the human developer or coding agent after reviewing context, not by CSReview.
- **Context matters**: Consider the application type (internal tool vs public API) when assessing severity
- **False positives**: Only report confirmed vulnerabilities, avoid noise
- **Prioritize**: Critical and High findings should be clearly highlighted
- **Respect scope**: Only analyze code in the specified project, don't test external services
- **MD report precision**: File paths and line numbers in the MD report must be exact so humans or coding agents can safely inspect and plan remediation.
- **HTML report language**: Generate the HTML report in the same language as the user's conversation language
- **MD report language**: Always generate the MD report in English regardless of user language (for agent consumption)
- **Compliance findings**: Clearly map each compliance gap to the specific regulation article/section
- **Vibe coding markers**: Tag findings with a Vibe Risk boolean (Yes/No). This is a heuristic signal, not a numeric score and not proof of AI authorship.
- **Database findings**: Include specific database engine version requirements when relevant
- **SLSA scoring**: Clearly indicate current SLSA level and what's needed to reach level 3
- **Unknown frameworks**: If the analyzed code uses a framework the agent is not familiar with (e.g., Lazarus, Delphi, niche frameworks), the agent MUST research using official documentation from the framework's official website, database vendor documentation, and community forums before reporting findings and suggesting fixes
- **Documentation sourcing**: For each finding, reference the official documentation of the relevant framework, database, or platform (e.g., PostgreSQL docs, Supabase docs, Firebase docs, Appwrite docs, MongoDB docs, etc.)
- **Forum research**: When encountering unusual errors or obscure vulnerabilities, search relevant community forums (Stack Overflow, GitHub Issues, framework-specific forums) to provide accurate, tested solutions
- **Transparency**: Report all steps taken during the analysis, including what was checked, what was found, and what research was conducted to arrive at recommendations

## Example Invocation

User: "Run a security review on this project"
User: "Check for vulnerabilities in my Supabase backend"
User: "Audit this code for data leakage"
User: "Do a pentest analysis before deployment"
User: "Find any SQL injection or XSS vulnerabilities"
User: "Verify LGPD and GDPR compliance in my codebase"
User: "Check if my code has vibe coding vulnerabilities"
User: "Analyze my database security for PostgreSQL and MongoDB"
User: "Run OWASP ASVS verification on this project"
User: "Check supply chain security (SLSA)"
User: "@csreview"
User: "@csreview review src/auth.ts src/middleware/"
User: "@csreview adversarial src/api/payments/"
User: "@csreview security-review src/components/"
User: "@csreview request-review main..feature/auth"
User: "@csreview review csreview-reports/codex_security-findings.md"

## Output

- **Primary**: `csreview-reports/<agent>_security-report.html` under the selected output directory (visual report in user's language for human review)
- **Secondary**: `csreview-reports/<agent>_security-findings.md` under the selected output directory (structured report in English for remediation planning)
- **Tertiary**: Verbal summary of critical/high findings in chat including compliance gaps and vibe coding risks
- **Optional**: JSON export available via HTML report button
