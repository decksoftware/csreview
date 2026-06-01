# CSReview - Code Security Review Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Skill Type](https://img.shields.io/badge/Type-AI%20Agent%20Skill-blue)]()
[![Compatibility](https://img.shields.io/badge/Compatibility-Trae%20%7C%20Claude%20Code%20%7C%20Codex%20%7C%20Qwen%20%7C%20OpenCode%20%7C%20Antigravity%20%7C%20Qoder-green)]()

## Purpose & Utility

**CSReview** is a universal AI agent skill for development-time security alignment of the local workspace a developer is actively building. It applies a penetration tester's adversarial mindset to local source, configuration, dependencies, and infrastructure files (static SAST + SCA), but it does not perform live penetration testing against running, deployed, or production systems.

### CSReview is READ-ONLY

CSReview **NEVER modifies, deletes, or moves any files** in the analyzed project. It only:
- Identifies security problems and locates them precisely
- Suggests solutions based on the frameworks and technologies in use
- Researches official documentation when encountering unfamiliar frameworks
- Reports all findings to the developer and coding agent

The actual fixes are applied by the human developer or the coding agent, not by CSReview.

CSReview exists to slow down unsafe "vibe coding" before release: it inspects local code, dependency manifests, framework configuration, database/BaaS rules, frontend/backend boundaries, and platform-specific surfaces, then writes a detailed report explaining what is exposed and why. It does not assume enough business or schema context to change the audited system itself.

### Scope

- **IN SCOPE**: the local development workspace/project, including local source code, configuration, `.env` files, infrastructure-as-code, and BaaS rule files. Local SAST/SCA tools such as Semgrep, npm audit, OSV-Scanner, and framework-native scanners may be run against that local code only.
- **GOAL**: improve the SECURITY and EFFICIENCY (cost/performance) of the project under development.
- **OUT OF SCOPE / PROHIBITED**: testing, probing, or calling live, deployed, or production systems; external service endpoints used by the app; DAST against running targets; modifying audited code; exfiltrating data.
- **Reference documentation research is ALLOWED**: reading OWASP, CWE, CVE/NVD, OSV, vendor advisories, and official framework documentation to ground remediation is allowed. That is reading documentation, not probing a target.

### Global Skill Installation Only

CSReview is a **global agent skill**. Install it in the AI agent's global skills directory, never inside the project being audited unless the user explicitly asks for a project-local installation.

Examples of global skill directories:

- Codex: `~/.codex/skills/csreview` or `~/.agents/skills/csreview`
- Trae / SOLO: `~/.trae/skills/csreview`
- Claude Code: `~/.claude/skills/csreview`

Do not create project-local agent folders or instruction files such as `<project>/.trae/skills/csreview`, `<project>/.codex/skills/csreview`, `<project>/AGENTS.md`, `<project>/CLAUDE.md`, `.cursorrules`, or `.windsurfrules` solely to install CSReview. Those are allowed only when the user deliberately chooses project-scoped installation. The audited project should contain its own source code plus generated report artifacts such as `csreview-reports/<agent>_security-report.html`, which are ignored by Git.

### Semgrep is Mandatory for Agent Analysis

Every CSReview run must attempt to call **Semgrep** as the baseline SAST layer:

```bash
semgrep --version
semgrep --config auto --json --quiet <project_path>
```

If Semgrep is unavailable, the report must explicitly mark the run as lower-confidence Agent-Only analysis and tell the user how to install Semgrep. Semgrep is declared in the package metadata as a required external tool because the official distribution is a CLI installed with `pipx`, `uv`, Homebrew, Docker, or platform package managers rather than as a normal npm dependency.

For dependency analysis, CSReview also attempts read-only SCA checks when available:
- `npm audit --json` for Node.js projects
- `osv-scanner scan --format json <project_path>` for multi-ecosystem dependency vulnerability scanning

Framework-native linters and scanners such as ESLint security plugins, pip-audit, Bandit, Gosec, cargo audit, dotnet vulnerable package checks, Checkov, Hadolint, Trivy, and Snyk should be called when relevant to the detected stack.

### Stack-Native Tool Recommendation Matrix

After detecting the workspace stack, CSReview selects read-only tools that are native or commonly recommended for that ecosystem. Run a tool only if it is already available in the user's environment or already configured in the workspace. Do not install missing tools inside the analyzed project. If a tool is unavailable, the report records it as a `missing recommended tool`.

| Detected stack | Prefer read-only commands and scanners |
| --- | --- |
| JavaScript / TypeScript / React / Node | `npm audit --json`, configured `eslint`, `eslint-plugin-security`, `eslint-plugin-react`, `eslint-plugin-react-hooks`, `typescript-eslint`, Semgrep |
| .NET / C# / ASP.NET | `dotnet build --no-restore`, `dotnet format analyzers --verify-no-changes`, `dotnet package list --include-transitive --vulnerable --format json` or `dotnet list package --include-transitive --vulnerable --format json`, Roslyn analyzers, Semgrep |
| Kotlin / Android / JVM | `gradlew lint` or `./gradlew lint`, Android Lint, `detekt`, `ktlint`, Qodana, Gradle dependency checks, OSV-Scanner, Semgrep |
| Go | `go vet ./...`, `govulncheck ./...`, `gosec ./...`, `staticcheck ./...`, `golangci-lint run`, OSV-Scanner, Semgrep |
| Python | `pip-audit`, `bandit -r`, `ruff check`, `safety`, OSV-Scanner, Semgrep |
| Java / Spring | Maven/Gradle dependency checks, SpotBugs/FindSecBugs when configured, Checkstyle/PMD when configured, Qodana, OSV-Scanner, Semgrep |
| Rust | `cargo audit`, `cargo deny check`, `cargo clippy --all-targets --all-features`, OSV-Scanner, Semgrep |
| PHP / Ruby / Flutter | `composer audit`, PHPStan/Psalm, `bundle audit`, Brakeman, `dart analyze`, `flutter analyze`, OSV-Scanner, Semgrep |
| IaC / containers / BaaS | Checkov, Trivy, Hadolint, Terraform validators, Supabase/Firebase/Appwrite rule validation when configured, Semgrep |

### External Research is Mandatory When Uncertain

Every coding agent using CSReview must research externally when it is unsure about framework behavior, security defaults, dependency advisories, CVE details, exploitability, or safe remediation. The expected source order is:

- official framework documentation, release notes, migration guides, and security pages
- vendor security advisories for the affected product, database, cloud service, BaaS, package manager, or SDK
- specialized security references such as OWASP, CWE, CVE/NVD, GitHub Security Advisories, OSV.dev, and Snyk

Do not guess. If external sources disagree or the exact version cannot be confirmed, CSReview must mark the finding as lower confidence and explain the uncertainty in the report.

No-findings results are not proof that a system is secure. Reports must state that a clean run only means CSReview and the available external tools did not detect reportable issues in the analyzed scope.

### Report Handoff

After every run, CSReview must show the user:

- **Agent name prefix**: report filenames begin with the coding agent name, for example `csreview-reports/codex_security-report.html` and `csreview-reports/codex_security-findings.md`. Other agents replace `codex` with their own name.
- Generic names such as `security-report.html`, `security-findings.md`, `csreview-report.html`, and `csreview-report.md` are invalid because they hide which agent produced the analysis.
- Use `--agent-name <agent>` or `CSREVIEW_AGENT_NAME=<agent>` so each agent writes its own report files.
- **HTML report path**: `csreview-reports/<agent>_security-report.html` or the configured output HTML file, for the user to click/open in a browser.
- **Markdown report path**: `csreview-reports/<agent>_security-findings.md` or the configured output Markdown file, for the coding agent to read before planning remediation.

The verbal summary is not enough for implementation. A coding agent must analyze the Markdown report and then inspect the referenced source files, schemas, tests, framework documentation, and security advisories before proposing or applying changes.

### Why This Exists

Security vulnerabilities cost companies billions annually. Most development teams lack dedicated security engineers to review code before deployment. With the rise of **vibe coding** (non-technical users building software with AI agents), security risks have multiplied. CSReview bridges this gap by providing:

1. **Development-Time Security Alignment**: Goes beyond basic linting with static source/config review, Semgrep/SCA evidence, and a security consultant's adversarial reasoning without probing live systems
2. **Dual Report System**:
   - **HTML Report** in the user's language for human understanding
   - **Markdown Report** in English for AI coding agents to parse and plan remediations without changing the audited code automatically
3. **Universal Compatibility**: Works with any AI coding agent (Trae, OpenCode, Qwen CLI, Codex, Claude Code, Antigravity, Qoder, Cursor, Windsurf, Cline, GitHub Copilot CLI, Aider, Continue, DevChat)
4. **Multi-Platform Coverage**: Analyzes code for macOS, iOS, Linux, Windows, web, mobile, and backend systems
5. **Vibe Coding Protection**: Specifically detects vulnerabilities commonly introduced by AI-generated code
6. **Compliance Verification**: Checks against LGPD, GDPR, SOC 2, HIPAA, CCPA/CPRA requirements
7. **Database Security**: Deep analysis of SQL, NoSQL, and BaaS platform configurations
8. **Supply Chain Security**: SLSA 3 framework verification
9. **OWASP ASVS**: Systematic verification against V1-V14 categories

### Real-World Use Cases

- **Pre-release security gate**: Run before release while reviewing only the local workspace
- **Code review enhancement**: Augment human code reviews with automated security analysis
- **Legacy code audit**: Identify vulnerabilities in existing codebases
- **Compliance preparation**: Find issues before security audits (SOC 2, ISO 27001, LGPD/GDPR)
- **Vibe coding verification**: Check AI-generated code for common security anti-patterns
- **Database security audit**: Verify RLS policies, access controls, and configurations
- **CI/CD integration**: Can be triggered in automated pipelines via AI agents
- **Learning tool**: Understand vulnerability patterns and secure coding practices

## Features

### 9-Phase Analysis Pipeline

| Phase | Name | Description |
|-------|------|-------------|
| 0 | **Tool Detection** | Require a Semgrep attempt, detect framework-native linters/scanners (eslint, npm audit, bandit, trivy, snyk, gosec, codeql, etc.), and use available tools for real file-by-file scanning |
| 1 | **Reconnaissance** | Project structure scan, secret detection, external service mapping |
| 2 | **Ultra-Deep Security** | Injection, auth, data leakage, XSS/CSRF, config, deps, cloud, .NET, Delphi/Lazarus, Go, DLL/installer, platform-specific, logic flaws |
| 3 | **Database Security** | SQL/NoSQL/BaaS structure analysis, Firebase cost & performance, access patterns |
| 4 | **SLSA 3 Supply Chain** | Source integrity, build integrity, dependency security, deployment security |
| 5 | **OWASP ASVS** | V1-V14 verification categories (Architecture, Auth, Session, Access, Crypto, etc.) |
| 6 | **Compliance** | LGPD, GDPR, SOC 2 Type II, HIPAA, CCPA/CPRA regulatory analysis |
| 7 | **Vibe Coding** | AI-generated code pattern detection, risk scoring, behavioral analysis |
| 8 | **Report Generation** | HTML (user language) + MD (English for agents) dual report system |

### Analysis Modes

CSReview operates in one of three modes depending on installed tools:

| Mode | Tools Installed | Accuracy | Confidence | Recommended For |
|------|----------------|----------|------------|-----------------|
| **Self-Hosted** | All/most tools installed locally | Highest | CONFIRMED/TOOL-ONLY | Production audits, compliance |
| **Hybrid** | Some tools installed | High | Mixed CONFIRMED + AI-ONLY | Development, CI/CD |
| **Agent-Only** | No tools installed | Lower | AI-ESTIMATED only | Quick checks, learning |

**Supported Security Tools:**
| Tool | Purpose | Languages |
|------|---------|-----------|
| **Semgrep** | Static analysis (SAST) | 30+ languages |
| **OSV-Scanner** | Dependency vulnerability scanning | npm, pip, Maven, Go, Cargo, RubyGems, NuGet, OS packages, containers |
| **Bandit** | Python security linter | Python |
| **Trivy** | Vulnerability + misconfig scanner | All (deps, containers, IaC) |
| **Snyk** | Dependency vulnerabilities | All |
| **Gosec** | Go security linter | Go |
| **ESLint Security** | JS/TS security rules | JavaScript, TypeScript |
| **CodeQL** | Semantic code analysis | JS, TS, Python, Go, Java, C#, C++ |
| **pip-audit** | Python dependency audit | Python |
| **cargo audit** | Rust dependency audit | Rust |
| **npm audit** | Node.js dependency audit | JavaScript, TypeScript |
| **dotnet** | .NET dependency audit | C#, .NET |
| **Checkov** | Infrastructure-as-code security | Terraform, CloudFormation, K8s |
| **Hadolint** | Dockerfile security | Docker |
| **Brakeman** | Rails security scanner | Ruby |
| **Grype** | Container/filesystem vulnerabilities | All |
| **RetireJS** | JS library vulnerabilities | JavaScript |
| **Safety** | Python dependency checker | Python |
| **OWASP Dep-Check** | Dependency vulnerability check | Java, .NET, Node.js |

### Built-in Code Review System

CSReview includes a complete code review system - no additional skills or plugins required:

| Mode | Command | Description |
|------|---------|-------------|
| **Standard Review** | `@csreview review [files]` | Code quality, architecture, performance, testing, documentation |
| **Adversarial Review** | `@csreview adversarial [files]` | Red-team mindset: boundary conditions, failure modes, edge cases |
| **Security Review** | `@csreview security-review [files]` | Security-focused review with vulnerability detection |
| **Request Review** | `@csreview request-review [scope]` | Review of PR/branch/commit with change-type detection |
| **Remediation Planning** | `@csreview review csreview-reports/codex_security-findings.md` | Parse the report, understand context, and plan fixes for a human or coding agent to apply deliberately |

### Analysis Capabilities

| Category | Coverage |
|----------|----------|
| **Injection** | SQL, NoSQL, Command, LDAP, XPath, Template (SSTI) |
| **Authentication** | JWT, Session, RLS Policies, OAuth, IDOR, Privilege Escalation |
| **Data Leakage** | Log exposure, PII, Stack traces, Debug mode, Cache |
| **Cross-Site** | XSS (Reflected/Stored/DOM), CSRF, CORS, Clickjacking |
| **Configuration** | Security headers, TLS/SSL, File uploads, Rate limiting |
| **Dependencies** | CVEs, Supply chain, Typosquatting, License compliance |
| **Cloud/Backend** | Supabase (RLS, Storage), Firebase (Rules, Auth), Appwrite, Neon, PocketBase, Convex |
| **Database Security** | PostgreSQL, MySQL, MariaDB, SQL Server, Firebird, SQLite, Oracle, MongoDB, Redis, CouchDB, DynamoDB, Cassandra |
| **Cost Analysis** | Firebase Firestore/RTDB/Storage/Functions cost estimation, unbounded query detection, trigger cost analysis |
| **.NET** | ASP.NET Core, Blazor, EF Core, NuGet security, assembly signing, BinaryFormatter |
| **Delphi/Lazarus** | VCL, FMX, LCL, FireDAC, dbExpress, IBX, FIBPlus, zeoslib, Firebird connectivity |
| **Go** | Gin, Echo, Fiber, GORM, govulncheck, CGo boundary, unsafe.Pointer |
| **Binary/Installer** | DLL hijacking, ASLR/DEP, code signing, Inno Setup, NSIS, WiX, MSI, Authenticode |
| **Platform-Specific** | macOS, iOS, Linux, Windows native vulnerabilities |
| **System-Level** | Path traversal, Symlinks, IPC, Memory corruption, TOCTOU |
| **Business Logic** | Race conditions, Mass assignment, Deserialization flaws |
| **Supply Chain** | SLSA 3: Signed commits, build provenance, SBOM, artifact signing |
| **Compliance** | LGPD, GDPR, SOC 2, HIPAA, CCPA/CPRA gap analysis |
| **Vibe Coding** | AI-generated code anti-patterns, risk scoring |

### Supported Technologies

#### Languages & Frameworks
- **Frontend**: React, Vue, Nuxt, Angular, Svelte, Next.js
- **Mobile**: Flutter, Kotlin (Android), Swift (iOS), React Native
- **Backend**: Python, Node.js, C#, Go, Java, PHP, Ruby
- **Systems**: C, C++, Rust
- **Desktop**: Electron, Tauri, native apps
- **.NET Ecosystem**: .NET Framework, .NET Core, .NET 5/6/7/8/9, ASP.NET Core, Blazor, MAUI, WPF, WinForms, Xamarin
- **Delphi/Lazarus**: Delphi (VCL, FMX), Lazarus (LCL), Free Pascal, Object Pascal
- **Go**: Go standard library, Gin, Echo, Fiber, GORM, and Go modules

#### Installer & Binary Security
- **DLL Analysis**: DLL hijacking, side-loading, missing ASLR/DEP, unsigned DLLs
- **Installers**: Inno Setup, NSIS, WiX, InstallShield, MSI packages
- **Binary Security**: Code signing, Authenticode, checksum integrity
- **Package Formats**: NuGet, Chocolatey, WinGet, DEB, RPM, APK, IPA, DMG

#### Databases & Backends
- **SQL**: PostgreSQL, MySQL, MariaDB, SQL Server, Firebird, SQLite, Oracle
- **NoSQL**: MongoDB, Redis, CouchDB, DynamoDB, Cassandra, ArangoDB
- **BaaS**: Supabase, Firebase, Appwrite, AWS Amplify, Nhost, Neon, PocketBase, Convex, PlanetScale, Turso

#### AI Agent Compatibility

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

### Output Reports

1. **`csreview-reports/<agent>_security-report.html`** - Visual dashboard for humans (in user's language)
   - Security score (0-100)
   - SLSA Level indicator
   - OWASP ASVS compliance percentage
   - Regulatory compliance status (LGPD/GDPR/SOC2/HIPAA/CCPA)
   - Vibe Coding Risk indicator
   - Severity distribution charts
   - Database security findings
   - Compliance matrix
   - Detailed findings with code snippets
   - Exploitation scenarios
   - Recommended fixes with corrected code
   - OWASP/CWE references

2. **`csreview-reports/<agent>_security-findings.md`** - Structured report for AI agents (always in English)
   - Machine-readable findings
   - Exact file paths and line numbers
   - Vibe Risk scoring (AI-Likely, AI-Possible, Human-Likely)
   - Compliance mapping per finding
   - Database security findings (SQL/NoSQL/BaaS)
   - SLSA assessment
   - OWASP ASVS compliance table
   - Compliance matrix (LGPD/GDPR/SOC2/HIPAA/CCPA)
   - Vulnerable code blocks
   - Corrected code ready to apply
   - Fix priority order
   - Agent execution instructions

## Installation

### For AI Agents

Install CSReview from outside the project you want to audit. Do not clone or copy the skill into the target project's `.trae`, `.codex`, `.agents`, `.claude`, or instruction-file locations unless the user explicitly requested local project installation.

1. Clone this repository into a tools/downloads location:
```bash
git clone https://github.com/decksoftware/csreview.git
cd csreview
```

2. Copy the skill to your agent's global skills directory:
```bash
# Codex
mkdir -p ~/.codex/skills/csreview
cp -R csreview/. ~/.codex/skills/csreview/

# Codex alternate global skill root
mkdir -p ~/.agents/skills/csreview
cp -R csreview/. ~/.agents/skills/csreview/

# Trae / SOLO
mkdir -p ~/.trae/skills/csreview
cp -R csreview/. ~/.trae/skills/csreview/

# Claude Code
mkdir -p ~/.claude/skills/csreview
cp -R csreview/. ~/.claude/skills/csreview/
```

PowerShell example:
```powershell
git clone https://github.com/decksoftware/csreview.git
Set-Location .\csreview
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills" | Out-Null
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills\csreview" | Out-Null
Copy-Item -Recurse -Force .\csreview\* "$env:USERPROFILE\.codex\skills\csreview"
```

3. The globally installed skill will be automatically detected and can be invoked with:
   - `@csreview`
   - "Run a security review on this project"
   - "Check for vulnerabilities"
   - "Do a pentest analysis"
   - "Verify LGPD and GDPR compliance"
   - "Check if my code has vibe coding vulnerabilities"

### External Security Tools

CSReview works standalone, but installing external tools enhances accuracy and provides additional validation layers. When tools are installed, CSReview operates in **Self-Hosted** or **Hybrid** mode with higher confidence levels. The npm package declares these tools in its `csreview` metadata:

- Required external tool: `semgrep`
- Recommended external tools: `osv-scanner`, `npm audit`

#### Semgrep (Required Baseline)

**Semgrep** is the primary external SAST tool used by CSReview. Agents must attempt to run it on every audit. It provides advanced static analysis rules across 30+ languages and significantly improves detection accuracy.

**Why install Semgrep?**
- Validates CSReview findings with industry-standard SAST rules
- Detects patterns that regex-based scanning may miss
- Provides CONFIRMED/TOOL-ONLY confidence level for findings
- Community rules cover OWASP Top 10, CWE, and framework-specific issues
- Free tier available for local scanning

**Installation:**

```bash
# pipx (recommended isolated install)
pipx install semgrep

# uv tool install
uv tool install semgrep

# Homebrew (macOS/Linux)
brew install semgrep

# Docker
docker pull semgrep/semgrep
```

**Verify installation:**
```bash
semgrep --version
# Expected output: X.Y.Z

semgrep --config auto --json --quiet .
# Verifies Semgrep can access community rules
```

**Important:** Semgrep must be available in the system PATH for CSReview to detect it globally. After installation, verify it's accessible from any directory:
```bash
# Open a NEW terminal and run:
where semgrep    # Windows
which semgrep    # macOS/Linux
semgrep --version
```

If `semgrep` is not found in PATH after installation:
- **Windows**: Add the Python Scripts directory to PATH (e.g., `C:\Users\<user>\AppData\Local\Programs\Python\PythonXX\Scripts\`)
- **macOS/Linux**: Ensure `~/.local/bin` or the pip install location is in your `$PATH`

#### OSV-Scanner (Recommended SCA Complement)

**OSV-Scanner** complements Semgrep by checking dependency manifests and lockfiles against the OSV vulnerability database. Semgrep answers "is this code pattern dangerous?"; OSV answers "is this dependency/version known vulnerable?"

**Installation:**

```bash
# Windows
winget install Google.OSVScanner

# macOS/Linux with Homebrew
brew install osv-scanner

# Go install
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
```

**Verify and scan:**

```bash
osv-scanner --version
osv-scanner scan --format json .
```

CSReview only uses OSV-Scanner in scan/report mode. It does not run OSV guided remediation or any dependency update command.

**Other Supported Tools:**

| Tool | Install Command | Purpose |
|------|----------------|---------|
| OSV-Scanner | `winget install Google.OSVScanner` / `brew install osv-scanner` | Multi-ecosystem dependency vulnerability scanning |
| Bandit | `pip install bandit` | Python security linter |
| Trivy | `brew install trivy` / [docs](https://aquasecurity.github.io/trivy/) | Vulnerability + misconfig scanner |
| Snyk | `npm install -g snyk` | Dependency vulnerabilities |
| Gosec | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | Go security linter |
| pip-audit | `pip install pip-audit` | Python dependency audit |
| cargo audit | `cargo install cargo-audit` | Rust dependency audit |
| Checkov | `pip install checkov` | Infrastructure-as-code security |
| Hadolint | `brew install hadolint` / `docker pull hadolint/hadolint` | Dockerfile security |

CSReview automatically detects which tools are installed and adjusts its analysis mode accordingly. If Semgrep is missing, CSReview continues only as a lower-confidence report and clearly flags that limitation.

### Manual Invocation

Simply ask your AI coding assistant:
> "Use the csreview skill to analyze this project for security vulnerabilities"

## Usage Examples

### Basic Security Scan
```
@csreview
```

### Targeted Analysis
```
@csreview Check specifically for SQL injection and authentication flaws
```

### Pre-Deployment Review
```
@csreview Run a full local workspace security review before release
```

### Backend Security
```
@csreview Analyze my Supabase backend for RLS policy gaps and data leakage
```

### Database Security
```
@csreview Check my PostgreSQL and MongoDB database security configurations
```

### Compliance Verification
```
@csreview Verify LGPD and GDPR compliance in my codebase
```

### Vibe Coding Check
```
@csreview Check if my code has vibe coding vulnerabilities from AI-generated code
```

### Supply Chain Security
```
@csreview Check supply chain security (SLSA level)
```

### OWASP ASVS Verification
```
@csreview Run OWASP ASVS verification on this project
```

### Mobile App Security
```
@csreview Check this Flutter app for iOS and Android security issues
```

### Standard Code Review
```
@csreview review src/auth.ts src/middleware/
```

### Adversarial Review (Red Team)
```
@csreview adversarial src/api/payments/
```

### Request Review of Changes
```
@csreview request-review main..feature/auth
```

### Plan Remediation from Report
``` 
@csreview review csreview-reports/codex_security-findings.md
```

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| **Critical** | Direct data breach, RCE, auth bypass, exposed PII | Immediate |
| **High** | Significant vulnerability, exploitable with effort | 24-48h |
| **Medium** | Moderate risk, requires specific conditions | 1 week |
| **Low** | Minor issue, defense-in-depth improvement | Next sprint |
| **Info** | Best practice recommendation | Consider |

## How It Works

```
CSReview Workflow (8 Phases)

Phase 1: Reconnaissance & Mapping
  - Project structure scan
  - Technology identification
  - Secret detection
  - External service mapping

Phase 2: Ultra-Deep Security Analysis
  - Injection vulnerability checks
  - Authentication & authorization review
  - Data leakage analysis
  - Cross-site vulnerability scan
  - Configuration security audit
  - Dependency vulnerability check
  - Cloud/Backend security review
  - Platform-specific checks (macOS/iOS/Linux/Win)
  - Business logic flaw analysis

Phase 3: Database Security Analysis
  - SQL database structure and query security
  - NoSQL database configuration and injection checks
  - BaaS platform security (Supabase, Firebase, Appwrite, Neon, etc.)
  - Access control and encryption verification

Phase 4: SLSA 3 Supply Chain Security
  - Source integrity (signed commits, branch protection)
  - Build integrity (CI/CD, provenance, signing)
  - Dependency security (lock files, pinning, SBOM)
  - Deployment security (env separation, secret management)

Phase 5: OWASP ASVS Verification
  - V1-V14 systematic verification
  - Architecture, Auth, Session, Access, Validation
  - Crypto, Error handling, Data protection
  - Communication, Business logic, API security

Phase 6: Regulatory Compliance Analysis
  - LGPD (Brazil)
  - GDPR (EU)
  - SOC 2 Type II
  - HIPAA (US Health)
  - CCPA/CPRA (California)

Phase 7: Vibe Coding Protection
  - AI-generated code pattern detection
  - Risk scoring (AI-Likely, AI-Possible, Human-Likely)
  - Behavioral pattern analysis
  - Common AI anti-pattern identification

Phase 8: Report Generation
  - HTML report (user language) for human review
  - Markdown report (English) for human/coding-agent remediation planning
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Areas for Contribution
- Additional vulnerability detection patterns
- Support for more languages/frameworks
- Enhanced report formatting
- CI/CD integration examples
- Documentation improvements
- Additional compliance frameworks
- Database-specific security checks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OWASP Top 10 - https://owasp.org/www-project-top-ten/
- OWASP ASVS - https://owasp.org/www-project-application-security-verification-standard/
- SLSA Framework - https://slsa.dev/
- CWE Database - https://cwe.mitre.org/
- Security research community worldwide

## Support

- **Issues**: [GitHub Issues](https://github.com/decksoftware/csreview/issues)
- **Discussions**: [GitHub Discussions](https://github.com/decksoftware/csreview/discussions)

---

**Made with secure software development in mind**
