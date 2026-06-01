# CSReview - Code Security Review Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Skill Type](https://img.shields.io/badge/Type-AI%20Agent%20Skill-blue)]()
[![Compatibility](https://img.shields.io/badge/Compatibility-Trae%20%7C%20Claude%20Code%20%7C%20Codex%20%7C%20Qwen%20%7C%20OpenCode%20%7C%20Antigravity%20%7C%20Qoder-green)]()

## Purpose & Utility

**CSReview** is a universal AI agent skill that performs **ultra-deep security audits** (automated pentest level) on codebases across multiple languages, frameworks, and platforms.

### CSReview is READ-ONLY

CSReview **NEVER modifies, deletes, or moves any files** in the analyzed project. It only:
- Identifies security problems and locates them precisely
- Suggests solutions based on the frameworks and technologies in use
- Researches official documentation when encountering unfamiliar frameworks
- Reports all findings to the developer and coding agent

The actual fixes are applied by the human developer or the coding agent, not by CSReview.

### Why This Exists

Security vulnerabilities cost companies billions annually. Most development teams lack dedicated security engineers to review code before deployment. With the rise of **vibe coding** (non-technical users building software with AI agents), security risks have multiplied. CSReview bridges this gap by providing:

1. **Automated Pentest-Level Analysis**: Goes beyond basic linting - performs the same depth of analysis a human security consultant would do
2. **Dual Report System**:
   - **HTML Report** in the user's language for human understanding
   - **Markdown Report** in English for AI coding agents to parse and fix vulnerabilities
3. **Universal Compatibility**: Works with any AI coding agent (Trae, OpenCode, Qwen CLI, Codex, Claude Code, Antigravity, Qoder, Cursor, Windsurf, Cline, GitHub Copilot CLI, Aider, Continue, DevChat)
4. **Multi-Platform Coverage**: Analyzes code for macOS, iOS, Linux, Windows, web, mobile, and backend systems
5. **Vibe Coding Protection**: Specifically detects vulnerabilities commonly introduced by AI-generated code
6. **Compliance Verification**: Checks against LGPD, GDPR, SOC 2, HIPAA, CCPA/CPRA requirements
7. **Database Security**: Deep analysis of SQL, NoSQL, and BaaS platform configurations
8. **Supply Chain Security**: SLSA 3 framework verification
9. **OWASP ASVS**: Systematic verification against V1-V14 categories

### Real-World Use Cases

- **Pre-deployment security gate**: Run before pushing to production
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
| 0 | **Tool Detection** | Detect installed security tools (semgrep, bandit, trivy, snyk, gosec, eslint, codeql, etc.) and use them for real file-by-file scanning |
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
| **Apply Fixes** | `@csreview apply-fixes [report]` | Parse and apply fixes from a CSReview report |

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
| **Trae / SOLO** | Native skill via `.trae/skills/csreview/SKILL.md` |
| **OpenCode** | Compatible via project instructions |
| **Qwen CLI** | Compatible via system prompt injection |
| **Codex** | Compatible via AGENTS.md or project instructions |
| **Claude Code** | Compatible via CLAUDE.md or project instructions |
| **Antigravity** | Compatible via project configuration |
| **Qoder** | Compatible via agent configuration |
| **Cursor / Windsurf / Cline** | Compatible via `.cursorrules` or `.windsurfrules` |
| **GitHub Copilot CLI** | Compatible via `.github/copilot-instructions.md` |
| **Aider / Continue / DevChat** | Compatible via project conventions file |

### Output Reports

1. **`security-report.html`** - Visual dashboard for humans (in user's language)
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

2. **`security-findings.md`** - Structured report for AI agents (always in English)
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

1. Clone this repository:
```bash
git clone https://github.com/decksoftware/csreview.git
```

2. Copy the skill to your agent's skills directory:
```bash
# For Trae/SOLO
cp -r csreview/csreview ~/.trae/skills/csreview

# For Claude Code - add to CLAUDE.md or copy to skills directory

# For other agents - check their skill/plugin documentation
```

3. The skill will be automatically detected and can be invoked with:
   - `@csreview`
   - "Run a security review on this project"
   - "Check for vulnerabilities"
   - "Do a pentest analysis"
   - "Verify LGPD and GDPR compliance"
   - "Check if my code has vibe coding vulnerabilities"

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
@csreview Run a full security audit before production deployment
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

### Apply Fixes from Report
```
@csreview apply-fixes security-findings.md
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
  - Markdown report (English) for AI agent auto-fix
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
