# CSReview - Code Security Review Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Skill Type](https://img.shields.io/badge/Type-AI%20Agent%20Skill-blue)]()
[![Compatibility](https://img.shields.io/badge/Compatibility-Trae%20%7C%20Claude%20Code%20%7C%20Codex%20%7C%20Antigravity-green)]()

## 🎯 Purpose & Utility

**CSReview** is a universal AI agent skill that performs **ultra-deep security audits** (automated pentest level) on codebases across multiple languages, frameworks, and platforms.

### Why This Exists

Security vulnerabilities cost companies billions annually. Most development teams lack dedicated security engineers to review code before deployment. CSReview bridges this gap by providing:

1. **Automated Pentest-Level Analysis**: Goes beyond basic linting - performs the same depth of analysis a human security consultant would do
2. **Dual Report System**: 
   - **HTML Report** for human developers to understand vulnerabilities visually
   - **Markdown Report** for AI agents to automatically fix the findings
3. **Universal Compatibility**: Works with any AI coding agent (Trae, Claude Code, GitHub Copilot/Codex, Antigravity, Cursor, etc.)
4. **Multi-Platform Coverage**: Analyzes code for macOS, iOS, Linux, Windows, web, mobile, and backend systems

### Real-World Use Cases

- **Pre-deployment security gate**: Run before pushing to production
- **Code review enhancement**: Augment human code reviews with automated security analysis
- **Legacy code audit**: Identify vulnerabilities in existing codebases
- **Compliance preparation**: Find issues before security audits (SOC2, ISO 27001, LGPD/GDPR)
- **CI/CD integration**: Can be triggered in automated pipelines via AI agents
- **Learning tool**: Understand vulnerability patterns and secure coding practices

## 🚀 Features

### Analysis Capabilities

| Category | Coverage |
|----------|----------|
| **Injection** | SQL, NoSQL, Command, LDAP, XPath, Template (SSTI) |
| **Authentication** | JWT, Session, RLS Policies, OAuth, IDOR, Privilege Escalation |
| **Data Leakage** | Log exposure, PII, Stack traces, Debug mode, Cache |
| **Cross-Site** | XSS (Reflected/Stored/DOM), CSRF, CORS, Clickjacking |
| **Configuration** | Security headers, TLS/SSL, File uploads, Rate limiting |
| **Dependencies** | CVEs, Supply chain, License compliance |
| **Cloud/Backend** | Supabase (RLS, Storage), Firebase (Rules, Auth), Appwrite |
| **Platform-Specific** | macOS, iOS, Linux, Windows native vulnerabilities |
| **System-Level** | Path traversal, Symlinks, IPC, Memory corruption, TOCTOU |
| **Business Logic** | Race conditions, Mass assignment, Deserialization flaws |

### Supported Technologies

- **Frontend**: React, Vue, Nuxt, Angular, Svelte, Next.js
- **Mobile**: Flutter, Kotlin (Android), Swift (iOS), React Native
- **Backend**: Python, Node.js, C#, Go, Java, PHP, Ruby
- **Systems**: C, C++, Rust
- **Databases**: PostgreSQL, MySQL, MariaDB, SQL Server, Firebird, MongoDB, Redis
- **BaaS**: Supabase, Firebase, Appwrite, AWS Amplify, Nhost

### Output Reports

1. **`security-report.html`** - Visual dashboard for humans
   - Security score (0-100)
   - Severity distribution charts
   - Vulnerability category breakdown
   - Detailed findings with code snippets
   - Exploitation scenarios
   - Recommended fixes with corrected code
   - OWASP/CWE references

2. **`security-findings.md`** - Structured report for AI agents
   - Machine-readable findings
   - Exact file paths and line numbers
   - Vulnerable code blocks
   - Corrected code ready to apply
   - Fix priority order
   - Agent execution instructions

## 📦 Installation

### For AI Agents (Trae, Claude Code, Codex, Antigravity)

1. Clone this repository:
```bash
git clone https://github.com/dev-ecd-dm/csreview.git
```

2. Copy the skill to your agent's skills directory:
```bash
# For Trae/SOLO
cp -r csreview/csreview ~/.trae/skills/csreview

# For Claude Code
cp -r csreview/csreview ~/.claude/skills/csreview

# For other agents - check their skill/plugin documentation
```

3. The skill will be automatically detected and can be invoked with:
   - `@csreview`
   - "Run a security review on this project"
   - "Check for vulnerabilities"
   - "Do a pentest analysis"

### Manual Invocation

Simply ask your AI coding assistant:
> "Use the csreview skill to analyze this project for security vulnerabilities"

## 📖 Usage Examples

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

### Mobile App Security
```
@csreview Check this Flutter app for iOS and Android security issues
```

## 📊 Report Samples

### HTML Report Structure
```
┌─────────────────────────────────────────┐
│  Security Audit Report                  │
│  Project: my-app | Score: 67/100        │
├─────────────────────────────────────────┤
│  📊 Executive Summary                   │
│  ├── Security Score Gauge               │
│  ├── Severity Distribution Chart        │
│  ├── Category Breakdown                 │
│  └── Top 5 Critical Findings            │
│                                         │
│  🔍 Detailed Findings                   │
│  ├── [CRITICAL] SQL Injection in Auth   │
│  ├── [HIGH] XSS in User Comments        │
│  ├── [MEDIUM] CORS Misconfiguration     │
│  └── [LOW] Missing Security Headers     │
└─────────────────────────────────────────┘
```

### Markdown Report Structure
```markdown
# Security Findings Report

| ID | Severity | Category | File | Line | Issue |
|----|----------|----------|------|------|-------|
| 001 | CRITICAL | SQL Injection | src/auth.ts | 45 | Raw SQL query |
| 002 | HIGH | XSS | src/components/Comment.vue | 12 | Unsanitized v-html |

### Finding #001
**Severity**: CRITICAL
**File**: `src/auth.ts:45`
**Fix Required**: [corrected code block]
```

## 🎯 Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| **Critical** | Direct data breach, RCE, auth bypass, exposed PII | Immediate |
| **High** | Significant vulnerability, exploitable with effort | 24-48h |
| **Medium** | Moderate risk, requires specific conditions | 1 week |
| **Low** | Minor issue, defense-in-depth improvement | Next sprint |
| **Info** | Best practice recommendation | Consider |

## 🔧 How It Works

```
┌──────────────────────────────────────────────────────┐
│                    CSReview Workflow                  │
├──────────────────────────────────────────────────────┤
│                                                      │
│  Phase 1: Reconnaissance & Mapping                   │
│  ├── Project structure scan                          │
│  ├── Technology identification                       │
│  ├── Secret detection                                │
│  └── External service mapping                        │
│                                                      │
│  Phase 2: Ultra-Deep Security Analysis               │
│  ├── Injection vulnerability checks                  │
│  ├── Authentication & authorization review           │
│  ├── Data leakage analysis                           │
│  ├── Cross-site vulnerability scan                   │
│  ├── Configuration security audit                    │
│  ├── Dependency vulnerability check                  │
│  ├── Cloud/Backend security review                   │
│  ├── Platform-specific checks (macOS/iOS/Linux/Win)  │
│  └── Business logic flaw analysis                    │
│                                                      │
│  Phase 3: Report Generation                          │
│  ├── Generate security-report.html (human-readable)  │
│  └── Generate security-findings.md (agent-readable)  │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Areas for Contribution
- Additional vulnerability detection patterns
- Support for more languages/frameworks
- Enhanced report formatting
- CI/CD integration examples
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP Top 10 - https://owasp.org/www-project-top-ten/
- CWE Database - https://cwe.mitre.org/
- Security research community worldwide

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/dev-ecd-dm/csreview/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dev-ecd-dm/csreview/discussions)

---

**Made with ❤️ for secure software development**
