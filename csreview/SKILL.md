---
name: "csreview"
description: "Ultra-deep security audit and pentest analysis for codebases. Generates HTML report for humans and MD report for agents. Invoke when user requests security review, code audit, vulnerability scan, or pentest analysis."
---

# CSReview - Code Security Review

## Overview

This skill performs ultra-deep security analysis (automated pentest level) on codebases across multiple languages, frameworks, and platforms. It identifies vulnerabilities, data leakage risks, misconfigurations, and security flaws, then generates:

1. **HTML Report** (`security-report.html`) - Visual report for human review with executive summary, charts, and detailed findings
2. **Markdown Report** (`security-findings.md`) - Structured report for AI agents to automatically fix vulnerabilities

**CSReview is READ-ONLY**: It never modifies, deletes, or moves any files. It only identifies problems, locates them precisely, and suggests solutions based on the frameworks and technologies in use. The actual fixes are applied by the human developer or the coding agent. When encountering unfamiliar frameworks, CSReview researches official documentation and community forums to provide accurate recommendations.

The analysis covers 8 phases: Reconnaissance, Ultra-Deep Security, Database Security, SLSA 3 Supply Chain, OWASP ASVS, Compliance (LGPD/GDPR/SOC2/HIPAA/CCPA-CPRA), Vibe Coding Protection, and Dual Report Generation.

CSReview includes built-in **Code Review** capabilities (equivalent to codex:review, codex:adversarial-review, code-review, requesting-code-review, receiving-code-review) - no additional skills or plugins required.

## When to Invoke

- User requests security review or code audit
- User asks for vulnerability scan or pentest analysis
- User wants to check for data leakage or exposed secrets
- User mentions SQL injection, XSS, auth flaws, or security concerns
- Before production deployment for security validation
- User asks to review Supabase, Firebase, Appwrite, Neon, or similar backend security
- User invokes `@csreview` or mentions CSReview
- User wants compliance verification (LGPD, GDPR, SOC 2, HIPAA)
- User built code with AI agents and wants to verify security (vibe coding check)
- User wants database structure security validation (SQL/NoSQL/BaaS)
- User requests code review (`@csreview review [files]`)
- User requests adversarial review (`@csreview adversarial [files]`)
- User requests security-focused review (`@csreview security-review [files]`)
- User wants to review changes in a PR or branch (`@csreview request-review [scope]`)
- User wants to apply fixes from a report (`@csreview apply-fixes [report]`)

## Supported Technologies

### Languages & Frameworks
- **Frontend**: React, Vue, Nuxt, Angular, Svelte, Next.js
- **Mobile**: Flutter, Kotlin (Android), Swift (iOS), React Native
- **Backend**: Python, Node.js, C#, Go, Java, PHP, Ruby
- **Systems**: C, C++, Rust
- **Desktop**: Electron, Tauri, native apps

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

**Cross-Agent Behavior**: Regardless of which agent invokes this skill, the analysis depth, report format, and vulnerability detection remain consistent. The HTML report is always generated in the user's language; the MD report is always in English for agent consumption.

## Analysis Phases

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

#### 2.10 Logic & Business Flaws
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

### Phase 4: SLSA 3 Supply Chain Security

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

Systematic verification against OWASP Application Security Verification Standard (ASVS) 4.0.

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

### Phase 7: Vibe Coding Protection

Specific analysis for code generated by AI coding agents (vibe coding) which often introduces security vulnerabilities due to non-expert users building software.

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

#### 7.2 AI Agent Behavioral Patterns

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

#### 7.3 Vibe Coding Risk Scoring

Each finding includes a "Vibe Risk" score indicating how likely it was introduced by AI-assisted development:

| Risk Level | Description | Indicator |
|------------|-------------|-----------|
| **AI-Likely** | Pattern commonly generated by AI agents | Classic AI anti-pattern with no security consideration |
| **AI-Possible** | Could be AI-generated or human oversight | Common mistake that AI agents frequently make |
| **Human-Likely** | More likely a deliberate (though poor) choice | Intentional but insecure design decision |
| **Uncertain** | Cannot determine origin | Ambiguous pattern |

### Phase 8: Report Generation

Generate TWO reports in the project root:

---

## Report 1: HTML Report (For Humans)

File: `security-report.html`

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
│ Exploitation Scenario:                          │
│ Step-by-step how an attacker could exploit      │
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
          <span>Vibe Risk: AI-Likely</span>
          <span>Compliance: OWASP ASVS V5.3, GDPR Art.32</span>
        </div>
        <div class="finding-content">
          <h3>Description</h3>
          <p>...</p>
          <h3>Vulnerable Code</h3>
          <pre><code class="language-typescript">...</code></pre>
          <h3>Exploitation Scenario</h3>
          <p>...</p>
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

File: `security-findings.md`

This report is structured for AI agents to parse and automatically fix vulnerabilities. It contains machine-readable findings with exact file locations, vulnerable code, and corrected code blocks. **Always generated in English** regardless of user language.

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
**Vibe Coding Risk**: [AI-Likely: count] | [AI-Possible: count] | [Human-Likely: count]

---

## Summary Table

| ID | Severity | Category | File | Line | Issue | Vibe Risk | Compliance |
|----|----------|----------|------|------|-------|-----------|------------|
| 001 | CRITICAL | SQL Injection | src/auth.ts | 45 | Raw SQL query with user input | AI-Likely | ASVS V5.3, GDPR Art.32 |
| 002 | HIGH | XSS | src/components/UserInput.vue | 12 | Unsanitized v-html binding | AI-Likely | ASVS V5.2, LGPD Art.46 |
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
**Vibe Risk**: AI-Likely
**Compliance**: OWASP ASVS V5.3, GDPR Art.32, LGPD Art.46, SOC 2 CC6.1

#### Description
Raw SQL query constructed with string concatenation using user-supplied input, allowing SQL injection attacks.

#### Vulnerable Code
```typescript:src/auth.ts:40-50
// Lines 40-50
const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
const result = await db.query(query);
```

#### Exploitation Scenario
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
**Recommendations**: [list of actions to reach SLSA 3]

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

### AI-Likely Vulnerabilities
Findings with high probability of being introduced by AI coding agents:

| ID | Pattern | Risk Level | Recommendation |
|----|---------|------------|----------------|
| 001 | String concatenation SQL | AI-Likely | Replace with parameterized queries |
| 003 | MD5 password hashing | AI-Likely | Switch to bcrypt/Argon2 |

### AI Code Quality Score
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
1. AI-Likely vulnerabilities (most likely to be widespread if generated by AI)
2. Compliance-critical findings (regulatory violations)
3. Database security issues
4. Supply chain concerns

## Agent Instructions

When fixing these findings (note: CSReview only reports; the coding agent or developer applies fixes):

1. Read the vulnerable file at the specified line numbers
2. Understand the context before applying the fix
3. If the framework is unfamiliar, research official documentation before applying fixes
4. Apply the corrected code exactly as shown
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
@csreview apply-fixes [report.md]            → Apply fixes from report (Mode 5)
```

## Execution Workflow

When invoked, follow these steps:

1. **Announce the scan**: Inform user about starting security analysis
2. **Phase 1 - Recon**: Scan project structure, identify technologies, map attack surface
3. **Phase 2 - Deep Analysis**: Systematically check each vulnerability category (injection, auth, data leakage, XSS, CSRF, config, deps, cloud, platform-specific, logic flaws)
4. **Phase 3 - Database Security**: Analyze SQL/NoSQL/BaaS database structures, access patterns, and configurations
5. **Phase 4 - SLSA 3**: Assess supply chain integrity (source, build, dependency, deployment)
6. **Phase 5 - OWASP ASVS**: Systematic verification against V1-V14 categories
7. **Phase 6 - Compliance**: Check LGPD, GDPR, SOC 2, HIPAA, CCPA-CPRA requirements
8. **Phase 7 - Vibe Coding**: Detect AI-generated code vulnerability patterns and risk scoring
9. **Progress updates**: Keep user informed of analysis progress throughout
10. **Phase 8 - Report Generation**: Create BOTH reports:
    - `security-report.html` (visual report in user's language for human review)
    - `security-findings.md` (structured report in English for AI agent fixes)
11. **Deliver reports**: Provide paths to both generated files
12. **Summary**: Give brief verbal summary of critical/high findings including compliance gaps and vibe coding risks
13. **Offer auto-fix**: Ask if user wants agent to automatically fix findings using the MD report

## Important Guidelines

- **READ-ONLY**: CSReview NEVER modifies, deletes, or moves any files in the analyzed project. It only identifies, reports, and suggests fixes.
- **Never expose secrets in chat**: If you find hardcoded credentials, mention them in the reports only, not in the conversation
- **Be thorough but practical**: Focus on exploitable vulnerabilities, not theoretical edge cases
- **Provide actionable fixes**: Every finding must include a concrete solution with corrected code, but the fix is applied by the human developer or coding agent, not by CSReview
- **Context matters**: Consider the application type (internal tool vs public API) when assessing severity
- **False positives**: Only report confirmed vulnerabilities, avoid noise
- **Prioritize**: Critical and High findings should be clearly highlighted
- **Respect scope**: Only analyze code in the specified project, don't test external services
- **MD report precision**: File paths and line numbers in the MD report must be exact for agent auto-fix to work
- **HTML report language**: Generate the HTML report in the same language as the user's conversation language
- **MD report language**: Always generate the MD report in English regardless of user language (for agent consumption)
- **Compliance findings**: Clearly map each compliance gap to the specific regulation article/section
- **Vibe coding markers**: Tag findings with AI-Likelihood score to help users understand if vulnerability was likely AI-introduced
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
User: "@csreview apply-fixes security-findings.md"

## Output

- **Primary**: `security-report.html` in project root (visual report in user's language for human review)
- **Secondary**: `security-findings.md` in project root (structured report in English for AI agent auto-fix)
- **Tertiary**: Verbal summary of critical/high findings in chat including compliance gaps and vibe coding risks
- **Optional**: JSON export available via HTML report button
