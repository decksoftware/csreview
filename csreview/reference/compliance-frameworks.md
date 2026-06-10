# CSReview Reference - Compliance & Framework Correlation

**Honesty contract**: the engine maps findings to the frameworks below by CWE
correlation only (see `COMPLIANCE_MAP` in `src/detector.js`). It does NOT
compute per-article PASS/FAIL verdicts, ASVS coverage percentages, or SLSA
levels, and the agent MUST NOT fabricate such numbers in summaries. Per-article
or per-requirement assessments may appear in a report only when a human or the
agent explicitly evaluated that requirement against the workspace and says so.
Compliance output is **indicative correlation, not an audited compliance
verification**.

## SLSA Supply Chain Review (SLSA Build L3, v1.2)

Checklist for the agent's supply-chain review. Reference requirements with
track + level + version (e.g. "SLSA Build L3 (v1.2)").

**Source integrity**: signed commits, branch protection, required reviews,
CODEOWNERS, repository permission audit, 2FA enforcement.

**Build integrity**: automated CI/CD, reproducible/hermetic builds, hosted build
service, signed build attestations/provenance, artifact signing
(Sigstore/cosign/GPG), base image verification.

**Dependency security**: lock files present and committed, exact version
pinning, integrity hashes, SBOM generation and maintenance, automated
vulnerability scanning, typosquatting review, license audit.

**Deployment security**: dev/staging/production separation, secrets in a
vault/manager (not code or committed env files), restricted and audited
deployment access, rollback capability, audited IaC templates.

## OWASP ASVS 5.0.0 Review Areas

Systematic verification areas from the OWASP Application Security Verification
Standard 5.0.0 (stable since 2025-05-30). Reference requirements with the
version, e.g. `v5.0.0-1.2.5`. The engine's `COMPLIANCE_MAP` correlates CWEs to
ASVS chapters; chapter-by-chapter verification is agent/human work.

- **V1 Architecture**: threat model, security architecture, trust boundaries
- **V2 Authentication**: password policy, MFA, credential storage
  (bcrypt/scrypt/Argon2 — never MD5/SHA1), lockout, recovery
- **V3 Session Management**: random session IDs, lifecycle/timeout, cookie
  flags (HttpOnly/Secure/SameSite), session binding
- **V4 Access Control**: default deny, function-level and data-level checks,
  JWT verification, OAuth scopes
- **V5 Validation & Encoding**: input validation at every entry point,
  context-aware output encoding, deserialization safety, mass assignment
- **V6 Stored Cryptography**: key management, modern algorithms (AES-256,
  RSA-2048+; never DES/RC4), CSPRNG, key rotation
- **V7 Errors & Logging**: no sensitive info in errors, security event logging,
  log integrity, PII redaction, log injection prevention
- **V8 Data Protection**: classification, encryption at rest and in transit
  (TLS 1.2+), PII minimization, retention/deletion
- **V9 Communication**: TLS configuration, certificate validation/pinning, HSTS
- **V10 Malicious Code**: no backdoors/time bombs, anti-tampering
- **V11 Business Logic**: flow validation, abuse prevention, rate limiting
- **V12 Files & Resources**: upload restrictions, execution prevention, path
  traversal protection
- **V13 API & Web Services**: API authn/authz, rate limiting, GraphQL
  introspection off in production, WebSocket security
- **V14 Configuration**: secure build/deploy, security headers, debug off in
  production

## Regulatory Correlation Checklists

These lists support the agent when the user asks for a privacy/compliance
review. Many items are process/documentation controls that cannot be verified
from source code alone — say so explicitly instead of guessing.

### LGPD (Brazil)

Data inventory and classification; documented legal basis; granular consent and
withdrawal; data subject rights endpoints (access, correction, deletion,
portability); DPO contact; cross-border transfer safeguards; 72h ANPD breach
notification plan; privacy by design/default; processor agreements.

### GDPR (EU)

LGPD items plus: DPIA for high-risk processing; records of processing (ROPA);
right to be forgotten (automated deletion); machine-readable data portability;
timestamped, versioned consent records; EU representative for non-EU companies;
SCCs for international transfers.

### SOC 2 Type II

Security (access controls), availability (SLA monitoring, DR), processing
integrity (validation, error handling), confidentiality (classification,
encryption), privacy (collection/use/retention/disposal), continuous monitoring
and audit logging, change management.

### HIPAA (US)

PHI mapping in the codebase; role-based access with minimum-necessary; audit
logging of PHI access; AES-256 at rest and TLS 1.2+ in transit; BAAs with third
parties handling PHI; HIPAA-specific breach procedures; de-identification
methods; integrity controls. (BAA and similar contractual controls are process
items — not verifiable from code.)

### CCPA/CPRA (California)

Right to know/delete/opt-out/correct/limit; "Do Not Sell" mechanism when
applicable; opt-in for sensitive personal information; service provider
agreements; data minimization; documented retention schedules.
