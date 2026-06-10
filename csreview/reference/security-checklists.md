# CSReview Reference - Security Review Checklists

Reference material for the agent's contextual review pass (after the engine run).
These checklists guide what to LOOK FOR when reading flagged files and their
surroundings. They are not detector rules: the deterministic engine and the
external tools report what they detect; the agent uses these lists to reason
about context the tools cannot see.

## Injection Vulnerabilities

- **SQL Injection**: raw queries, string concatenation, ORM misuse
- **NoSQL Injection**: MongoDB operator injection, Redis command injection
- **Command Injection**: exec(), system(), subprocess calls with user input
- **LDAP / XPath Injection**: directory and XML query manipulation
- **Template Injection**: SSTI in Jinja2, Twig, EJS, and similar engines

## Authentication & Authorization

- **JWT flaws**: missing validation, weak secrets, algorithm confusion
- **Session management**: insecure cookies, missing HttpOnly/Secure flags
- **RLS policies**: missing or bypassable Row Level Security (Supabase/Postgres)
- **Role-based access**: privilege escalation, missing authorization checks
- **IDOR**: insecure direct object references exposing other users' data
- **OAuth/OpenID**: misconfigured flows, token leakage, redirect URI flaws

## Data Leakage

- Sensitive data in console.log/logger/error messages; stack traces shown to users
- PII in API responses without filtering; debug endpoints enabled in production
- Server/framework version disclosure in headers; sensitive data cached in browser/CDN

## Cross-Site Vulnerabilities

- **XSS**: reflected, stored, DOM-based (dangerouslySetInnerHTML, v-html, innerHTML)
- **CSRF**: missing tokens, SameSite cookie misconfiguration
- **CORS**: overly permissive origins, wildcard Access-Control-Allow-Origin
- **Clickjacking**: missing X-Frame-Options or CSP frame-ancestors

## Insecure Configurations

- Missing security headers (CSP, HSTS, X-Content-Type-Options)
- Weak TLS ciphers, missing certificate pinning, HTTP fallback
- File uploads without type/size validation; path traversal in file operations
- Missing rate limiting on authentication and expensive endpoints
- Verbose error handling and information disclosure

## Dependency & Supply Chain

- Known CVEs in dependencies (engine: package audit + OSV-Scanner)
- Suspicious packages, typosquatting, compromised or hallucinated dependencies
- Restrictive licenses in production dependencies

## Cloud & BaaS Backends

**Supabase**: missing RLS on sensitive tables; `allow all authenticated` policies;
service role key in client code; public storage buckets; edge functions without
auth; realtime subscriptions without authorization; missing webhook validation.

**Firebase/Firestore**: rules allowing unauthenticated read/write; rules without
`request.auth` checks; storage rules without file type/size validation; missing
App Check; API keys with excessive permissions; functions without auth; missing
subcollection rules.

**Appwrite**: collection permissions set to `any`; missing attribute validation;
function execution without auth; broad storage permissions; missing webhook
signature validation; over-scoped API keys.

**Neon**: connection strings with credentials in code; missing SSL/TLS
enforcement; unrestricted branch access; missing RLS.

**PocketBase**: default admin credentials; permissive collection rules; missing
field encryption; upload rules without validation; missing rate limiting.

**Convex**: missing authentication in functions; broad document access; missing
mutation validation; sensitive data in logged function arguments.

## Firebase Cost & Performance Patterns

Cost-relevant patterns the agent should flag when reviewing Firebase projects
(report them as findings with cost impact context):

**Rules**: `allow read, write: if true;` (cost explosion); `allow read: if
request.auth != null;` on whole collections; root-level `.read/.write: true` in
Realtime Database; missing `request.resource.size` limits; `allow list` without
`request.query.limit`.

**Queries**: `getDocs(collection(...))` without `.limit()` or pagination;
missing cursors (`startAfter`/`endBefore`); `onSnapshot` listeners without
unsubscribe; `getDocs()` inside loops (N+1); reading whole documents when few
fields are needed; `ref.once('value')` on root or large nodes.

**Cloud Functions**: `onWrite`/`onCreate` triggers on high-write collections;
HTTP functions without rate limiting (DDoS = cost spike); over-allocated memory;
recursive trigger patterns (function writes to the collection that triggers it);
unnecessary reads before writes.

**Storage**: no upload size limits (client AND server); missing file cleanup on
deletion; missing App Check; missing CDN cache headers; missing lifecycle rules.

**Indexes & connections**: missing composite indexes (full scans); over-indexing
high-write fields; listeners not cleaned up on unmount; multiple app instances;
unbatched bulk writes.

**Estimation**: flag unbounded queries that could read entire collections,
single user actions that fan out into N operations, and projected storage growth
without cleanup policies. Recommend budget alerts and spending limits.

## Platform-Specific Surfaces

**macOS**: App Sandbox escapes, Keychain access patterns, TCC permission abuse,
plist exposure, XPC vulnerabilities, Gatekeeper bypass, world-readable files.

**iOS**: insecure URL schemes, Keychain exposure, TLS validation bypass,
UserDefaults storing secrets, ATS disabled, screenshot/cache exposure, insecure
WKWebView configuration.

**Linux**: SUID/SGID binaries, cron injection, insecure systemd units, sudoers
misconfigurations, exposed Unix sockets, container escape vectors, insecure
mounts.

**Windows**: registry exposure of secrets, UAC bypass, insecure COM objects,
DLL hijacking, named pipe ACLs, service privilege escalation, insecure file
ACLs, token impersonation.

**Cross-platform**: path traversal, symlink attacks, environment variable
injection, predictable temp files, TOCTOU races, buffer overflows in native
code, unprotected IPC, plaintext credential storage.

## .NET / ASP.NET

- Missing `[Authorize]` attributes; CORS `AllowAnyOrigin` in production
- Missing anti-forgery tokens; insecure cookie configuration
- Secrets in `appsettings.json` without user-secrets/key vault
- `ASPNETCORE_ENVIRONMENT=Development` in production; missing HSTS
- EF Core: `FromSqlRaw` with interpolated input; unparameterized dynamic LINQ;
  connection strings in plain text; N+1 lazy loading
- NuGet: untrusted sources, missing `nuget.config` restrictions, missing lock files
- Binary: BinaryFormatter/SoapFormatter deserialization, missing strong naming,
  reflection-based type loading from untrusted input

## Delphi / Lazarus / Free Pascal

- Hardcoded credentials in `.dpr`/`.lpr`/`.pas`; plaintext connection strings
  (dbExpress/FireDAC/SQLdb); Firebird/InterBase embedded passwords
- Missing parameterized queries (including `EXECUTE STATEMENT` in Firebird PSQL)
- Unencrypted `.fdb`/`.gdb`/SQLite files; missing TLS on Indy/Synapse sockets
- Unsafe pointer operations; missing `{$RANGECHECKS ON}`/`{$OVERFLOWCHECKS ON}`;
  buffer issues in `Move`/`FillChar`/`GetMem`
- Insecure INI/registry storage of sensitive data

## Go

- SQL via `fmt.Sprintf` instead of parameterized queries
- `exec.Command` with unsanitized input; user-controlled paths in file reads
- `template.HTML` bypassing auto-escaping; `unsafe.Pointer`/CGo boundaries
- Goroutine leaks (missing context cancellation); data races on shared state
- CORS `AllowAllOrigins: true`; missing body size limits; missing rate limiting
- Modules: `replace` directives to untrusted sources; missing `go.sum`;
  `govulncheck` findings

## Installers, DLLs & Binaries

- DLL hijacking/side-loading; missing ASLR/DEP flags; unsigned DLLs
- Installer custom actions with elevated privileges; unsigned installers;
  insecure file permissions set at install; leftover sensitive files on uninstall
- Auto-update over HTTP or without signature verification; debug symbols/PDB in
  release; missing compiler hardening flags (`/GS`, `/DYNAMICBASE`, `/NXCOMPAT`)

## Logic & Business Flaws

- Race conditions and TOCTOU; business logic bypass (payment/validation skips)
- Mass assignment from unfiltered user input
- Insecure deserialization (pickle, YAML, BinaryFormatter, unsafe JSON revivers)

## Database Security (SQL / NoSQL)

**Structure**: schema flaws enabling leakage; missing FK constraints; missing
audit columns; missing soft-delete for compliance data.

**Queries**: dynamic SQL built by concatenation; injectable stored procedures;
`SELECT *` on sensitive tables; unbounded queries without LIMIT enabling
exfiltration.

**Access**: app connections using DBA-privileged users; default credentials;
databases reachable from public networks; missing TLS; connection strings in
version control.

**Per engine**:
- PostgreSQL: RLS policies, `pg_hba.conf`, superuser roles, `search_path` injection
- MySQL/MariaDB: GRANT scope, `LOAD DATA INFILE`, `secure-file-priv`, binlog exposure
- SQL Server: `xp_cmdshell`, `TRUSTWORTHY` databases, dynamic SQL in procedures
- Firebird: SYSDBA default password, UDF library security
- SQLite: file permissions, encryption at rest, journal mode
- Oracle: TNS listener security, default accounts, PL/SQL privilege escalation
- MongoDB: auth disabled, `0.0.0.0` bind, operator injection, missing schema validation
- Redis: no `requirepass`, dangerous commands enabled (FLUSHALL/CONFIG/EVAL), no TLS
- CouchDB: admin party mode, permissive `_security`, exposed admin panel
- DynamoDB: over-permissive IAM, missing encryption at rest, unbounded scans
- Cassandra: AllowAllAuthenticator, missing encryption, broad grants
