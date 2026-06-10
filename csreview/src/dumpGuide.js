// @ts-check
// Phase 9 helper (READ-ONLY): generate a per-backend "how to make a safe local dump"
// guide so the user can prepare an ISOLATED local copy for behavioral DB testing.
// This module never connects to any database and never reads secret VALUES — it only
// detects which backends a project uses and renders an instructional HTML report.
import fs from 'fs';
import path from 'path';
import { safeResolveInside } from './pathSafety.js';
import { sanitizeAgentName } from './agentName.js';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// fileBased: the database lives in a file. Finding that file in the repo/installer is
// itself a data-exposure finding, flagged before any test.
export const BACKENDS = [
  {
    id: 'postgres',
    name: 'PostgreSQL',
    fileBased: false,
    deps: ['pg', 'postgres', 'pg-promise', 'slonik'],
    extensions: [],
    files: [],
    hints: ['postgres://', 'postgresql://'],
    copy: 'pg_dump --no-owner --no-privileges --schema-only -d "$DATABASE_URL" > schema.sql   # add data only if a test truly needs it',
    restore: 'createdb app_test && psql app_test < schema.sql',
    needs: 'RLS policies, roles/grants, CHECK/FK constraints, sensitive columns.',
    notes: 'Prefer schema-only + 2-3 synthetic users (zero real PII). Never dump production.',
  },
  {
    id: 'supabase',
    name: 'Supabase (PostgreSQL + RLS)',
    fileBased: false,
    deps: ['@supabase/supabase-js', 'supabase'],
    extensions: [],
    files: ['supabase/config.toml', 'supabase/migrations'],
    hints: ['supabase.co'],
    copy: 'supabase db dump -f schema.sql        # + supabase db dump --role-only -f roles.sql  (RLS/roles)',
    restore: 'supabase start  (local stack) — or restore schema.sql into a throwaway local PostgreSQL',
    needs: 'RLS policies on user-scoped tables, roles, exposed service_role usage.',
    notes: 'RLS testing only needs schema + synthetic users. Never point at the hosted project URL.',
  },
  {
    id: 'mysql',
    name: 'MySQL / MariaDB',
    fileBased: false,
    deps: ['mysql', 'mysql2', 'mariadb'],
    extensions: [],
    files: ['my.cnf'],
    hints: ['mysql://', 'mariadb://'],
    copy: 'mysqldump --no-data db > schema.sql        # add data only if needed',
    restore: 'mysql -e "CREATE DATABASE app_test" && mysql app_test < schema.sql',
    needs: 'GRANTs, constraints, sensitive columns.',
    notes: 'Use a local test instance. Never dump production credentials/data.',
  },
  {
    id: 'mongodb',
    name: 'MongoDB',
    fileBased: false,
    deps: ['mongodb', 'mongoose'],
    extensions: [],
    files: [],
    hints: ['mongodb://', 'mongodb+srv://'],
    copy: 'mongodump --uri="mongodb://localhost:27017/db" --out=dump/',
    restore: 'mongorestore --db app_test dump/db/',
    needs: 'Schema validation rules, indexes, field-level access, operator-injection surface.',
    notes: 'Restore to a local throwaway mongod. Prefer a minimized/synthetic dataset.',
  },
  {
    id: 'sqlite',
    name: 'SQLite',
    fileBased: true,
    deps: ['better-sqlite3', 'sqlite3', 'sql.js'],
    extensions: ['.db', '.sqlite', '.sqlite3'],
    files: [],
    hints: ['sqlite:'],
    copy: 'cp app.db app_test.db        # or: sqlite3 app.db ".dump" > dump.sql',
    restore: 'open the copy: sqlite3 app_test.db   (schema: ".schema")',
    needs: 'Schema/constraints, sensitive columns, default/seed credentials.',
    notes: 'File-based: a .db/.sqlite file in the repo is a data-exposure finding by itself.',
  },
  {
    id: 'firebird',
    name: 'Firebird / InterBase',
    fileBased: true,
    deps: ['node-firebird'],
    extensions: ['.fdb', '.gdb'],
    files: [],
    hints: ['firebird'],
    copy: 'gbak -b -user SYSDBA -password <pwd> /path/db.fdb /path/backup.fbk',
    restore: 'gbak -c /path/backup.fbk /path/app_test.fdb   (schema: isql -x app_test.fdb)',
    needs: 'Roles/grants, parameterization in PSQL, embedded credentials.',
    notes: 'Classic risks: default SYSDBA/masterkey password, unencrypted .fdb. File in repo = finding.',
  },
  {
    id: 'msaccess',
    name: 'Microsoft Access (MDB/ACCDB)',
    fileBased: true,
    deps: [],
    extensions: ['.mdb', '.accdb'],
    files: [],
    hints: ['microsoft.ace.oledb', 'microsoft.jet.oledb'],
    copy: 'copy the .mdb/.accdb file (it IS the database)',
    restore:
      'inspect with mdb-tools: mdb-schema file.mdb / mdb-tables file.mdb / mdb-export file.mdb <table>   (or ODBC on Windows)',
    needs: 'Schema, weak DB password, plaintext sensitive data.',
    notes:
      'Weak/no encryption and weak passwords are common; often shipped inside installers. File in repo/installer = finding.',
  },
  {
    id: 'libreoffice_base',
    name: 'LibreOffice Base (.odb)',
    fileBased: true,
    deps: [],
    extensions: ['.odb'],
    files: [],
    hints: [],
    copy: 'copy the .odb file (it is a ZIP with an embedded HSQLDB/Firebird DB)',
    restore: 'unzip app.odb -d app_odb/  → inspect app_odb/database/ (embedded HSQLDB "script" file is readable SQL)',
    needs: 'Embedded DB schema, embedded credentials, plaintext data.',
    notes:
      'Embedded DB is usually unencrypted; embedded HSQLDB defaults to user SA with EMPTY password. .odb in repo = finding.',
  },
  {
    id: 'hsqldb',
    name: 'HSQLDB (HyperSQL)',
    fileBased: true,
    deps: [],
    extensions: ['.script', '.lobs'],
    files: [],
    hints: ['jdbc:hsqldb:'],
    copy: "copy the *.script/*.data/*.properties files (the .script file IS readable SQL)   # or run SQL: SCRIPT 'dump.sql'",
    restore: 'point a local HSQLDB instance at the copied files',
    needs: 'Schema/constraints, default credentials.',
    notes:
      'Default user SA with EMPTY password is the classic issue; files are unencrypted by default. Files in repo = finding.',
  },
  {
    id: 'pocketbase',
    name: 'PocketBase (SQLite)',
    fileBased: true,
    deps: ['pocketbase'],
    extensions: [],
    files: ['pb_data', 'pb_migrations'],
    hints: [],
    copy: 'copy pb_data/data.db (SQLite) — or use the admin UI: Settings → Backups',
    restore: 'point a local PocketBase at the copied pb_data/',
    needs: 'Collection API rules, default admin credentials, field-level access.',
    notes: 'File-based: pb_data/data.db in the repo is a data-exposure finding.',
  },
  {
    id: 'appwrite',
    name: 'Appwrite',
    fileBased: false,
    deps: ['appwrite', 'node-appwrite'],
    extensions: [],
    files: ['appwrite.json'],
    hints: [],
    copy: 'export collections via the appwrite CLI (or dump the MariaDB container with mariadb-dump)',
    restore: 'spin up a local Appwrite and import the export',
    needs: 'Collection permissions, attribute validation, API key scope.',
    notes: 'Use a local instance; never export from the production project.',
  },
  {
    id: 'nocodb',
    name: 'NocoDB',
    fileBased: false,
    deps: ['nocodb'],
    extensions: [],
    files: [],
    hints: ['nc_db', 'nocodb'],
    copy: 'dump the underlying DB (pg_dump/mysqldump) plus the NocoDB meta database',
    restore: 'restore the underlying DB + meta locally',
    needs: 'Base/table ACLs, underlying DB constraints.',
    notes: 'Treat the underlying DB with the same backend rules above.',
  },
  {
    id: 'firebase',
    name: 'Firebase / Firestore',
    fileBased: false,
    deps: ['firebase', 'firebase-admin'],
    extensions: [],
    files: ['firebase.json', 'firestore.rules', '.firebaserc'],
    hints: ['firebaseio.com'],
    copy: 'firebase firestore:export ./fs-export   (or gcloud firestore export)',
    restore: 'firebase emulators:start  +  import ./fs-export into the local emulator',
    needs: 'Security rules (request.auth checks), App Check, unbounded reads.',
    notes: 'Test against the local emulator only; never export from the live project into a shared place.',
  },
];

/**
 * Detect which backends a project uses from path/dep/connection-scheme signals.
 * @param {{paths?: string[], deps?: string[], hints?: string[]}} signals
 */
export function detectBackends(signals = {}) {
  const paths = (signals.paths || []).map((p) =>
    String(p || '')
      .replace(/\\/g, '/')
      .toLowerCase(),
  );
  const deps = new Set((signals.deps || []).map((d) => String(d || '').toLowerCase()));
  const hints = (signals.hints || []).map((h) => String(h || '').toLowerCase());

  const detected = [];
  for (const backend of BACKENDS) {
    const byExt = (backend.extensions || []).some((ext) => paths.some((p) => p.endsWith(ext)));
    const byFile = (backend.files || []).some((f) => {
      const needle = f.toLowerCase();
      return paths.some(
        (p) => p === needle || p.endsWith('/' + needle) || p.includes(needle + '/') || p.includes(needle),
      );
    });
    const byDep = (backend.deps || []).some((d) => deps.has(d.toLowerCase()));
    const byHint = (backend.hints || []).some((h) => hints.some((x) => x.includes(h)));
    if (byExt || byFile || byDep || byHint) {
      detected.push(backend);
    }
  }
  return detected;
}

function backendCard(backend) {
  return `<article class="backend${backend.fileBased ? ' file-based' : ''}">
  <h2>${escapeHtml(backend.name)}</h2>
  ${backend.fileBased ? '<p class="flag">⚠️ File-based database — if this file is in your repository or installer, that is already a data-exposure finding. Remove it and rotate any exposed data.</p>' : ''}
  <h3>1. Make a copy (prefer schema-only)</h3>
  <pre><code>${escapeHtml(backend.copy)}</code></pre>
  <h3>2. Restore / inspect locally (throwaway)</h3>
  <pre><code>${escapeHtml(backend.restore)}</code></pre>
  <p><strong>What CSReview tests:</strong> ${escapeHtml(backend.needs)}</p>
  <p class="notes"><strong>Safety:</strong> ${escapeHtml(backend.notes)}</p>
</article>`;
}

export function renderDumpGuideHtml(projectName, detected) {
  const cards =
    detected.length > 0
      ? detected.map(backendCard).join('\n')
      : '<p>No supported database backend was detected in this project. If you use one, prepare a schema-only copy of a local test instance before Phase 9.</p>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CSReview Phase 9 - Local DB Dump Guide</title>
<style>
body { font-family: Arial, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #172033; }
main { max-width: 1040px; margin: 0 auto; }
.golden { background: #fef3c7; border: 1px solid #fde68a; border-radius: 8px; padding: 16px; margin: 16px 0; }
.backend { background: #fff; border: 1px solid #dbe3ef; border-left: 5px solid #2563eb; border-radius: 8px; padding: 18px; margin: 16px 0; }
.backend.file-based { border-left-color: #ca8a04; }
.flag { background: #fff7ed; border: 1px solid #fed7aa; padding: 10px; border-radius: 6px; }
.notes { color: #475569; }
pre { overflow: auto; background: #111827; color: #e5e7eb; padding: 14px; border-radius: 6px; }
</style>
</head>
<body>
<main>
<h1>CSReview — Local Database Dump Guide (Phase 9 prerequisite)</h1>
<div class="golden">
<p><strong>Why this exists:</strong> Phase 9 (Local DAST + DB behavioral tests) is the only stage that really validates, at runtime, that your fixes hold. To do it safely you must test a <strong>local, isolated COPY</strong> — never the real database.</p>
<ul>
<li><strong>Golden rule:</strong> copy/restore to a throwaway local instance. Never test production, staging, or the source database.</li>
<li><strong>Least data:</strong> prefer a <strong>schema-only</strong> dump plus 2-3 <strong>synthetic</strong> users — most checks (RLS, constraints, grants, default creds) need no real data and carry zero PII risk.</li>
<li>If you must use real data, <strong>anonymize/minimize</strong> it, store the copy in a secure local place, and delete it after testing.</li>
<li>A database dump/file committed to the repository is itself a <strong>critical</strong> finding.</li>
</ul>
</div>
<p><strong>Project:</strong> ${escapeHtml(projectName)}</p>
<h2>Detected backends</h2>
${cards}
</main>
</body>
</html>`;
}

function readPackageDeps(rootDir) {
  try {
    // Contained resolution (rejects traversal / absolute escapes) instead of a
    // raw path.join — the joined component is a constant, but this keeps the
    // codebase's read-only safe-path invariant and clears the scanner warning.
    const pkgPath = safeResolveInside(rootDir, 'package.json');
    if (!pkgPath || !fs.existsSync(pkgPath)) return [];
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    return Object.keys({
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.peerDependencies || {}),
    });
  } catch {
    return [];
  }
}

/**
 * Generate the dump guide HTML for a scanned project.
 * @param {{root?: string, name?: string, files?: string[], configFiles?: string[], depFiles?: string[], baasFiles?: string[]}} projectInfo
 * @param {string} outputPath
 * @param {{agentName?: string, deps?: string[], hints?: string[]}} [options]
 */
export function generateDumpGuide(projectInfo = {}, outputPath, options = {}) {
  const paths = [
    ...(projectInfo.files || []),
    ...(projectInfo.configFiles || []),
    ...(projectInfo.depFiles || []),
    ...(projectInfo.baasFiles || []),
  ];
  const deps = options.deps || (projectInfo.root ? readPackageDeps(projectInfo.root) : []);
  const detected = detectBackends({ paths, deps, hints: options.hints || [] });

  const projectName = projectInfo.name || (projectInfo.root ? path.basename(projectInfo.root) : 'project');
  const html = renderDumpGuideHtml(projectName, detected);

  if (outputPath) {
    fs.writeFileSync(outputPath, html, 'utf8');
  }

  return { detected: detected.map((b) => b.id), outputPath, html };
}

export { sanitizeAgentName };
