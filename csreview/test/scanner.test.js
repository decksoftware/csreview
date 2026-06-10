// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanProject } from '../src/scanner.js';

// Monorepo coverage: config, dependency, and BaaS files live in nested
// workspaces (apps/*, services/*, packages/*), not only at the project root.
// The scanner must discover them recursively while still honoring the
// generated-cache exclusions (node_modules etc.).

function makeMonorepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-scanner-'));
  const write = (rel, content) => {
    const abs = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  };
  write('package.json', JSON.stringify({ name: 'monorepo', private: true }));
  write('apps/web/package.json', JSON.stringify({ name: 'web', dependencies: { nuxt: '^4.0.0' } }));
  write('apps/web/.env.production', 'PLACEHOLDER=value\n');
  write('services/api/Dockerfile', 'FROM node:24-alpine\n');
  write('services/api/firestore.rules', "rules_version = '2';\n");
  write('packages/lib/src/index.js', 'export const x = 1;\n');
  write('node_modules/leftpad/package.json', JSON.stringify({ name: 'leftpad' }));
  write('node_modules/leftpad/.env', 'SECRET=should-not-be-scanned\n');
  return root;
}

test('scanProject discovers nested config/dep/BaaS files in a monorepo', async () => {
  const root = makeMonorepo();
  const info = await scanProject(root);

  assert.ok(info.depFiles.includes('apps/web/package.json'), `nested package.json missing: ${info.depFiles}`);
  assert.ok(info.configFiles.includes('apps/web/.env.production'), `nested .env missing: ${info.configFiles}`);
  assert.ok(info.configFiles.includes('services/api/Dockerfile'), `nested Dockerfile missing: ${info.configFiles}`);
  assert.ok(
    info.baasFiles.includes('services/api/firestore.rules'),
    `nested firestore.rules missing: ${info.baasFiles}`,
  );
});

test('scanProject detects frameworks declared in nested workspace manifests', async () => {
  const root = makeMonorepo();
  const info = await scanProject(root);
  assert.ok(info.frameworks.includes('Nuxt'), `Nuxt not detected from apps/web/package.json: ${info.frameworks}`);
});

test('scanProject keeps generated caches excluded and orders dep files root-first', async () => {
  const root = makeMonorepo();
  const info = await scanProject(root);

  const all = [...info.files, ...info.configFiles, ...info.depFiles, ...info.baasFiles];
  assert.ok(
    !all.some((f) => f.includes('node_modules')),
    `node_modules leaked into discovery: ${all.filter((f) => f.includes('node_modules'))}`,
  );
  assert.ok(
    all.every((f) => !f.includes('\\')),
    'discovered paths must be /-normalized for cross-platform reports',
  );
  assert.equal(info.depFiles[0], 'package.json', 'root manifest must sort before nested ones');
});
