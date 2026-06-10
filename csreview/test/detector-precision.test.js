// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectVulnerabilities } from '../src/detector.js';

// A small labeled corpus to guard detector precision (no false positives on safe
// code) and recall (catches the intended vulnerable class). Each positive lists
// the CWE it must surface; each negative must produce no HIGH/CRITICAL finding.

const POSITIVES = [
  {
    name: 'js-sqli',
    file: 'src/a.js',
    language: 'javascript',
    cwe: 'CWE-89',
    code: 'export const f = (id) => db.query(`SELECT * FROM users WHERE id=${id}`);\n',
  },
  {
    name: 'js-eval',
    file: 'src/b.js',
    language: 'javascript',
    cwe: 'CWE-95',
    code: 'export const run = (req) => eval(req.body.code);\n',
  },
  {
    name: 'js-cmd',
    file: 'src/c.js',
    language: 'javascript',
    cwe: 'CWE-78',
    code: 'export const ls = (req) => exec("ls " + req.query.dir);\n',
  },
  {
    name: 'react-xss',
    file: 'src/d.jsx',
    language: 'javascript',
    cwe: 'CWE-79',
    code: 'export const C = (userInput) => <div dangerouslySetInnerHTML={{ __html: userInput }} />;\n',
  },
  {
    name: 'dom-xss',
    file: 'src/e.js',
    language: 'javascript',
    cwe: 'CWE-79',
    code: 'export const set = (el, userInput) => { el.innerHTML = userInput; };\n',
  },
  {
    name: 'weak-md5',
    file: 'src/f.js',
    language: 'javascript',
    cwe: 'CWE-328',
    code: 'import crypto from "crypto";\nexport const h = (x) => crypto.createHash("md5").update(x).digest("hex");\n',
  },
  {
    name: 'py-pickle',
    file: 'src/g.py',
    language: 'python',
    cwe: 'CWE-502',
    code: 'import pickle\n\ndef load(data):\n    return pickle.loads(data)\n',
  },
  {
    name: 'py-shell',
    file: 'src/h.py',
    language: 'python',
    cwe: 'CWE-78',
    code: 'import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n',
  },
  {
    name: 'go-sqli',
    file: 'src/i.go',
    language: 'go',
    cwe: 'CWE-89',
    code: 'package main\nfunc q(db DB, x string) { db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", x)) }\n',
  },
  {
    name: 'aws-secret',
    file: 'src/j.js',
    language: 'javascript',
    cwe: 'CWE-798',
    code: 'export const key = "AKIAIOSFODNN7EXAMPLE";\n',
  },
  {
    name: 'jwt-none',
    file: 'src/k.js',
    language: 'javascript',
    cwe: 'CWE-347',
    code: 'export const opts = { algorithm: "none" };\n',
  },
  {
    name: 'path-traversal',
    file: 'src/l.js',
    language: 'javascript',
    cwe: 'CWE-22',
    code: 'import fs from "fs";\nexport const read = (req, cb) => fs.readFile(req.query.path, cb);\n',
  },
  {
    name: 'js-xxe-noent',
    file: 'src/m.js',
    language: 'javascript',
    cwe: 'CWE-611',
    code: 'import libxmljs from "libxmljs";\nexport const parse = (xml) => libxmljs.parseXml(xml, { noent: true });\n',
  },
  {
    name: 'py-xxe-resolve-entities',
    file: 'src/m2.py',
    language: 'python',
    cwe: 'CWE-611',
    code: 'from lxml import etree\n\nparser = etree.XMLParser(resolve_entities=True)\n',
  },
  {
    name: 'php-xxe-libxml-noent',
    file: 'src/m3.php',
    language: 'php',
    cwe: 'CWE-611',
    code: '<?php\n$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT);\n',
  },
];

const NEGATIVES = [
  {
    name: 'param-query',
    file: 'src/n1.js',
    language: 'javascript',
    code: 'export const f = (id) => db.query("SELECT * FROM users WHERE id = ?", [id]);\n',
  },
  {
    name: 'json-parse',
    file: 'src/n2.js',
    language: 'javascript',
    code: 'export const f = (req) => JSON.parse(req.body.data);\n',
  },
  {
    name: 'exec-file',
    file: 'src/n3.js',
    language: 'javascript',
    code: 'import { execFile } from "child_process";\nexport const ls = (safeDir) => execFile("ls", [safeDir]);\n',
  },
  {
    name: 'text-content',
    file: 'src/n4.js',
    language: 'javascript',
    code: 'export const set = (el, userInput) => { el.textContent = userInput; };\n',
  },
  {
    name: 'sha256',
    file: 'src/n5.js',
    language: 'javascript',
    code: 'import crypto from "crypto";\nexport const h = (x) => crypto.createHash("sha256").update(x).digest("hex");\n',
  },
  {
    name: 'yaml-safe',
    file: 'src/n6.py',
    language: 'python',
    code: 'import yaml\n\ndef load(data):\n    return yaml.safe_load(data)\n',
  },
  {
    name: 'subprocess-list',
    file: 'src/n7.py',
    language: 'python',
    code: 'import subprocess\n\ndef run(d):\n    return subprocess.run(["ls", d])\n',
  },
  {
    name: 'go-param',
    file: 'src/n8.go',
    language: 'go',
    code: 'package main\nfunc q(db DB, id string) { db.Query("SELECT * FROM t WHERE id=$1", id) }\n',
  },
  {
    name: 'random-bytes',
    file: 'src/n9.js',
    language: 'javascript',
    code: 'import crypto from "crypto";\nexport const token = () => crypto.randomBytes(32).toString("hex");\n',
  },
  { name: 'plain', file: 'src/n10.js', language: 'javascript', code: 'export const x = (a, b) => compute(a, b);\n' },
  // WEAK_CIPHER must not fire on the "des" substring inside includes/excludes/modes
  // (the reported false positives: args.includes('--no-update-check'), ids.includes('postgres')).
  {
    name: 'includes-not-cipher',
    file: 'src/n11.js',
    language: 'javascript',
    code: "export const f = (args) => args.includes('--no-update-check');\n",
  },
  {
    name: 'includes-postgres',
    file: 'src/n12.js',
    language: 'javascript',
    code: "export const ok = (ids) => ids.includes('postgres');\n",
  },
  {
    name: 'excludes-modes',
    file: 'src/n13.js',
    language: 'javascript',
    code: 'export const modes = ["a"];\nexport const g = (x) => x.excludes;\n',
  },
  // XML_XXE must require an explicitly insecure entity configuration. Browser
  // DOMParser never resolves external entities, and noent:false / nonet:true /
  // resolve_entities=False are the SAFE configurations.
  {
    name: 'domparser-benign',
    file: 'src/n14.js',
    language: 'javascript',
    code: 'export const parse = (html) => new DOMParser().parseFromString(html, "text/html");\n',
  },
  {
    name: 'libxml-safe-config',
    file: 'src/n15.js',
    language: 'javascript',
    code: 'import libxml from "libxmljs";\nexport const parse = (data) => libxml.parseXml(data, { noent: false, nonet: true });\n',
  },
  {
    name: 'py-xxe-safe',
    file: 'src/n16.py',
    language: 'python',
    code: 'from lxml import etree\n\nparser = etree.XMLParser(resolve_entities=False)\n',
  },
];

function runOne(sample) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-corpus-'));
  const abs = path.join(root, sample.file);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, sample.code, 'utf8');
  return detectVulnerabilities({
    root,
    files: [{ path: sample.file, language: sample.language, kind: 'source' }],
  });
}

function canonicalCwe(cwe) {
  return (String(cwe || '').match(/CWE-\d+/i) || [''])[0].toUpperCase();
}

test('detector recall on the positive corpus is >= 0.8', () => {
  let hits = 0;
  const misses = [];
  for (const sample of POSITIVES) {
    const findings = runOne(sample);
    if (findings.some((f) => canonicalCwe(f.cwe) === sample.cwe)) {
      hits += 1;
    } else {
      misses.push(sample.name);
    }
  }
  const recall = hits / POSITIVES.length;
  assert.ok(recall >= 0.8, `recall ${recall.toFixed(2)} too low; missed: ${misses.join(', ')}`);
});

test('detector produces no HIGH/CRITICAL false positives on the negative corpus', () => {
  const falsePositives = [];
  for (const sample of NEGATIVES) {
    const findings = runOne(sample);
    const highOrCritical = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    if (highOrCritical.length > 0) {
      falsePositives.push(`${sample.name}: ${highOrCritical.map((f) => f.id).join(', ')}`);
    }
  }
  assert.equal(falsePositives.length, 0, `unexpected false positives: ${falsePositives.join(' | ')}`);
});

// Regression guard for the XML_XXE pattern: the old `.*?(?!.*noent)` lookahead
// was always satisfiable, so ANY line mentioning an XML parser (including the
// entity-free browser DOMParser) produced a CRITICAL. The pattern must fire on
// explicitly insecure entity configuration and stay silent otherwise.
test('XML_XXE fires only on explicitly insecure entity configuration', () => {
  const insecure = POSITIVES.filter((sample) => sample.cwe === 'CWE-611');
  assert.ok(insecure.length >= 3, 'expected XXE positives in the corpus');
  for (const sample of insecure) {
    const findings = runOne(sample);
    assert.ok(
      findings.some((f) => canonicalCwe(f.cwe) === 'CWE-611'),
      `${sample.name}: expected a CWE-611 finding`,
    );
  }
  for (const sample of NEGATIVES.filter((s) =>
    ['domparser-benign', 'libxml-safe-config', 'py-xxe-safe'].includes(s.name),
  )) {
    const findings = runOne(sample);
    const xxe = findings.filter((f) => canonicalCwe(f.cwe) === 'CWE-611');
    assert.equal(
      xxe.length,
      0,
      `${sample.name}: safe XML usage must not raise CWE-611 (got ${xxe.map((f) => f.id).join(', ')})`,
    );
  }
});
