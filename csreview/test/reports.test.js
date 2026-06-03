// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateMarkdownReport, escapeMdInline, mdCodeSpan, fencedCode } from '../src/reports/markdown.js';
import { buildSarifLog, generateSarifReport } from '../src/reports/sarif.js';
import { generateHtmlReport } from '../src/reports/html.js';

function tmpFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csreview-reports-'));
  return path.join(dir, name);
}

function baseFinding(overrides = {}) {
  return {
    id: 'F1',
    severity: 'HIGH',
    category: 'Injection',
    name: 'Example finding',
    description: 'An example description.',
    file: 'src/app.js',
    line: 10,
    vulnerableCode: 'const x = 1;',
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized queries.',
    confidence: 'HIGH',
    references: ['https://example.test/ref'],
    ...overrides,
  };
}

test('escapeMdInline neutralizes table, code-span, link, and HTML metacharacters', () => {
  const escaped = escapeMdInline('a | b `c` [x](javascript:alert(1)) <script>');
  assert.match(escaped, /\\\|/); // pipe escaped
  assert.match(escaped, /\\`/); // backtick escaped
  assert.match(escaped, /\\\[x\\\]/); // brackets escaped -> no link
  assert.match(escaped, /&lt;script&gt;/); // HTML escaped
  assert.doesNotMatch(escaped, /<\s*script\b/i);
});

test('escapeMdInline collapses newlines so a field cannot break a table row', () => {
  assert.equal(escapeMdInline('line1\nline2'), 'line1 line2');
  assert.equal(escapeMdInline('line1\r\nline2'), 'line1 line2');
});

test('fencedCode always uses a fence longer than any backtick run in the snippet', () => {
  const block = fencedCode('a ``` b ```` c', 'javascript');
  const fenceMatch = block.match(/^(`+)javascript\n/);
  assert.ok(fenceMatch, 'opening fence present');
  assert.ok(fenceMatch[1].length >= 5, 'fence longer than the 4-backtick run inside');
  assert.match(block, /a ``` b ```` c/); // original content preserved verbatim
});

test('fencedCode ignores unsafe language identifiers', () => {
  const block = fencedCode('code', 'js"><script>');
  assert.match(block, /^```\ncode\n```$/);
});

test('mdCodeSpan strips backticks and escapes pipes so paths cannot break out', () => {
  assert.equal(mdCodeSpan('a`b|c'), '`ab\\|c`');
});

test('Markdown report escapes attacker-controlled finding fields', () => {
  const out = tmpFile('mal_security-findings.md');
  const finding = baseFinding({
    id: 'MAL1',
    name: 'Inject | pipe and <script>alert(1)</script> and [click](javascript:alert(2))',
    description: 'line1\nline2 with <img src=x onerror=alert(3)>',
    file: 'src/evil`name|x.js',
    vulnerableCode: 'before ``` injected.md.heading ``` after',
  });
  generateMarkdownReport({ name: 'demo', files: ['src/app.js'], configFiles: [] }, [finding], out, {});
  const md = fs.readFileSync(out, 'utf8');

  // Inline HTML neutralized in name/description (code block contains no HTML here).
  assert.doesNotMatch(md, /<script>/i);
  assert.doesNotMatch(md, /<img /);
  assert.match(md, /&lt;script&gt;/);
  // Pipe in name escaped so the findings-index table is not broken.
  assert.match(md, /Inject \\\| pipe/);
  // Link injection neutralized.
  assert.match(md, /\\\[click\\\]/);
  // Newline in description collapsed.
  assert.match(md, /line1 line2/);
  // Code fence breakout prevented: snippet with ``` is wrapped in a longer fence.
  assert.match(md, /````+\w*\nbefore ``` injected\.md\.heading ``` after\n````+/);
});

test('buildSarifLog produces a valid 2.1.0 log with mapped levels and rules', () => {
  const findings = [
    baseFinding({ id: 'C1', severity: 'CRITICAL', cwe: 'CWE-89', category: 'Injection' }),
    baseFinding({ id: 'M1', severity: 'MEDIUM', cwe: 'CWE-330', category: 'Cryptography' }),
    baseFinding({ id: 'L1', severity: 'LOW', cwe: '', category: 'Configuration' }),
  ];
  const log = buildSarifLog({ name: 'demo' }, findings, { packageVersion: '9.9.9' });

  assert.equal(log.version, '2.1.0');
  assert.equal(log.runs[0].tool.driver.name, 'CSReview');
  assert.equal(log.runs[0].tool.driver.version, '9.9.9');
  assert.equal(log.runs[0].results.length, 3);

  const [c, m, l] = log.runs[0].results;
  assert.equal(c.level, 'error');
  assert.equal(m.level, 'warning');
  assert.equal(l.level, 'note');

  assert.equal(c.ruleId, 'CWE-89');
  assert.equal(l.ruleId, 'Configuration'); // falls back to category when no CWE
  assert.equal(c.locations[0].physicalLocation.region.startLine, 10);
  assert.ok(c.partialFingerprints.csreviewFingerprint);

  // Rules are de-duplicated by ruleId.
  const ruleIds = log.runs[0].tool.driver.rules.map((r) => r.id);
  assert.deepEqual([...new Set(ruleIds)], ruleIds);
});

test('SARIF never embeds raw vulnerable code (no secret leakage)', () => {
  const out = tmpFile('demo_security.sarif');
  const finding = baseFinding({
    name: 'Hardcoded secret',
    description: 'A secret was hardcoded.',
    vulnerableCode: 'const key = "SUPER_SECRET_TOKEN_ABCDEF123456";',
    fix: 'Move to env vars.',
  });
  generateSarifReport({ name: 'demo' }, [finding], out, {});
  const raw = fs.readFileSync(out, 'utf8');

  assert.doesNotMatch(raw, /SUPER_SECRET_TOKEN_ABCDEF123456/);
  const parsed = JSON.parse(raw);
  assert.equal(parsed.version, '2.1.0');
  assert.match(parsed.runs[0].results[0].message.text, /Hardcoded secret/);
});

test('buildSarifLog tolerates empty findings', () => {
  const log = buildSarifLog({ name: 'demo' }, [], {});
  assert.equal(log.runs[0].results.length, 0);
  assert.deepEqual(log.runs[0].tool.driver.rules, []);
});

test('HTML report logs its generation and save (parity with Markdown/SARIF logs)', () => {
  const out = tmpFile('demo_security-report.html');
  const projectInfo = {
    name: 'demo',
    files: ['src/app.js'],
    configFiles: [],
    depFiles: [],
    baasFiles: [],
    frameworks: [],
    techStack: [],
    projectType: 'unknown',
  };
  const logs = [];
  const orig = console.log;
  console.log = (...args) => logs.push(args.join(' '));
  try {
    const returned = generateHtmlReport(projectInfo, [baseFinding()], out, {});
    assert.equal(returned, out);
  } finally {
    console.log = orig;
  }
  // The missing "Generating HTML report..." line is what made the HTML report
  // look absent in the run output even though it was always written.
  assert.ok(
    logs.some((l) => l.includes('Generating HTML report...')),
    'expected a "Generating HTML report..." log line',
  );
  assert.ok(
    logs.some((l) => l.includes('HTML report saved to')),
    'expected an "HTML report saved to ..." log line',
  );
  assert.ok(fs.existsSync(out), 'HTML file written');
});

test('Markdown does not allow link injection through a crafted CWE id (M1)', () => {
  const out = tmpFile('cwe_security-findings.md');
  const finding = baseFinding({ id: 'CWEINJ', cwe: 'x)](http://evil.com) and [pwn](http://evil2.com' });
  generateMarkdownReport({ name: 'demo', files: ['src/app.js'], configFiles: [] }, [finding], out, {});
  const md = fs.readFileSync(out, 'utf8');

  // The junk cwe must NOT be interpolated into the cwe.mitre.org URL position.
  assert.doesNotMatch(md, /definitions\/x\)/);
  // The bracket characters in the field are escaped, so no nested live link.
  assert.match(md, /\\\[pwn\\\]/);
});
