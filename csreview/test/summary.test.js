// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { originBreakdown, labelForSource } from '../src/reports/summary.js';

test('labelForSource maps known sources and formats subagent domains', () => {
  assert.equal(labelForSource('semgrep'), 'Semgrep');
  assert.equal(labelForSource('osv-scanner'), 'OSV-Scanner');
  assert.equal(labelForSource('npm-audit'), 'npm audit');
  assert.equal(labelForSource('csreview-detector'), 'CSReview detector (heuristic)');
  assert.equal(labelForSource('subagent:rust'), 'Subagent: rust');
  assert.equal(labelForSource('mystery-tool'), 'mystery-tool');
});

test('originBreakdown counts findings per source and flags corroborated ones', () => {
  const { confirmed, total, rows } = originBreakdown([
    { sources: ['csreview-detector', 'gitleaks'], confidence: 'CONFIRMED' },
    { sources: ['semgrep'] },
    { source: 'osv-scanner' },
    { sources: ['csreview-detector'] },
    {}, // no source -> defaults to the detector
  ]);
  assert.equal(total, 5);
  assert.equal(confirmed, 1);
  const map = Object.fromEntries(rows.map((r) => [r.source, r.count]));
  assert.equal(map['gitleaks'], 1);
  assert.equal(map['semgrep'], 1);
  assert.equal(map['osv-scanner'], 1);
  assert.equal(map['csreview-detector'], 3); // 2 explicit + 1 default
});

test('originBreakdown rows sort by count desc and it tolerates empty input', () => {
  assert.deepEqual(originBreakdown([]), { confirmed: 0, total: 0, rows: [] });
  const { rows } = originBreakdown([{ source: 'semgrep' }, { source: 'semgrep' }, { source: 'gitleaks' }]);
  assert.equal(rows[0].source, 'semgrep');
  assert.equal(rows[0].count, 2);
});
