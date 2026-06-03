// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateSecurityScore, getConfidenceFactor, getSeverityWeight } from '../src/score.js';

test('getConfidenceFactor maps known levels and defaults unknown to full weight', () => {
  assert.equal(getConfidenceFactor('CONFIRMED'), 1.0);
  assert.equal(getConfidenceFactor('TOOL-ONLY'), 1.0);
  assert.equal(getConfidenceFactor('HIGH'), 1.0);
  assert.equal(getConfidenceFactor('MEDIUM'), 0.7);
  assert.equal(getConfidenceFactor('low'), 0.4);
  assert.equal(getConfidenceFactor(undefined), 1.0);
  assert.equal(getConfidenceFactor('something-else'), 1.0);
});

test('getSeverityWeight returns 0 for unknown severities', () => {
  assert.equal(getSeverityWeight('CRITICAL'), 25);
  assert.equal(getSeverityWeight('NOPE'), 0);
});

test('empty findings yield a perfect score', () => {
  assert.equal(calculateSecurityScore([], { files: ['a.js'] }), 100);
});

test('legacy invariant: a config-only critical drives the score to 0', () => {
  const score = calculateSecurityScore([{ severity: 'CRITICAL', file: '.env' }], {
    files: [],
    configFiles: ['.env'],
    depFiles: [],
    baasFiles: [],
  });
  assert.equal(score, 0);
});

test('legacy invariant: a critical in a large project still caps at <= 49', () => {
  const score = calculateSecurityScore([{ severity: 'CRITICAL', file: 'src/vulnerable.js' }], {
    files: Array.from({ length: 100 }, (_, i) => `src/file-${i}.js`),
  });
  assert.ok(score <= 49);
});

test('low-confidence findings dampen the density term (score higher than high-confidence)', () => {
  const project = {
    files: ['s/a.js', 's/b.js', 's/c.js', 's/d.js', 's/e.js'],
    configFiles: [],
    depFiles: [],
    baasFiles: [],
  };
  const mediums = (confidence) => Array.from({ length: 4 }, () => ({ severity: 'MEDIUM', confidence, file: 's/a.js' }));

  const highConfidence = calculateSecurityScore(mediums('HIGH'), project);
  const lowConfidence = calculateSecurityScore(mediums('LOW'), project);

  assert.ok(lowConfidence > highConfidence, `expected low(${lowConfidence}) > high(${highConfidence})`);
});

test('CONFIRMED findings count at full weight (same as HIGH confidence)', () => {
  const project = {
    files: ['s/a.js', 's/b.js', 's/c.js', 's/d.js', 's/e.js'],
    configFiles: [],
    depFiles: [],
    baasFiles: [],
  };
  const mediums = (confidence) => Array.from({ length: 4 }, () => ({ severity: 'MEDIUM', confidence, file: 's/a.js' }));

  assert.equal(calculateSecurityScore(mediums('CONFIRMED'), project), calculateSecurityScore(mediums('HIGH'), project));
});

test('safety: even a low-confidence critical still caps the score at <= 49', () => {
  const score = calculateSecurityScore([{ severity: 'CRITICAL', confidence: 'LOW', file: 'src/x.js' }], {
    files: Array.from({ length: 100 }, (_, i) => `src/file-${i}.js`),
  });
  assert.ok(score <= 49);
});
