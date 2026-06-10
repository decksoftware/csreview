// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs, normalizeFailOn, countFindingsAtOrAbove } from '../src/cliArgs.js';

// The CLI is a security gate: a mistyped flag must be a hard error, never a
// silently ignored no-op (`--basline x.json` running WITHOUT the baseline is
// exactly the failure mode a scanner cannot afford).

test('parseCliArgs rejects unknown flags instead of silently ignoring them', () => {
  assert.throws(() => parseCliArgs(['.', '--basline', 'known.json']), /basline/);
  assert.throws(() => parseCliArgs(['.', '--fail-no', 'high']), /fail-no/);
});

test('parseCliArgs parses the documented surface', () => {
  const parsed = parseCliArgs([
    'C:/proj',
    '--output',
    'reports',
    '--agent-name',
    'claude',
    '--baseline',
    'base.json',
    '--strict-partials',
    '--fail-on',
    'high',
  ]);
  assert.equal(parsed.targetArg, 'C:/proj');
  assert.equal(parsed.output, 'reports');
  assert.equal(parsed.agentName, 'claude');
  assert.equal(parsed.baseline, 'base.json');
  assert.equal(parsed.strictPartials, true);
  assert.equal(parsed.failOn, 'HIGH');
  assert.equal(parsed.version, false);
});

test('parseCliArgs supports -o, -h, -v shorthands and --doctor with target', () => {
  assert.equal(parseCliArgs(['.', '-o', 'out']).output, 'out');
  assert.equal(parseCliArgs(['-h']).help, true);
  assert.equal(parseCliArgs(['-v']).version, true);
  const doctor = parseCliArgs(['--doctor', 'C:/proj']);
  assert.equal(doctor.doctor, true);
  assert.equal(doctor.targetArg, 'C:/proj');
});

test('normalizeFailOn validates the severity level', () => {
  assert.equal(normalizeFailOn('high'), 'HIGH');
  assert.equal(normalizeFailOn('CRITICAL'), 'CRITICAL');
  assert.equal(normalizeFailOn(undefined), null);
  assert.throws(() => normalizeFailOn('severe'), /fail-on/);
  assert.throws(() => normalizeFailOn('info'), /fail-on/);
});

test('countFindingsAtOrAbove counts findings at or above the gate severity', () => {
  const counts = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };
  assert.equal(countFindingsAtOrAbove(counts, 'CRITICAL'), 1);
  assert.equal(countFindingsAtOrAbove(counts, 'HIGH'), 3);
  assert.equal(countFindingsAtOrAbove(counts, 'MEDIUM'), 6);
  assert.equal(countFindingsAtOrAbove({ HIGH: 0 }, 'HIGH'), 0);
  assert.equal(countFindingsAtOrAbove({}, 'LOW'), 0);
});
