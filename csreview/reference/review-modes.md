# CSReview Reference - Code Review Modes

Detail for the five review modes summarized in SKILL.md. These are agent
methodologies layered on top of the engine run; they do not change what the
engine writes.

## Mode 1 - Standard Code Review (`@csreview review [files]`)

Quality: readability, naming, complexity, dead code, duplication, SOLID/DRY,
separation of concerns. Architecture: pattern fit, coupling, dependency
direction. Performance: algorithmic complexity, leaks, N+1 queries, caching,
bundle impact. Testing: coverage gaps, missing edge cases, isolation, mock
overuse. Documentation: missing docstrings on public APIs, stale comments,
undocumented breaking changes.

## Mode 2 - Adversarial Review (`@csreview adversarial [files]`)

Red-team mindset: actively try to break the change. Boundary exploitation,
race conditions, resource exhaustion, error-handling bypass, state corruption,
validation gaps at every layer. Failure modes: external service down, malformed
input, extreme load, concurrent modification, full disk/memory. Edge cases:
empty/null, maximum sizes, Unicode, timezones, float precision, integer
overflow. Ask: "How can I make this fail?", "What is the worst input?", "What
assumption can be wrong?", "Can I bypass this check?"

## Mode 3 - Security-Focused Review (`@csreview security-review [files]`)

Apply the security and database checklists (see
`reference/security-checklists.md`) to the specific changed files, assess the
security impact of each change, and flag architectural changes that require
threat-model updates. Vibe-risk heuristics from the engine apply here.

## Mode 4 - Requesting a Review (`@csreview request-review [scope]`)

Protocol: identify scope (files/functions/modules) → choose depth → select
modes (quality/adversarial/security) → build a checklist for the change type →
execute → prioritize by severity and actionability. Change types: new feature
(full + adversarial), bug fix (correctness + regression), refactor (behavior
preservation), configuration (security impact), dependency update
(vulnerability + license), migration (integrity + rollback).

## Mode 5 - Receiving Review Findings

(`@csreview review csreview-reports/codex_security-findings.md`)

Parse the Markdown report → categorize by severity → for each finding:
acknowledge, research the fix (official docs first), propose, apply (coding
agent's responsibility, never CSReview's), verify nothing new broke. Fix
verification checklist: addresses the specific vulnerability; preserves
behavior; follows framework practice; introduces no new issues; tested;
documented when behavior changes. After all fixes, re-run the engine —
optionally with `--baseline` so only NEW findings fail CI.
