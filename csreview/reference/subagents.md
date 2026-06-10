# CSReview Reference - Subagent Orchestration Protocol

Detailed protocol for the scatter-gather workflow summarized in SKILL.md. Use it
only when the agent runtime supports subagents AND the workspace is large
enough to justify the extra token/runtime cost; otherwise run sequentially.

## Dependency graph

1. **Phase 0 + Phase 1 sequential gate** — detect tools, run the
   engine-orchestrated SAST/SCA once (the `csreview` CLI does this), and build
   the shared project map (techStack, frameworks, package managers, BaaS files,
   IaC files, routes, cached tool JSON).
2. **Compatibility-gated fan-out** — spawn only subagents matching the map: no
   Delphi subagent without Pascal files, no Firebase subagent without Firebase
   rules/config, no Go subagent without Go modules.
3. **Parallel validation** — subagents validate candidate findings in their
   domain from the shared map, local files, and cached tool output. They never
   rerun whole-tree scanners.
4. **Gather barrier** — wait for all subagents before correlation.
5. **Reduce** — one coordinator merges partials, then runs
   `dedup -> ASVS -> compliance -> score -> report` in that order.
6. **Single writer** — subagents write only partial JSON to
   `csreview-reports/.partials/<subagent>.json`; the coordinator (in practice:
   the engine CLI re-run after partials exist) is the only writer of the final
   reports.

## Partial file contract

Every partial finding uses the canonical finding schema and sets
`source: "subagent:<domain>"` (e.g. `subagent:auth`):

```json
{
  "severity": "HIGH",
  "category": "Authentication",
  "name": "JWT signature not verified",
  "description": "...",
  "file": "src/middleware/auth.ts",
  "line": 42,
  "vulnerableCode": "...",
  "cwe": "CWE-347",
  "owasp": "A07:2021",
  "fix": "...",
  "confidence": "MEDIUM",
  "exploitation": "...",
  "references": ["https://..."],
  "source": "subagent:auth"
}
```

Required fields (validated by the engine): `severity`, `category`, `name`,
`description`, `file`, `line`, `cwe`, `fix`, `confidence`, `source`. Optional
partial metadata may list `toolExecutions` so the coordinator can verify
whole-tree tools ran only once.

## Engine enforcement

When `csreview-reports/.partials/` exists, the engine reads the partial JSON,
validates the schema, merges valid `subagent:*` findings into the final set
(deduplicating against `csreview-detector`, `semgrep`, `npm-audit`,
`osv-scanner`, and the provisioned tools — matching `file:line:CWE` evidence is
promoted to `CONFIRMED`), and exposes `partialReconciliation` in its result.
`--strict-partials` (CLI) or `reconcilePartials(outputDir, findings, { strict:
true })` makes the run fail when the Definition of Done does not reconcile:
final subagent finding count must equal the deduplicated partial count, and no
whole-tree tool may appear executed more than once in partial metadata.
