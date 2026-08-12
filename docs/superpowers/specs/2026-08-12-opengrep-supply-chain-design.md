# OpenGrep and Tool Supply Chain Design

**Status:** Approved

**Date:** 2026-08-12

## Purpose

Replace Semgrep immediately with OpenGrep and make every executable and rule used by CSReview traceable, reproducible, and independent of the repository being audited.

## Decisions

- Semgrep is removed without a compatibility alias. Source code, CLI options, environment variables, package metadata, reports, documentation, and workflows must not retain Semgrep as a supported engine.
- OpenGrep is the only primary SAST engine. The initial approved version is `1.26.0`.
- `--config auto`, registry identifiers, rule URLs, autofix, local builds, and untrusted validators are forbidden. The default scan is offline and uses the rulepack shipped with CSReview.
- A user may provide extra rules only with `--opengrep-config <path>`. The value must resolve to a local file or directory; URLs and registry-style names are rejected.
- Tool downloads remain opt-in through `--provision-tools`.

## OpenGrep artifact policy

CSReview keeps an allowlist keyed by operating system, architecture, version, release URL, filename, size ceiling, and SHA-256. Version `1.26.0` uses the official `opengrep/opengrep` GitHub release. The approved self-contained artifact digests are:

| Platform | Artifact | SHA-256 |
| --- | --- | --- |
| Windows x64 | `opengrep_windows_x86.exe` | `4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3` |
| Linux glibc x64 | `opengrep_manylinux_x86` | `40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26` |
| Linux glibc arm64 | `opengrep_manylinux_aarch64` | `3042a3b1aa98fa93407b9d66a45ab1f179b5b367e76965f56afdbd2c038fb1fa` |
| Linux musl x64 | `opengrep_musllinux_x86` | `18aeca114221e2816ec26e1a731f1a2583408c8e4578cd868cd2d47c12fd29f8` |
| Linux musl arm64 | `opengrep_musllinux_aarch64` | `d4e20ac57b6f9bb32c2b0ffc0501b8c6acb92ecee60f11f1cd72db9b11647857` |
| macOS x64 | `opengrep_osx_x86` | `36c00a2b6eeb45796275e69cb8f74ef27c42724a1b3c98f6c8d861bad7a8529d` |
| macOS arm64 | `opengrep_osx_arm64` | `513ff8491f7254c9a672cf8421136a537eb53b2a8af748568bd697acdc59eefe` |

The download layer preserves the existing HTTPS host allowlist, manual redirect validation, response-size cap, timeout, and `execFile`-without-shell behavior. A downloaded artifact is written to a temporary private directory, hashed, moved into the cache atomically, hashed again, and only then made executable.

## Private cache boundary

Tool cache paths are outside the audited target:

- Windows: `%LOCALAPPDATA%\CSReview\tools`
- Linux/macOS with `XDG_CACHE_HOME`: `$XDG_CACHE_HOME/csreview/tools`
- Linux/macOS fallback: `~/.cache/csreview/tools`

Each cached artifact lives under `<tool>/<version>/<sha256>/` with a JSON manifest containing `tool`, `version`, `platform`, `arch`, `sourceUrl`, `sha256`, `size`, and `installedAt`.

Before every execution CSReview must:

1. use `lstat` and reject symbolic links;
2. resolve the real path and prove it remains below the private cache root;
3. prove it is outside the audited target;
4. validate the manifest schema;
5. recompute and compare the artifact SHA-256.

`<target>/.csreview/bin` is never read or executed. Legacy directories are left untouched and explicitly reported as ignored.

Tools found on `PATH` are resolved to absolute paths. A path inside the target is rejected. OpenGrep is accepted as a complete primary engine only when its version and digest match the approved artifact table; another build is reported as unavailable rather than silently trusted.

## OpenGrep adapter

`src/opengrep.js` owns argument construction, execution, JSON parsing, error classification, and normalization. Its default invocation is equivalent to:

```text
opengrep scan --config <bundled-rulepack> --json --quiet --disable-version-check <excludes> <target>
```

It must never pass `--allow-local-builds`, `--allow-untrusted-validators`, `--autofix`, a remote config, or `auto`. The process receives a minimal environment and bounded timeout/output buffers. Exit status, timeout, malformed JSON, rule errors, and partial file skips are distinct diagnostic states.

## CSReview rulepack

The npm package includes an offline rulepack under `rules/`. CSReview owns the stable rule IDs and the compatibility tests.

GitLab `security-products/sast-rules` release `v2.9.2`, commit `0d3cd9c48c031ce25b9a003ca7b8e4f1370c409c`, is an audited seed only. Its complete archive is not redistributed because it mixes MIT/Apache rules with LGPL, GPL, Commons Clause, GitLab EE, and unclear entries. Only individually reviewed rules whose source license is MIT or Apache-2.0 may enter the CSReview pack.

`rules/manifest.json` records, for every imported rule, its CSReview ID, upstream project, immutable commit, source path, SPDX license, source hash, transformed hash, and attribution. License and notice files ship with the package. A rule update is an explicit source change, never a runtime download.

Each rule has:

- at least one positive fixture;
- at least one negative fixture;
- `opengrep scan --validate` coverage;
- an integration assertion over normalized JSON;
- no warnings about ignored or unsupported fields.

## CI and distribution

The Semgrep workflow is replaced by an OpenGrep workflow. GitHub Actions are pinned to full commit SHAs. OpenGrep is fetched at the approved version and verified against the platform digest before scanning. A scanner failure is not `continue-on-error` and cannot upload a misleading clean result.

The npm package `files` list includes `rules/` and license notices. Package keywords, README, SKILL, references, doctor output, examples, and reports name OpenGrep only.

## Verification

- A fake executable in `<target>/.csreview/bin` is ignored and never invoked.
- A symlinked, modified, wrong-version, wrong-size, or wrong-hash cache entry is rejected.
- Redirects to non-allowlisted hosts are rejected.
- The default scan succeeds with network access disabled after provisioning.
- A remote `--opengrep-config`, `auto`, or registry name is rejected before process execution.
- The vulnerable and safe fixtures prove the shipped rules behave as intended.
- A repository-wide case-insensitive search of active source, package metadata, user documentation, and workflows finds no Semgrep engine, option, install instruction, or supported-tool claim. Immutable migration specifications and third-party attribution metadata are excluded from this assertion.

## References

- OpenGrep release: <https://github.com/opengrep/opengrep/releases/tag/v1.26.0>
- OpenGrep repository: <https://github.com/opengrep/opengrep>
- GitLab SAST rules seed: <https://gitlab.com/gitlab-org/security-products/sast-rules/-/releases/v2.9.2>
