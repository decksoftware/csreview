# CSReview Reference - External Tool Detection, Invocation & Installation

The engine orchestrates OpenGrep 1.26.0, the lockfile-selected Node package audit, and
OSV-Scanner deterministically (plus Gitleaks/Trivy/gosec/Bandit under
`--provision-tools`). Everything else here is **agent-recommended**: run a tool
only if it is already available or the user opted into provisioning, report its
results as supplemental evidence, and never install tools into the analyzed
project.

## Detection commands

```bash
opengrep --version         # engine accepts exactly 1.26.0
osv-scanner --version
npm --version              # npm audit (npm lockfiles)
pnpm --version             # pnpm audit (pnpm-lock.yaml)
bun --version              # bun audit (bun.lock / bun.lockb)
yarn --version             # yarn audit (agent-recommended; not engine-parsed)
bandit --version           # Python AST security
trivy --version            # vulns + misconfig + secrets (fs scan)
gosec --version            # Go security
gitleaks version           # secrets (provisionable)
codeql version
npx eslint --version
snyk --version
safety --version
grype version
hadolint --version
tflint --version
checkov --version
brakeman --version
retire --version
pip-audit --version
cargo audit --version
dotnet --version           # dotnet list package --vulnerable
govulncheck -version
```

## Per-tool invocation (read-only forms)

```bash
# OpenGrep — bundled offline rules plus an optional existing local config
opengrep scan --config <csreview_rules> --json --quiet --disable-version-check <project_path>
# --opengrep-config <path> adds a local file/directory. URLs, auto, and registry
# references are rejected before the process starts.

# Dependency SCA
osv-scanner scan --format json <project_path>
npm audit --json
pnpm audit --json
bun audit --json
dotnet list package --vulnerable --include-transitive
cargo audit --json
pip-audit --format json --desc

# Stack-native SAST / config scanners
bandit -r <project_path> -f json -ll -i --skip B101
trivy fs --format json --scanners vuln,misconfig,secret <project_path>
gosec -fmt json -out <tmp>/gosec-report.json -severity medium ./...
checkov -d <project_path> -o json --quiet --compact
hadolint <project_path>/Dockerfile --format json
snyk test --json --severity-threshold=medium
```

Never run fix/update/remediation subcommands (e.g. `osv-scanner fix`,
`npm audit fix`) during a CSReview run — the scan is read-only.

## Installation pointers (for "missing recommended tool" entries)

```bash
csreview <project_path> --provision-tools  # approved OpenGrep 1.26.0 artifact
winget install Google.OSVScanner    # or: brew install osv-scanner
pip install bandit
pip install pip-audit
pip install checkov
cargo install cargo-audit
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
npm install -g snyk
choco install trivy                 # or: scoop install trivy / brew install trivy
choco install hadolint              # or: brew install hadolint
npm install --save-dev eslint-plugin-security eslint-plugin-no-unsanitized
```

With `--provision-tools`, the engine downloads the approved OpenGrep 1.26.0,
Gitleaks, Trivy, and gosec artifacts from their official GitHub releases and
verifies SHA-256 before execution. OpenGrep is stored outside the audited target
in CSReview's private user cache, keyed by version and digest with a validated
manifest. Stack-native tools run from an isolated, gitignored `.csreview/bin/`.
Nothing is installed globally or as a project dependency. Bandit is
PyPI-distributed and is only used when already installed.
