# Runner Guard

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Vigilant-LLC/runner-guard)](https://github.com/Vigilant-LLC/runner-guard/releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)

**CI/CD source-to-sink vulnerability scanner for GitHub Actions**

Runner Guard detects pipeline injection vulnerabilities, unpinned supply chain dependencies, AI configuration poisoning, and invisible steganographic payloads in GitHub Actions workflows. It checks your installed packages against known compromised versions, scans multiple repos in parallel, and auto-fixes what it finds.

```
                    ┌─────────────────┐
                    │  Workflow YAML   │
                    └────────┬────────┘
                             ▼
              ┌──────────────────────────┐
              │   Parser                 │  Triggers, permissions, jobs,
              │   (YAML → structured)    │  steps, expressions, actions
              └──────────┬───────────────┘
                         ▼
              ┌──────────────────────────┐
              │   Source-to-Sink Tracker  │  Attacker inputs → shell sinks
              │   (taint analysis)       │  via expressions, env, outputs
              └──────────┬───────────────┘
                         ▼
              ┌──────────────────────────┐
              │   Rule Engine            │  18 rules + 31 IOC signatures
              │   (detect + classify)    │  + 41 compromised packages
              └──────────┬───────────────┘
                         ▼
              ┌──────────────────────────┐
              │   Reporter               │  Console, JSON, SARIF, CSV
              │   (output + score)       │  Runner Guard Score (0-100)
              └──────────────────────────┘
```

---

## Install

```bash
# Homebrew (macOS/Linux)
brew install Vigilant-LLC/tap/runner-guard

# One-liner (macOS/Linux)
curl -sSfL https://raw.githubusercontent.com/Vigilant-LLC/runner-guard/main/install.sh | bash

# From source
go install github.com/Vigilant-LLC/runner-guard/cmd/runner-guard@latest
```

Pre-built binaries for Linux, macOS, and Windows (amd64/arm64) on the [Releases page](https://github.com/Vigilant-LLC/runner-guard/releases).

---

## Features

- **18 detection rules** covering fork checkout exploits, expression injection, secret exfiltration, unpinned actions, AI config injection, and supply chain steganography with permissions-aware severity
- **41 compromised package versions** across 13 confirmed supply chain attack campaigns (UNC1069/Axios, TeamPCP, npm debug/chalk, Solana web3.js, and more)
- **31 threat signatures across 6 campaign files** -- GlassWorm, TeamPCP, UNC1069/Axios, Telnyx, and general supply chain IOCs
- **Batch scanning** -- scan multiple repos from a file or stdin with `--repos`, parallel scanning with `--concurrency`, output as console summary table, JSON, or CSV
- **Runner Guard Score** -- CI/CD security score (0-100) with letter grade and category breakdown (Pinning, Permissions, Injection, Triggers, IOCs)
- **AI config injection detection** across Claude, GitHub Copilot, Cursor, and MCP tooling -- the first scanner to cover this attack surface
- **Auto-fix** -- pin unpinned third-party actions to immutable commit SHAs, extract unsafe expressions from `run:` blocks into `env:` mappings
- **Interactive CLI menu** -- run `runner-guard` with no arguments for a guided experience
- **SARIF output** for native GitHub Code Scanning integration
- **Remote scanning** -- scan any public GitHub repo by URL without cloning
- **Single binary** -- zero dependencies, all rules embedded, runs anywhere Go compiles

---

## Quick Start

### Scan a repo

![Runner Guard Scan](docs/scan-clean.gif)

```bash
runner-guard scan .                              # local repo
runner-guard scan github.com/owner/repo          # remote repo
runner-guard scan . --format sarif --output r.sarif  # SARIF for GitHub Security tab
runner-guard scan . --fail-on high               # CI gate
```

### Check for compromised packages

![Check Dependencies](docs/check-deps-demo.gif)

```bash
runner-guard check-deps .                        # scan lock files
runner-guard check-deps . --format json          # JSON output
```

### Batch scan multiple repos

![Batch Scan](docs/batch-demo.gif)

```bash
runner-guard scan --repos repos.txt              # from file
runner-guard scan --repos repos.txt --concurrency 10 --format csv
cat repos.txt | runner-guard scan --repos -      # from stdin
```

### Auto-fix

```bash
runner-guard fix .                               # pin actions + extract expressions
runner-guard fix . --dry-run                     # preview changes
```

### Interactive menu

![Interactive Menu](docs/menu-demo.gif)

```bash
runner-guard                                     # no args = guided menu
```

---

## What It Detects

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RGS-001 | pull_request_target with Fork Code Checkout | Critical | Workflow checks out fork code in privileged base repo context with secret access |
| RGS-002 | Expression Injection via Untrusted Input | Critical | Attacker-controlled input interpolated directly in shell `run:` block |
| RGS-003 | Dynamic Command Construction from Step Outputs | High | Step outputs combined with git diff/find/ls to construct shell commands |
| RGS-004 | Privileged Trigger with No Author Check | High | `issue_comment` trigger with secrets and no authorization check |
| RGS-005 | Excessive Permissions on Untrusted Trigger | Medium | Write permissions on workflows triggered by external users |
| RGS-006 | Dangerous Sink in Run Block | High | Remote script piped to shell (curl pipe bash) |
| RGS-007 | Unpinned Third-Party Action | Medium/Low | Mutable tag instead of commit SHA. Low when job has read-only permissions. |
| RGS-008 | Secrets Exposure in Run Block | Medium | Secret interpolated in `run:` block instead of `env:` mapping |
| RGS-009 | Fork Code Execution via Build Tools | Critical | Build tools execute attacker code from fork checkout |
| RGS-010 | AI Agent Config Poisoning via Fork PR | High | CLAUDE.md or AI config loaded from fork checkout |
| RGS-011 | MCP Config Injection via Fork Checkout | High | .mcp.json read from fork-controlled checkout |
| RGS-012 | External Network Access with Secrets | Medium | Outbound HTTP with secrets in privileged context |
| RGS-014 | Expression Injection via workflow_dispatch | High | Dispatch input interpolated in shell `run:` block |
| RGS-015 | Actions Runner Debug Logging Enabled | Medium | Debug env vars exposing secrets in logs |
| RGS-016 | Unicode Steganography in Workflow File | Critical | Invisible Unicode in YAML -- active compromise indicator |
| RGS-017 | Unicode Steganography in Referenced Script | High | Invisible Unicode in files executed by workflows |
| RGS-018 | Suspicious Payload Execution Pattern | High | Eval+decode chains, known IOCs, C2 patterns |
| RGS-019 | Step Output Interpolated in run Block | Medium | Step output may carry attacker-controlled data |

**RGS-010** and **RGS-011** are unique to Runner Guard. No other CI/CD scanner detects AI configuration injection attacks.

---

## GitHub Action

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
      - uses: Vigilant-LLC/runner-guard@d80646c2af65ace4f57e0a8f0568eacfed76ed71 # v2.8.0
        with:
          fail-on: high
          sarif-upload: 'true'
```

Findings appear in the GitHub Security tab under Code Scanning alerts.

---

## Demo Scenarios

### Fork Checkout Kill Chain

![Fork Checkout Demo](docs/demo-fork-checkout.gif)

`pull_request_target` checks out fork code with full secret access. Detects RGS-001 (checkout), RGS-007 (unpinned actions), RGS-009 (build tool execution), RGS-012 (exfiltration).

```bash
runner-guard demo --scenario fork-checkout
```

### Expression Injection (Microsoft/Akri Pattern)

![Expression Injection Demo](docs/demo-microsoft.gif)

`issue_comment` trigger interpolates attacker data into shell. Detects RGS-002 (injection), RGS-004 (no auth check), RGS-006 (curl pipe bash), RGS-008 (secrets in args).

```bash
runner-guard demo --scenario microsoft
```

### AI Configuration Injection

![AI Config Injection Demo](docs/demo-ai-injection.gif)

Fork PR modifies CLAUDE.md/copilot-instructions.md to hijack AI agents in privileged CI. Detects RGS-010 (AI config) and RGS-011 (MCP config).

```bash
runner-guard demo --scenario ai-injection
```

### GlassWorm Supply Chain Attack

![GlassWorm Detection Demo](docs/glassworm-demo.gif)

Invisible Unicode steganography, known IOC variables, eval+decode patterns. Detects RGS-016 (Unicode), RGS-018 (IOC patterns).

```bash
runner-guard demo --scenario glassworm
```

---

## Advanced Usage

### Rule groups and filters

```bash
runner-guard scan . --group steganography           # scan only steganography rules
runner-guard scan . --rules RGS-016,RGS-018         # specific rules
runner-guard scan . --group ai-config --rules RGS-001  # combine
```

**Groups:** `injection`, `permissions`, `secrets`, `supply-chain`, `ai-config`, `steganography`, `debug`

### Auto-fix details

The fix engine:
- **Pins actions** to immutable commit SHAs with version comments
- **Extracts Tier-1 expressions** from `run:` blocks into `env:` mappings
- **Extracts secrets** from `run:` blocks into `env:` mappings
- **Shell-aware** -- `${VAR}` for bash, `$env:VAR` for PowerShell, `%VAR%` for cmd
- **Handles single-quoted contexts** and **skips brace expansions**

### Baseline management

```bash
runner-guard baseline create                         # generate baseline
runner-guard scan . --baseline .runner-guard-baseline.json  # suppress known
runner-guard baseline update                         # update after triage
```

### Inline suppression

```yaml
- uses: some-org/action@v1  # runner-guard:ignore
```

---

## The Threat Landscape

### Active Supply Chain Campaign (March 2026)

A coordinated attack campaign escalated through multiple phases:

- **Phase 1-2 (March 12)**: reviewdog and tj-actions/changed-files compromised, harvesting CI/CD credentials from 23,000+ repositories
- **Phase 3 (March 19-27)**: Trivy, Checkmarx, LiteLLM, and Telnyx compromised by TeamPCP. Cisco lost 300+ source code repos.
- **Phase 4 (March 30)**: Axios (100M weekly downloads) compromised with a RAT. Attributed to North Korean threat actor UNC1069.

Runner Guard includes IOC signatures for all confirmed phases organized in `rules/signatures/` by campaign.

### CI/CD Pipeline Injection

Workflows triggered by `pull_request_target` run with the base repository's secrets. When combined with `actions/checkout` pointing at fork code, an attacker's build scripts execute with full credentials. In documented incidents, attackers exfiltrated PATs and pushed malicious commits to main branches within minutes, fully automated by AI agents.

### Supply Chain Steganography

The GlassWorm campaign compromised 433+ components using invisible Unicode characters that encode executable payloads invisible to code review. Runner Guard detects this at the byte level (RGS-016/017/018).

### AI Config Injection

When `pull_request_target` workflows check out fork code, attackers can modify CLAUDE.md, copilot-instructions.md, .cursorrules, or .mcp.json to hijack AI code review agents. Runner Guard is the first scanner to detect this attack surface (RGS-010/011).

---

## Contributing

Runner Guard welcomes contributions, especially new detection rules:

1. Create a YAML rule file in `rules/` (see `rules/RGS-001-prt-fork-checkout.yaml`)
2. Add detection logic in `internal/rules/` if needed
3. Add a test case in `internal/taint/`
4. Submit a PR describing the real-world attack pattern

To add threat signatures without writing Go code, add a YAML file to `rules/signatures/` and rebuild. See existing files for format.

Report false positives. Accuracy is critical -- a scanner that cries wolf gets disabled.

---

## About Vigilant

[Vigilant](https://vigilantdefense.com) is a cybersecurity company who stands between organizations and the threats that want to destroy them. We don't believe in passive defense -- we operate with a warfare mindset, hunting threats before they become breaches.

We built Runner Guard because we've weaponized these exact attack chains against banks, government agencies, and critical infrastructure in red team engagements. When autonomous AI agents started exploiting them at scale, we built the scanner we wished existed.

- **[ThreatCert](https://vigilantdefense.com)** -- attack surface intelligence platform mapping full kill chains with audit-ready evidence
- **[CyberDNA](https://vigilantdefense.com)** -- analysis workspace with Vigilant's zero-breach guarantee

Vigilant donates 25% of profit to organizations combating human trafficking and supporting orphan care worldwide.

For enterprise support, custom rule development, or security assessments, visit [vigilantdefense.com](https://vigilantdefense.com).

---

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 Vigilant.
