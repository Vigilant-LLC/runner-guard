// Runner Guard — CI/CD Pipeline Security Scanner
// Copyright (c) Vigilant. All rights reserved.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	runnerguard "github.com/Vigilant-LLC/runner-guard"
	"github.com/Vigilant-LLC/runner-guard/internal/autofix"
	"github.com/Vigilant-LLC/runner-guard/internal/batch"
	"github.com/Vigilant-LLC/runner-guard/internal/cli"
	"github.com/Vigilant-LLC/runner-guard/internal/config"
	"github.com/Vigilant-LLC/runner-guard/internal/deps"
	"github.com/Vigilant-LLC/runner-guard/internal/git"
	ghclient "github.com/Vigilant-LLC/runner-guard/internal/github"
	"github.com/Vigilant-LLC/runner-guard/internal/monitor"
	"github.com/Vigilant-LLC/runner-guard/internal/reporter"
	"github.com/Vigilant-LLC/runner-guard/internal/rules"
	"github.com/Vigilant-LLC/runner-guard/internal/scanner"
)

// Build-time variables injected via ldflags:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	version = "3.0.2"
	commit  = "dev"
	date    = "unknown"
)

// separator is the heavy horizontal line used in headers and demo banners.
var separator = strings.Repeat("\u2501", 58)

// ---------------------------------------------------------------------------
// Demo scenario definitions
// ---------------------------------------------------------------------------

type demoScenario struct {
	Key         string // CLI name: fork-checkout, microsoft, ai-injection
	File        string // filename inside demo/vulnerable/workflows/
	Title       string // banner title
	Description string // banner body
	Context     string // DemoContext string injected into findings
}

var scenarios = []demoScenario{
	{
		Key:  "fork-checkout",
		File: "ci-vulnerable.yml",
		Title: "Fork Checkout Kill Chain",
		Description: "This workflow replicates the configuration pattern exploited\n" +
			"by autonomous AI agents to steal PATs, tamper with releases,\n" +
			"and push malicious code via privileged fork checkouts.",
		Context: "This is the exact pattern used in documented CI/CD pipeline compromises.",
	},
	{
		Key:  "microsoft",
		File: "comment-trigger.yml",
		Title: "Microsoft / Akri Issue-Comment Injection",
		Description: "This workflow replicates the issue_comment injection\n" +
			"pattern found across hundreds of Microsoft repositories,\n" +
			"enabling arbitrary code execution via crafted comments.",
		Context: "This replicates the Microsoft/Akri issue_comment injection pattern.",
	},
	{
		Key:  "ai-injection",
		File: "ai-config-attack.yml",
		Title: "AI Config Poisoning via Fork PR",
		Description: "This demonstrates how AI config files (CLAUDE.md) can be\n" +
			"weaponized through fork PRs when checked out and processed\n" +
			"in a privileged pull_request_target context.",
		Context: "This demonstrates how AI config files (CLAUDE.md) can be weaponized through fork PRs.",
	},
	{
		Key:  "glassworm",
		File: "glassworm-steganography.yml",
		Title: "GlassWorm Supply Chain Attack (Unicode Steganography + IOC Detection)",
		Description: "This workflow contains invisible Unicode characters consistent\n" +
			"with GlassWorm-style steganographic payload encoding, known\n" +
			"malware IOC variables, and dangerous eval+decode patterns.\n" +
			"These techniques were used in the GlassWorm campaign (2025-2026)\n" +
			"to compromise 433+ GitHub, npm, and VSCode components.",
		Context: "This replicates the GlassWorm supply chain attack pattern using invisible Unicode steganography and known IOCs.",
	},
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// If no arguments provided, show interactive menu.
	if len(os.Args) == 1 {
		cli.Version = version
		selection := cli.ShowMenu()
		if selection == "" {
			return
		}
		// Map menu selection to os.Args for cobra to process.
		switch {
		case strings.HasPrefix(selection, "scan:"):
			path := strings.TrimPrefix(selection, "scan:")
			os.Args = []string{os.Args[0], "scan", path}
		case strings.HasPrefix(selection, "batch:"):
			reposPath := strings.TrimPrefix(selection, "batch:")
			os.Args = []string{os.Args[0], "scan", "--repos", reposPath}
		case strings.HasPrefix(selection, "check-deps:"):
			path := strings.TrimPrefix(selection, "check-deps:")
			os.Args = []string{os.Args[0], "check-deps", path}
		case strings.HasPrefix(selection, "audit-deps:"):
			path := strings.TrimPrefix(selection, "audit-deps:")
			os.Args = []string{os.Args[0], "audit-deps", path}
		case strings.HasPrefix(selection, "monitor:"):
			path := strings.TrimPrefix(selection, "monitor:")
			os.Args = []string{os.Args[0], "monitor", path}
		case strings.HasPrefix(selection, "fix:"):
			path := strings.TrimPrefix(selection, "fix:")
			os.Args = []string{os.Args[0], "fix", path}
		case selection == "demo":
			os.Args = []string{os.Args[0], "demo"}
		default:
			return
		}
	}

	rootCmd := newRootCmd()

	rootCmd.AddCommand(
		newScanCmd(),
		newCheckDepsCmd(),
		newAuditDepsCmd(),
		newMonitorCmd(),
		newDemoCmd(),
		newBaselineCmd(),
		newFixCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "runner-guard",
		Short: "Runner Guard — CI/CD Pipeline Security Scanner",
		Long: `Runner Guard detects source-to-sink injection vulnerabilities, excessive
permissions, unpinned actions, AI config poisoning, and other security
anti-patterns in GitHub Actions workflows.

Built by Vigilant.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------

func newScanCmd() *cobra.Command {
	var (
		format      string
		failOn      string
		baseline    string
		changedOnly bool
		output      string
		noColor     bool
		rulesFlag   string
		groupFlag   string
		reposFile   string
		orgFlag     string
		concurrency int
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan GitHub Actions workflows for security issues",
		Long: `Scan recursively finds .yml/.yaml files under <path>/.github/workflows/
and evaluates them against Runner Guard's built-in rule set.

Path can be:
  - A local directory:     runner-guard scan .
  - A GitHub repository:   runner-guard scan github.com/owner/repo
  - With a branch:         runner-guard scan github.com/owner/repo@main
  - Multiple repos:        runner-guard scan --repos repos.txt
  - From stdin:            cat repos.txt | runner-guard scan --repos -
  - Entire org:            runner-guard scan --org myorg`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Org scanning mode: --org flag
			if orgFlag != "" {
				return runOrgScan(orgFlag, concurrency, failOn, format, noColor, output, rulesFlag, groupFlag)
			}

			// Batch mode: --repos flag
			if reposFile != "" {
				return runBatchScan(reposFile, concurrency, failOn, format, noColor, output, rulesFlag, groupFlag)
			}

			if len(args) == 0 {
				return fmt.Errorf("path argument required (or use --repos/--org for batch scanning)")
			}

			start := time.Now()
			path := args[0]

			// Honour --no-color and auto-detect non-TTY.
			if noColor || !isTTY() {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Load .runner-guard.yaml config file.
			fileCfg := loadConfigFile(path)

			// Merge config file settings with CLI flags (CLI flags take precedence).
			effectiveFailOn := mergeString(failOn, "high", fileCfg)
			effectiveFormat := mergeString(format, "console", fileCfg)
			effectiveBaseline := baseline
			if effectiveBaseline == "" && fileCfg != nil && fileCfg.Baseline != "" {
				effectiveBaseline = fileCfg.Baseline
			}
			effectiveChangedOnly := changedOnly
			if !effectiveChangedOnly && fileCfg != nil && fileCfg.ChangedOnly {
				effectiveChangedOnly = true
			}

			cfg := scanner.Config{
				Path:        path,
				Format:      effectiveFormat,
				FailOn:      effectiveFailOn,
				Baseline:    effectiveBaseline,
				ChangedOnly: effectiveChangedOnly,
				NoColor:     noColor || !isTTY(),
				Output:      output,
				RulesFS:     runnerguard.RulesFS,
			}

			// Apply --rules and --group filters.
			if rulesFlag != "" {
				cfg.RuleIDs = splitAndTrim(rulesFlag)
			}
			if groupFlag != "" {
				cfg.Groups = splitAndTrim(groupFlag)
			}

			// Apply config-based ignore rules/files.
			if fileCfg != nil {
				cfg.IgnoreRules = fileCfg.IgnoreRules
				cfg.IgnoreFiles = fileCfg.IgnoreFiles
			}

			var result *scanner.Result
			var err error

			if ghclient.IsRemotePath(path) {
				// Remote GitHub scanning.
				result, err = runRemoteScan(cfg)
			} else if cfg.ChangedOnly {
				// Changed-only mode: resolve changed files first.
				result, err = runChangedOnlyScan(cfg)
			} else {
				result, err = scanner.Run(cfg)
			}

			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Select output destination.
			var w io.Writer = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			duration := time.Since(start)

			// Write report in the chosen format.
			if err := writeReport(w, result.Findings, effectiveFormat, noColor || !isTTY(), duration, false); err != nil {
				return err
			}

			os.Exit(result.ExitCode)
			return nil // unreachable, but keeps the compiler happy
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "console", "Output format: console, json, sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Minimum severity to exit non-zero: low, medium, high, critical")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Path to baseline JSON file for suppression")
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false, "Only scan workflow files changed in current git branch")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write report to file instead of stdout")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")
	cmd.Flags().StringVar(&rulesFlag, "rules", "", "Run only specific rules (comma-separated, e.g. RGS-016,RGS-018)")
	cmd.Flags().StringVar(&groupFlag, "group", "", "Run only rules in specific groups (comma-separated: injection, permissions, secrets, supply-chain, ai-config, steganography, debug)")
	cmd.Flags().StringVar(&reposFile, "repos", "", "Path to file with repos to scan (one per line, or '-' for stdin)")
	cmd.Flags().StringVar(&orgFlag, "org", "", "Scan all public repos in a GitHub organization")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Max concurrent scans for batch/org mode")

	return cmd
}

// runBatchScan handles --repos batch scanning mode.
func runBatchScan(reposFile string, concurrency int, failOn, format string, noColor bool, output, rulesFlag, groupFlag string) error {
	start := time.Now()

	if noColor || !isTTY() {
		color.NoColor = true
	}

	printHeader(os.Stderr)

	repos, err := batch.ParseRepoFile(reposFile)
	if err != nil {
		return err
	}

	if len(repos) == 0 {
		fmt.Fprintln(os.Stderr, "No repos found in file")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Batch scanning %d repos (concurrency: %d)...\n\n", len(repos), concurrency)

	cfg := batch.Config{
		Repos:       repos,
		Concurrency: concurrency,
		FailOn:      failOn,
		Format:      format,
		NoColor:     noColor || !isTTY(),
		RulesFS:     runnerguard.RulesFS,
	}

	if rulesFlag != "" {
		cfg.RuleIDs = splitAndTrim(rulesFlag)
	}
	if groupFlag != "" {
		cfg.Groups = splitAndTrim(groupFlag)
	}

	result := batch.Run(cfg)

	// Select output destination.
	var w io.Writer = os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	duration := time.Since(start)

	switch format {
	case "json":
		if err := batch.WriteJSONReport(w, result); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
	case "csv":
		if err := batch.WriteCSVReport(w, result); err != nil {
			return fmt.Errorf("writing CSV report: %w", err)
		}
	default:
		batch.WriteConsoleReport(w, result, noColor || !isTTY(), duration)
	}

	os.Exit(result.ExitCode)
	return nil
}

// runOrgScan lists all repos in a GitHub org and scans them using batch infrastructure.
func runOrgScan(org string, concurrency int, failOn, format string, noColor bool, output, rulesFlag, groupFlag string) error {
	start := time.Now()

	if noColor || !isTTY() {
		color.NoColor = true
	}

	printHeader(os.Stderr)

	fmt.Fprintf(os.Stderr, "Listing repositories for organization %s...\n", org)

	repos, err := ghclient.ListOrgRepos(org)
	if err != nil {
		return fmt.Errorf("listing org repos: %w", err)
	}

	if len(repos) == 0 {
		fmt.Fprintln(os.Stderr, "No public repositories found in organization.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d public repositories. Scanning (concurrency: %d)...\n\n", len(repos), concurrency)

	cfg := batch.Config{
		Repos:       repos,
		Concurrency: concurrency,
		FailOn:      failOn,
		Format:      format,
		NoColor:     noColor || !isTTY(),
		RulesFS:     runnerguard.RulesFS,
	}

	if rulesFlag != "" {
		cfg.RuleIDs = splitAndTrim(rulesFlag)
	}
	if groupFlag != "" {
		cfg.Groups = splitAndTrim(groupFlag)
	}

	result := batch.Run(cfg)

	// Select output destination.
	var w io.Writer = os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	duration := time.Since(start)

	switch format {
	case "json":
		if err := batch.WriteJSONReport(w, result); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
	case "csv":
		if err := batch.WriteCSVReport(w, result); err != nil {
			return fmt.Errorf("writing CSV report: %w", err)
		}
	default:
		batch.WriteConsoleReport(w, result, noColor || !isTTY(), duration)
	}

	os.Exit(result.ExitCode)
	return nil
}

// ---------------------------------------------------------------------------
// check-deps command
// ---------------------------------------------------------------------------

func newCheckDepsCmd() *cobra.Command {
	var (
		format  string
		failOn  string
		output  string
		noColor bool
	)

	cmd := &cobra.Command{
		Use:   "check-deps [path]",
		Short: "Check dependencies for known compromised packages",
		Long: `Scans lock files (package-lock.json, requirements.txt, go.sum) in the
given directory and checks installed packages against a database of known
compromised versions from confirmed supply chain attacks.

Supported ecosystems: npm, PyPI, Go`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			if noColor || !isTTY() {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Load the compromised packages database.
			db, err := deps.LoadDatabase(runnerguard.RulesFS)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Loaded %d compromised package entries\n", len(db.Packages))
			fmt.Fprintf(os.Stderr, "Scanning %s for lock files...\n", dir)

			findings, err := deps.CheckDependencies(dir, db)
			if err != nil {
				return err
			}

			// Select output destination.
			var w io.Writer = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			if format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				enc.Encode(findings)
			} else {
				writeDepFindings(w, findings, noColor || !isTTY())
			}

			if len(findings) == 0 {
				fmt.Fprintln(os.Stderr, "\nNo compromised packages detected.")
				return nil
			}

			// Check fail-on threshold.
			for _, f := range findings {
				if severityMeetsThreshold(f.Package.Severity, failOn) {
					os.Exit(1)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "console", "Output format: console, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Minimum severity to exit non-zero: low, medium, high, critical")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write report to file")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")

	return cmd
}

func writeDepFindings(w io.Writer, findings []deps.Finding, noColor bool) {
	if len(findings) == 0 {
		return
	}

	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", white("Compromised Packages Detected"))
	fmt.Fprintln(w)

	for _, f := range findings {
		sev := red("CRITICAL")
		if f.Package.Severity == "high" {
			sev = yellow("HIGH")
		}

		fmt.Fprintf(w, "  [%s] %s@%s\n", sev, f.Installed.Name, f.Installed.Version)
		fmt.Fprintf(w, "    Campaign:  %s (%s)\n", f.Package.Campaign, f.Package.Date)
		fmt.Fprintf(w, "    Lock file: %s\n", f.Installed.LockFile)
		fmt.Fprintf(w, "    %s\n", f.Package.Description)
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Total: %d compromised package(s) found\n", len(findings))
}

func severityMeetsThreshold(severity, threshold string) bool {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return levels[severity] >= levels[threshold]
}

// ---------------------------------------------------------------------------
// audit-deps command
// ---------------------------------------------------------------------------

func newAuditDepsCmd() *cobra.Command {
	var (
		format      string
		failOn      string
		output      string
		noColor     bool
		concurrency int
		rulesFlag   string
		groupFlag   string
	)

	cmd := &cobra.Command{
		Use:   "audit-deps [path]",
		Short: "Audit upstream dependency CI/CD pipelines for vulnerabilities",
		Long: `Resolves your project's dependencies to their source repositories and
scans each repository's CI/CD pipeline for security vulnerabilities.

Answers: "Are my dependencies' build pipelines secure?"

Supported ecosystems: npm, PyPI, Go`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			if noColor || !isTTY() {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			cfg := deps.AuditConfig{
				Dir:         dir,
				Concurrency: concurrency,
				FailOn:      failOn,
				RulesFS:     runnerguard.RulesFS,
			}

			if rulesFlag != "" {
				cfg.RuleIDs = splitAndTrim(rulesFlag)
			}
			if groupFlag != "" {
				cfg.Groups = splitAndTrim(groupFlag)
			}

			results, err := deps.AuditUpstream(cfg)
			if err != nil {
				return err
			}

			if len(results) == 0 {
				fmt.Fprintln(os.Stderr, "No dependencies with resolvable source repos found.")
				return nil
			}

			// Select output destination.
			var w io.Writer = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			if format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				enc.Encode(results)
			} else {
				writeAuditReport(w, results, noColor || !isTTY())
			}

			// Check fail-on threshold across all upstream findings.
			for _, r := range results {
				for _, f := range r.Findings {
					if severityMeetsThreshold(f.Severity, failOn) {
						os.Exit(1)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "console", "Output format: console, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Minimum severity to exit non-zero")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write report to file")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Max concurrent upstream scans")
	cmd.Flags().StringVar(&rulesFlag, "rules", "", "Run only specific rules")
	cmd.Flags().StringVar(&groupFlag, "group", "", "Run only rules in specific groups")

	return cmd
}

func writeAuditReport(w io.Writer, results []deps.AuditResult, noColor bool) {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	sep := strings.Repeat("\u2501", 70)

	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%s\n", white("Upstream Pipeline Audit"))
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	// Calculate column widths from data.
	pkgWidth := 20
	repoWidth := 15
	for _, r := range results {
		if len(r.Package) > pkgWidth {
			pkgWidth = len(r.Package)
		}
		sr := shortRepo(r.Repo)
		if len(sr) > repoWidth {
			repoWidth = len(sr)
		}
	}
	if pkgWidth > 40 {
		pkgWidth = 40
	}
	if repoWidth > 30 {
		repoWidth = 30
	}

	// Summary table.
	fmtStr := fmt.Sprintf("%%-%ds  %%-%ds  %%6s  %%5s  %%6s\n", pkgWidth, repoWidth)
	fmt.Fprintf(w, fmtStr, white("Package"), white("Repo"), white("Score"), white("Grade"), white("Issues"))
	fmt.Fprintf(w, fmtStr, strings.Repeat("-", pkgWidth), strings.Repeat("-", repoWidth), "------", "-----", "------")

	totalFindings := 0
	cleanCount := 0
	errorCount := 0

	for _, r := range results {
		if r.Error != "" {
			if r.Error != "no workflows" {
				fmt.Fprintf(w, fmtStr, r.Package, gray(shortRepo(r.Repo)), red("ERR"), "-", r.Error)
				errorCount++
			}
			continue
		}

		findings := len(r.Findings)
		totalFindings += findings

		if findings == 0 {
			cleanCount++
		}

		gradeColor := green
		switch {
		case r.Score.Total < 60:
			gradeColor = red
		case r.Score.Total < 80:
			gradeColor = yellow
		case r.Score.Total < 90:
			gradeColor = cyan
		}

		issueStr := fmt.Sprintf("%d", findings)
		if findings == 0 {
			issueStr = green("0")
		}

		fmt.Fprintf(w, fmtStr,
			r.Package,
			gray(shortRepo(r.Repo)),
			gradeColor(fmt.Sprintf("%d", r.Score.Total)),
			gradeColor(r.Score.Grade),
			issueStr,
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)

	scanned := len(results) - errorCount
	fmt.Fprintf(w, "%d upstream pipelines scanned, %d findings, %d clean\n", scanned, totalFindings, cleanCount)
	fmt.Fprintln(w, sep)

	// Detail for repos with findings.
	for _, r := range results {
		if len(r.Findings) == 0 || r.Error != "" {
			continue
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s (%s) - score %d/100 %s\n",
			white(">>"), white(r.Package), gray(r.Repo), r.Score.Total, r.Score.Grade)

		for _, f := range r.Findings {
			sev := strings.ToUpper(f.Severity)
			switch strings.ToLower(f.Severity) {
			case "critical":
				sev = red(sev)
			case "high":
				sev = red(sev)
			case "medium":
				sev = yellow(sev)
			case "low":
				sev = cyan(sev)
			}
			fmt.Fprintf(w, "  [%s] %s %s - %s\n", sev, f.RuleID, gray(f.File), f.RuleName)
		}
	}
}

func shortRepo(repo string) string {
	return strings.TrimPrefix(repo, "github.com/")
}

// ---------------------------------------------------------------------------
// monitor command
// ---------------------------------------------------------------------------

func newMonitorCmd() *cobra.Command {
	var (
		interval    int
		alertMode   string
		webhookURL  string
		concurrency int
	)

	cmd := &cobra.Command{
		Use:   "monitor [path]",
		Short: "Continuously monitor dependencies for new compromised releases",
		Long: `Polls package registries (npm, PyPI) for new releases of your
dependencies and runs threat signature detection against release metadata.

Alerts when a dependency publishes a version that matches known IOC patterns
or appears in the compromised packages database.

Examples:
  runner-guard monitor .                           # monitor deps in current dir
  runner-guard monitor . --interval 60             # poll every 60 seconds
  runner-guard monitor . --alert slack --webhook-url https://hooks.slack.com/...
  runner-guard monitor . --alert pagerduty          # uses RUNNER_GUARD_PAGERDUTY_KEY env var`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			printHeader(os.Stderr)

			cfg := monitor.Config{
				Dir:         dir,
				Interval:    time.Duration(interval) * time.Second,
				AlertMode:   alertMode,
				WebhookURL:  webhookURL,
				RulesFS:     runnerguard.RulesFS,
				Concurrency: concurrency,
			}

			return monitor.Run(cfg)
		},
	}

	cmd.Flags().IntVar(&interval, "interval", 300, "Poll interval in seconds (default: 300)")
	cmd.Flags().StringVar(&alertMode, "alert", "console", "Alert mode: console, slack, webhook, pagerduty")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "Webhook URL for alerts (or set RUNNER_GUARD_WEBHOOK_URL env var)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Max concurrent registry checks")

	return cmd
}

// ---------------------------------------------------------------------------
// demo command
// ---------------------------------------------------------------------------

func newDemoCmd() *cobra.Command {
	var scenario string

	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run built-in demo scenarios showing real-world CI/CD attack patterns",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()

			// Demo always uses console, always uses color (unless non-TTY).
			noColor := !isTTY()
			if noColor {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Determine which scenarios to run.
			selected := filterScenarios(scenario)
			if len(selected) == 0 {
				return fmt.Errorf("unknown scenario %q; options: all, fork-checkout, microsoft, ai-injection, glassworm", scenario)
			}

			for _, sc := range selected {
				// Print scenario banner.
				printDemoBanner(sc)

				// Load the demo workflow file from the embedded FS.
				files, err := loadDemoFiles(runnerguard.DemoFS, sc)
				if err != nil {
					return err
				}

				// Build demo contexts map — every rule gets this scenario's context.
				demoContexts := buildDemoContexts(sc)

				cfg := scanner.Config{
					Format:       "console",
					FailOn:       "critical", // never exit non-zero in demo
					NoColor:      noColor,
					IsDemo:       true,
					DemoContexts: demoContexts,
					RulesFS:      runnerguard.RulesFS,
				}

				result, err := scanner.RunOnBytes(cfg, files)
				if err != nil {
					return fmt.Errorf("demo scan failed for %s: %w", sc.Key, err)
				}

				duration := time.Since(start)
				reporter.ReportConsole(os.Stdout, result.Findings, noColor, duration, true)
				fmt.Fprintln(os.Stdout)
			}

			// Closing prompt.
			boldCyan := color.New(color.FgCyan, color.Bold)
			boldCyan.Fprintln(os.Stdout, "\u2192 Run runner-guard scan . to check your own pipelines")

			return nil
		},
	}

	cmd.Flags().StringVar(&scenario, "scenario", "all", "Demo scenario: all, fork-checkout, microsoft, ai-injection, glassworm")

	return cmd
}

// ---------------------------------------------------------------------------
// baseline command
// ---------------------------------------------------------------------------

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline [path]",
		Short: "Generate a baseline file from current findings",
		Long: `Scans the given path and writes all current finding fingerprints to
.runner-guard-baseline.json. Future scans using --baseline will suppress
these findings, letting you focus on new issues.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			cfg := scanner.Config{
				Path:    path,
				Format:  "console",
				FailOn:  "critical",
				RulesFS: runnerguard.RulesFS,
			}

			fingerprints, count, err := scanner.GenerateBaselineFingerprints(cfg)
			if err != nil {
				return fmt.Errorf("baseline scan failed: %w", err)
			}

			data, err := json.MarshalIndent(fingerprints, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding baseline: %w", err)
			}

			outputPath := ".runner-guard-baseline.json"
			if err := os.WriteFile(outputPath, data, 0644); err != nil {
				return fmt.Errorf("writing baseline file: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Baseline written: %d findings recorded. Future scans will suppress these.\n", count)
			return nil
		},
	}

	return cmd
}

// ---------------------------------------------------------------------------
// version command
// ---------------------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Runner Guard version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "runner-guard version v%s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// printHeader prints the CLI banner to the given writer.
func printHeader(w io.Writer) {
	fmt.Fprintf(w, "Runner Guard v%s | Vigilant\n", version)
	fmt.Fprintln(w, separator)
}

// printDemoBanner prints a scenario-specific demo banner to stdout.
func printDemoBanner(sc demoScenario) {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, separator)
	boldWhite := color.New(color.FgWhite, color.Bold)
	boldWhite.Fprintf(os.Stdout, "DEMO SCENARIO: %s\n", sc.Title)
	fmt.Fprintln(os.Stdout, sc.Description)
	fmt.Fprintln(os.Stdout, separator)
	fmt.Fprintln(os.Stdout)
}

// filterScenarios returns the subset of scenarios matching the --scenario flag.
func filterScenarios(name string) []demoScenario {
	if strings.EqualFold(name, "all") || name == "" {
		return scenarios
	}

	for _, sc := range scenarios {
		if strings.EqualFold(sc.Key, name) {
			return []demoScenario{sc}
		}
	}
	return nil
}

// loadDemoFiles reads the demo workflow file from the embedded FS and returns
// it as a map suitable for scanner.RunOnBytes.
func loadDemoFiles(demoFS fs.FS, sc demoScenario) (map[string][]byte, error) {
	path := "demo/vulnerable/workflows/" + sc.File
	data, err := fs.ReadFile(demoFS, path)
	if err != nil {
		return nil, fmt.Errorf("loading demo file %s: %w", path, err)
	}
	return map[string][]byte{sc.File: data}, nil
}

// buildDemoContexts creates a demo context map where every known rule ID maps
// to the scenario's context string. This ensures that any rule that fires on
// the demo file will carry the contextual explanation.
func buildDemoContexts(sc demoScenario) map[string]string {
	// All rules could potentially fire on a demo file.
	ruleIDs := []string{
		"RGS-001", "RGS-002", "RGS-003", "RGS-004",
		"RGS-005", "RGS-006", "RGS-007", "RGS-008",
		"RGS-009", "RGS-010", "RGS-011", "RGS-012",
		"RGS-014", "RGS-015", "RGS-016", "RGS-017",
		"RGS-018", "RGS-019",
	}

	contexts := make(map[string]string, len(ruleIDs))
	for _, id := range ruleIDs {
		contexts[id] = sc.Context
	}
	return contexts
}

// writeReport dispatches to the appropriate reporter based on the format string.
func writeReport(w io.Writer, findings []rules.Finding, format string, noColor bool, duration time.Duration, isDemo bool) error {
	switch strings.ToLower(format) {
	case "json":
		return reporter.ReportJSON(w, findings)
	case "sarif":
		return reporter.ReportSARIF(w, findings)
	default: // "console" or anything unrecognised
		reporter.ReportConsole(w, findings, noColor, duration, isDemo)
		return nil
	}
}

// ---------------------------------------------------------------------------
// fix command
// ---------------------------------------------------------------------------

func newFixCmd() *cobra.Command {
	var dryRun bool
	var ruleFilter string

	cmd := &cobra.Command{
		Use:   "fix [path]",
		Short: "Auto-fix security issues in GitHub Actions workflows",
		Long: `Scans workflow files and automatically remediates security findings.

Supported auto-fixes:
  RGS-002  Extract untrusted expressions from run blocks into env vars
  RGS-007  Pin third-party actions to commit SHAs
  RGS-008  Extract secrets from run blocks into env vars
  RGS-014  Extract workflow_dispatch inputs from run blocks into env vars
  RGS-015  Remove ACTIONS_RUNNER_DEBUG / ACTIONS_STEP_DEBUG env vars

Use --dry-run to preview changes without modifying files.
Use --rule to apply a specific rule's fix (e.g. --rule RGS-007).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			printHeader(os.Stderr)

			// Determine which fixes to run.
			fixFuncs := make(map[string]autofix.FixFunc)
			if ruleFilter != "" {
				fn, ok := autofix.Registry[ruleFilter]
				if !ok {
					return fmt.Errorf("no auto-fix available for rule %s", ruleFilter)
				}
				fixFuncs[ruleFilter] = fn
			} else {
				for id, fn := range autofix.Registry {
					fixFuncs[id] = fn
				}
			}

			var allResults []autofix.FixResult
			for ruleID, fn := range fixFuncs {
				results, err := fn(dir, dryRun)
				if err != nil {
					errColor := color.New(color.FgRed)
					errColor.Fprintf(os.Stderr, "  Warning: %s fix failed: %v\n", ruleID, err)
					continue
				}
				allResults = append(allResults, results...)
			}

			if len(allResults) == 0 {
				boldGreen := color.New(color.FgGreen, color.Bold)
				boldGreen.Fprintln(os.Stdout, "\u2713 No auto-fixable issues found.")
				return nil
			}

			verb := "Fixed"
			if dryRun {
				verb = "Would fix"
			}

			var succeeded, failed int
			for _, r := range allResults {
				if r.Error != "" {
					failed++
					errColor := color.New(color.FgRed)
					errColor.Fprintf(os.Stdout, "  \u2717 [%s] %s\n", r.RuleID, r.Error)
				} else {
					succeeded++
					okColor := color.New(color.FgGreen)
					okColor.Fprintf(os.Stdout, "  \u2713 [%s] %s\n", r.RuleID, r.Detail)
					fileColor := color.New(color.FgBlue)
					fileColor.Fprintf(os.Stdout, "    %s (line %d)\n", r.File, r.LineNum)
				}
			}

			fmt.Fprintln(os.Stdout)
			if dryRun {
				fmt.Fprintf(os.Stdout, "Dry run: %d fixes would be applied", succeeded)
			} else {
				fmt.Fprintf(os.Stdout, "%s: %d issues remediated", verb, succeeded)
			}
			if failed > 0 {
				fmt.Fprintf(os.Stdout, " (%d failed)", failed)
			}
			fmt.Fprintln(os.Stdout)

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without modifying files")
	cmd.Flags().StringVar(&ruleFilter, "rule", "", "Apply fix for a specific rule only (e.g. RGS-007)")

	return cmd
}

// ---------------------------------------------------------------------------
// Remote scanning helper
// ---------------------------------------------------------------------------

func runRemoteScan(cfg scanner.Config) (*scanner.Result, error) {
	fmt.Fprintf(os.Stderr, "Fetching workflows from %s...\n", cfg.Path)

	files, err := ghclient.FetchWorkflows(cfg.Path)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return &scanner.Result{Findings: nil, ExitCode: 0}, nil
	}

	fmt.Fprintf(os.Stderr, "Scanning %d workflow files...\n", len(files))
	return scanner.RunOnBytes(cfg, files)
}

// ---------------------------------------------------------------------------
// Changed-only scanning helper
// ---------------------------------------------------------------------------

func runChangedOnlyScan(cfg scanner.Config) (*scanner.Result, error) {
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		absPath = cfg.Path
	}

	if !git.IsGitRepo(absPath) {
		return nil, fmt.Errorf("--changed-only requires a git repository, but %s is not", cfg.Path)
	}

	changed, err := git.ChangedWorkflows(absPath, "")
	if err != nil {
		return nil, fmt.Errorf("detecting changed workflows: %w", err)
	}

	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "No workflow files changed in current branch.")
		return &scanner.Result{Findings: nil, ExitCode: 0}, nil
	}

	fmt.Fprintf(os.Stderr, "Scanning %d changed workflow files...\n", len(changed))
	cfg.ChangedFiles = changed
	return scanner.Run(cfg)
}

// ---------------------------------------------------------------------------
// Config file helpers
// ---------------------------------------------------------------------------

func loadConfigFile(path string) *config.Config {
	dir := path
	if ghclient.IsRemotePath(path) {
		dir = "."
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}

	cfg, err := config.Load(absDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: error loading config: %v\n", err)
		return nil
	}
	return cfg // may be nil if no config found
}

func mergeString(flag, defaultVal string, cfg *config.Config) string {
	if flag != defaultVal {
		return flag // CLI flag explicitly set
	}
	if cfg != nil {
		switch defaultVal {
		case "high":
			if cfg.FailOn != "" {
				return cfg.FailOn
			}
		case "console":
			if cfg.Format != "" {
				return cfg.Format
			}
		}
	}
	return defaultVal
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// isTTY returns true when stdout is connected to a terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
