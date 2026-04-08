package deps

import (
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	ghclient "github.com/Vigilant-LLC/runner-guard/v3/internal/github"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/rules"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/scanner"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/score"
)

// AuditResult holds the scan result for one upstream dependency's pipeline.
type AuditResult struct {
	Package   string          `json:"package"`
	Ecosystem string          `json:"ecosystem"`
	Version   string          `json:"version"`
	Repo      string          `json:"repo"`
	Findings  []rules.Finding `json:"findings"`
	Score     score.Score     `json:"score"`
	Duration  time.Duration   `json:"duration"`
	Error     string          `json:"error,omitempty"`
}

// AuditConfig configures an upstream pipeline audit.
type AuditConfig struct {
	Dir         string   // project directory to scan lock files in
	Concurrency int      // max parallel scans
	FailOn      string   // severity threshold
	RulesFS     fs.FS    // embedded rules
	RuleIDs     []string // rule filter
	Groups      []string // group filter
}

// AuditUpstream resolves dependencies to source repos and scans their CI/CD pipelines.
func AuditUpstream(cfg AuditConfig) ([]AuditResult, error) {
	// Discover and parse lock files.
	lockFiles, err := DiscoverLockFiles(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("discovering lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil, nil
	}

	// Collect all dependencies.
	var allDeps []Dependency
	for _, lf := range lockFiles {
		deps, err := lf.Parse()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", lf.Path, err)
			continue
		}
		allDeps = append(allDeps, deps...)
	}

	if len(allDeps) == 0 {
		return nil, nil
	}

	// Resolve dependencies to GitHub repos (dedup by repo).
	fmt.Fprintf(os.Stderr, "Resolving %d dependencies to source repos...\n", len(allDeps))

	type depInfo struct {
		repo      string
		name      string
		version   string
		ecosystem string
	}

	seen := make(map[string]bool)
	var targets []depInfo

	for _, dep := range allDeps {
		repo := ResolveToRepo(dep)
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		targets = append(targets, depInfo{
			repo:      repo,
			name:      dep.Name,
			version:   dep.Version,
			ecosystem: dep.Ecosystem,
		})
	}

	fmt.Fprintf(os.Stderr, "Resolved %d unique repos from %d dependencies\n", len(targets), len(allDeps))

	if len(targets) == 0 {
		return nil, nil
	}

	// Scan each upstream repo's CI/CD pipeline.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	results := make([]AuditResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t depInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			fmt.Fprintf(os.Stderr, "[%d/%d] Scanning %s (%s)...\n", idx+1, len(targets), t.name, t.repo)

			ar := AuditResult{
				Package:   t.name,
				Ecosystem: t.ecosystem,
				Version:   t.version,
				Repo:      t.repo,
			}

			// Fetch workflows from the upstream repo.
			files, err := ghclient.FetchWorkflows(t.repo)
			if err != nil {
				ar.Error = err.Error()
				ar.Duration = time.Since(start)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s ERROR: %v\n", idx+1, len(targets), t.name, err)
				results[idx] = ar
				return
			}

			if len(files) == 0 {
				ar.Error = "no workflows"
				ar.Duration = time.Since(start)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s no workflows\n", idx+1, len(targets), t.name)
				results[idx] = ar
				return
			}

			scanCfg := scanner.Config{
				Path:    t.repo,
				FailOn:  cfg.FailOn,
				NoColor: true,
				RulesFS: cfg.RulesFS,
				RuleIDs: cfg.RuleIDs,
				Groups:  cfg.Groups,
			}

			result, err := scanner.RunOnBytes(scanCfg, files)
			ar.Duration = time.Since(start)

			if err != nil {
				ar.Error = err.Error()
				fmt.Fprintf(os.Stderr, "[%d/%d] %s ERROR: %v\n", idx+1, len(targets), t.name, err)
			} else {
				ar.Findings = result.Findings
				ar.Score = score.Calculate(result.Findings)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s OK (%d findings, score %d/100, %s)\n",
					idx+1, len(targets), t.name, len(result.Findings), ar.Score.Total, ar.Duration)
			}

			results[idx] = ar
		}(i, target)
	}

	wg.Wait()
	return results, nil
}
