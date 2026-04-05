package batch

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	ghclient "github.com/Vigilant-LLC/runner-guard/internal/github"
	"github.com/Vigilant-LLC/runner-guard/internal/rules"
	"github.com/Vigilant-LLC/runner-guard/internal/scanner"
	"github.com/Vigilant-LLC/runner-guard/internal/score"
)

// RepoResult holds the scan result for a single repository.
type RepoResult struct {
	Repo     string          `json:"repo"`
	Findings []rules.Finding `json:"findings"`
	Score    score.Score     `json:"score"`
	Duration time.Duration   `json:"duration"`
	Error    string          `json:"error,omitempty"`
}

// Config configures a batch scan.
type Config struct {
	Repos       []string // list of repo paths/URLs to scan
	Concurrency int      // max parallel scans (0 = sequential)
	FailOn      string   // severity threshold for exit code
	Format      string   // output format
	NoColor     bool     // suppress ANSI
	RulesFS     fs.FS    // embedded rules
	RuleIDs     []string // rule filter
	Groups      []string // group filter
	IgnoreRules []string // rules to suppress
	IgnoreFiles []string // files to suppress
}

// Result holds the aggregated results of a batch scan.
type Result struct {
	Results  []RepoResult
	ExitCode int
}

// ParseRepoFile reads a repo list from a file path or stdin ("-").
// Lines starting with # are comments, blank lines are ignored.
func ParseRepoFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening repos file: %w", err)
		}
		defer f.Close()
		r = f
	}

	var repos []string
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		repos = append(repos, line)
	}
	if err := scan.Err(); err != nil {
		return nil, fmt.Errorf("reading repos file: %w", err)
	}
	return repos, nil
}

// Run executes a batch scan across all repos in the config.
func Run(cfg Config) *Result {
	results := make([]RepoResult, len(cfg.Repos))
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	exitCode := 0

	for i, repo := range cfg.Repos {
		wg.Add(1)
		go func(idx int, repoPath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			fmt.Fprintf(os.Stderr, "[%d/%d] Scanning %s...\n", idx+1, len(cfg.Repos), repoPath)

			scanCfg := scanner.Config{
				Path:        repoPath,
				FailOn:      cfg.FailOn,
				NoColor:     true,
				RulesFS:     cfg.RulesFS,
				RuleIDs:     cfg.RuleIDs,
				Groups:      cfg.Groups,
				IgnoreRules: cfg.IgnoreRules,
				IgnoreFiles: cfg.IgnoreFiles,
			}

			var result *scanner.Result
			var err error

			if ghclient.IsRemotePath(repoPath) {
				// Check if local path exists
				files, fetchErr := ghclient.FetchWorkflows(repoPath)
				if fetchErr != nil {
					err = fetchErr
				} else if len(files) == 0 {
					duration := time.Since(start)
					rr := RepoResult{Repo: repoPath, Duration: duration, Error: "no workflows found (repo may not exist or has no .github/workflows/)"}
					fmt.Fprintf(os.Stderr, "[%d/%d] %s SKIP: no workflows found (%s)\n", idx+1, len(cfg.Repos), repoPath, duration)
					results[idx] = rr
					return
				} else {
					result, err = scanner.RunOnBytes(scanCfg, files)
				}
			} else {
				if _, statErr := os.Stat(repoPath); os.IsNotExist(statErr) {
					duration := time.Since(start)
					rr := RepoResult{Repo: repoPath, Duration: duration, Error: "path does not exist"}
					fmt.Fprintf(os.Stderr, "[%d/%d] %s ERROR: path does not exist (%s)\n", idx+1, len(cfg.Repos), repoPath, duration)
					results[idx] = rr
					return
				}
				result, err = scanner.Run(scanCfg)
			}

			duration := time.Since(start)
			rr := RepoResult{
				Repo:     repoPath,
				Duration: duration,
			}

			if err != nil {
				rr.Error = err.Error()
				fmt.Fprintf(os.Stderr, "[%d/%d] %s ERROR: %s (%s)\n", idx+1, len(cfg.Repos), repoPath, err, duration)
			} else {
				rr.Findings = result.Findings
				rr.Score = score.Calculate(result.Findings)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s OK (%d findings, score %d/100, %s)\n",
					idx+1, len(cfg.Repos), repoPath, len(result.Findings), rr.Score.Total, duration)

				mu.Lock()
				if result.ExitCode > exitCode {
					exitCode = result.ExitCode
				}
				mu.Unlock()
			}

			results[idx] = rr
		}(i, repo)
	}

	wg.Wait()

	return &Result{
		Results:  results,
		ExitCode: exitCode,
	}
}
