// Package monitor provides continuous dependency monitoring.
// It polls package registries for new releases and runs threat
// signature detection against release metadata changes.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Vigilant-LLC/runner-guard/internal/deps"
	"github.com/Vigilant-LLC/runner-guard/internal/rules"
)

// Config holds monitor configuration.
type Config struct {
	Dir         string        // project directory with lock files
	Interval    time.Duration // poll interval
	AlertMode   string        // "console", "slack"
	WebhookURL  string        // Slack webhook URL (if alert=slack)
	RulesFS     fs.FS         // embedded rules for signature loading
	Concurrency int           // max parallel registry checks
}

// Alert represents a detected threat in a new package release.
type Alert struct {
	Package    string    `json:"package"`
	Ecosystem  string    `json:"ecosystem"`
	OldVersion string    `json:"old_version"`
	NewVersion string    `json:"new_version"`
	Signature  string    `json:"signature"`
	Detail     string    `json:"detail"`
	Severity   string    `json:"severity"`
	Timestamp  time.Time `json:"timestamp"`
}

// state tracks the last known version for each package.
type state struct {
	mu       sync.RWMutex
	versions map[string]string // "ecosystem:name" -> version
}

func newState() *state {
	return &state{versions: make(map[string]string)}
}

func (s *state) get(ecosystem, name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[ecosystem+":"+name]
}

func (s *state) set(ecosystem, name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[ecosystem+":"+name] = version
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Run starts the monitor loop. It blocks until the context is cancelled
// or a SIGINT/SIGTERM is received.
func Run(cfg Config) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}

	// Load signatures for pattern matching.
	sigs, err := rules.LoadSignatures(cfg.RulesFS)
	if err != nil {
		return fmt.Errorf("loading signatures: %w", err)
	}

	// Also load the compromised packages DB for version matching.
	db, err := deps.LoadDatabase(cfg.RulesFS)
	if err != nil {
		return fmt.Errorf("loading compromised packages DB: %w", err)
	}

	// Discover and parse lock files to build initial dependency list.
	allDeps, err := discoverDeps(cfg.Dir)
	if err != nil {
		return err
	}

	if len(allDeps) == 0 {
		return fmt.Errorf("no dependencies found in %s", cfg.Dir)
	}

	fmt.Fprintf(os.Stderr, "Monitoring %d packages (%s)\n", len(allDeps), ecosystemSummary(allDeps))
	fmt.Fprintf(os.Stderr, "Poll interval: %s\n", cfg.Interval)
	fmt.Fprintf(os.Stderr, "Alert mode: %s\n", cfg.AlertMode)
	if url := resolveWebhookURL(cfg); url != "" && cfg.AlertMode != "console" {
		fmt.Fprintf(os.Stderr, "Webhook: configured\n")
	}
	fmt.Fprintf(os.Stderr, "Loaded %d threat signatures, %d compromised package entries\n",
		len(sigs), len(db.Packages))
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n\n")

	// Set initial state from lock file versions.
	st := newState()
	for _, d := range allDeps {
		st.set(d.Ecosystem, d.Name, d.Version)
	}

	// Set up graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nShutting down monitor...\n")
		cancel()
	}()

	// Initial check.
	alerts := pollAll(ctx, allDeps, st, sigs, db, cfg.Concurrency)
	dispatchAlerts(alerts, cfg)

	// Main loop.
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Monitor stopped.\n")
			return nil
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "[%s] Polling %d packages...\n",
				time.Now().Format("15:04:05"), len(allDeps))
			alerts := pollAll(ctx, allDeps, st, sigs, db, cfg.Concurrency)
			dispatchAlerts(alerts, cfg)
		}
	}
}

// discoverDeps finds and parses all lock files in the directory.
func discoverDeps(dir string) ([]deps.Dependency, error) {
	lockFiles, err := deps.DiscoverLockFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("discovering lock files: %w", err)
	}

	var allDeps []deps.Dependency
	for _, lf := range lockFiles {
		parsed, err := lf.Parse()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", lf.Path, err)
			continue
		}
		allDeps = append(allDeps, parsed...)
	}
	return allDeps, nil
}

// pollAll checks all dependencies for new versions in parallel.
func pollAll(ctx context.Context, allDeps []deps.Dependency, st *state, sigs []*rules.ThreatSignature, db *deps.Database, concurrency int) []Alert {
	var (
		mu     sync.Mutex
		alerts []Alert
		wg     sync.WaitGroup
	)

	sem := make(chan struct{}, concurrency)

	for _, d := range allDeps {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(dep deps.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			latest, metadata, err := fetchLatestVersion(dep.Ecosystem, dep.Name)
			if err != nil || latest == "" {
				return
			}

			known := st.get(dep.Ecosystem, dep.Name)
			if latest == known {
				return // no change
			}

			// New version detected.
			fmt.Fprintf(os.Stderr, "  New release: %s %s -> %s\n", dep.Name, known, latest)
			st.set(dep.Ecosystem, dep.Name, latest)

			var found []Alert

			// Check against compromised packages DB.
			newDep := deps.Dependency{
				Name:      dep.Name,
				Version:   latest,
				Ecosystem: dep.Ecosystem,
			}
			if finding := db.Check(newDep); finding != nil {
				found = append(found, Alert{
					Package:    dep.Name,
					Ecosystem:  dep.Ecosystem,
					OldVersion: known,
					NewVersion: latest,
					Signature:  "compromised-packages-db",
					Detail:     finding.Description,
					Severity:   finding.Package.Severity,
					Timestamp:  time.Now(),
				})
			}

			// Run signature detection against the metadata.
			found = append(found, matchSignatures(dep.Name, dep.Ecosystem, known, latest, metadata, sigs)...)

			if len(found) > 0 {
				mu.Lock()
				alerts = append(alerts, found...)
				mu.Unlock()
			}
		}(d)
	}

	wg.Wait()
	return alerts
}

// fetchLatestVersion queries the appropriate registry for the latest version.
// Returns the version string and raw metadata for signature scanning.
func fetchLatestVersion(ecosystem, name string) (string, string, error) {
	switch ecosystem {
	case "npm":
		return fetchNpmLatest(name)
	case "pypi":
		return fetchPyPILatest(name)
	default:
		// Go modules don't have a simple "latest" endpoint for polling.
		return "", "", nil
	}
}

// fetchNpmLatest gets the latest version from the npm registry.
func fetchNpmLatest(name string) (string, string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/latest", name)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("npm registry returned %d for %s", resp.StatusCode, name)
	}

	var data struct {
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
		Name    string            `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", err
	}

	// Build metadata string for signature matching.
	var metadata strings.Builder
	metadata.WriteString(fmt.Sprintf("name: %s\n", data.Name))
	metadata.WriteString(fmt.Sprintf("version: %s\n", data.Version))
	for k, v := range data.Scripts {
		metadata.WriteString(fmt.Sprintf("script.%s: %s\n", k, v))
	}

	return data.Version, metadata.String(), nil
}

// fetchPyPILatest gets the latest version from the PyPI registry.
func fetchPyPILatest(name string) (string, string, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("pypi returned %d for %s", resp.StatusCode, name)
	}

	var data struct {
		Info struct {
			Version     string `json:"version"`
			Name        string `json:"name"`
			Description string `json:"description"`
			HomePage    string `json:"home_page"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", err
	}

	var metadata strings.Builder
	metadata.WriteString(fmt.Sprintf("name: %s\n", data.Info.Name))
	metadata.WriteString(fmt.Sprintf("version: %s\n", data.Info.Version))
	metadata.WriteString(fmt.Sprintf("description: %s\n", data.Info.Description))
	metadata.WriteString(fmt.Sprintf("homepage: %s\n", data.Info.HomePage))

	return data.Info.Version, metadata.String(), nil
}

// matchSignatures runs threat signatures against package metadata.
func matchSignatures(name, ecosystem, oldVersion, newVersion, metadata string, sigs []*rules.ThreatSignature) []Alert {
	var alerts []Alert

	for _, sig := range sigs {
		// Check package name against ioc-package signatures.
		if sig.Type == "ioc-package" {
			if sig.Match(name) {
				alerts = append(alerts, Alert{
					Package:    name,
					Ecosystem:  ecosystem,
					OldVersion: oldVersion,
					NewVersion: newVersion,
					Signature:  sig.ID,
					Detail:     fmt.Sprintf("Package name matches IOC: %s (%s)", sig.Description, sig.Campaign),
					Severity:   sig.Severity,
					Timestamp:  time.Now(),
				})
			}
			continue
		}

		// Check metadata content against all other signature types.
		if metadata != "" && sig.Match(metadata) {
			alerts = append(alerts, Alert{
				Package:    name,
				Ecosystem:  ecosystem,
				OldVersion: oldVersion,
				NewVersion: newVersion,
				Signature:  sig.ID,
				Detail:     fmt.Sprintf("Metadata matches IOC: %s (%s)", sig.Description, sig.Campaign),
				Severity:   sig.Severity,
				Timestamp:  time.Now(),
			})
		}
	}

	return alerts
}

// resolveWebhookURL returns the webhook URL from config or environment.
// Environment variable takes precedence over the flag.
func resolveWebhookURL(cfg Config) string {
	if env := os.Getenv("RUNNER_GUARD_WEBHOOK_URL"); env != "" {
		return env
	}
	return cfg.WebhookURL
}

// dispatchAlerts sends alerts to the configured output.
// Console alerts are always printed so container logs capture them.
// Webhook/Slack alerts are sent in addition when configured.
func dispatchAlerts(alerts []Alert, cfg Config) {
	if len(alerts) == 0 {
		return
	}

	// Always print to console so logs capture it.
	printConsoleAlerts(alerts)

	// Additionally send to configured alert channel.
	url := resolveWebhookURL(cfg)
	switch cfg.AlertMode {
	case "slack":
		sendSlackAlerts(alerts, url)
	case "webhook":
		sendWebhookAlerts(alerts, url)
	}
}

// printConsoleAlerts writes alerts to stdout.
func printConsoleAlerts(alerts []Alert) {
	for _, a := range alerts {
		fmt.Printf("\n[%s] ALERT: %s@%s (%s)\n", strings.ToUpper(a.Severity), a.Package, a.NewVersion, a.Ecosystem)
		if a.OldVersion != "" {
			fmt.Printf("  Previous version: %s\n", a.OldVersion)
		}
		fmt.Printf("  Signature: %s\n", a.Signature)
		fmt.Printf("  %s\n", a.Detail)
		fmt.Printf("  Time: %s\n", a.Timestamp.Format(time.RFC3339))
	}
	fmt.Println()
}

// sendSlackAlerts posts alerts to a Slack webhook.
func sendSlackAlerts(alerts []Alert, webhookURL string) {
	if webhookURL == "" {
		fmt.Fprintf(os.Stderr, "Warning: --webhook-url not set, falling back to console\n")
		printConsoleAlerts(alerts)
		return
	}

	for _, a := range alerts {
		text := fmt.Sprintf(":rotating_light: *Runner Guard Alert*\n*Package:* %s@%s (%s)\n*Severity:* %s\n*Signature:* %s\n*Detail:* %s",
			a.Package, a.NewVersion, a.Ecosystem, strings.ToUpper(a.Severity), a.Signature, a.Detail)

		payload := fmt.Sprintf(`{"text":%q}`, text)
		resp, err := httpClient.Post(webhookURL, "application/json", strings.NewReader(payload))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Slack alert failed: %v\n", err)
			continue
		}
		resp.Body.Close()
	}
}

// sendWebhookAlerts posts alerts as JSON to a generic webhook URL.
// Compatible with PagerDuty, Opsgenie, or any HTTP endpoint that accepts JSON.
func sendWebhookAlerts(alerts []Alert, webhookURL string) {
	if webhookURL == "" {
		fmt.Fprintf(os.Stderr, "Warning: no webhook URL configured (use --webhook-url or RUNNER_GUARD_WEBHOOK_URL env var)\n")
		return
	}

	payload, err := json.Marshal(alerts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal alerts: %v\n", err)
		return
	}

	resp, err := httpClient.Post(webhookURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: webhook alert failed: %v\n", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Fprintf(os.Stderr, "Webhook alert sent (%d alerts)\n", len(alerts))
	} else {
		fmt.Fprintf(os.Stderr, "Warning: webhook returned status %d\n", resp.StatusCode)
	}
}

// ecosystemSummary returns a human-readable summary of ecosystems.
func ecosystemSummary(allDeps []deps.Dependency) string {
	counts := make(map[string]int)
	for _, d := range allDeps {
		counts[d.Ecosystem]++
	}

	var parts []string
	for eco, count := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", count, eco))
	}
	return strings.Join(parts, ", ")
}
