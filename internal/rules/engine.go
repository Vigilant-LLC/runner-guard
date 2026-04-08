package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/v3/internal/parser"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/taint"
	"gopkg.in/yaml.v3"
)

// Finding represents a single security finding produced by the rule engine.
type Finding struct {
	RuleID         string   `json:"rule_id"`
	RuleName       string   `json:"name"`
	Severity       string   `json:"severity"`
	File           string   `json:"file"`
	JobID          string   `json:"job_id"`
	StepName       string   `json:"step_name"`
	LineNumber     int      `json:"line"`
	Description    string   `json:"description"`
	Evidence       string   `json:"evidence"`
	AttackScenario string   `json:"attack_scenario"`
	Fix            string   `json:"fix"`
	References     []string `json:"references"`
	DemoContext    string   `json:"demo_context,omitempty"`
}

// ThreatSignature represents a single IOC pattern loaded from signatures.yaml.
type ThreatSignature struct {
	ID          string   `yaml:"id"`
	ThreatActor string   `yaml:"threat_actor"`
	Type        string   `yaml:"type"`
	Pattern     string   `yaml:"pattern"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	FirstSeen   string   `yaml:"first_seen"`
	References  []string `yaml:"references"`
	Campaign    string   // populated from parent SignaturesFile.Campaign
	compiled    *regexp.Regexp
}

// Match returns true if the compiled pattern matches the given text.
func (s *ThreatSignature) Match(text string) bool {
	if s.compiled == nil {
		return false
	}
	return s.compiled.MatchString(text)
}

// LoadSignatures is the public API for loading threat signatures from the
// embedded rules filesystem. Used by the monitor package for IOC matching.
func LoadSignatures(fsys fs.FS) ([]*ThreatSignature, error) {
	return loadSignatures(fsys)
}

// SignaturesFile is the top-level structure of a signature YAML file.
type SignaturesFile struct {
	Version     int                `yaml:"version"`
	LastUpdated string             `yaml:"last_updated"`
	Campaign    string             `yaml:"campaign"`
	Description string             `yaml:"description"`
	Signatures  []*ThreatSignature `yaml:"signatures"`
}

// Engine is the rule evaluation engine that loads rule metadata and runs
// all registered rule checkers against parsed workflows.
type Engine struct {
	rules      map[string]*RuleMetadata
	checkers   map[string]RuleChecker
	signatures []*ThreatSignature // loaded from signatures.yaml
}

// RuleChecker is a function that evaluates a single parsed workflow and returns
// any findings. Each rule ID maps to one RuleChecker.
type RuleChecker func(wf *parser.Workflow) []Finding

// NewEngine creates a new Engine, loads rule metadata from the provided filesystem,
// and registers all built-in rule checker functions.
func NewEngine(fsys fs.FS) (*Engine, error) {
	meta, err := LoadRules(fsys)
	if err != nil {
		return nil, err
	}

	sigs, _ := loadSignatures(fsys)

	e := &Engine{
		rules:      meta,
		checkers:   make(map[string]RuleChecker),
		signatures: sigs,
	}

	e.registerCheckers()
	return e, nil
}

// loadSignatures reads and compiles threat signatures from the rules/signatures/
// directory. Each .yaml file in the directory represents a campaign or threat
// actor. Falls back to reading rules/signatures.yaml for backward compatibility.
func loadSignatures(fsys fs.FS) ([]*ThreatSignature, error) {
	var allSignatures []*ThreatSignature

	// Try directory-based loading first (rules/signatures/*.yaml).
	dirEntries, dirErr := fs.ReadDir(fsys, "rules/signatures")
	if dirErr == nil {
		for _, entry := range dirEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}
			path := "rules/signatures/" + entry.Name()
			sigs, err := loadSignatureFile(fsys, path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load signature file %s: %v\n", path, err)
				continue
			}
			allSignatures = append(allSignatures, sigs...)
		}
		if len(allSignatures) > 0 {
			return allSignatures, nil
		}
	}

	// Fallback: try single-file format (rules/signatures.yaml) for backward compat.
	sigs, err := loadSignatureFile(fsys, "rules/signatures.yaml")
	if err != nil {
		// Neither directory nor single file found — return empty (no signatures).
		return nil, nil
	}
	return sigs, nil
}

// loadSignatureFile reads a single signature YAML file, parses it, and returns
// compiled signatures. Invalid patterns are skipped with a warning.
func loadSignatureFile(fsys fs.FS, path string) ([]*ThreatSignature, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}

	var sf SignaturesFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	seen := make(map[string]bool)
	var valid []*ThreatSignature
	for _, sig := range sf.Signatures {
		if sig.Pattern == "" || seen[sig.ID] {
			continue
		}
		compiled, err := regexp.Compile(sig.Pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid signature pattern %q (%s) in %s: %v\n", sig.ID, sig.Pattern, path, err)
			continue
		}
		sig.compiled = compiled
		sig.Campaign = sf.Campaign
		seen[sig.ID] = true
		valid = append(valid, sig)
	}
	return valid, nil
}

// NewEngineWithDefaults creates an Engine with default (empty) metadata for all rules.
// This is useful when rule YAML files are not available (e.g., in tests).
func NewEngineWithDefaults() *Engine {
	e := &Engine{
		rules:    defaultRuleMetadata(),
		checkers: make(map[string]RuleChecker),
	}
	e.registerCheckers()
	return e
}

func (e *Engine) registerCheckers() {
	e.checkers["RGS-001"] = e.checkRGS001
	e.checkers["RGS-002"] = e.checkRGS002
	e.checkers["RGS-003"] = e.checkRGS003
	e.checkers["RGS-004"] = e.checkRGS004
	e.checkers["RGS-005"] = e.checkRGS005
	e.checkers["RGS-006"] = e.checkRGS006
	e.checkers["RGS-007"] = e.checkRGS007
	e.checkers["RGS-008"] = e.checkRGS008
	e.checkers["RGS-009"] = e.checkRGS009
	e.checkers["RGS-010"] = e.checkRGS010
	e.checkers["RGS-011"] = e.checkRGS011
	e.checkers["RGS-012"] = e.checkRGS012
	e.checkers["RGS-014"] = e.checkRGS014
	e.checkers["RGS-015"] = e.checkRGS015
	e.checkers["RGS-016"] = e.checkRGS016
	e.checkers["RGS-017"] = e.checkRGS017
	e.checkers["RGS-018"] = e.checkRGS018
	e.checkers["RGS-019"] = e.checkRGS019
}

// Evaluate runs all registered checkers against all provided workflows,
// deduplicates findings, and sorts by severity then file then line number.
func (e *Engine) Evaluate(workflows []*parser.Workflow) []Finding {
	return e.EvaluateFiltered(workflows, nil, nil, nil)
}

// EvaluateFiltered runs only the checkers matching the given rule IDs and/or
// groups. If both ruleIDs and groups are nil/empty, all checkers run. When
// both are provided, their union is used (a rule matching either is included).
func (e *Engine) EvaluateFiltered(workflows []*parser.Workflow, ruleIDs []string, groups []string, demoContexts map[string]string) []Finding {
	allowed := e.resolveAllowedRules(ruleIDs, groups)

	var all []Finding
	for _, wf := range workflows {
		for ruleID, checker := range e.checkers {
			if allowed != nil {
				if !allowed[ruleID] {
					continue
				}
			}
			findings := checker(wf)
			if len(demoContexts) > 0 {
				for i := range findings {
					if ctx, ok := demoContexts[findings[i].RuleID]; ok {
						findings[i].DemoContext = ctx
					}
				}
			}
			all = append(all, findings...)
		}
	}
	return deduplicateAndSort(all)
}

// EvaluateWithDemoContext is the same as Evaluate but populates DemoContext
// on findings using the provided mapping from rule ID to demo context string.
func (e *Engine) EvaluateWithDemoContext(workflows []*parser.Workflow, demoContexts map[string]string) []Finding {
	return e.EvaluateFiltered(workflows, nil, nil, demoContexts)
}

// resolveAllowedRules builds a set of rule IDs that should run based on
// explicit rule IDs and/or group names. Returns nil if no filtering is needed.
func (e *Engine) resolveAllowedRules(ruleIDs []string, groups []string) map[string]bool {
	if len(ruleIDs) == 0 && len(groups) == 0 {
		return nil // no filtering
	}

	allowed := make(map[string]bool)

	// Add explicitly listed rule IDs.
	for _, id := range ruleIDs {
		allowed[strings.ToUpper(id)] = true
	}

	// Add rules belonging to the requested groups.
	if len(groups) > 0 {
		groupSet := make(map[string]bool, len(groups))
		for _, g := range groups {
			groupSet[strings.ToLower(g)] = true
		}
		for id, meta := range e.rules {
			if meta.Group != "" && groupSet[strings.ToLower(meta.Group)] {
				allowed[id] = true
			}
		}
	}

	return allowed
}

// ListGroups returns a sorted list of group names and their member rule IDs.
func (e *Engine) ListGroups() map[string][]string {
	groups := make(map[string][]string)
	for id, meta := range e.rules {
		if meta.Group != "" {
			groups[meta.Group] = append(groups[meta.Group], id)
		}
	}
	for g := range groups {
		sort.Strings(groups[g])
	}
	return groups
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// hasTrigger returns true if the workflow has the specified trigger.
func hasTrigger(wf *parser.Workflow, triggerName string) bool {
	for _, t := range wf.Triggers {
		if strings.EqualFold(t, triggerName) {
			return true
		}
	}
	return false
}

// hasCommentTrigger returns true if the workflow triggers on issue_comment,
// pull_request_review_comment, or similar comment-based events.
func hasCommentTrigger(wf *parser.Workflow) bool {
	commentTriggers := []string{
		"issue_comment",
		"pull_request_review_comment",
	}
	for _, ct := range commentTriggers {
		if hasTrigger(wf, ct) {
			return true
		}
	}
	return false
}

// checkoutsForkCode returns true if any step in the workflow checks out PR head
// (fork) code using actions/checkout with a ref pointing to the PR head.
// It also returns the matching step.
func checkoutsForkCode(wf *parser.Workflow) (bool, *parser.Step) {
	prHeadRefs := []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.head_ref",
	}

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !isCheckoutAction(step.Uses) {
				continue
			}

			// Check the ref field in the with map
			refVal, hasRef := step.With["ref"]
			if hasRef {
				lower := strings.ToLower(refVal)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						return true, step
					}
				}
			}

			// If pull_request_target and checkout has no explicit ref, the default
			// is the base branch (safe). But if the ref contains any expression
			// referencing PR head, flag it.
			for _, expr := range step.Expressions {
				lower := strings.ToLower(expr)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						return true, step
					}
				}
			}
		}
	}
	return false, nil
}

// hasSecretsAccess checks if a step or its parent job references secrets.
func hasSecretsAccess(step *parser.Step, job *parser.Job) bool {
	// Check step expressions
	for _, expr := range step.Expressions {
		if strings.Contains(strings.ToLower(expr), "secrets.") {
			return true
		}
	}

	// Check step env
	for _, v := range step.Env {
		if strings.Contains(strings.ToLower(v), "secrets.") {
			return true
		}
	}

	// Check job env
	for _, v := range job.Env {
		if strings.Contains(strings.ToLower(v), "secrets.") {
			return true
		}
	}

	// Check job secrets refs
	if len(job.Secrets) > 0 {
		return true
	}

	return false
}

// hasAuthorCheck returns true if any step in the job has an if condition
// that checks author_association or actor.
func hasAuthorCheck(job *parser.Job) bool {
	for _, step := range job.Steps {
		if step.If == "" {
			continue
		}
		lower := strings.ToLower(step.If)
		if strings.Contains(lower, "author_association") ||
			strings.Contains(lower, "actor") {
			return true
		}
	}
	return false
}

// severityOrder returns a numeric sort value for severity levels.
// Lower number = higher severity.
func severityOrder(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// deduplicateAndSort removes duplicate findings (same RuleID + File + JobID + LineNumber)
// and sorts by severity (critical > high > medium > low), then file, then line number.
func deduplicateAndSort(findings []Finding) []Finding {
	type dedupKey struct {
		RuleID     string
		File       string
		JobID      string
		LineNumber int
	}

	seen := make(map[dedupKey]bool)
	var unique []Finding

	for _, f := range findings {
		key := dedupKey{
			RuleID:     f.RuleID,
			File:       f.File,
			JobID:      f.JobID,
			LineNumber: f.LineNumber,
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		si, sj := severityOrder(unique[i].Severity), severityOrder(unique[j].Severity)
		if si != sj {
			return si < sj
		}
		if unique[i].File != unique[j].File {
			return unique[i].File < unique[j].File
		}
		return unique[i].LineNumber < unique[j].LineNumber
	})

	return unique
}

// isCheckoutAction returns true if the uses string refers to actions/checkout.
func isCheckoutAction(uses string) bool {
	return strings.HasPrefix(strings.ToLower(uses), "actions/checkout")
}

// effectivePermissions returns the resolved permissions for a job.
// Job-level permissions override workflow-level when set.
func effectivePermissions(wf *parser.Workflow, job *parser.Job) map[string]string {
	if len(job.Permissions) > 0 {
		return job.Permissions
	}
	return wf.Permissions
}

// isReadOnlyPermissions returns true if the permissions map only grants read
// access. Returns false if permissions are empty (default is write), if any
// scope has "write" access, or if "_all" is "write-all".
func isReadOnlyPermissions(perms map[string]string) bool {
	if len(perms) == 0 {
		return false // no permissions block = default (broad access)
	}

	// Check for global permission strings.
	if all, ok := perms["_all"]; ok {
		return all == "read-all" || all == "read"
	}

	// Check individual scopes - all must be "read" or "none".
	for _, v := range perms {
		if v == "write" {
			return false
		}
	}
	return true
}

// makeFinding builds a Finding from the engine's loaded rule metadata.
func (e *Engine) makeFinding(ruleID string, wf *parser.Workflow, jobID string, step *parser.Step, evidence string) Finding {
	f := Finding{
		RuleID:   ruleID,
		File:     wf.Path,
		JobID:    jobID,
		Evidence: evidence,
	}

	if step != nil {
		f.StepName = step.Name
		f.LineNumber = step.LineNumber
	}

	if meta, ok := e.rules[ruleID]; ok {
		f.RuleName = meta.Name
		f.Severity = meta.Severity
		f.Description = meta.Description
		f.AttackScenario = meta.AttackScenario
		f.Fix = meta.Fix
		f.References = meta.References
	}

	return f
}

// defaultRuleMetadata returns built-in metadata for all rules so the engine
// works even without YAML rule files.
func defaultRuleMetadata() map[string]*RuleMetadata {
	return map[string]*RuleMetadata{
		"RGS-001": {ID: "RGS-001", Name: "pull_request_target with Fork Code Checkout", Severity: "critical", Group: "injection"},
		"RGS-002": {ID: "RGS-002", Name: "Expression Injection via Untrusted Input", Severity: "high", Group: "injection"},
		"RGS-003": {ID: "RGS-003", Name: "Dynamic Command Construction from Step Outputs", Severity: "high", Group: "injection"},
		"RGS-004": {ID: "RGS-004", Name: "Privileged Trigger with Secrets and No Author Check", Severity: "high", Group: "permissions"},
		"RGS-005": {ID: "RGS-005", Name: "Excessive Permissions on Untrusted Trigger", Severity: "medium", Group: "permissions"},
		"RGS-006": {ID: "RGS-006", Name: "Dangerous Sink in Run Block", Severity: "high", Group: "supply-chain"},
		"RGS-007": {ID: "RGS-007", Name: "Unpinned Third-Party Action", Severity: "medium", Group: "supply-chain"},
		"RGS-008": {ID: "RGS-008", Name: "Secrets Exposure in Run Block", Severity: "medium", Group: "secrets"},
		"RGS-009": {ID: "RGS-009", Name: "Fork Code Execution via Build Tools", Severity: "critical", Group: "injection"},
		"RGS-010": {ID: "RGS-010", Name: "AI Agent Config Poisoning via Fork PR", Severity: "high", Group: "ai-config"},
		"RGS-011": {ID: "RGS-011", Name: "MCP Config Injection via Fork Checkout", Severity: "high", Group: "ai-config"},
		"RGS-012": {ID: "RGS-012", Name: "External Network Access with Secrets Context", Severity: "medium", Group: "secrets"},
		"RGS-014": {ID: "RGS-014", Name: "Expression Injection via workflow_dispatch Input", Severity: "high", Group: "injection"},
		"RGS-015": {ID: "RGS-015", Name: "Actions Runner Debug Logging Enabled", Severity: "medium", Group: "debug"},
		"RGS-016": {ID: "RGS-016", Name: "Unicode Steganography in Workflow File", Severity: "critical", Group: "steganography"},
		"RGS-017": {ID: "RGS-017", Name: "Unicode Steganography in Referenced Script", Severity: "high", Group: "steganography"},
		"RGS-018": {ID: "RGS-018", Name: "Suspicious Payload Execution Pattern", Severity: "high", Group: "steganography"},
		"RGS-019": {ID: "RGS-019", Name: "Step Output Interpolated in run Block", Severity: "medium", Group: "injection"},
	}
}

// ---------------------------------------------------------------------------
// Compiled regex patterns shared across checkers
// ---------------------------------------------------------------------------

var (
	// stepOutputPattern matches ${{ steps.<id>.outputs.<name> }} style expressions.
	stepOutputPattern = regexp.MustCompile(`\$\{\{\s*steps\.\w+\.outputs\.\w+`)

	// gitDiffPattern matches git diff, find, ls commands in run blocks.
	gitDiffPattern = regexp.MustCompile(`(?i)(git\s+diff|git\s+log|find\s+|ls\s+|git\s+show)`)

	// shaPattern matches a 40-character hexadecimal SHA.
	shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

	// executionCommandPattern matches build tool / interpreter invocations.
	executionCommandPattern = regexp.MustCompile(`(?i)\b(go\s+run|go\s+build|go\s+test|make\b|node\s|npm\s|npx\s|python\s|python3\s|pip\s|pip3\s|ruby\s|bash\s|sh\s)`)

	// aiConfigPattern matches AI agent configuration file references.
	aiConfigPattern = regexp.MustCompile(`(?i)(CLAUDE\.md|\.claude/|copilot-instructions\.md|AGENTS\.md|\.github/copilot-instructions)`)

	// mcpConfigPattern matches MCP configuration file references.
	mcpConfigPattern = regexp.MustCompile(`(?i)(\.mcp\.json|mcp-config\.json|mcp_servers\.json|\.cursor/mcp\.json|claude_desktop_config\.json)`)

	// curlWgetPattern matches curl or wget commands.
	curlWgetPattern = regexp.MustCompile(`(?i)\b(curl|wget)\s+`)

	// urlPattern extracts URLs from curl/wget invocations.
	urlPattern = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)

	// dispatchInputPattern matches ${{ github.event.inputs.* }} expressions.
	dispatchInputPattern = regexp.MustCompile(`(?i)github\.event\.inputs\.`)

	// exprPattern matches ${{ ... }} expression syntax in run blocks.
	exprPattern = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

	// sensitivePermissions lists scopes where write access is dangerous.
	sensitivePermissions = []string{
		"contents",
		"packages",
		"deployments",
		"id-token",
		"actions",
		"security-events",
		"pages",
		"pull-requests",
		"issues",
		"statuses",
		"checks",
	}
)

// ---------------------------------------------------------------------------
// RGS-001: pull_request_target with Fork Code Checkout
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS001(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !isCheckoutAction(step.Uses) {
				continue
			}

			prHeadRefs := []string{
				"github.event.pull_request.head.sha",
				"github.event.pull_request.head.ref",
				"github.head_ref",
			}

			// Check with.ref for PR head references
			refVal, hasRef := step.With["ref"]
			if hasRef {
				lower := strings.ToLower(refVal)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						f := e.makeFinding("RGS-001", wf, jobID, step,
							"actions/checkout with ref: "+refVal)
						findings = append(findings, f)
						break
					}
				}
			}

			// Also check all expressions in the step for PR head refs
			if !hasRef {
				for _, expr := range step.Expressions {
					lower := strings.ToLower(expr)
					for _, prRef := range prHeadRefs {
						if strings.Contains(lower, strings.ToLower(prRef)) {
							f := e.makeFinding("RGS-001", wf, jobID, step,
								"actions/checkout expression references PR head: "+expr)
							findings = append(findings, f)
							break
						}
					}
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-002: Expression Injection via Untrusted Input
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS002(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only check expressions in the run block itself, not in env/with
			// (where they are safely assigned to variables).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				if taint.IsTainted(expr, taint.Tier1Sources) {
					f := e.makeFinding("RGS-002", wf, jobID, step,
						"Tainted expression in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-003: Dynamic Command Construction from Step Outputs
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS003(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check for git diff/find/ls patterns in the run block
			if !gitDiffPattern.MatchString(step.Run) {
				continue
			}

			// Check for step output expressions
			if stepOutputPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-003", wf, jobID, step,
					"Run block uses git diff/find/ls and references step outputs: "+
						truncate(step.Run, 200))
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-004: Privileged Trigger with Secrets and No Author Check
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS004(wf *parser.Workflow) []Finding {
	privilegedTriggers := hasCommentTrigger(wf) ||
		hasTrigger(wf, "workflow_run") ||
		hasTrigger(wf, "issue_comment")

	if !privilegedTriggers {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		if hasAuthorCheck(job) {
			continue
		}

		for _, step := range job.Steps {
			if hasSecretsAccess(step, job) {
				f := e.makeFinding("RGS-004", wf, jobID, step,
					"Privileged trigger with secrets access and no author/actor check")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-005: Excessive Permissions on Untrusted Trigger
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS005(wf *parser.Workflow) []Finding {
	untrusted := hasTrigger(wf, "pull_request_target") || hasCommentTrigger(wf)
	if !untrusted {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, scope := range sensitivePermissions {
			perm, ok := job.Permissions[scope]
			if ok && strings.EqualFold(perm, "write") {
				f := e.makeFinding("RGS-005", wf, jobID, nil,
					"Permission '"+scope+": write' on untrusted trigger")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-006: Dangerous Sink in Run Block
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS006(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			found, desc := taint.HasDangerousSink(step.Run)
			if found {
				// Only flag if there are also expressions in the run block
				if len(step.Expressions) > 0 {
					evidence := "Dangerous sink (" + desc + ") with expression injection: " + truncate(step.Run, 200)
					f := e.makeFinding("RGS-006", wf, jobID, step, evidence)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-007: Unpinned Third-Party Action
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS007(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		// Check if this job has read-only permissions (reduces severity).
		perms := effectivePermissions(wf, job)
		readOnly := isReadOnlyPermissions(perms)

		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Skip first-party, local, and Docker container actions
			lower := strings.ToLower(step.Uses)
			if strings.HasPrefix(lower, "actions/") ||
				strings.HasPrefix(lower, "github/") ||
				strings.HasPrefix(lower, "./") ||
				strings.HasPrefix(lower, "docker://") {
				continue
			}

			// Parse the ref from uses (format: owner/repo@ref)
			atIdx := strings.LastIndex(step.Uses, "@")
			if atIdx == -1 {
				// No ref at all — flag it
				f := e.makeFinding("RGS-007", wf, jobID, step,
					"Third-party action with no version pin: "+step.Uses)
				if readOnly {
					f.Severity = "low"
					f.Evidence += " (job has read-only permissions, reducing impact)"
				}
				findings = append(findings, f)
				continue
			}

			ref := step.Uses[atIdx+1:]
			if !shaPattern.MatchString(ref) {
				f := e.makeFinding("RGS-007", wf, jobID, step,
					"Third-party action pinned to mutable ref '"+ref+"': "+step.Uses)
				if readOnly {
					f.Severity = "low"
					f.Evidence += " (job has read-only permissions, reducing impact)"
				}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-008: Secrets Exposure in Run Block
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS008(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only check expressions in the run block itself, not in env/with
			// (where they are safely assigned to variables — the correct pattern).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				lower := strings.ToLower(expr)
				if strings.Contains(lower, "secrets.") || strings.Contains(lower, "github.token") {
					f := e.makeFinding("RGS-008", wf, jobID, step,
						"Secrets/token referenced in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-009: Fork Code Execution via Build Tools
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS009(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	forkCheckout, checkoutStep := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if executionCommandPattern.MatchString(step.Run) {
				evidence := "Fork code checkout"
				if checkoutStep != nil {
					evidence += " at step '" + checkoutStep.Name + "'"
				}
				evidence += " followed by build/exec command: " + truncate(step.Run, 200)

				f := e.makeFinding("RGS-009", wf, jobID, step, evidence)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-010: AI Agent Config Poisoning via Fork PR
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS010(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	forkCheckout, _ := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			// Check run blocks for AI config file references
			if step.Run != "" && aiConfigPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-010", wf, jobID, step,
					"Fork checkout with AI config file reference in run block: "+truncate(step.Run, 200))
				findings = append(findings, f)
			}

			// Check step names for AI config references
			if step.Name != "" && aiConfigPattern.MatchString(step.Name) {
				f := e.makeFinding("RGS-010", wf, jobID, step,
					"Fork checkout with AI config reference in step name: "+step.Name)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-011: MCP Config Injection via Fork Checkout
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS011(wf *parser.Workflow) []Finding {
	forkCheckout, _ := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			// Check run blocks for MCP config file references
			if step.Run != "" && mcpConfigPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-011", wf, jobID, step,
					"Fork checkout with MCP config file reference: "+truncate(step.Run, 200))
				findings = append(findings, f)
			}

			// Check checkout path for MCP config
			if isCheckoutAction(step.Uses) {
				if path, ok := step.With["path"]; ok && mcpConfigPattern.MatchString(path) {
					f := e.makeFinding("RGS-011", wf, jobID, step,
						"Fork checkout into path containing MCP config: "+path)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-012: External Network Access with Secrets Context
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS012(wf *parser.Workflow) []Finding {
	var findings []Finding

	githubDomains := []string{
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"github.io",
		"ghcr.io",
		"pkg.github.com",
	}

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check if step has curl/wget
			if !curlWgetPattern.MatchString(step.Run) {
				continue
			}

			// Check if the step or job has secrets or publishing access
			if !hasSecretsAccess(step, job) {
				continue
			}

			// Extract URLs and check if any are non-GitHub
			urls := urlPattern.FindAllString(step.Run, -1)
			for _, u := range urls {
				isGitHub := false
				for _, ghDomain := range githubDomains {
					if strings.Contains(strings.ToLower(u), ghDomain) {
						isGitHub = true
						break
					}
				}
				if !isGitHub {
					f := e.makeFinding("RGS-012", wf, jobID, step,
						"curl/wget to non-GitHub URL with secrets access: "+u)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-014: Expression Injection via workflow_dispatch Input
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS014(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only flag expressions that appear in the run block itself,
			// not in env/with (where they are safely assigned to variables).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				if dispatchInputPattern.MatchString(expr) {
					f := e.makeFinding("RGS-014", wf, jobID, step,
						"workflow_dispatch input interpolated in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-015: Actions Runner Debug Logging Enabled
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS015(wf *parser.Workflow) []Finding {
	var findings []Finding

	debugVars := []string{"ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"}

	// Check workflow-level env.
	if envRaw, ok := wf.Raw["env"]; ok {
		if envMap, ok := envRaw.(map[string]interface{}); ok {
			for _, dv := range debugVars {
				if val, ok := envMap[dv]; ok {
					if isTrue(val) {
						f := e.makeFinding("RGS-015", wf, "", nil,
							"Debug variable "+dv+" enabled at workflow level")
						findings = append(findings, f)
					}
				}
			}
		}
	}

	// Check job-level and step-level env.
	for jobID, job := range wf.Jobs {
		for _, dv := range debugVars {
			if val, ok := job.Env[dv]; ok {
				if strings.EqualFold(val, "true") {
					f := e.makeFinding("RGS-015", wf, jobID, nil,
						"Debug variable "+dv+" enabled at job level")
					findings = append(findings, f)
				}
			}
		}

		for _, step := range job.Steps {
			for _, dv := range debugVars {
				if val, ok := step.Env[dv]; ok {
					if strings.EqualFold(val, "true") {
						f := e.makeFinding("RGS-015", wf, jobID, step,
							"Debug variable "+dv+" enabled at step level")
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings
}

// isTrue checks if a YAML value represents boolean true.
func isTrue(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true")
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	// Normalize newlines and collapse whitespace for display
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// RGS-016: Unicode Steganography in Workflow File
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS016(wf *parser.Workflow) []Finding {
	data := wf.RawBytes
	if len(data) == 0 {
		return nil
	}

	result := scanBytesForSuspiciousUnicode(data, 3)
	if result == nil {
		return nil
	}

	evidence := formatScanResult(result, " in workflow file")

	f := e.makeFinding("RGS-016", wf, "", nil, evidence)
	f.LineNumber = result.FirstLine
	return []Finding{f}
}

// ---------------------------------------------------------------------------
// RGS-017: Unicode Steganography in Referenced Script
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS017(wf *parser.Workflow) []Finding {
	repoRoot := repoRootFromWorkflowPath(wf.Path)
	if repoRoot == "" {
		return nil
	}

	refFiles := resolveReferencedFiles(wf, repoRoot)
	if len(refFiles) == 0 {
		return nil
	}

	var findings []Finding
	for _, absPath := range refFiles {
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}

		result := scanBytesForSuspiciousUnicode(data, 3)
		if result == nil {
			continue
		}

		// Compute relative path for display.
		relPath := absPath
		if rel, err := filepath.Rel(repoRoot, absPath); err == nil {
			relPath = rel
		}

		evidence := formatScanResult(result,
			fmt.Sprintf(" in referenced file '%s'", relPath))

		f := e.makeFinding("RGS-017", wf, "", nil, evidence)
		f.LineNumber = result.FirstLine
		findings = append(findings, f)
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-018: Suspicious Payload Execution Pattern
// ---------------------------------------------------------------------------

// Built-in payload patterns (technique-based, stable across threat actors).
var payloadPatterns = []struct {
	pattern *regexp.Regexp
	desc    string
}{
	// Existing decode-and-execute patterns
	{regexp.MustCompile(`(?i)eval\s*\(\s*(bytes\.fromhex|bytearray|codecs\.decode|base64\.b64decode)`), "Python eval+decode chain"},
	{regexp.MustCompile(`(?i)\bbase64\s+(--decode|-d)\b.*\|\s*(ba)?sh`), "base64 decode piped to shell"},
	{regexp.MustCompile(`(?i)String\.fromCharCode\s*\(.*\beval\b`), "JS eval of decoded characters"},
	{regexp.MustCompile(`(?i)Buffer\.from\s*\(.*'(hex|base64)'`), "Node.js Buffer decode pattern"},
	{regexp.MustCompile(`(?i)codecs\.decode\s*\(.*'unicode.escape'`), "Python Unicode escape decode"},

	// Reverse shell patterns
	{regexp.MustCompile(`(?i)bash\s+-i\s+>&\s*/dev/tcp/`), "Bash reverse shell via /dev/tcp"},
	{regexp.MustCompile(`(?i)\bnc\s+(-e|--exec)\s+`), "Netcat reverse shell"},
	{regexp.MustCompile(`(?i)\bmkfifo\b.*\b(nc|ncat|netcat)\b`), "Named pipe reverse shell"},
	{regexp.MustCompile(`(?i)\bsocat\b.*\bexec\b`), "Socat reverse shell"},

	// Curl/wget piped to shell
	{regexp.MustCompile(`(?i)\bcurl\b[^|;]*\|\s*(ba)?sh`), "curl piped to shell"},
	{regexp.MustCompile(`(?i)\bwget\b[^|;]*-O\s*-[^|;]*\|\s*(ba)?sh`), "wget piped to shell"},
	{regexp.MustCompile(`(?i)\bcurl\b[^|;]*\|\s*python`), "curl piped to Python interpreter"},
	{regexp.MustCompile(`(?i)\bwget\b[^|;]*\|\s*python`), "wget piped to Python interpreter"},

	// PowerShell encoded/obfuscated commands
	{regexp.MustCompile(`(?i)powershell\b.*-(enc|encodedcommand)\s+`), "PowerShell encoded command"},
	{regexp.MustCompile(`(?i)\bpwsh\b.*-(enc|encodedcommand)\s+`), "pwsh encoded command"},
	{regexp.MustCompile(`(?i)\bIEX\s*\(\s*(New-Object|Invoke-WebRequest|iwr|wget)`), "PowerShell download-and-execute"},

	// Python exec with compression/encoding
	{regexp.MustCompile(`(?i)\bexec\s*\(\s*compile\s*\(`), "Python exec(compile(...))"},
	{regexp.MustCompile(`(?i)\bexec\s*\(\s*zlib\.decompress\s*\(`), "Python exec(zlib.decompress(...))"},
	{regexp.MustCompile(`(?i)__import__\s*\(\s*['"]zlib['"]\s*\)\.decompress`), "Python dynamic zlib import and decompress"},
	{regexp.MustCompile(`(?i)\bexec\s*\(\s*marshal\.loads\s*\(`), "Python exec(marshal.loads(...))"},

	// Environment variable exfiltration
	{regexp.MustCompile(`(?i)\b(env|printenv|set)\b[^|;]*\|\s*(curl|wget|nc|ncat)\b`), "Environment variable exfiltration"},
	{regexp.MustCompile(`(?i)\b(GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|NPM_TOKEN)\b.*\b(curl|wget|nc)\b`), "Secret token exfiltration attempt"},

	// Hex decode execution
	{regexp.MustCompile(`(?i)\bxxd\s+-r\s+-p\b.*\|\s*(ba)?sh`), "Hex decode piped to shell"},
	{regexp.MustCompile(`(?i)\bprintf\b.*\\\\x[0-9a-f].*\|\s*(ba)?sh`), "Printf hex escape piped to shell"},
	{regexp.MustCompile(`(?i)\bpython3?\s+-c\s+.*\\x[0-9a-f]`), "Python hex string execution"},

	// Ruby/Perl eval patterns
	{regexp.MustCompile(`(?i)\bruby\s+-e\s+.*\beval\b`), "Ruby eval execution"},
	{regexp.MustCompile(`(?i)\bperl\s+-e\s+.*\beval\s+(pack|unpack)\b`), "Perl eval pack/unpack"},

	// Suspicious file operations in CI
	{regexp.MustCompile(`(?i)\bchmod\s+\+x\b.*(/tmp|/dev/shm|/var/tmp)`), "Executable staged in temp directory"},
	{regexp.MustCompile(`(?i)\bcrontab\b.*-[li]?\s*<<`), "Crontab injection via heredoc"},
}

func (e *Engine) checkRGS018(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check built-in payload patterns.
			for _, pp := range payloadPatterns {
				if pp.pattern.MatchString(step.Run) {
					evidence := fmt.Sprintf("Dangerous pattern: %s | Run block: %s",
						pp.desc, truncate(step.Run, 200))
					f := e.makeFinding("RGS-018", wf, jobID, step, evidence)
					findings = append(findings, f)
				}
			}

			// Check loaded threat signatures (IOCs from signatures.yaml).
			for _, sig := range e.signatures {
				if sig.compiled != nil && sig.compiled.MatchString(step.Run) {
					evidence := fmt.Sprintf("Matched threat signature: %s (%s, %s) | Run block: %s",
						sig.Description, sig.ThreatActor, sig.ID, truncate(step.Run, 200))
					f := e.makeFinding("RGS-018", wf, jobID, step, evidence)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-019: Step Output Interpolated in run Block
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS019(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			matches := stepOutputPattern.FindAllString(step.Run, -1)
			for _, match := range matches {
				f := e.makeFinding("RGS-019", wf, jobID, step,
					"Step output interpolated in run block: "+match+"}}")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

