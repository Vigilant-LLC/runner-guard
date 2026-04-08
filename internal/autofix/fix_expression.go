package autofix

import (
	"github.com/Vigilant-LLC/runner-guard/v3/internal/taint"
)

// FixExpressionInjection extracts Tier-1 untrusted expressions from run: blocks
// into env: variable mappings. Fixes RGS-002.
func FixExpressionInjection(dir string, dryRun bool) ([]FixResult, error) {
	matcher := func(expr string) bool {
		return taint.IsTainted(expr, taint.Tier1Sources)
	}
	return ExtractExpressionsToEnv(dir, matcher, "RGS-002", dryRun)
}
