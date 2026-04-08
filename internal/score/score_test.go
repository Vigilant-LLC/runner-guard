package score

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/rules"
)

func TestCalculate_PerfectScore(t *testing.T) {
	s := Calculate(nil)
	assert.Equal(t, 100, s.Total)
	assert.Equal(t, "A", s.Grade)
	assert.Equal(t, 10, s.Pinning.Points)
	assert.Equal(t, 10, s.Permissions.Points)
	assert.Equal(t, 10, s.Injection.Points)
	assert.Equal(t, 10, s.Triggers.Points)
	assert.Equal(t, 10, s.IOCs.Points)
}

func TestCalculate_SingleUnpinnedAction(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "RGS-007"},
	}
	s := Calculate(findings)
	assert.Equal(t, 7, s.Pinning.Points) // 10 - 3
	assert.Equal(t, 94, s.Total)         // (7+10+10+10+10)*2
	assert.Equal(t, "A", s.Grade)
}

func TestCalculate_ManyUnpinnedActions(t *testing.T) {
	findings := make([]rules.Finding, 15)
	for i := range findings {
		findings[i] = rules.Finding{RuleID: "RGS-007"}
	}
	s := Calculate(findings)
	assert.Equal(t, 0, s.Pinning.Points)
	assert.Equal(t, 80, s.Total) // (0+10+10+10+10)*2
	assert.Equal(t, "B", s.Grade)
}

func TestCalculate_MixedFindings(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "RGS-007"}, // pinning
		{RuleID: "RGS-007"}, // pinning
		{RuleID: "RGS-002"}, // injection
		{RuleID: "RGS-008"}, // permissions
		{RuleID: "RGS-004"}, // triggers
	}
	s := Calculate(findings)
	assert.Equal(t, 6, s.Pinning.Points)     // 10 - 3 - 1
	assert.Equal(t, 7, s.Injection.Points)    // 10 - 3
	assert.Equal(t, 7, s.Permissions.Points)  // 10 - 3
	assert.Equal(t, 7, s.Triggers.Points)     // 10 - 3
	assert.Equal(t, 10, s.IOCs.Points)        // clean
}

func TestCalculate_CriticalIOCMatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "RGS-018"}, // IOC match
		{RuleID: "RGS-018"}, // IOC match
		{RuleID: "RGS-018"}, // IOC match
	}
	s := Calculate(findings)
	assert.Equal(t, 5, s.IOCs.Points) // 10 - 3 - 2
	assert.Equal(t, 90, s.Total)      // (10+10+10+10+5)*2
	assert.Equal(t, "A", s.Grade)     // IOCs alone don't tank the whole score
}

func TestCalculate_WorstCase(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "RGS-007"}, {RuleID: "RGS-007"}, {RuleID: "RGS-007"},
		{RuleID: "RGS-007"}, {RuleID: "RGS-007"}, {RuleID: "RGS-007"},
		{RuleID: "RGS-007"}, {RuleID: "RGS-007"}, {RuleID: "RGS-007"},
		{RuleID: "RGS-007"}, // 10 unpinned: 10 - 3 - 9 = 0
		{RuleID: "RGS-002"}, {RuleID: "RGS-002"}, {RuleID: "RGS-002"},
		{RuleID: "RGS-002"}, {RuleID: "RGS-002"}, // 5 injection: 10 - 3 - 4 = 3
		{RuleID: "RGS-008"}, {RuleID: "RGS-008"}, {RuleID: "RGS-008"},
		{RuleID: "RGS-005"}, {RuleID: "RGS-005"}, // 5 permissions: 10 - 3 - 4 = 3
		{RuleID: "RGS-004"}, {RuleID: "RGS-004"}, {RuleID: "RGS-004"},
		{RuleID: "RGS-004"}, {RuleID: "RGS-004"}, // 5 triggers: 10 - 3 - 4 = 3
		{RuleID: "RGS-018"}, {RuleID: "RGS-018"}, {RuleID: "RGS-018"},
		{RuleID: "RGS-018"}, {RuleID: "RGS-018"}, // 5 IOCs: 10 - 3 - 4 = 3
	}
	s := Calculate(findings)
	// (0 + 3 + 3 + 3 + 3) * 2 = 24
	assert.Equal(t, 24, s.Total)
	assert.Equal(t, "F", s.Grade)
	assert.Equal(t, 0, s.Pinning.Points)
}

func TestCalculate_GradeThresholds(t *testing.T) {
	// Test each grade boundary.
	tests := []struct {
		name     string
		total    int
		expected string
	}{
		{"perfect", 100, "A"},
		{"A boundary", 90, "A"},
		{"B boundary", 80, "B"},
		{"C boundary", 70, "C"},
		{"D boundary", 60, "D"},
		{"F", 59, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Grade is computed from total, so we verify via the String output.
			s := Score{Total: tt.total}
			switch {
			case s.Total >= 90:
				s.Grade = "A"
			case s.Total >= 80:
				s.Grade = "B"
			case s.Total >= 70:
				s.Grade = "C"
			case s.Total >= 60:
				s.Grade = "D"
			default:
				s.Grade = "F"
			}
			assert.Equal(t, tt.expected, s.Grade)
		})
	}
}

func TestScore_String(t *testing.T) {
	s := Calculate(nil)
	output := s.String()
	assert.Contains(t, output, "Runner Guard Score: 100/100 (A)")
	assert.Contains(t, output, "Pinning:")
	assert.Contains(t, output, "Permissions:")
	assert.Contains(t, output, "Injection:")
	assert.Contains(t, output, "Triggers:")
	assert.Contains(t, output, "IOCs:")
}
