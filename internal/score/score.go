package score

import (
	"fmt"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/v3/internal/rules"
)

// Score represents a CI/CD security score for a scanned repository.
type Score struct {
	Total   int    // 0-100
	Grade   string // A, B, C, D, F
	Pinning Category
	Permissions Category
	Injection Category
	Triggers Category
	IOCs    Category
}

// Category represents one dimension of the security score.
type Category struct {
	Points  int    // 0-10
	MaxPts  int    // always 10
	Detail  string // human-readable detail
}

// Calculate computes a Runner Guard Score from scan findings.
func Calculate(findings []rules.Finding) Score {
	s := Score{
		Pinning:     Category{MaxPts: 10, Points: 10},
		Permissions: Category{MaxPts: 10, Points: 10},
		Injection:   Category{MaxPts: 10, Points: 10},
		Triggers:    Category{MaxPts: 10, Points: 10},
		IOCs:        Category{MaxPts: 10, Points: 10},
	}

	// Count findings by category.
	var pinCount, permCount, injCount, trigCount, iocCount int

	for _, f := range findings {
		switch f.RuleID {
		case "RGS-007": // unpinned actions
			pinCount++
		case "RGS-008", "RGS-005": // secrets in run blocks, excessive permissions
			permCount++
		case "RGS-001", "RGS-002", "RGS-003", "RGS-014": // expression/script injection
			injCount++
		case "RGS-004", "RGS-009": // dangerous triggers, fork code exec
			trigCount++
		case "RGS-016", "RGS-017", "RGS-018": // unicode steg, IOC matches
			iocCount++
		case "RGS-006", "RGS-012": // curl-pipe-bash, network exfil
			permCount++
		case "RGS-010", "RGS-011": // AI config injection
			trigCount++
		case "RGS-015": // debug logging
			permCount++
		case "RGS-019": // step output in run
			injCount++
		}
	}

	// Deduct points per finding. More severe deductions for more findings.
	s.Pinning = deduct(s.Pinning, pinCount, "unpinned action(s)")
	s.Permissions = deduct(s.Permissions, permCount, "permission/secret issue(s)")
	s.Injection = deduct(s.Injection, injCount, "injection risk(s)")
	s.Triggers = deduct(s.Triggers, trigCount, "unsafe trigger(s)")
	s.IOCs = deduct(s.IOCs, iocCount, "IOC match(es)")

	// Total is weighted sum. Each category contributes equally (20% each).
	s.Total = (s.Pinning.Points + s.Permissions.Points + s.Injection.Points +
		s.Triggers.Points + s.IOCs.Points) * 2 // *2 because 5 categories * 10 max = 50, scale to 100

	// Cap at 0-100.
	if s.Total < 0 {
		s.Total = 0
	}
	if s.Total > 100 {
		s.Total = 100
	}

	// Grade.
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

	return s
}

// deduct reduces points based on finding count. First finding costs 3 points,
// each additional costs 1 more, minimum 0.
func deduct(cat Category, count int, label string) Category {
	if count == 0 {
		cat.Detail = "no issues detected"
		return cat
	}

	penalty := 0
	if count >= 1 {
		penalty = 3 // first finding is a 3-point hit
	}
	if count >= 2 {
		penalty += (count - 1) // each additional finding is 1 more point
	}

	cat.Points -= penalty
	if cat.Points < 0 {
		cat.Points = 0
	}

	cat.Detail = fmt.Sprintf("%d %s", count, label)
	return cat
}

// String returns the formatted score output for console display.
func (s Score) String() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\nRunner Guard Score: %d/100 (%s)\n", s.Total, s.Grade))
	b.WriteString("──────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Pinning:      %d/%d  (%s)\n", s.Pinning.Points, s.Pinning.MaxPts, s.Pinning.Detail))
	b.WriteString(fmt.Sprintf("  Permissions:  %d/%d  (%s)\n", s.Permissions.Points, s.Permissions.MaxPts, s.Permissions.Detail))
	b.WriteString(fmt.Sprintf("  Injection:    %d/%d  (%s)\n", s.Injection.Points, s.Injection.MaxPts, s.Injection.Detail))
	b.WriteString(fmt.Sprintf("  Triggers:     %d/%d  (%s)\n", s.Triggers.Points, s.Triggers.MaxPts, s.Triggers.Detail))
	b.WriteString(fmt.Sprintf("  IOCs:         %d/%d  (%s)\n", s.IOCs.Points, s.IOCs.MaxPts, s.IOCs.Detail))

	return b.String()
}
