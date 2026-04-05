package batch

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/Vigilant-LLC/runner-guard/internal/score"
)

// WriteConsoleReport writes a human-readable batch scan report.
func WriteConsoleReport(w io.Writer, result *Result, noColor bool, totalDuration time.Duration) {
	color.NoColor = noColor

	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	separator := strings.Repeat("\u2501", 70)

	fmt.Fprintln(w, separator)
	fmt.Fprintf(w, "%s\n", boldWhite("Runner Guard Batch Scan Results"))
	fmt.Fprintf(w, "%s repos scanned in %s\n", boldWhite(fmt.Sprintf("%d", len(result.Results))), totalDuration)
	fmt.Fprintln(w, separator)
	fmt.Fprintln(w)

	// Summary table header.
	fmt.Fprintf(w, "%-50s %6s %6s %5s\n", boldWhite("Repository"), boldWhite("Score"), boldWhite("Grade"), boldWhite("Issues"))
	fmt.Fprintf(w, "%-50s %6s %6s %5s\n", strings.Repeat("-", 50), "------", "-----", "------")

	totalFindings := 0
	totalErrors := 0
	for _, rr := range result.Results {
		if rr.Error != "" {
			fmt.Fprintf(w, "%-50s %6s %6s %5s\n", rr.Repo, red("ERR"), "-", rr.Error)
			totalErrors++
			continue
		}

		findings := len(rr.Findings)
		totalFindings += findings

		gradeColor := green
		switch {
		case rr.Score.Total < 60:
			gradeColor = red
		case rr.Score.Total < 80:
			gradeColor = yellow
		case rr.Score.Total < 90:
			gradeColor = cyan
		}

		issueStr := fmt.Sprintf("%d", findings)
		if findings == 0 {
			issueStr = green("0")
		}

		fmt.Fprintf(w, "%-50s %6s %6s %5s\n",
			rr.Repo,
			gradeColor(fmt.Sprintf("%d", rr.Score.Total)),
			gradeColor(rr.Score.Grade),
			issueStr,
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, separator)
	fmt.Fprintf(w, "Total: %d findings across %d repos", totalFindings, len(result.Results)-totalErrors)
	if totalErrors > 0 {
		fmt.Fprintf(w, " (%d errors)", totalErrors)
	}
	fmt.Fprintln(w)

	// Severity breakdown.
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, rr := range result.Results {
		for _, f := range rr.Findings {
			counts[strings.ToLower(f.Severity)]++
		}
	}
	fmt.Fprintf(w, "Severity: %s Critical | %s High | %s Medium | %s Low\n",
		red(fmt.Sprintf("%d", counts["critical"])),
		red(fmt.Sprintf("%d", counts["high"])),
		yellow(fmt.Sprintf("%d", counts["medium"])),
		cyan(fmt.Sprintf("%d", counts["low"])),
	)
	fmt.Fprintln(w, separator)

	// Per-repo details for repos with findings.
	for _, rr := range result.Results {
		if len(rr.Findings) == 0 || rr.Error != "" {
			continue
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s (%d findings, score %s)\n",
			boldWhite(">>"), boldWhite(rr.Repo), len(rr.Findings),
			gradeString(rr.Score),
		)
		fmt.Fprintln(w, gray(strings.Repeat("-", 60)))

		for _, f := range rr.Findings {
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

// WriteJSONReport writes a JSON batch scan report.
func WriteJSONReport(w io.Writer, result *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result.Results)
}

// WriteCSVReport writes a CSV summary of the batch scan.
func WriteCSVReport(w io.Writer, result *Result) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	cw.Write([]string{"Repository", "Score", "Grade", "Findings", "Critical", "High", "Medium", "Low", "Duration", "Error"})

	for _, rr := range result.Results {
		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		for _, f := range rr.Findings {
			counts[strings.ToLower(f.Severity)]++
		}
		cw.Write([]string{
			rr.Repo,
			fmt.Sprintf("%d", rr.Score.Total),
			rr.Score.Grade,
			fmt.Sprintf("%d", len(rr.Findings)),
			fmt.Sprintf("%d", counts["critical"]),
			fmt.Sprintf("%d", counts["high"]),
			fmt.Sprintf("%d", counts["medium"]),
			fmt.Sprintf("%d", counts["low"]),
			rr.Duration.String(),
			rr.Error,
		})
	}
	return nil
}

func gradeString(s score.Score) string {
	return fmt.Sprintf("%d/100 %s", s.Total, s.Grade)
}
