package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Vigilant-LLC/runner-guard/internal/parser"
)

// ---------------------------------------------------------------------------
// Unicode steganography detection
// ---------------------------------------------------------------------------

// UnicodeHit records a single suspicious invisible Unicode character found
// during a byte-level scan.
type UnicodeHit struct {
	Offset    int    // byte offset in the file
	Line      int    // 1-based line number
	Column    int    // 1-based column (rune count from start of line)
	Codepoint rune   // the suspicious code point
	Category  string // human-readable category name
}

// isSuspiciousRune returns true and a category name if the rune is an
// invisible Unicode character that could be used for steganography.
func isSuspiciousRune(r rune, byteOffset int) (bool, string) {
	switch {
	// Zero-width and directional formatting
	case r >= 0x200B && r <= 0x200F:
		names := map[rune]string{
			0x200B: "zero-width space",
			0x200C: "zero-width non-joiner",
			0x200D: "zero-width joiner",
			0x200E: "left-to-right mark",
			0x200F: "right-to-left mark",
		}
		if name, ok := names[r]; ok {
			return true, name
		}
		return true, "zero-width/directional"

	// Line/paragraph separators
	case r == 0x2028:
		return true, "line separator"
	case r == 0x2029:
		return true, "paragraph separator"

	// Invisible operators
	case r >= 0x2060 && r <= 0x2064:
		return true, "invisible operator"

	// Variation selectors (GlassWorm's primary vector)
	case r >= 0xFE00 && r <= 0xFE0F:
		return true, "variation selector"

	// BOM — only suspicious when NOT at byte position 0
	case r == 0xFEFF && byteOffset > 0:
		return true, "byte order mark (not at file start)"

	// Supplementary variation selectors
	case r >= 0xE0100 && r <= 0xE01EF:
		return true, "supplementary variation selector"

	// Tag characters (invisible text encoding)
	case r >= 0xE0001 && r <= 0xE007F:
		return true, "tag character"
	}

	return false, ""
}

// ScanResult holds the aggregated results of a Unicode steganography scan.
type ScanResult struct {
	Hits          []UnicodeHit
	TotalCount    int
	CategoryMap   map[string]int // category -> count
	AffectedLines []int          // sorted, deduplicated line numbers
	FirstLine     int
	FirstColumn   int
}

// scanBytesForSuspiciousUnicode scans raw bytes for invisible Unicode
// characters that could indicate steganographic payloads. Returns nil
// if the count is below the threshold (default 3).
func scanBytesForSuspiciousUnicode(data []byte, threshold int) *ScanResult {
	if threshold <= 0 {
		threshold = 3
	}

	var hits []UnicodeHit
	categoryMap := make(map[string]int)
	lineSet := make(map[int]bool)

	line := 1
	col := 1
	offset := 0

	for offset < len(data) {
		r, size := utf8.DecodeRune(data[offset:])
		if r == utf8.RuneError && size <= 1 {
			offset++
			col++
			continue
		}

		if suspicious, category := isSuspiciousRune(r, offset); suspicious {
			hit := UnicodeHit{
				Offset:    offset,
				Line:      line,
				Column:    col,
				Codepoint: r,
				Category:  category,
			}
			hits = append(hits, hit)
			categoryMap[category]++
			lineSet[line] = true
		}

		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		offset += size
	}

	if len(hits) < threshold {
		return nil
	}

	// Collect and sort affected lines.
	var affectedLines []int
	for l := range lineSet {
		affectedLines = append(affectedLines, l)
	}
	for i := 0; i < len(affectedLines); i++ {
		for j := i + 1; j < len(affectedLines); j++ {
			if affectedLines[j] < affectedLines[i] {
				affectedLines[i], affectedLines[j] = affectedLines[j], affectedLines[i]
			}
		}
	}

	return &ScanResult{
		Hits:          hits,
		TotalCount:    len(hits),
		CategoryMap:   categoryMap,
		AffectedLines: affectedLines,
		FirstLine:     hits[0].Line,
		FirstColumn:   hits[0].Column,
	}
}

// formatScanResult produces a human-readable evidence string from a ScanResult.
func formatScanResult(result *ScanResult, context string) string {
	if result == nil {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d invisible Unicode characters detected%s", result.TotalCount, context)

	// Character breakdown.
	b.WriteString(" | Breakdown: ")
	first := true
	for category, count := range result.CategoryMap {
		if !first {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d× %s", count, category)
		first = false
	}

	// Location info.
	fmt.Fprintf(&b, " | First at line %d, col %d", result.FirstLine, result.FirstColumn)
	if len(result.AffectedLines) > 0 {
		b.WriteString(" | Affected lines: ")
		for i, l := range result.AffectedLines {
			if i > 0 {
				b.WriteString(", ")
			}
			if i >= 10 {
				fmt.Fprintf(&b, "... (%d more)", len(result.AffectedLines)-i)
				break
			}
			fmt.Fprintf(&b, "%d", l)
		}
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// Referenced file resolution for RGS-017
// ---------------------------------------------------------------------------

// fileRefPattern pairs a regex with the files it implies should be checked.
type fileRefPattern struct {
	pattern *regexp.Regexp
	files   []string // static file paths to check (nil = use capture group)
}

// fileRefPatterns maps command patterns to the files they typically execute.
var fileRefPatterns = []fileRefPattern{
	{regexp.MustCompile(`(?i)\bpip3?\s+install\s+\.`), []string{"setup.py", "setup.cfg", "pyproject.toml"}},
	{regexp.MustCompile(`(?i)\bpython3?\s+setup\.py\b`), []string{"setup.py"}},
	{regexp.MustCompile(`(?i)\bnpm\s+(install|ci|run|test)\b`), []string{"package.json"}},
	{regexp.MustCompile(`(?i)\bnode\s+(\S+\.js)\b`), nil},
	{regexp.MustCompile(`(?i)\bbash\s+(\S+\.sh)\b`), nil},
	{regexp.MustCompile(`(?i)\bsh\s+(\S+\.sh)\b`), nil},
	{regexp.MustCompile(`(?i)\bpython3?\s+(\S+\.py)\b`), nil},
	{regexp.MustCompile(`(?i)\bmake\b`), []string{"Makefile", "makefile", "GNUmakefile"}},
	{regexp.MustCompile(`(?i)\bdocker\s+build\b`), []string{"Dockerfile", "dockerfile"}},
	{regexp.MustCompile(`(?i)\bgo\s+(run|build|test)\b`), []string{"main.go"}},
}

// resolveReferencedFiles extracts file paths referenced by workflow run blocks
// and local action uses, resolves them relative to the repo root, and returns
// absolute paths that actually exist on disk. Symlinks are not followed.
func resolveReferencedFiles(wf *parser.Workflow, repoRoot string) []string {
	if repoRoot == "" {
		return nil
	}

	seen := make(map[string]bool)
	var result []string

	addIfExists := func(relPath string) {
		absPath := filepath.Join(repoRoot, relPath)
		if seen[absPath] {
			return
		}
		seen[absPath] = true

		info, err := os.Lstat(absPath)
		if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return
		}
		result = append(result, absPath)
	}

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			// Check run blocks for file references.
			if step.Run != "" {
				for _, pat := range fileRefPatterns {
					matches := pat.pattern.FindStringSubmatch(step.Run)
					if matches == nil {
						continue
					}
					if pat.files != nil {
						for _, f := range pat.files {
							addIfExists(f)
						}
					} else if len(matches) > 1 && matches[1] != "" {
						addIfExists(matches[1])
					}
				}
			}

			// Check uses for local actions (./path).
			if strings.HasPrefix(step.Uses, "./") {
				actionDir := strings.Split(step.Uses, "@")[0]
				addIfExists(filepath.Join(actionDir, "action.yml"))
				addIfExists(filepath.Join(actionDir, "action.yaml"))
			}
		}
	}

	return result
}

// repoRootFromWorkflowPath derives the repository root from a workflow file
// path by walking up from .github/workflows/.
func repoRootFromWorkflowPath(wfPath string) string {
	dir := filepath.Dir(wfPath)
	for dir != "" && dir != "/" && dir != "." {
		base := filepath.Base(dir)
		if base == "workflows" {
			parent := filepath.Dir(dir)
			if filepath.Base(parent) == ".github" {
				return filepath.Dir(parent)
			}
		}
		dir = filepath.Dir(dir)
	}
	return ""
}
