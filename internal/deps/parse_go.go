package deps

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseGoSum parses a go.sum file and returns all dependencies.
// go.sum format: module version hash
// e.g., github.com/fatih/color v1.16.0 h1:abc123...
func ParseGoSum(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]bool) // dedup module@version
	var result []Dependency

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		module := parts[0]
		version := parts[1]

		// go.sum has two entries per module: one for go.mod, one for the zip.
		// The /go.mod suffix appears on the version for the go.mod hash.
		version = strings.TrimSuffix(version, "/go.mod")

		// Strip the v prefix for comparison (our DB stores without v)
		cleanVersion := strings.TrimPrefix(version, "v")

		key := module + "@" + cleanVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		result = append(result, Dependency{
			Name:      module,
			Version:   cleanVersion,
			Ecosystem: "go",
		})
	}

	return result, scanner.Err()
}
