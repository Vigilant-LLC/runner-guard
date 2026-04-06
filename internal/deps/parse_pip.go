package deps

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseRequirementsTxt parses a requirements.txt file and returns all dependencies.
// Handles formats: package==version, package>=version, package~=version, package[extras]==version
func ParseRequirementsTxt(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	var result []Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Remove extras like [security]
		if idx := strings.Index(line, "["); idx >= 0 {
			end := strings.Index(line, "]")
			if end > idx {
				line = line[:idx] + line[end+1:]
			}
		}

		// Parse version specifier
		name, version := parseRequirement(line)
		if name == "" || version == "" {
			continue
		}

		result = append(result, Dependency{
			Name:      strings.ToLower(name), // PyPI is case-insensitive
			Version:   version,
			Ecosystem: "pypi",
		})
	}

	return result, scanner.Err()
}

// parseRequirement extracts name and pinned version from a requirement line.
// Returns empty strings if the version is not pinned (==).
func parseRequirement(line string) (string, string) {
	// Only match exact pins (==) for compromised package checking
	if idx := strings.Index(line, "=="); idx >= 0 {
		name := strings.TrimSpace(line[:idx])
		version := strings.TrimSpace(line[idx+2:])
		// Remove any environment markers after ;
		if semi := strings.Index(version, ";"); semi >= 0 {
			version = strings.TrimSpace(version[:semi])
		}
		return name, version
	}
	return "", ""
}
