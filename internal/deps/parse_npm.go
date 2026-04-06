package deps

import (
	"encoding/json"
	"fmt"
	"os"
)

// packageLockJSON represents the structure of package-lock.json (v2/v3).
type packageLockJSON struct {
	Packages map[string]packageLockEntry `json:"packages"`
	// v1 format
	Dependencies map[string]packageLockV1Entry `json:"dependencies"`
}

type packageLockEntry struct {
	Version string `json:"version"`
}

type packageLockV1Entry struct {
	Version string `json:"version"`
}

// ParsePackageLock parses a package-lock.json file and returns all dependencies.
func ParsePackageLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var result []Dependency

	// v2/v3 format: packages map with "node_modules/name" keys
	if len(lock.Packages) > 0 {
		for key, entry := range lock.Packages {
			if key == "" {
				continue // skip the root entry
			}
			name := extractNpmName(key)
			if name == "" || entry.Version == "" {
				continue
			}
			result = append(result, Dependency{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: "npm",
			})
		}
		return result, nil
	}

	// v1 format: flat dependencies map
	for name, entry := range lock.Dependencies {
		if entry.Version == "" {
			continue
		}
		result = append(result, Dependency{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: "npm",
		})
	}

	return result, nil
}

// extractNpmName extracts the package name from a node_modules path.
func extractNpmName(key string) string {
	const prefix = "node_modules/"
	idx := len(key) - 1
	for idx >= 0 {
		for i := idx; i >= 0; i-- {
			if i+len(prefix) <= len(key) && key[i:i+len(prefix)] == prefix {
				return key[i+len(prefix):]
			}
		}
		break
	}
	return key
}
