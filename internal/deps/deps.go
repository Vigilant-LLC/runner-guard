package deps

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Dependency represents a single installed dependency.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // npm, pypi, go
	LockFile  string `json:"lock_file"` // which lock file it came from
}

// CompromisedPackage represents a known bad package version.
type CompromisedPackage struct {
	Name        string   `yaml:"name" json:"name"`
	Ecosystem   string   `yaml:"ecosystem" json:"ecosystem"`
	Versions    []string `yaml:"versions" json:"versions"`
	Campaign    string   `yaml:"campaign" json:"campaign"`
	Date        string   `yaml:"date" json:"date"`
	Severity    string   `yaml:"severity" json:"severity"`
	Description string   `yaml:"description" json:"description"`
	References  []string `yaml:"references,omitempty" json:"references,omitempty"`
}

// Finding represents a matched compromised dependency.
type Finding struct {
	Package     CompromisedPackage `json:"package"`
	Installed   Dependency         `json:"installed"`
	Description string             `json:"description"`
}

// Database holds the loaded compromised packages.
type Database struct {
	Packages []CompromisedPackage
}

// dbFile is the YAML structure for the compromised-packages.yaml file.
type dbFile struct {
	Packages []CompromisedPackage `yaml:"packages"`
}

// LoadDatabase loads the compromised packages database from the embedded FS.
func LoadDatabase(rulesFS fs.FS) (*Database, error) {
	data, err := fs.ReadFile(rulesFS, "rules/compromised-packages.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading compromised packages DB: %w", err)
	}

	var db dbFile
	if err := yaml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parsing compromised packages DB: %w", err)
	}

	return &Database{Packages: db.Packages}, nil
}

// Check tests a dependency against the database. Returns a Finding if compromised.
func (db *Database) Check(dep Dependency) *Finding {
	for _, pkg := range db.Packages {
		if !strings.EqualFold(pkg.Name, dep.Name) {
			continue
		}
		if pkg.Ecosystem != dep.Ecosystem {
			continue
		}
		for _, v := range pkg.Versions {
			if v == "*" || v == dep.Version {
				return &Finding{
					Package:   pkg,
					Installed: dep,
					Description: fmt.Sprintf("Compromised version %s@%s detected (%s campaign: %s)",
						dep.Name, dep.Version, pkg.Severity, pkg.Campaign),
				}
			}
		}
	}
	return nil
}

// CheckDependencies scans a directory for lock files and checks all dependencies
// against the compromised packages database.
func CheckDependencies(dir string, db *Database) ([]Finding, error) {
	var allFindings []Finding

	lockFiles, err := DiscoverLockFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("discovering lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil, nil
	}

	for _, lf := range lockFiles {
		relPath, _ := filepath.Rel(dir, lf.Path)
		if relPath == "" {
			relPath = lf.Path
		}

		deps, err := lf.Parse()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", relPath, err)
			continue
		}

		for _, dep := range deps {
			dep.LockFile = relPath
			if finding := db.Check(dep); finding != nil {
				allFindings = append(allFindings, *finding)
			}
		}
	}

	return allFindings, nil
}
