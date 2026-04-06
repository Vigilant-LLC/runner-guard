package deps

import (
	"os"
	"path/filepath"
)

// LockFile represents a discovered lock file with its parser.
type LockFile struct {
	Path      string
	Ecosystem string
	Parse     func() ([]Dependency, error)
}

// DiscoverLockFiles walks a directory and returns all recognized lock files.
func DiscoverLockFiles(dir string) ([]LockFile, error) {
	var lockFiles []LockFile

	// Known lock file patterns and their parsers.
	patterns := map[string]struct {
		ecosystem string
		parser    func(path string) ([]Dependency, error)
	}{
		"package-lock.json": {"npm", ParsePackageLock},
		"requirements.txt":  {"pypi", ParseRequirementsTxt},
		"go.sum":            {"go", ParseGoSum},
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable dirs
		}
		if info.IsDir() {
			// Skip common non-project directories.
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" || name == "__pycache__" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}

		if p, ok := patterns[info.Name()]; ok {
			filePath := path // capture for closure
			lockFiles = append(lockFiles, LockFile{
				Path:      filePath,
				Ecosystem: p.ecosystem,
				Parse: func() ([]Dependency, error) {
					return p.parser(filePath)
				},
			})
		}

		return nil
	})

	return lockFiles, err
}
