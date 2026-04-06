package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabase_Check_Match(t *testing.T) {
	db := &Database{
		Packages: []CompromisedPackage{
			{Name: "axios", Ecosystem: "npm", Versions: []string{"1.14.1", "0.30.4"}, Campaign: "UNC1069", Severity: "critical"},
		},
	}

	finding := db.Check(Dependency{Name: "axios", Version: "1.14.1", Ecosystem: "npm"})
	require.NotNil(t, finding)
	assert.Equal(t, "UNC1069", finding.Package.Campaign)
	assert.Contains(t, finding.Description, "1.14.1")
}

func TestDatabase_Check_NoMatch_DifferentVersion(t *testing.T) {
	db := &Database{
		Packages: []CompromisedPackage{
			{Name: "axios", Ecosystem: "npm", Versions: []string{"1.14.1"}, Campaign: "UNC1069", Severity: "critical"},
		},
	}

	finding := db.Check(Dependency{Name: "axios", Version: "1.7.2", Ecosystem: "npm"})
	assert.Nil(t, finding)
}

func TestDatabase_Check_NoMatch_DifferentEcosystem(t *testing.T) {
	db := &Database{
		Packages: []CompromisedPackage{
			{Name: "axios", Ecosystem: "npm", Versions: []string{"1.14.1"}, Campaign: "UNC1069", Severity: "critical"},
		},
	}

	finding := db.Check(Dependency{Name: "axios", Version: "1.14.1", Ecosystem: "pypi"})
	assert.Nil(t, finding)
}

func TestDatabase_Check_WildcardVersion(t *testing.T) {
	db := &Database{
		Packages: []CompromisedPackage{
			{Name: "evil-pkg", Ecosystem: "npm", Versions: []string{"*"}, Campaign: "test", Severity: "critical"},
		},
	}

	finding := db.Check(Dependency{Name: "evil-pkg", Version: "9.9.9", Ecosystem: "npm"})
	require.NotNil(t, finding)
}

func TestDatabase_Check_CaseInsensitive(t *testing.T) {
	db := &Database{
		Packages: []CompromisedPackage{
			{Name: "LiteLLM", Ecosystem: "pypi", Versions: []string{"1.82.7"}, Campaign: "TeamPCP", Severity: "critical"},
		},
	}

	finding := db.Check(Dependency{Name: "litellm", Version: "1.82.7", Ecosystem: "pypi"})
	require.NotNil(t, finding)
}

func TestParsePackageLock_V3(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "package-lock.json")
	content := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "test", "version": "1.0.0"},
    "node_modules/axios": {"version": "1.14.1"},
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/@scope/pkg": {"version": "2.0.0"}
  }
}`
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0644))

	deps, err := ParsePackageLock(tmp)
	require.NoError(t, err)
	assert.Len(t, deps, 3)

	names := map[string]string{}
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "npm", d.Ecosystem)
	}
	assert.Equal(t, "1.14.1", names["axios"])
	assert.Equal(t, "4.18.2", names["express"])
	assert.Equal(t, "2.0.0", names["@scope/pkg"])
}

func TestParseRequirementsTxt(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "requirements.txt")
	content := `# This is a comment
flask==3.0.0
litellm==1.82.7
requests>=2.31.0
-e git+https://github.com/foo/bar.git
boto3[s3]==1.26.0
numpy==1.24.0 ; python_version >= "3.8"
`
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0644))

	deps, err := ParseRequirementsTxt(tmp)
	require.NoError(t, err)

	names := map[string]string{}
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "pypi", d.Ecosystem)
	}

	assert.Equal(t, "3.0.0", names["flask"])
	assert.Equal(t, "1.82.7", names["litellm"])
	assert.Equal(t, "1.26.0", names["boto3"])
	assert.Equal(t, "1.24.0", names["numpy"])
	// requests has >= not ==, should NOT be included
	assert.Empty(t, names["requests"])
}

func TestParseGoSum(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "go.sum")
	content := `github.com/fatih/color v1.16.0 h1:abc123=
github.com/fatih/color v1.16.0/go.mod h1:def456=
github.com/spf13/cobra v1.8.0 h1:ghi789=
github.com/spf13/cobra v1.8.0/go.mod h1:jkl012=
`
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0644))

	deps, err := ParseGoSum(tmp)
	require.NoError(t, err)
	assert.Len(t, deps, 2) // deduplicated

	names := map[string]string{}
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "go", d.Ecosystem)
	}
	assert.Equal(t, "1.16.0", names["github.com/fatih/color"])
	assert.Equal(t, "1.8.0", names["github.com/spf13/cobra"])
}

func TestDiscoverLockFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "random.txt"), []byte(""), 0644)

	lockFiles, err := DiscoverLockFiles(dir)
	require.NoError(t, err)
	assert.Len(t, lockFiles, 3)

	ecosystems := map[string]bool{}
	for _, lf := range lockFiles {
		ecosystems[lf.Ecosystem] = true
	}
	assert.True(t, ecosystems["npm"])
	assert.True(t, ecosystems["pypi"])
	assert.True(t, ecosystems["go"])
}

func TestDiscoverLockFiles_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "axios")
	os.MkdirAll(nmDir, 0755)
	os.WriteFile(filepath.Join(nmDir, "package-lock.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0644)

	lockFiles, err := DiscoverLockFiles(dir)
	require.NoError(t, err)
	assert.Len(t, lockFiles, 1) // only root, not node_modules
}
