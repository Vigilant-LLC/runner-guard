package batch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRepoFile_Basic(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "repos.txt")
	content := `# Comment line
github.com/owner/repo1
github.com/owner/repo2

# Another comment
/local/path/to/repo
`
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0644))

	repos, err := ParseRepoFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"github.com/owner/repo1",
		"github.com/owner/repo2",
		"/local/path/to/repo",
	}, repos)
}

func TestParseRepoFile_Empty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "repos.txt")
	require.NoError(t, os.WriteFile(tmp, []byte("# Only comments\n\n"), 0644))

	repos, err := ParseRepoFile(tmp)
	require.NoError(t, err)
	assert.Empty(t, repos)
}

func TestParseRepoFile_NotFound(t *testing.T) {
	_, err := ParseRepoFile("/nonexistent/file.txt")
	assert.Error(t, err)
}

func TestParseRepoFile_WhitespaceHandling(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "repos.txt")
	content := `
  github.com/owner/repo1
github.com/owner/repo2
`
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0644))

	repos, err := ParseRepoFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"github.com/owner/repo1",
		"github.com/owner/repo2",
	}, repos)
}
