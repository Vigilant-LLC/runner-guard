package deps

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"git+https://github.com/axios/axios.git", "github.com/axios/axios"},
		{"https://github.com/expressjs/express.git", "github.com/expressjs/express"},
		{"git://github.com/lodash/lodash.git", "github.com/lodash/lodash"},
		{"https://github.com/owner/repo", "github.com/owner/repo"},
		{"https://gitlab.com/owner/repo", ""},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, normalizeGitURL(tt.input), "input: %s", tt.input)
	}
}

func TestExtractGitHubRepo(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://github.com/pallets/flask", "github.com/pallets/flask"},
		{"https://github.com/BerriAI/litellm/tree/main", "github.com/BerriAI/litellm"},
		{"http://github.com/owner/repo.git", "github.com/owner/repo"},
		{"https://gitlab.com/owner/repo", ""},
		{"https://pypi.org/project/flask", ""},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, extractGitHubRepo(tt.input), "input: %s", tt.input)
	}
}

func TestResolveGo(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/fatih/color", "github.com/fatih/color"},
		{"github.com/spf13/cobra", "github.com/spf13/cobra"},
		{"github.com/owner/repo/v2/subpkg", "github.com/owner/repo"},
		{"golang.org/x/crypto", ""},
		{"google.golang.org/grpc", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, resolveGo(tt.input), "input: %s", tt.input)
	}
}
