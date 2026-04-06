package deps

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// ResolveToRepo maps a dependency to its GitHub repository URL.
// Returns empty string if the repo cannot be determined.
func ResolveToRepo(dep Dependency) string {
	switch dep.Ecosystem {
	case "npm":
		return resolveNpm(dep.Name)
	case "pypi":
		return resolvePyPI(dep.Name)
	case "go":
		return resolveGo(dep.Name)
	default:
		return ""
	}
}

// resolveNpm looks up a package on the npm registry and extracts the GitHub repo URL.
func resolveNpm(name string) string {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	resp, err := httpClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var data struct {
		Repository struct {
			URL string `json:"url"`
		} `json:"repository"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}

	return normalizeGitURL(data.Repository.URL)
}

// resolvePyPI looks up a package on PyPI and extracts the GitHub repo URL.
func resolvePyPI(name string) string {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := httpClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var data struct {
		Info struct {
			ProjectURLs map[string]string `json:"project_urls"`
			HomePage    string            `json:"home_page"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}

	// Try project_urls first - look for Source, Repository, GitHub, Code
	for _, key := range []string{"Source", "Source Code", "Repository", "GitHub", "Code", "Homepage"} {
		if u, ok := data.Info.ProjectURLs[key]; ok {
			if repo := extractGitHubRepo(u); repo != "" {
				return repo
			}
		}
	}

	// Fall back to home_page
	if repo := extractGitHubRepo(data.Info.HomePage); repo != "" {
		return repo
	}

	return ""
}

// resolveGo extracts the GitHub repo from a Go module path.
// Go module paths that start with github.com are already repo URLs.
func resolveGo(name string) string {
	if strings.HasPrefix(name, "github.com/") {
		parts := strings.SplitN(name, "/", 4)
		if len(parts) >= 3 {
			return "github.com/" + parts[1] + "/" + parts[2]
		}
	}
	return ""
}

// normalizeGitURL cleans up repository URLs from registry metadata.
// Handles formats like:
//   - git+https://github.com/owner/repo.git
//   - git://github.com/owner/repo.git
//   - https://github.com/owner/repo.git
//   - https://github.com/owner/repo
func normalizeGitURL(raw string) string {
	if raw == "" {
		return ""
	}

	raw = strings.TrimPrefix(raw, "git+")
	raw = strings.TrimPrefix(raw, "git://")
	raw = strings.TrimPrefix(raw, "ssh://git@")
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")

	if !strings.HasPrefix(raw, "github.com/") {
		return ""
	}

	// Ensure we have owner/repo only
	parts := strings.SplitN(raw, "/", 4)
	if len(parts) >= 3 {
		return "github.com/" + parts[1] + "/" + parts[2]
	}

	return ""
}

// extractGitHubRepo pulls a github.com/owner/repo path from a URL.
func extractGitHubRepo(url string) string {
	if url == "" {
		return ""
	}
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimSuffix(url, ".git")

	if !strings.HasPrefix(url, "github.com/") {
		return ""
	}

	parts := strings.SplitN(url, "/", 4)
	if len(parts) >= 3 {
		return "github.com/" + parts[1] + "/" + parts[2]
	}

	return ""
}
