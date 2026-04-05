package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Version is set at build time via ldflags.
var Version = "dev"

// MenuOption represents one option in the interactive menu.
type MenuOption struct {
	Label     string
	Available bool
	ComingSoon string // version when this ships, e.g. "v2.7.0"
}

// ShowMenu displays the interactive CLI menu and returns the user's
// selection as a command string that maps to a cobra command.
// Returns empty string if the user cancels (Ctrl+C or invalid input).
func ShowMenu() string {
	options := []MenuOption{
		{Label: "Scan a single repo (local or remote)", Available: true},
		{Label: "Scan multiple repositories (from file)", Available: true},
		{Label: "Check dependencies for known compromises", Available: false, ComingSoon: "v2.8.0"},
		{Label: "Audit upstream dependency pipelines", Available: false, ComingSoon: "v2.9.0"},
		{Label: "Fix vulnerabilities (auto-pin + extract)", Available: true},
		{Label: "Install pre-commit hook", Available: false, ComingSoon: "v3.0.0"},
		{Label: "Generate Dependabot config", Available: false, ComingSoon: "v3.0.0"},
		{Label: "Run demo (vulnerable workflow examples)", Available: true},
	}

	fmt.Println()
	fmt.Printf("Runner Guard — CI/CD Security Scanner %s\n", Version)
	fmt.Println()
	fmt.Println("What would you like to do?")
	fmt.Println()

	for i, opt := range options {
		if opt.Available {
			fmt.Printf("  %d. %s\n", i+1, opt.Label)
		} else {
			fmt.Printf("  %d. %s  [Coming in %s]\n", i+1, opt.Label, opt.ComingSoon)
		}
	}

	fmt.Println()
	fmt.Print("Select (1-8): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		return showScanSubMenu(reader)
	case "2":
		return showBatchSubMenu(reader)
	case "3":
		fmt.Println("\n  Dependency checking is coming in v2.8.0.")
		fmt.Println("  This will check your lock files against known compromised packages.")
		return ""
	case "4":
		fmt.Println("\n  Upstream pipeline audit is coming in v2.9.0.")
		fmt.Println("  This will scan the CI/CD pipelines of your upstream dependencies.")
		return ""
	case "5":
		return showFixSubMenu(reader)
	case "6":
		fmt.Println("\n  Pre-commit hook is coming in v3.0.0.")
		fmt.Println("  This will scan workflow changes before they are committed.")
		return ""
	case "7":
		fmt.Println("\n  Dependabot config generator is coming in v3.0.0.")
		fmt.Println("  This will create a dependabot.yml after pinning your actions.")
		return ""
	case "8":
		return "demo"
	default:
		fmt.Printf("\n  Invalid selection: %s\n", input)
		return ""
	}
}

func showScanSubMenu(reader *bufio.Reader) string {
	fmt.Println()
	fmt.Println("Scan a single repo")
	fmt.Println()
	fmt.Println("  a. Local directory")
	fmt.Println("     Scans the repo in your current working directory.")
	fmt.Println("     Make sure you are inside the root of the git repo you want to scan.")
	fmt.Println()
	fmt.Println("  b. Remote GitHub repo")
	fmt.Println("     Scans a public GitHub repo without cloning it.")
	fmt.Println("     Enter the repo URL when prompted (e.g. github.com/owner/repo)")
	fmt.Println()
	fmt.Print("Select (a/b): ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "a", "":
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting current directory: %v\n", err)
			return ""
		}
		absPath, _ := filepath.Abs(cwd)
		fmt.Printf("\n  Scanning: %s\n", absPath)
		fmt.Print("  Is this correct? (Y/n): ")

		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm == "n" || confirm == "no" {
			fmt.Print("  Enter path to scan: ")
			path, _ := reader.ReadString('\n')
			path = strings.TrimSpace(path)
			if path == "" {
				return ""
			}
			return "scan:" + path
		}
		return "scan:."

	case "b":
		fmt.Print("\n  Enter GitHub repo URL (e.g. github.com/owner/repo): ")
		url, _ := reader.ReadString('\n')
		url = strings.TrimSpace(url)
		if url == "" {
			return ""
		}
		return "scan:" + url

	default:
		fmt.Printf("\n  Invalid selection: %s\n", input)
		return ""
	}
}

func showBatchSubMenu(reader *bufio.Reader) string {
	fmt.Println()
	fmt.Println("Scan multiple repositories")
	fmt.Println()
	fmt.Println("  a. Load from file")
	fmt.Println("     Enter path to a file with repo URLs, one per line.")
	fmt.Println()
	fmt.Println("  b. Enter repos manually")
	fmt.Println("     Type repo URLs one per line, blank line when done.")
	fmt.Println()
	fmt.Print("Select (a/b): ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "a", "":
		fmt.Println()
		fmt.Println("  Example repos.txt:")
		fmt.Println("    github.com/owner/repo1")
		fmt.Println("    github.com/owner/repo2")
		fmt.Println("    /path/to/local/repo")
		fmt.Println()
		fmt.Print("  Path to repos file: ")

		path, err := reader.ReadString('\n')
		if err != nil {
			return ""
		}
		path = strings.TrimSpace(path)
		if path == "" {
			return ""
		}
		return "batch:" + path

	case "b":
		fmt.Println()
		fmt.Println("  Enter repo URLs one per line (blank line to start scanning):")
		fmt.Println()

		// Write repos to a temp file so the scan command can read it
		tmpFile, err := os.CreateTemp("", "runner-guard-repos-*.txt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating temp file: %v\n", err)
			return ""
		}

		count := 0
		for {
			fmt.Print("  > ")
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			tmpFile.WriteString(line + "\n")
			count++
		}
		tmpFile.Close()

		if count == 0 {
			os.Remove(tmpFile.Name())
			return ""
		}

		fmt.Printf("\n  Scanning %d repos...\n", count)
		return "batch:" + tmpFile.Name()

	default:
		fmt.Printf("\n  Invalid selection: %s\n", input)
		return ""
	}
}

func showFixSubMenu(reader *bufio.Reader) string {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current directory: %v\n", err)
		return ""
	}
	absPath, _ := filepath.Abs(cwd)
	fmt.Printf("\n  Fix will apply to: %s\n", absPath)
	fmt.Println("  This will pin unpinned actions to commit SHAs and extract unsafe")
	fmt.Println("  expressions from run blocks into env mappings.")
	fmt.Print("  Continue? (Y/n): ")

	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm == "n" || confirm == "no" {
		return ""
	}
	return "fix:."
}
