package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRegistryReportPack(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "pack")
	manifest, err := WriteRegistryReportPack(sampleRegistryReport(), RegistryReportPackOptions{
		OutputDir:         outputDir,
		TopSkillLimit:     5,
		ExampleSkillLimit: 5,
	})
	if err != nil {
		t.Fatalf("WriteRegistryReportPack() error = %v", err)
	}

	wantFiles := []string{"report.md", "top-skills.csv", "top-vulnerabilities.csv", "summary.json", "README.md"}
	for _, name := range wantFiles {
		if !containsPath(manifest.Files, filepath.Join(outputDir, name)) {
			t.Fatalf("manifest missing %s: %+v", name, manifest.Files)
		}
		data, err := os.ReadFile(filepath.Join(outputDir, name))
		if err != nil {
			t.Fatalf("read report pack file %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("report pack file %s was empty", name)
		}
	}

	topSkills, err := os.ReadFile(filepath.Join(outputDir, "top-skills.csv"))
	if err != nil {
		t.Fatalf("read top-skills.csv: %v", err)
	}
	if !strings.Contains(string(topSkills), "owner,slug,display_name,risk_level") || !strings.Contains(string(topSkills), "acme,risky") {
		t.Fatalf("top-skills.csv missing expected content:\n%s", string(topSkills))
	}

	topVulns, err := os.ReadFile(filepath.Join(outputDir, "top-vulnerabilities.csv"))
	if err != nil {
		t.Fatalf("read top-vulnerabilities.csv: %v", err)
	}
	if !strings.Contains(string(topVulns), "id,ecosystem,package_name") || !strings.Contains(string(topVulns), "GHSA-test-lodash") {
		t.Fatalf("top-vulnerabilities.csv missing expected content:\n%s", string(topVulns))
	}
}

func TestWriteHermesRegistryReportPackUsesHermesCopy(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "pack")
	_, err := WriteRegistryReportPack(sampleHermesRegistryReport(), RegistryReportPackOptions{
		OutputDir:         outputDir,
		TopSkillLimit:     5,
		ExampleSkillLimit: 5,
	})
	if err != nil {
		t.Fatalf("WriteRegistryReportPack() error = %v", err)
	}

	reportMarkdown, err := os.ReadFile(filepath.Join(outputDir, "report.md"))
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}
	for _, want := range []string{
		"# Hermes Skills Risk Report",
		"Bundled skills scanned",
		"Optional skills scanned",
		"Highest-risk Hermes skills",
		"Reproducibility",
	} {
		if !strings.Contains(string(reportMarkdown), want) {
			t.Fatalf("Hermes report pack markdown missing %q:\n%s", want, string(reportMarkdown))
		}
	}
}

func containsPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
