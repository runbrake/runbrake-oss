package registry

import (
	"path/filepath"
	"testing"
)

func TestScanHermesGitHubSourceScansBundledAndOptionalSkills(t *testing.T) {
	report, err := ScanHermes(ScanOptions{
		Registry:       "hermes",
		MirrorPath:     filepath.Join("testdata", "hermes-repo"),
		SourceCommit:   "fixture-commit",
		Now:            fixedRegistryTime,
		ScannerVersion: "test",
		DependencyScan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Discovered != 5 {
		t.Fatalf("discovered = %d, want 5", report.Summary.Discovered)
	}
	if report.Summary.Scanned != 5 {
		t.Fatalf("scanned = %d, want 5", report.Summary.Scanned)
	}
	if report.Source.Type != SourceHermesGitHub {
		t.Fatalf("source type = %q, want %q", report.Source.Type, SourceHermesGitHub)
	}
	if report.Source.Commit != "fixture-commit" {
		t.Fatalf("source commit = %q, want fixture-commit", report.Source.Commit)
	}

	bundled := findSkill(t, report, "devops", "docker-management")
	if bundled.Category != "devops" {
		t.Fatalf("bundled category = %q, want devops", bundled.Category)
	}
	if bundled.Bundled == nil || !*bundled.Bundled {
		t.Fatalf("bundled flag = %v, want true", bundled.Bundled)
	}
	if bundled.SourcePath != "skills/devops/docker-management/SKILL.md" {
		t.Fatalf("bundled source path = %q", bundled.SourcePath)
	}
	if bundled.SourceCommit != "fixture-commit" {
		t.Fatalf("bundled source commit = %q", bundled.SourceCommit)
	}
	if !hasDependency(bundled.Dependencies, "npm", "lodash", "4.17.20") {
		t.Fatalf("bundled dependencies missing lodash: %+v", bundled.Dependencies)
	}

	optional := findSkill(t, report, "security", "1password")
	if optional.Category != "security" {
		t.Fatalf("optional category = %q, want security", optional.Category)
	}
	if optional.Bundled == nil || *optional.Bundled {
		t.Fatalf("optional bundled flag = %v, want false", optional.Bundled)
	}
	if optional.SourcePath != "optional-skills/security/1password/SKILL.md" {
		t.Fatalf("optional source path = %q", optional.SourcePath)
	}

	topLevel := findSkill(t, report, "qa", "dogfood")
	if topLevel.Category != "qa" {
		t.Fatalf("top-level category = %q, want qa", topLevel.Category)
	}
	if topLevel.Bundled == nil || !*topLevel.Bundled {
		t.Fatalf("top-level bundled flag = %v, want true", topLevel.Bundled)
	}
	if topLevel.SourcePath != "skills/dogfood/SKILL.md" {
		t.Fatalf("top-level source path = %q", topLevel.SourcePath)
	}
}

func TestScanHermesSlugFilterIncludesTopLevelSkills(t *testing.T) {
	report, err := ScanHermes(ScanOptions{
		Registry:       "hermes",
		MirrorPath:     filepath.Join("testdata", "hermes-repo"),
		SourceCommit:   "fixture-commit",
		Now:            fixedRegistryTime,
		ScannerVersion: "test",
		Slugs:          []string{"dogfood"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Discovered != 5 {
		t.Fatalf("discovered = %d, want 5", report.Summary.Discovered)
	}
	if report.Summary.Scanned != 1 {
		t.Fatalf("scanned = %d, want 1", report.Summary.Scanned)
	}
	skill := findSkill(t, report, "qa", "dogfood")
	if skill.SourcePath != "skills/dogfood/SKILL.md" {
		t.Fatalf("source path = %q", skill.SourcePath)
	}
}
