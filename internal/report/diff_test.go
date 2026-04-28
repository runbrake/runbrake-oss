package report

import (
	"strings"
	"testing"

	"github.com/runbrake/runbrake-oss/internal/doctor"
)

func TestDiffScanReportsShowsFindingAndArtifactChanges(t *testing.T) {
	baseline := doctor.ScanReport{
		ID:             "baseline",
		ArtifactHashes: []string{"sha256:old"},
		Findings: []doctor.Finding{{
			ID:       "finding-old",
			RuleID:   "RB-SKILL-SHELL-EXECUTION",
			Severity: doctor.SeverityHigh,
			Title:    "Old shell",
		}},
	}
	current := doctor.ScanReport{
		ID:             "current",
		ArtifactHashes: []string{"sha256:new"},
		Findings: []doctor.Finding{{
			ID:       "finding-new",
			RuleID:   "RB-SKILL-REMOTE-SCRIPT-EXECUTION",
			Severity: doctor.SeverityCritical,
			Title:    "New remote script",
		}},
	}

	diff := DiffScanReports(baseline, current)
	if len(diff.AddedFindings) != 1 || diff.AddedFindings[0].RuleID != "RB-SKILL-REMOTE-SCRIPT-EXECUTION" {
		t.Fatalf("added findings = %+v, want remote script", diff.AddedFindings)
	}
	if len(diff.RemovedFindings) != 1 || diff.RemovedFindings[0].RuleID != "RB-SKILL-SHELL-EXECUTION" {
		t.Fatalf("removed findings = %+v, want shell", diff.RemovedFindings)
	}
	if len(diff.AddedArtifactHashes) != 1 || diff.AddedArtifactHashes[0] != "sha256:new" {
		t.Fatalf("added artifact hashes = %+v", diff.AddedArtifactHashes)
	}
	if len(diff.RemovedArtifactHashes) != 1 || diff.RemovedArtifactHashes[0] != "sha256:old" {
		t.Fatalf("removed artifact hashes = %+v", diff.RemovedArtifactHashes)
	}

	rendered, err := RenderScanReportDiffMarkdown(diff)
	if err != nil {
		t.Fatalf("RenderScanReportDiffMarkdown error = %v", err)
	}
	for _, want := range []string{"# RunBrake Scan Diff", "Added findings", "RB-SKILL-REMOTE-SCRIPT-EXECUTION", "sha256:new"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("diff markdown missing %q:\n%s", want, rendered)
		}
	}
}
