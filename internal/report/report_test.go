package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/runbrake/runbrake-oss/internal/doctor"
)

func TestRenderConsoleMatchesGoldenOutput(t *testing.T) {
	got, err := RenderConsole(sampleResult())
	if err != nil {
		t.Fatalf("RenderConsole() error = %v", err)
	}

	wantBytes, err := os.ReadFile("testdata/console.golden")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if got != string(wantBytes) {
		t.Fatalf("console output mismatch\nwant:\n%s\ngot:\n%s", string(wantBytes), got)
	}
}

func TestRenderMarkdownRedactsEvidence(t *testing.T) {
	got, err := RenderMarkdown(sampleResult())
	if err != nil {
		t.Fatalf("RenderMarkdown() error = %v", err)
	}

	if strings.Contains(got, "sk-test-raw-secret") {
		t.Fatalf("markdown leaked raw secret: %s", got)
	}

	if !strings.Contains(got, "[REDACTED:api_key:abc12345]") {
		t.Fatalf("markdown missing redacted evidence: %s", got)
	}
}

func TestRenderJSONMatchesScanReportContractShape(t *testing.T) {
	got, err := RenderJSON(sampleResult())
	if err != nil {
		t.Fatalf("RenderJSON() error = %v", err)
	}

	var report doctor.ScanReport
	if err := json.Unmarshal([]byte(got), &report); err != nil {
		t.Fatalf("json did not unmarshal as ScanReport: %v", err)
	}

	if report.ID == "" || report.AgentID == "" || report.GeneratedAt == "" {
		t.Fatalf("missing contract fields in %+v", report)
	}
}

func TestRenderSARIFProducesMinimalValidSARIF(t *testing.T) {
	got, err := RenderSARIF(sampleResult())
	if err != nil {
		t.Fatalf("RenderSARIF() error = %v", err)
	}

	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal([]byte(got), &sarif); err != nil {
		t.Fatalf("sarif did not unmarshal: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", sarif.Version)
	}

	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("SARIF runs/results = %+v, want one result", sarif.Runs)
	}

	if strings.Contains(got, "sk-test-raw-secret") {
		t.Fatalf("sarif leaked raw secret: %s", got)
	}
}

func TestRenderSkillScanUsesSkillScanTitle(t *testing.T) {
	result := sampleResult()
	result.Report.AgentID = "skill-scan"

	console, err := RenderConsole(result)
	if err != nil {
		t.Fatalf("RenderConsole() error = %v", err)
	}
	if !strings.Contains(console, "RunBrake Skill Scan") {
		t.Fatalf("skill console title missing:\n%s", console)
	}

	sarif, err := RenderSARIF(result)
	if err != nil {
		t.Fatalf("RenderSARIF() error = %v", err)
	}
	if !strings.Contains(sarif, `"name": "RunBrake Skill Scan"`) {
		t.Fatalf("skill SARIF title missing:\n%s", sarif)
	}
}

func sampleResult() doctor.Result {
	return doctor.Result{
		Root:            "fixture://sample",
		OpenClawVersion: "1.2.0",
		Inventory: doctor.Inventory{
			Skills: []doctor.Artifact{{
				Kind:          "skill",
				Name:          "shell-helper",
				Version:       "0.1.0",
				Source:        "https://example.invalid/shell-helper",
				InstallMethod: "url",
				Hash:          "sha256:1111111111111111",
			}},
		},
		Report: doctor.ScanReport{
			ID:             "scan-sample",
			AgentID:        "agent-sample",
			ScannerVersion: "test",
			GeneratedAt:    "2026-04-28T12:00:00Z",
			Summary: doctor.Summary{
				High: 1,
			},
			ArtifactHashes: []string{"sha256:1111111111111111"},
			Findings: []doctor.Finding{{
				ID:          "finding-sample",
				RuleID:      "RB-SECRET-PLAINTEXT",
				Severity:    "high",
				Confidence:  0.95,
				Title:       "Plaintext secret detected",
				Evidence:    []string{"config contains [REDACTED:api_key:abc12345]"},
				Remediation: "Move secrets into a dedicated secret manager and rotate exposed credentials.",
			}},
		},
	}
}
