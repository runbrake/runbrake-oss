package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/runbrake/runbrake-oss/internal/doctor"
)

type ScanReportDiff struct {
	BaselineID            string           `json:"baselineId"`
	CurrentID             string           `json:"currentId"`
	AddedFindings         []doctor.Finding `json:"addedFindings"`
	RemovedFindings       []doctor.Finding `json:"removedFindings"`
	AddedArtifactHashes   []string         `json:"addedArtifactHashes"`
	RemovedArtifactHashes []string         `json:"removedArtifactHashes"`
}

func DiffScanReports(baseline doctor.ScanReport, current doctor.ScanReport) ScanReportDiff {
	return ScanReportDiff{
		BaselineID:            baseline.ID,
		CurrentID:             current.ID,
		AddedFindings:         findingsOnlyIn(current.Findings, baseline.Findings),
		RemovedFindings:       findingsOnlyIn(baseline.Findings, current.Findings),
		AddedArtifactHashes:   stringsOnlyIn(current.ArtifactHashes, baseline.ArtifactHashes),
		RemovedArtifactHashes: stringsOnlyIn(baseline.ArtifactHashes, current.ArtifactHashes),
	}
}

func RenderScanReportDiffJSON(diff ScanReportDiff) (string, error) {
	payload, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload) + "\n", nil
}

func RenderScanReportDiffMarkdown(diff ScanReportDiff) (string, error) {
	var b strings.Builder
	fmt.Fprintln(&b, "# RunBrake Scan Diff")
	fmt.Fprintf(&b, "\n- Baseline: `%s`\n", valueOrUnknown(diff.BaselineID))
	fmt.Fprintf(&b, "- Current: `%s`\n", valueOrUnknown(diff.CurrentID))
	fmt.Fprintf(&b, "- Added findings: `%d`\n", len(diff.AddedFindings))
	fmt.Fprintf(&b, "- Removed findings: `%d`\n", len(diff.RemovedFindings))
	fmt.Fprintf(&b, "- Added artifact hashes: `%d`\n", len(diff.AddedArtifactHashes))
	fmt.Fprintf(&b, "- Removed artifact hashes: `%d`\n\n", len(diff.RemovedArtifactHashes))

	renderFindingList(&b, "Added findings", diff.AddedFindings)
	renderFindingList(&b, "Removed findings", diff.RemovedFindings)
	renderStringList(&b, "Added artifact hashes", diff.AddedArtifactHashes)
	renderStringList(&b, "Removed artifact hashes", diff.RemovedArtifactHashes)
	return b.String(), nil
}

func (diff ScanReportDiff) HasAddedHighRisk() bool {
	for _, finding := range diff.AddedFindings {
		if finding.Severity == doctor.SeverityCritical || finding.Severity == doctor.SeverityHigh {
			return true
		}
	}
	return false
}

func findingsOnlyIn(left []doctor.Finding, right []doctor.Finding) []doctor.Finding {
	rightKeys := map[string]bool{}
	for _, finding := range right {
		rightKeys[findingKey(finding)] = true
	}
	out := []doctor.Finding{}
	for _, finding := range left {
		if !rightKeys[findingKey(finding)] {
			out = append(out, finding)
		}
	}
	return out
}

func findingKey(finding doctor.Finding) string {
	return strings.Join([]string{
		finding.RuleID,
		string(finding.Severity),
		finding.Title,
		strings.Join(finding.Evidence, "\x00"),
	}, "\x00")
}

func stringsOnlyIn(left []string, right []string) []string {
	rightValues := map[string]bool{}
	for _, value := range right {
		rightValues[value] = true
	}
	out := []string{}
	for _, value := range left {
		if !rightValues[value] {
			out = append(out, value)
		}
	}
	return out
}

func renderFindingList(b *strings.Builder, title string, findings []doctor.Finding) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(findings) == 0 {
		fmt.Fprintln(b, "None.")
		fmt.Fprintln(b)
		return
	}
	for _, finding := range findings {
		fmt.Fprintf(b, "- `%s` %s %s\n", finding.RuleID, finding.Severity, finding.Title)
	}
	fmt.Fprintln(b)
}

func renderStringList(b *strings.Builder, title string, values []string) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(values) == 0 {
		fmt.Fprintln(b, "None.")
		fmt.Fprintln(b)
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "- `%s`\n", value)
	}
	fmt.Fprintln(b)
}
