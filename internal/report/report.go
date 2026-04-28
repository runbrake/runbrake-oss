package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/runbrake/runbrake-oss/internal/doctor"
)

func RenderConsole(result doctor.Result) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", reportName(result))
	fmt.Fprintf(&b, "OpenClaw root: %s\n", result.Root)
	fmt.Fprintf(&b, "Scanner version: %s\n", result.Report.ScannerVersion)
	fmt.Fprintf(&b, "Generated at: %s\n", result.Report.GeneratedAt)
	fmt.Fprintf(&b, "OpenClaw version: %s\n", valueOrUnknown(result.OpenClawVersion))
	fmt.Fprintf(&b, "Findings: %d critical, %d high, %d medium, %d low, %d info\n",
		result.Report.Summary.Critical,
		result.Report.Summary.High,
		result.Report.Summary.Medium,
		result.Report.Summary.Low,
		result.Report.Summary.Info,
	)
	fmt.Fprintf(&b, "Inventory: %d skill, %d plugins\n", len(result.Inventory.Skills), len(result.Inventory.Plugins))

	if len(result.Report.Findings) == 0 {
		fmt.Fprintf(&b, "No risky OpenClaw findings detected.\n")
		return b.String(), nil
	}

	for _, finding := range result.Report.Findings {
		fmt.Fprintf(&b, "\n%s %s %s (confidence %.2f)\n",
			strings.ToUpper(string(finding.Severity)),
			finding.RuleID,
			finding.Title,
			finding.Confidence,
		)
		fmt.Fprintf(&b, "  Evidence:\n")
		for _, item := range finding.Evidence {
			fmt.Fprintf(&b, "  - %s\n", item)
		}
		fmt.Fprintf(&b, "  Remediation: %s\n", finding.Remediation)
	}

	return b.String(), nil
}

func RenderMarkdown(result doctor.Result) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s Report\n\n", reportName(result))
	fmt.Fprintf(&b, "- OpenClaw root: `%s`\n", result.Root)
	fmt.Fprintf(&b, "- Scanner version: `%s`\n", result.Report.ScannerVersion)
	fmt.Fprintf(&b, "- Generated at: `%s`\n", result.Report.GeneratedAt)
	fmt.Fprintf(&b, "- OpenClaw version: `%s`\n\n", valueOrUnknown(result.OpenClawVersion))
	fmt.Fprintf(&b, "Summary: %d critical, %d high, %d medium, %d low, %d info.\n\n",
		result.Report.Summary.Critical,
		result.Report.Summary.High,
		result.Report.Summary.Medium,
		result.Report.Summary.Low,
		result.Report.Summary.Info,
	)

	if len(result.Report.Findings) == 0 {
		fmt.Fprintf(&b, "No risky OpenClaw findings detected.\n")
		return b.String(), nil
	}

	fmt.Fprintf(&b, "| Severity | Rule | Finding | Evidence | Remediation |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | --- | --- |\n")
	for _, finding := range result.Report.Findings {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
			finding.Severity,
			finding.RuleID,
			escapeMarkdownTable(finding.Title),
			escapeMarkdownTable(strings.Join(finding.Evidence, "<br>")),
			escapeMarkdownTable(finding.Remediation),
		)
	}

	return b.String(), nil
}

func RenderJSON(result doctor.Result) (string, error) {
	payload, err := json.MarshalIndent(result.Report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload) + "\n", nil
}

func RenderSARIF(result doctor.Result) (string, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		Help             sarifMessage `json:"help"`
	}
	type sarifResult struct {
		RuleID  string       `json:"ruleId"`
		Level   string       `json:"level"`
		Message sarifMessage `json:"message"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name           string      `json:"name"`
				InformationURI string      `json:"informationUri"`
				Rules          []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	run := sarifRun{}
	run.Tool.Driver.Name = reportName(result)
	run.Tool.Driver.InformationURI = "https://runbrake.com"

	seenRules := map[string]bool{}
	for _, finding := range result.Report.Findings {
		if !seenRules[finding.RuleID] {
			seenRules[finding.RuleID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:   finding.RuleID,
				Name: finding.Title,
				ShortDescription: sarifMessage{
					Text: finding.Title,
				},
				Help: sarifMessage{
					Text: finding.Remediation,
				},
			})
		}

		run.Results = append(run.Results, sarifResult{
			RuleID: finding.RuleID,
			Level:  sarifLevel(finding.Severity),
			Message: sarifMessage{
				Text: finding.Title + ": " + strings.Join(finding.Evidence, "; "),
			},
		})
	}

	sort.Slice(run.Tool.Driver.Rules, func(i, j int) bool {
		return run.Tool.Driver.Rules[i].ID < run.Tool.Driver.Rules[j].ID
	})

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	payload, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload) + "\n", nil
}

func sarifLevel(severity doctor.Severity) string {
	switch severity {
	case doctor.SeverityCritical, doctor.SeverityHigh:
		return "error"
	case doctor.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func reportName(result doctor.Result) string {
	if strings.Contains(result.Report.AgentID, "skill-scan") {
		return "RunBrake Skill Scan"
	}
	return "RunBrake Doctor"
}

func escapeMarkdownTable(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "<br>")
	return value
}
