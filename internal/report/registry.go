package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/registry"
)

type RegistryEcosystemReportOptions struct {
	Title             string
	TopSkillLimit     int
	ExampleSkillLimit int
}

func RenderRegistrySummary(result registry.RegistryScanReport) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "RunBrake Registry Scan\n")
	fmt.Fprintf(&b, "Registry: %s\n", result.Registry)
	fmt.Fprintf(&b, "Source: %s\n", registrySourceLabel(result.Source))
	fmt.Fprintf(&b, "Scanner version: %s\n", result.ScannerVersion)
	fmt.Fprintf(&b, "Generated at: %s\n", result.GeneratedAt)
	fmt.Fprintf(&b, "Skills: discovered %d, scanned %d, skipped %d, clean %d, risky %d, errors %d\n",
		result.Summary.Discovered,
		result.Summary.Scanned,
		result.Summary.Skipped,
		result.Summary.Clean,
		result.Summary.Risky,
		result.Summary.Errors,
	)
	fmt.Fprintf(&b, "Findings: %d critical, %d high, %d medium, %d low, %d info\n",
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Info,
	)
	if result.Summary.Dependencies > 0 || result.Summary.Vulnerabilities > 0 {
		fmt.Fprintf(&b, "Dependencies: %d packages, %d vulnerable skills, %d vulnerabilities\n",
			result.Summary.Dependencies,
			result.Summary.VulnerableSkills,
			result.Summary.Vulnerabilities,
		)
	}

	if len(result.TopRules) > 0 {
		fmt.Fprintf(&b, "\nTop rules:\n")
		for _, rule := range result.TopRules {
			fmt.Fprintf(&b, "- %s %s x%d", rule.Severity, rule.RuleID, rule.Count)
			if strings.TrimSpace(rule.Title) != "" {
				fmt.Fprintf(&b, " - %s", rule.Title)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	if len(result.TopVulnerabilities) > 0 {
		fmt.Fprintf(&b, "\nTop vulnerabilities:\n")
		for _, vuln := range result.TopVulnerabilities {
			fmt.Fprintf(&b, "- %s %s %s@%s x%d",
				vuln.ID,
				valueOrUnknown(vuln.Severity),
				vuln.PackageName,
				vuln.PackageVersion,
				vuln.Count,
			)
			if strings.TrimSpace(vuln.Summary) != "" {
				fmt.Fprintf(&b, " - %s", vuln.Summary)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	if len(result.HighestRisk) > 0 {
		fmt.Fprintf(&b, "\nHighest-risk skills:\n")
		for _, row := range result.HighestRisk {
			fmt.Fprintf(&b, "- %s %s findings=%d critical=%d high=%d medium=%d low=%d info=%d",
				row.RiskLevel,
				registrySkillLabel(row.Owner, row.Slug, row.DisplayName),
				row.FindingCount,
				row.Critical,
				row.High,
				row.Medium,
				row.Low,
				row.Info,
			)
			fmt.Fprintf(&b, "\n")
		}
	}

	if result.Summary.Risky == 0 && result.Summary.Errors == 0 {
		fmt.Fprintf(&b, "\nNo risky registry findings detected.\n")
	}

	return b.String(), nil
}

func RenderRegistryEcosystemMarkdown(result registry.RegistryScanReport, options RegistryEcosystemReportOptions) (string, error) {
	title := strings.TrimSpace(options.Title)
	if title == "" {
		title = "OpenClaw Public Skills Risk Report"
	}
	topSkillLimit := options.TopSkillLimit
	if topSkillLimit <= 0 {
		topSkillLimit = 25
	}
	exampleSkillLimit := options.ExampleSkillLimit
	if exampleSkillLimit <= 0 {
		exampleSkillLimit = 25
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Generated from RunBrake registry scan `%s` on `%s`.\n\n", result.ID, result.GeneratedAt)

	fmt.Fprintf(&b, "## Executive Summary\n\n")
	fmt.Fprintf(&b, "RunBrake scanned `%d` public `%s` skills from `%s`. The scan found `%d` risky skills, `%d` clean skills, and `%d` scan errors.\n\n",
		result.Summary.Scanned,
		valueOrUnknown(result.Registry),
		registrySourceLabel(result.Source),
		result.Summary.Risky,
		result.Summary.Clean,
		result.Summary.Errors,
	)
	fmt.Fprintf(&b, "| Discovered | Scanned | Clean | Risky | Errors | Critical | High | Medium | Low | Info |\n")
	fmt.Fprintf(&b, "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		result.Summary.Discovered,
		result.Summary.Scanned,
		result.Summary.Clean,
		result.Summary.Risky,
		result.Summary.Errors,
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Info,
	)

	fmt.Fprintf(&b, "## Top Risk Signals\n\n")
	if len(result.TopRules) == 0 {
		fmt.Fprintf(&b, "No risk rules fired in this scan.\n\n")
	} else {
		fmt.Fprintf(&b, "| Rule | Severity | Count | Meaning |\n")
		fmt.Fprintf(&b, "| --- | --- | ---: | --- |\n")
		for _, rule := range result.TopRules {
			fmt.Fprintf(&b, "| `%s` | %s | %d | %s |\n",
				escapeMarkdownTable(rule.RuleID),
				rule.Severity,
				rule.Count,
				escapeMarkdownTable(rule.Title),
			)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Dependency And Vulnerability Intelligence\n\n")
	if result.Summary.Dependencies == 0 && len(result.TopVulnerabilities) == 0 {
		fmt.Fprintf(&b, "Dependency inventory was not included in this scan.\n\n")
	} else {
		fmt.Fprintf(&b, "| Dependencies | Vulnerable Skills | Vulnerable Dependencies | Vulnerabilities | Critical | High | Medium | Low | Unknown |\n")
		fmt.Fprintf(&b, "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
			result.Summary.Dependencies,
			result.Summary.VulnerableSkills,
			result.Summary.VulnerableDependencies,
			result.Summary.Vulnerabilities,
			result.Summary.VulnerabilityCritical,
			result.Summary.VulnerabilityHigh,
			result.Summary.VulnerabilityMedium,
			result.Summary.VulnerabilityLow,
			result.Summary.VulnerabilityUnknown,
		)
		if len(result.TopVulnerabilities) > 0 {
			fmt.Fprintf(&b, "| Advisory | Severity | Ecosystem | Package | Version | Hits | Summary |\n")
			fmt.Fprintf(&b, "| --- | --- | --- | --- | --- | ---: | --- |\n")
			for _, vuln := range result.TopVulnerabilities {
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %d | %s |\n",
					escapeMarkdownTable(vuln.ID),
					escapeMarkdownTable(vuln.Severity),
					escapeMarkdownTable(vuln.Ecosystem),
					escapeMarkdownTable(vuln.PackageName),
					escapeMarkdownTable(vuln.PackageVersion),
					vuln.Count,
					escapeMarkdownTable(vuln.Summary),
				)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	fmt.Fprintf(&b, "## Highest-Risk Skills\n\n")
	if len(result.HighestRisk) == 0 {
		fmt.Fprintf(&b, "No risky skills were ranked in this scan.\n\n")
	} else {
		fmt.Fprintf(&b, "| Skill | Display Name | Risk | Findings | Critical | High | Medium |\n")
		fmt.Fprintf(&b, "| --- | --- | --- | ---: | ---: | ---: | ---: |\n")
		for i, row := range result.HighestRisk {
			if i >= topSkillLimit {
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n",
				escapeMarkdownTable(skillPath(row.Owner, row.Slug)),
				escapeMarkdownTable(row.DisplayName),
				row.RiskLevel,
				row.FindingCount,
				row.Critical,
				row.High,
				row.Medium,
			)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Evidence Samples\n\n")
	examples := registryFindingExamples(result, exampleSkillLimit)
	if len(examples) == 0 {
		fmt.Fprintf(&b, "No finding evidence samples were available.\n\n")
	} else {
		for _, example := range examples {
			fmt.Fprintf(&b, "### %s\n\n", example.heading)
			fmt.Fprintf(&b, "- Rule: `%s` (%s)\n", example.ruleID, example.severity)
			fmt.Fprintf(&b, "- Finding: %s\n", example.title)
			if example.evidence != "" {
				fmt.Fprintf(&b, "- Evidence: `%s`\n", example.evidence)
			}
			if example.remediation != "" {
				fmt.Fprintf(&b, "- Remediation: %s\n", example.remediation)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	fmt.Fprintf(&b, "## Recommendations\n\n")
	fmt.Fprintf(&b, "- Skill users: scan before install, treat high and critical findings as review blockers, and prefer pinned versions with known hashes.\n")
	fmt.Fprintf(&b, "- Skill authors: remove shell execution where possible, document every network domain, avoid install-time scripts, and keep secrets out of examples and test files.\n")
	fmt.Fprintf(&b, "- Registry maintainers: prioritize review queues around remote script execution, shell access, obfuscation, plaintext secrets, and repeated unknown egress patterns.\n\n")

	fmt.Fprintf(&b, "## Methodology And Caveats\n\n")
	fmt.Fprintf(&b, "This report is static source analysis, not a malware verdict. Findings are risk signals that should be reviewed with skill intent, version history, and runtime behavior. Dependency vulnerability matches come from advisory data and are not malware verdicts. Evidence is locally redacted before export. Exit code `1` means high or critical findings were detected; exit code `2` means the command failed.\n\n")

	fmt.Fprintf(&b, "## Reproduce\n\n")
	fmt.Fprintf(&b, "- Registry: `%s`\n", result.Registry)
	fmt.Fprintf(&b, "- Source: `%s`\n", registrySourceLabel(result.Source))
	fmt.Fprintf(&b, "- Scanner version: `%s`\n", result.ScannerVersion)
	fmt.Fprintf(&b, "- Generated at: `%s`\n", result.GeneratedAt)

	return b.String(), nil
}

func RenderRegistryJSON(result registry.RegistryScanReport) (string, error) {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload) + "\n", nil
}

func RenderRegistrySARIF(result registry.RegistryScanReport) (string, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifactLocation struct {
		URI string `json:"uri"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		Help             sarifMessage `json:"help"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
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
	run.Tool.Driver.Name = "RunBrake Registry Scan"
	run.Tool.Driver.InformationURI = "https://runbrake.dev"

	seenRules := map[string]bool{}
	for _, skill := range result.Skills {
		for _, finding := range skill.Findings {
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
				RuleID:  finding.RuleID,
				Level:   sarifLevel(finding.Severity),
				Message: sarifMessage{Text: registryFindingMessage(skill, finding)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: registryArtifactURI(result.Registry, skill),
						},
					},
				}},
			})
		}
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

func registrySourceLabel(source registry.RegistrySource) string {
	switch source.Type {
	case registry.SourceGitHub:
		label := string(source.Type)
		if source.URL != "" {
			label += " " + source.URL
		}
		if source.Commit != "" {
			label += " @ " + source.Commit
		}
		if source.MirrorPath != "" {
			label += " (" + source.MirrorPath + ")"
		}
		return label
	case registry.SourceClawHub:
		label := string(source.Type)
		if source.APIBase != "" {
			label += " " + source.APIBase
		}
		return label
	default:
		return string(source.Type)
	}
}

func registrySkillLabel(owner string, slug string, displayName string) string {
	name := slug
	if owner != "" {
		name = owner + "/" + slug
	}
	if strings.TrimSpace(displayName) == "" {
		return name
	}
	return fmt.Sprintf("%s (%s)", name, displayName)
}

func registryFindingMessage(skill registry.RegistrySkillResult, finding doctor.Finding) string {
	prefix := registrySkillLabel(skill.Owner, skill.Slug, skill.DisplayName)
	evidence := strings.Join(finding.Evidence, "; ")
	if evidence == "" {
		return prefix + ": " + finding.Title
	}
	return prefix + ": " + finding.Title + ": " + evidence
}

func registryArtifactURI(registryName string, skill registry.RegistrySkillResult) string {
	registryName = strings.TrimSpace(registryName)
	if registryName == "" {
		registryName = "registry"
	}
	slug := strings.TrimSpace(skill.Slug)
	if slug == "" {
		slug = "unknown"
	}
	if strings.TrimSpace(skill.Owner) != "" {
		return fmt.Sprintf("registry://%s/%s/%s/SKILL.md", registryName, strings.TrimSpace(skill.Owner), slug)
	}
	return fmt.Sprintf("registry://%s/%s/SKILL.md", registryName, slug)
}

type registryFindingExample struct {
	heading     string
	ruleID      string
	severity    doctor.Severity
	title       string
	evidence    string
	remediation string
	score       int
}

func registryFindingExamples(result registry.RegistryScanReport, limit int) []registryFindingExample {
	examples := []registryFindingExample{}
	for _, skill := range result.Skills {
		for _, finding := range skill.Findings {
			examples = append(examples, registryFindingExample{
				heading:     registrySkillLabel(skill.Owner, skill.Slug, skill.DisplayName),
				ruleID:      finding.RuleID,
				severity:    finding.Severity,
				title:       finding.Title,
				evidence:    truncateForMarkdown(firstEvidence(finding.Evidence), 220),
				remediation: finding.Remediation,
				score:       findingExampleScore(finding.Severity, len(skill.Findings), skill.Slug),
			})
		}
	}
	sortRegistryFindingExamples(examples)
	return diverseRegistryFindingExamples(examples, result.TopRules, limit)
}

func sortRegistryFindingExamples(examples []registryFindingExample) {
	sort.SliceStable(examples, func(i, j int) bool {
		if examples[i].score != examples[j].score {
			return examples[i].score > examples[j].score
		}
		if severityRank(examples[i].severity) != severityRank(examples[j].severity) {
			return severityRank(examples[i].severity) < severityRank(examples[j].severity)
		}
		if examples[i].ruleID != examples[j].ruleID {
			return examples[i].ruleID < examples[j].ruleID
		}
		return examples[i].heading < examples[j].heading
	})
}

func diverseRegistryFindingExamples(examples []registryFindingExample, topRules []registry.RegistryRuleCount, limit int) []registryFindingExample {
	if limit <= 0 || len(examples) <= limit {
		return examples
	}
	selected := []registryFindingExample{}
	used := map[int]bool{}

	for _, rule := range topRules {
		if len(selected) >= limit {
			break
		}
		for index, example := range examples {
			if used[index] || example.ruleID != rule.RuleID {
				continue
			}
			selected = append(selected, example)
			used[index] = true
			break
		}
	}

	for index, example := range examples {
		if len(selected) >= limit {
			break
		}
		if used[index] {
			continue
		}
		selected = append(selected, example)
	}
	return selected
}

func firstEvidence(values []string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func truncateForMarkdown(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}

func findingExampleScore(severity doctor.Severity, findingCount int, slug string) int {
	return severityScore(severity)*100000 + findingCount*100 + stableTextScore(slug)
}

func severityScore(severity doctor.Severity) int {
	switch severity {
	case doctor.SeverityCritical:
		return 5
	case doctor.SeverityHigh:
		return 4
	case doctor.SeverityMedium:
		return 3
	case doctor.SeverityLow:
		return 2
	case doctor.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func severityRank(severity doctor.Severity) int {
	return 5 - severityScore(severity)
}

func stableTextScore(value string) int {
	total := 0
	for _, r := range value {
		total += int(r)
	}
	return total % 100
}

func skillPath(owner string, slug string) string {
	if strings.TrimSpace(owner) == "" {
		return slug
	}
	return owner + "/" + slug
}

func percentString(numerator int, denominator int) string {
	if denominator == 0 {
		return "0%"
	}
	value := (float64(numerator) / float64(denominator)) * 100
	return strconv.FormatFloat(value, 'f', 1, 64) + "%"
}
