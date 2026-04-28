package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/runbrake/runbrake-oss/internal/registry"
)

type RegistryReportPackOptions struct {
	OutputDir         string
	Title             string
	TopSkillLimit     int
	ExampleSkillLimit int
}

type RegistryReportPackManifest struct {
	OutputDir string   `json:"outputDir"`
	Files     []string `json:"files"`
}

func WriteRegistryReportPack(result registry.RegistryScanReport, options RegistryReportPackOptions) (RegistryReportPackManifest, error) {
	outputDir := strings.TrimSpace(options.OutputDir)
	if outputDir == "" {
		return RegistryReportPackManifest{}, fmt.Errorf("report pack output dir is required")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("create report pack dir: %w", err)
	}

	manifest := RegistryReportPackManifest{OutputDir: outputDir}
	write := func(name string, payload []byte) error {
		path := filepath.Join(outputDir, name)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, path)
		return nil
	}

	markdown, err := RenderRegistryEcosystemMarkdown(result, RegistryEcosystemReportOptions{
		Title:             options.Title,
		TopSkillLimit:     options.TopSkillLimit,
		ExampleSkillLimit: options.ExampleSkillLimit,
	})
	if err != nil {
		return RegistryReportPackManifest{}, err
	}
	if err := write("report.md", []byte(markdown)); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("write report.md: %w", err)
	}

	topSkills, err := topSkillsCSV(result)
	if err != nil {
		return RegistryReportPackManifest{}, err
	}
	if err := write("top-skills.csv", topSkills); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("write top-skills.csv: %w", err)
	}

	topVulns, err := topVulnerabilitiesCSV(result)
	if err != nil {
		return RegistryReportPackManifest{}, err
	}
	if err := write("top-vulnerabilities.csv", topVulns); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("write top-vulnerabilities.csv: %w", err)
	}

	summary, err := json.MarshalIndent(result.Summary, "", "  ")
	if err != nil {
		return RegistryReportPackManifest{}, err
	}
	if err := write("summary.json", append(summary, '\n')); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("write summary.json: %w", err)
	}

	readme := reportPackReadme(result)
	if err := write("README.md", []byte(readme)); err != nil {
		return RegistryReportPackManifest{}, fmt.Errorf("write README.md: %w", err)
	}

	return manifest, nil
}

func topSkillsCSV(result registry.RegistryScanReport) ([]byte, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"owner", "slug", "display_name", "risk_level", "findings", "critical", "high", "medium", "low", "info"}); err != nil {
		return nil, err
	}
	for _, row := range result.HighestRisk {
		if err := w.Write([]string{
			row.Owner,
			row.Slug,
			row.DisplayName,
			row.RiskLevel,
			strconv.Itoa(row.FindingCount),
			strconv.Itoa(row.Critical),
			strconv.Itoa(row.High),
			strconv.Itoa(row.Medium),
			strconv.Itoa(row.Low),
			strconv.Itoa(row.Info),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func topVulnerabilitiesCSV(result registry.RegistryScanReport) ([]byte, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"id", "ecosystem", "package_name", "package_version", "severity", "count", "summary"}); err != nil {
		return nil, err
	}
	for _, row := range result.TopVulnerabilities {
		if err := w.Write([]string{
			row.ID,
			row.Ecosystem,
			row.PackageName,
			row.PackageVersion,
			row.Severity,
			strconv.Itoa(row.Count),
			row.Summary,
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func reportPackReadme(result registry.RegistryScanReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# RunBrake Registry Report Pack\n\n")
	fmt.Fprintf(&b, "Generated from registry scan `%s` at `%s`.\n\n", result.ID, result.GeneratedAt)
	fmt.Fprintf(&b, "Files:\n\n")
	fmt.Fprintf(&b, "- `report.md`: publication-oriented Markdown report.\n")
	fmt.Fprintf(&b, "- `top-skills.csv`: highest-risk skill rows for spreadsheet review.\n")
	fmt.Fprintf(&b, "- `top-vulnerabilities.csv`: top OSV/advisory rows for spreadsheet review.\n")
	fmt.Fprintf(&b, "- `summary.json`: machine-readable aggregate counts.\n")
	fmt.Fprintf(&b, "\nDependency vulnerability matches are advisory data and are not malware verdicts.\n")
	return b.String()
}
