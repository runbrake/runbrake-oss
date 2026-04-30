package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/skills"
)

const defaultScannerVersion = "0.2.5"

type Finding = doctor.Finding

type RegistrySourceType string

const (
	SourceGitHub       RegistrySourceType = "github"
	SourceHermesGitHub RegistrySourceType = "hermes-github"
	SourceClawHub      RegistrySourceType = "clawhub"
	SourceLocal        RegistrySourceType = "local"
)

type ScanOptions struct {
	Registry              string
	MirrorPath            string
	SourceURL             string
	SourceCommit          string
	WorkDir               string
	APIBase               string
	Limit                 int
	Slugs                 []string
	Workers               int
	DependencyScan        bool
	VulnerabilityProvider string
	OSVAPIBase            string
	CacheDir              string
	ProgressInterval      int
	Progress              func(RegistryProgressEvent)
	Now                   time.Time
	ScannerVersion        string
	HTTPClient            *http.Client
	Timeout               time.Duration
	MaxDownloadBytes      int64
	MaxExtractedBytes     int64
	MaxRelevantFileBytes  int64
	MaxArchiveFiles       int
	AllowDomains          []string
	EgressProfile         string
	Suppressions          []skills.Suppression
}

type RegistryProgressEvent struct {
	Stage   string
	Current int
	Total   int
}

type RegistryScanReport struct {
	ID                 string                       `json:"id"`
	Registry           string                       `json:"registry"`
	Source             RegistrySource               `json:"source"`
	ScannerVersion     string                       `json:"scannerVersion"`
	GeneratedAt        string                       `json:"generatedAt"`
	Summary            RegistryScanSummary          `json:"summary"`
	Skills             []RegistrySkillResult        `json:"skills"`
	TopRules           []RegistryRuleCount          `json:"topRules,omitempty"`
	HighestRisk        []RegistryRiskRow            `json:"highestRisk,omitempty"`
	TopVulnerabilities []RegistryVulnerabilityCount `json:"topVulnerabilities,omitempty"`
}

type RegistrySource struct {
	Type       RegistrySourceType `json:"type"`
	URL        string             `json:"url,omitempty"`
	Commit     string             `json:"commit,omitempty"`
	APIBase    string             `json:"apiBase,omitempty"`
	MirrorPath string             `json:"mirrorPath,omitempty"`
}

type RegistryScanSummary struct {
	Discovered                int `json:"discovered"`
	Scanned                   int `json:"scanned"`
	Skipped                   int `json:"skipped"`
	Clean                     int `json:"clean"`
	Risky                     int `json:"risky"`
	Errors                    int `json:"errors"`
	Critical                  int `json:"critical"`
	High                      int `json:"high"`
	Medium                    int `json:"medium"`
	Low                       int `json:"low"`
	Info                      int `json:"info"`
	Dependencies              int `json:"dependencies,omitempty"`
	VulnerableSkills          int `json:"vulnerableSkills,omitempty"`
	VulnerableDependencies    int `json:"vulnerableDependencies,omitempty"`
	Vulnerabilities           int `json:"vulnerabilities,omitempty"`
	UniqueVulnerabilities     int `json:"uniqueVulnerabilities,omitempty"`
	VulnerabilityCritical     int `json:"vulnerabilityCritical,omitempty"`
	VulnerabilityHigh         int `json:"vulnerabilityHigh,omitempty"`
	VulnerabilityMedium       int `json:"vulnerabilityMedium,omitempty"`
	VulnerabilityLow          int `json:"vulnerabilityLow,omitempty"`
	VulnerabilityUnknown      int `json:"vulnerabilityUnknown,omitempty"`
	VulnerabilityQueryBatches int `json:"vulnerabilityQueryBatches,omitempty"`
}

type RegistrySkillResult struct {
	Owner                     string                   `json:"owner,omitempty"`
	OwnerDisplayName          string                   `json:"ownerDisplayName,omitempty"`
	OwnerUserID               string                   `json:"ownerUserId,omitempty"`
	Slug                      string                   `json:"slug"`
	DisplayName               string                   `json:"displayName,omitempty"`
	Version                   string                   `json:"version,omitempty"`
	PublishedAt               string                   `json:"publishedAt,omitempty"`
	CreatedAt                 string                   `json:"createdAt,omitempty"`
	UpdatedAt                 string                   `json:"updatedAt,omitempty"`
	LatestVersionCreatedAt    string                   `json:"latestVersionCreatedAt,omitempty"`
	Changelog                 string                   `json:"changelog,omitempty"`
	License                   string                   `json:"license,omitempty"`
	VersionCount              int                      `json:"versionCount,omitempty"`
	Downloads                 int                      `json:"downloads,omitempty"`
	InstallsCurrent           int                      `json:"installsCurrent,omitempty"`
	InstallsAllTime           int                      `json:"installsAllTime,omitempty"`
	Stars                     int                      `json:"stars,omitempty"`
	Comments                  int                      `json:"comments,omitempty"`
	Source                    string                   `json:"source,omitempty"`
	SourceURL                 string                   `json:"sourceUrl,omitempty"`
	SourceCommit              string                   `json:"sourceCommit,omitempty"`
	SourcePath                string                   `json:"sourcePath,omitempty"`
	Category                  string                   `json:"category,omitempty"`
	Bundled                   *bool                    `json:"bundled,omitempty"`
	Path                      string                   `json:"path,omitempty"`
	ManifestPath              string                   `json:"manifestPath,omitempty"`
	ArtifactHash              string                   `json:"artifactHash,omitempty"`
	RegistrySecurityStatus    string                   `json:"registrySecurityStatus,omitempty"`
	RegistryHasWarnings       bool                     `json:"registryHasWarnings,omitempty"`
	RegistrySecurityCheckedAt string                   `json:"registrySecurityCheckedAt,omitempty"`
	RegistrySecurityModel     string                   `json:"registrySecurityModel,omitempty"`
	RegistrySecurityHash      string                   `json:"registrySecurityHash,omitempty"`
	RegistryVirusTotalURL     string                   `json:"registryVirusTotalUrl,omitempty"`
	RegistryScannerVerdicts   []RegistryScannerVerdict `json:"registryScannerVerdicts,omitempty"`
	Dependencies              []RegistryDependency     `json:"dependencies,omitempty"`
	Vulnerabilities           []RegistryVulnerability  `json:"vulnerabilities,omitempty"`
	RiskLevel                 string                   `json:"riskLevel"`
	Summary                   doctor.Summary           `json:"summary"`
	FindingCount              int                      `json:"findingCount"`
	Findings                  []Finding                `json:"findings"`
	Error                     string                   `json:"error,omitempty"`
}

type RegistryScannerVerdict struct {
	Scanner    string  `json:"scanner"`
	Status     string  `json:"status,omitempty"`
	Verdict    string  `json:"verdict,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Summary    string  `json:"summary,omitempty"`
	CheckedAt  string  `json:"checkedAt,omitempty"`
}

type RegistryDependency struct {
	Ecosystem    string `json:"ecosystem"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	ManifestPath string `json:"manifestPath,omitempty"`
	Source       string `json:"source,omitempty"`
	Direct       bool   `json:"direct,omitempty"`
	Dev          bool   `json:"dev,omitempty"`
}

type RegistryVulnerability struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases,omitempty"`
	Ecosystem      string   `json:"ecosystem"`
	PackageName    string   `json:"packageName"`
	PackageVersion string   `json:"packageVersion,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	SeverityType   string   `json:"severityType,omitempty"`
	SeverityScore  string   `json:"severityScore,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Published      string   `json:"published,omitempty"`
	Modified       string   `json:"modified,omitempty"`
	FixedVersions  []string `json:"fixedVersions,omitempty"`
	References     []string `json:"references,omitempty"`
}

type RegistryVulnerabilityCount struct {
	ID             string `json:"id"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion,omitempty"`
	Ecosystem      string `json:"ecosystem"`
	Severity       string `json:"severity,omitempty"`
	Summary        string `json:"summary,omitempty"`
	Count          int    `json:"count"`
}

type RegistryRuleCount struct {
	RuleID   string          `json:"ruleId"`
	Severity doctor.Severity `json:"severity"`
	Title    string          `json:"title,omitempty"`
	Count    int             `json:"count"`
}

type RegistryRiskRow struct {
	Owner        string `json:"owner,omitempty"`
	Slug         string `json:"slug"`
	DisplayName  string `json:"displayName,omitempty"`
	RiskLevel    string `json:"riskLevel"`
	FindingCount int    `json:"findingCount"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	Medium       int    `json:"medium"`
	Low          int    `json:"low"`
	Info         int    `json:"info"`
}

type skillMetadata struct {
	Owner                  string
	OwnerDisplayName       string
	OwnerUserID            string
	Slug                   string
	DisplayName            string
	Version                string
	PublishedAt            string
	CreatedAt              string
	UpdatedAt              string
	LatestVersionCreatedAt string
	Changelog              string
	License                string
	VersionCount           int
	Downloads              int
	InstallsCurrent        int
	InstallsAllTime        int
	Stars                  int
	Comments               int
	Source                 string
	SourceURL              string
	SourceCommit           string
	SourcePath             string
	Category               string
	Bundled                *bool
}

func newReport(options ScanOptions, source RegistrySource) RegistryScanReport {
	now := resolvedNow(options.Now)
	scannerVersion := resolvedScannerVersion(options.ScannerVersion)
	registry := strings.TrimSpace(options.Registry)
	if registry == "" {
		registry = "openclaw"
	}

	report := RegistryScanReport{
		Registry:       registry,
		Source:         source,
		ScannerVersion: scannerVersion,
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		Skills:         []RegistrySkillResult{},
	}
	report.ID = "registry-scan-" + shortHash(strings.Join([]string{
		registry,
		string(source.Type),
		source.URL,
		source.APIBase,
		source.Commit,
		report.GeneratedAt,
	}, "|"))
	return report
}

func scanSkillDirectory(options ScanOptions, root string, meta skillMetadata) RegistrySkillResult {
	result := RegistrySkillResult{
		Owner:                  meta.Owner,
		OwnerDisplayName:       meta.OwnerDisplayName,
		OwnerUserID:            meta.OwnerUserID,
		Slug:                   meta.Slug,
		DisplayName:            meta.DisplayName,
		Version:                meta.Version,
		PublishedAt:            meta.PublishedAt,
		CreatedAt:              meta.CreatedAt,
		UpdatedAt:              meta.UpdatedAt,
		LatestVersionCreatedAt: meta.LatestVersionCreatedAt,
		Changelog:              meta.Changelog,
		License:                meta.License,
		VersionCount:           meta.VersionCount,
		Downloads:              meta.Downloads,
		InstallsCurrent:        meta.InstallsCurrent,
		InstallsAllTime:        meta.InstallsAllTime,
		Stars:                  meta.Stars,
		Comments:               meta.Comments,
		Source:                 meta.Source,
		SourceURL:              meta.SourceURL,
		SourceCommit:           meta.SourceCommit,
		SourcePath:             meta.SourcePath,
		Category:               meta.Category,
		Bundled:                meta.Bundled,
		Path:                   root,
		RiskLevel:              "unknown",
		Findings:               []Finding{},
	}

	scan, err := skills.Scan(skills.ScanOptions{
		Target:               root,
		Ecosystem:            scanEcosystem(options),
		Now:                  resolvedNow(options.Now),
		ScannerVersion:       resolvedScannerVersion(options.ScannerVersion),
		HTTPClient:           options.HTTPClient,
		Timeout:              options.Timeout,
		MaxDownloadBytes:     options.MaxDownloadBytes,
		MaxExtractedBytes:    options.MaxExtractedBytes,
		MaxRelevantFileBytes: options.MaxRelevantFileBytes,
		MaxArchiveFiles:      options.MaxArchiveFiles,
		AllowDomains:         options.AllowDomains,
		EgressProfile:        options.EgressProfile,
		Suppressions:         options.Suppressions,
	})
	if err != nil {
		result.RiskLevel = "error"
		result.Error = err.Error()
		return result
	}

	artifact := firstArtifact(scan.Inventory)
	result.DisplayName = firstNonEmpty(result.DisplayName, artifact.ManifestFields["displayName"], artifact.ManifestFields["name"], artifact.Name, result.Slug)
	result.Version = firstNonEmpty(result.Version, artifact.Version)
	result.Source = firstNonEmpty(result.Source, artifact.Source)
	result.Category = firstNonEmpty(result.Category, artifact.ManifestFields["category"])
	result.ManifestPath = artifact.ManifestPath
	result.ArtifactHash = artifact.Hash
	result.Findings = append([]Finding(nil), scan.Report.Findings...)
	if result.Findings == nil {
		result.Findings = []Finding{}
	}
	result.Summary = scan.Report.Summary
	result.FindingCount = len(result.Findings)
	result.RiskLevel = riskLevel(result.Summary)
	if options.DependencyScan || strings.EqualFold(strings.TrimSpace(options.VulnerabilityProvider), "osv") {
		result.Dependencies = ExtractDependencies(root)
	}
	return result
}

func scanEcosystem(options ScanOptions) string {
	if strings.EqualFold(strings.TrimSpace(options.Registry), "hermes") {
		return "hermes"
	}
	return ""
}

func firstArtifact(inventory doctor.Inventory) doctor.Artifact {
	if len(inventory.Skills) > 0 {
		return inventory.Skills[0]
	}
	if len(inventory.Plugins) > 0 {
		return inventory.Plugins[0]
	}
	return doctor.Artifact{}
}

func aggregateSkill(report *RegistryScanReport, skill RegistrySkillResult) {
	report.Summary.Scanned++
	if skill.Error != "" {
		report.Summary.Errors++
	}
	if skill.Error == "" && len(skill.Findings) == 0 {
		report.Summary.Clean++
	}
	if len(skill.Findings) > 0 {
		report.Summary.Risky++
	}
	addSeveritySummary(&report.Summary, skill.Summary)
	report.Skills = append(report.Skills, skill)
}

func finishReport(report *RegistryScanReport) {
	refreshRegistryEnrichmentSummary(report)
	report.TopRules = topRules(report.Skills)
	report.HighestRisk = highestRisk(report.Skills)
	report.TopVulnerabilities = topVulnerabilities(report.Skills)
	sort.SliceStable(report.Skills, func(i, j int) bool {
		if report.Skills[i].Owner != report.Skills[j].Owner {
			return report.Skills[i].Owner < report.Skills[j].Owner
		}
		return report.Skills[i].Slug < report.Skills[j].Slug
	})
}

func emitProgress(options ScanOptions, stage string, current int, total int) {
	if options.Progress == nil {
		return
	}
	interval := options.ProgressInterval
	if interval <= 0 {
		interval = 100
	}
	if current <= 0 || total <= 0 {
		return
	}
	if current != total && current%interval != 0 {
		return
	}
	options.Progress(RegistryProgressEvent{
		Stage:   stage,
		Current: current,
		Total:   total,
	})
}

func refreshRegistryEnrichmentSummary(report *RegistryScanReport) {
	report.Summary.Dependencies = 0
	report.Summary.VulnerableSkills = 0
	report.Summary.VulnerableDependencies = 0
	report.Summary.Vulnerabilities = 0
	report.Summary.UniqueVulnerabilities = 0
	report.Summary.VulnerabilityCritical = 0
	report.Summary.VulnerabilityHigh = 0
	report.Summary.VulnerabilityMedium = 0
	report.Summary.VulnerabilityLow = 0
	report.Summary.VulnerabilityUnknown = 0

	uniqueVulns := map[string]bool{}
	for _, skill := range report.Skills {
		report.Summary.Dependencies += len(skill.Dependencies)
		if len(skill.Vulnerabilities) == 0 {
			continue
		}
		report.Summary.VulnerableSkills++
		deps := map[string]bool{}
		for _, vuln := range skill.Vulnerabilities {
			key := vuln.Ecosystem + "|" + vuln.PackageName + "|" + vuln.PackageVersion
			deps[key] = true
			uniqueVulns[vuln.ID] = true
			report.Summary.Vulnerabilities++
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				report.Summary.VulnerabilityCritical++
			case "high":
				report.Summary.VulnerabilityHigh++
			case "medium", "moderate":
				report.Summary.VulnerabilityMedium++
			case "low":
				report.Summary.VulnerabilityLow++
			default:
				report.Summary.VulnerabilityUnknown++
			}
		}
		report.Summary.VulnerableDependencies += len(deps)
	}
	report.Summary.UniqueVulnerabilities = len(uniqueVulns)
}

func addSeveritySummary(total *RegistryScanSummary, summary doctor.Summary) {
	total.Critical += summary.Critical
	total.High += summary.High
	total.Medium += summary.Medium
	total.Low += summary.Low
	total.Info += summary.Info
}

func topRules(skills []RegistrySkillResult) []RegistryRuleCount {
	byRule := map[string]RegistryRuleCount{}
	for _, skill := range skills {
		for _, finding := range skill.Findings {
			count := byRule[finding.RuleID]
			count.RuleID = finding.RuleID
			count.Title = firstNonEmpty(count.Title, finding.Title)
			count.Count++
			if severityRank(finding.Severity) < severityRank(count.Severity) {
				count.Severity = finding.Severity
			}
			byRule[finding.RuleID] = count
		}
	}

	out := make([]RegistryRuleCount, 0, len(byRule))
	for _, count := range byRule {
		out = append(out, count)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func highestRisk(skills []RegistrySkillResult) []RegistryRiskRow {
	rows := []RegistryRiskRow{}
	for _, skill := range skills {
		if len(skill.Findings) == 0 {
			continue
		}
		rows = append(rows, RegistryRiskRow{
			Owner:        skill.Owner,
			Slug:         skill.Slug,
			DisplayName:  skill.DisplayName,
			RiskLevel:    skill.RiskLevel,
			FindingCount: len(skill.Findings),
			Critical:     skill.Summary.Critical,
			High:         skill.Summary.High,
			Medium:       skill.Summary.Medium,
			Low:          skill.Summary.Low,
			Info:         skill.Summary.Info,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if riskScore(rows[i]) != riskScore(rows[j]) {
			return riskScore(rows[i]) > riskScore(rows[j])
		}
		if rows[i].FindingCount != rows[j].FindingCount {
			return rows[i].FindingCount > rows[j].FindingCount
		}
		if rows[i].Owner != rows[j].Owner {
			return rows[i].Owner < rows[j].Owner
		}
		return rows[i].Slug < rows[j].Slug
	})
	if len(rows) > 100 {
		return rows[:100]
	}
	return rows
}

func topVulnerabilities(skills []RegistrySkillResult) []RegistryVulnerabilityCount {
	byVuln := map[string]RegistryVulnerabilityCount{}
	for _, skill := range skills {
		for _, vuln := range skill.Vulnerabilities {
			key := strings.Join([]string{vuln.ID, vuln.Ecosystem, vuln.PackageName, vuln.PackageVersion}, "|")
			count := byVuln[key]
			count.ID = vuln.ID
			count.Ecosystem = vuln.Ecosystem
			count.PackageName = vuln.PackageName
			count.PackageVersion = vuln.PackageVersion
			count.Severity = firstNonEmpty(count.Severity, vuln.Severity)
			count.Summary = firstNonEmpty(count.Summary, vuln.Summary)
			count.Count++
			byVuln[key] = count
		}
	}
	out := make([]RegistryVulnerabilityCount, 0, len(byVuln))
	for _, count := range byVuln {
		out = append(out, count)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityLabelRank(out[i].Severity) != severityLabelRank(out[j].Severity) {
			return severityLabelRank(out[i].Severity) < severityLabelRank(out[j].Severity)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > 100 {
		return out[:100]
	}
	return out
}

func riskScore(row RegistryRiskRow) int {
	return row.Critical*10000 + row.High*1000 + row.Medium*100 + row.Low*10 + row.Info
}

func riskLevel(summary doctor.Summary) string {
	switch {
	case summary.Critical > 0 || summary.High > 0:
		return "high"
	case summary.Medium > 0:
		return "medium"
	case summary.Low > 0:
		return "low"
	case summary.Info > 0:
		return "info"
	default:
		return "clean"
	}
}

func severityRank(severity doctor.Severity) int {
	switch severity {
	case doctor.SeverityCritical:
		return 0
	case doctor.SeverityHigh:
		return 1
	case doctor.SeverityMedium:
		return 2
	case doctor.SeverityLow:
		return 3
	case doctor.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func severityLabelRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium", "moderate":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func resolvedNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func resolvedScannerVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return defaultScannerVersion
	}
	return version
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func appendError(existing string, err error) string {
	if err == nil {
		return existing
	}
	if existing == "" {
		return err.Error()
	}
	return fmt.Sprintf("%s; %s", existing, err.Error())
}
