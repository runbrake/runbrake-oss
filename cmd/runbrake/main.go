package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/config"
	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/registry"
	"github.com/runbrake/runbrake-oss/internal/report"
	"github.com/runbrake/runbrake-oss/internal/skills"
	watchpkg "github.com/runbrake/runbrake-oss/internal/watch"
)

var version = "0.0.0-dev"

var defaultRegistryArchiveDir = filepath.Join("reports", "registry")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, osEnviron(), userHomeDir(), time.Now().UTC()))
}

func run(args []string, stdout io.Writer, stderr io.Writer, env map[string]string, homeDir string, now time.Time) int {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if fixed := env["RUNBRAKE_FIXED_TIME"]; fixed != "" {
		parsed, err := time.Parse(time.RFC3339, fixed)
		if err != nil {
			fmt.Fprintf(stderr, "invalid RUNBRAKE_FIXED_TIME: %v\n", err)
			return 2
		}
		now = parsed
	}

	if len(args) == 0 {
		cfg := config.Default()
		fmt.Fprintf(stdout, "%s %s\n", cfg.ProductName, version)
		return 0
	}

	switch args[0] {
	case "doctor":
		return runDoctor(args[1:], stdout, stderr, env, homeDir, now)
	case "export-report":
		return runExportReport(args[1:], stdout, stderr, env, homeDir, now)
	case "scan-skill":
		return runSkillScan(args[1:], stdout, stderr, now, false)
	case "scan-skills":
		return runSkillScan(args[1:], stdout, stderr, now, true)
	case "assess":
		return runAssess(args[1:], stdout, stderr, env, homeDir, now)
	case "watch-openclaw":
		return runWatchOpenClaw(args[1:], stdout, stderr, env, homeDir, now)
	case "scan-registry":
		return runRegistryScan(args[1:], stdout, stderr, now)
	case "summarize-registry-report":
		return runSummarizeRegistryReport(args[1:], stdout, stderr)
	case "registry-report-pack":
		return runRegistryReportPack(args[1:], stdout, stderr)
	case "diff-scan-report":
		return runDiffScanReport(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runWatchOpenClaw(args []string, stdout io.Writer, stderr io.Writer, env map[string]string, homeDir string, now time.Time) int {
	flags := flag.NewFlagSet("watch-openclaw", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "OpenClaw install path")
	statePath := flags.String("state", "", "watch state file path")
	once := flags.Bool("once", false, "run one deterministic watch scan and exit")
	format := flags.String("format", "console", "report format: console or json")
	var allowDomains multiStringFlag
	flags.Var(&allowDomains, "allow-domain", "additional allowed egress domain; may be repeated")
	egressProfile := flags.String("egress-profile", "balanced", "egress profile: balanced or audit")
	suppressionsPath := flags.String("suppressions", "", "JSON suppression file with reason and optional expiry")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "watch-openclaw received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	if !*once {
		fmt.Fprintln(stderr, "watch-openclaw currently requires --once")
		return 2
	}

	root := strings.TrimSpace(*path)
	if root == "" {
		discovered, err := doctor.DiscoverRoot(doctor.DiscoverOptions{
			Env:     env,
			HomeDir: homeDir,
		})
		if err != nil {
			fmt.Fprintf(stderr, "watch-openclaw failed: %v\n", err)
			return 2
		}
		root = discovered
	} else if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(stderr, "watch-openclaw failed: %v\n", err)
		return 2
	}
	suppressions, err := loadSuppressionsFile(*suppressionsPath)
	if err != nil {
		fmt.Fprintf(stderr, "load suppressions: %v\n", err)
		return 2
	}
	result, err := watchpkg.Scan(watchpkg.ScanOptions{
		Root:           root,
		StatePath:      *statePath,
		WriteState:     true,
		ScannerVersion: version,
		Now:            now,
		AllowDomains:   append([]string(nil), allowDomains...),
		EgressProfile:  *egressProfile,
		Suppressions:   suppressions,
	})
	if err != nil {
		fmt.Fprintf(stderr, "watch-openclaw failed: %v\n", err)
		return 2
	}
	rendered, err := renderWatchFormat(*format, result)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if _, err := io.WriteString(stdout, rendered); err != nil {
		fmt.Fprintf(stderr, "write watch output: %v\n", err)
		return 2
	}
	if result.HasCriticalRisk() {
		return 1
	}
	return 0
}

func runRegistryScan(args []string, stdout io.Writer, stderr io.Writer, now time.Time) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "scan-registry requires a registry name")
		return 2
	}
	registryName := strings.ToLower(strings.TrimSpace(args[0]))
	if registryName != "openclaw" {
		fmt.Fprintf(stderr, "unsupported registry %q; only openclaw is supported\n", args[0])
		return 2
	}

	flags := flag.NewFlagSet("scan-registry", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", string(registry.SourceGitHub), "registry source: github or clawhub")
	repo := flags.String("repo", registry.DefaultOpenClawSkillsRepo, "GitHub skills repository URL")
	mirrorPath := flags.String("mirror-path", "", "existing local GitHub mirror path")
	workDir := flags.String("workdir", filepath.Join(".cache", "runbrake", "registries", "openclaw-skills"), "local GitHub mirror workdir")
	apiBase := flags.String("api-base", registry.DefaultClawHubAPIBase, "ClawHub API base URL")
	limit := flags.Int("limit", 1000, "maximum skills to scan")
	slugs := flags.String("slugs", "", "comma-separated skill slugs or owner/slug pairs")
	workers := flags.Int("workers", 1, "parallel GitHub mirror scan workers")
	dependencyScan := flags.Bool("dependency-scan", false, "extract dependency inventory from supported manifests and lockfiles")
	vuln := flags.String("vuln", "none", "vulnerability enrichment provider: none or osv")
	osvAPIBase := flags.String("osv-api-base", registry.DefaultOSVAPIBase, "OSV API base URL")
	cacheDir := flags.String("cache-dir", "", "cache directory for resume-safe enrichment responses")
	progress := flags.Bool("progress", false, "print scan and enrichment progress to stderr")
	progressInterval := flags.Int("progress-interval", 100, "progress interval for scanned skills")
	failOn := flags.String("fail-on", "high", "exit 1 threshold: none, low, medium, high, or critical")
	var allowDomains multiStringFlag
	flags.Var(&allowDomains, "allow-domain", "additional allowed egress domain; may be repeated")
	egressProfile := flags.String("egress-profile", "balanced", "egress profile: balanced or audit")
	suppressionsPath := flags.String("suppressions", "", "JSON suppression file with reason and optional expiry")
	timeout := flags.Duration("timeout", 15*time.Second, "remote scanner request timeout")
	maxDownloadBytes := flags.Int64("max-download-bytes", 10<<20, "maximum remote skill download bytes")
	maxExtractedBytes := flags.Int64("max-extracted-bytes", 50<<20, "maximum extracted remote ZIP bytes")
	maxRelevantFileBytes := flags.Int64("max-file-bytes", 5<<20, "maximum relevant file bytes read by skill scanner")
	maxArchiveFiles := flags.Int("max-archive-files", 2048, "maximum files extracted from a remote ZIP")
	format := flags.String("format", "summary", "report format: summary, json, sarif")
	output := flags.String("output", "", "write report to file")
	archiveDir := flags.String("archive-dir", defaultRegistryArchiveDir, "also save registry artifacts under this repo directory; use none to disable")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "scan-registry received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	failThreshold, err := parseFailThreshold(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	suppressions, suppressionsErr := loadSuppressionsFile(*suppressionsPath)
	if suppressionsErr != nil {
		fmt.Fprintf(stderr, "load suppressions: %v\n", suppressionsErr)
		return 2
	}

	options := registry.ScanOptions{
		Registry:              registryName,
		MirrorPath:            *mirrorPath,
		SourceURL:             *repo,
		WorkDir:               *workDir,
		APIBase:               *apiBase,
		Limit:                 *limit,
		Slugs:                 splitCSV(*slugs),
		Workers:               *workers,
		DependencyScan:        *dependencyScan,
		VulnerabilityProvider: *vuln,
		OSVAPIBase:            *osvAPIBase,
		CacheDir:              *cacheDir,
		ProgressInterval:      *progressInterval,
		Now:                   now,
		ScannerVersion:        version,
		Timeout:               *timeout,
		MaxDownloadBytes:      *maxDownloadBytes,
		MaxExtractedBytes:     *maxExtractedBytes,
		MaxRelevantFileBytes:  *maxRelevantFileBytes,
		MaxArchiveFiles:       *maxArchiveFiles,
		AllowDomains:          append([]string(nil), allowDomains...),
		EgressProfile:         *egressProfile,
		Suppressions:          suppressions,
	}
	if *progress {
		options.Progress = func(event registry.RegistryProgressEvent) {
			printRegistryProgress(stderr, event)
		}
	}

	var result registry.RegistryScanReport
	switch strings.ToLower(strings.TrimSpace(*source)) {
	case string(registry.SourceGitHub):
		result, err = registry.ScanGitHub(options)
	case string(registry.SourceClawHub):
		result, err = registry.ScanClawHubAPI(options)
	default:
		fmt.Fprintf(stderr, "unsupported registry source %q\n", *source)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "scan-registry failed: %v\n", err)
		return 2
	}

	rendered, err := renderRegistryFormat(*format, result)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 2
	}
	if strings.TrimSpace(*output) != "" {
		archivedDir, err := archiveRegistryScanOutput(result, *format, rendered, *archiveDir)
		if err != nil {
			fmt.Fprintf(stderr, "archive registry output: %v\n", err)
			return 2
		}
		if archivedDir != "" {
			fmt.Fprintf(stderr, "registry artifacts archived to %s\n", archivedDir)
		}
	}

	shouldFail := registryMeetsFailThreshold(result, failThreshold)
	printRegistryExitExplanation(stderr, result, *output, failThreshold, shouldFail)
	if shouldFail {
		return 1
	}
	return 0
}

func runAssess(args []string, stdout io.Writer, stderr io.Writer, env map[string]string, homeDir string, now time.Time) int {
	flags := flag.NewFlagSet("assess", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "OpenClaw install path")
	statePath := flags.String("state", "", "watch state file path")
	format := flags.String("format", "markdown", "assessment format: markdown or json")
	output := flags.String("output", "", "write assessment to file")
	var allowDomains multiStringFlag
	flags.Var(&allowDomains, "allow-domain", "additional allowed egress domain; may be repeated")
	egressProfile := flags.String("egress-profile", "balanced", "egress profile: balanced or audit")
	suppressionsPath := flags.String("suppressions", "", "JSON suppression file with reason and optional expiry")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "assess received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	root, err := doctor.DiscoverRoot(doctor.DiscoverOptions{
		ExplicitPath: *path,
		Env:          env,
		HomeDir:      homeDir,
	})
	if err != nil {
		fmt.Fprintf(stderr, "assess failed: %v\n", err)
		return 2
	}
	suppressions, suppressionsErr := loadSuppressionsFile(*suppressionsPath)
	if suppressionsErr != nil {
		fmt.Fprintf(stderr, "load suppressions: %v\n", suppressionsErr)
		return 2
	}
	doctorResult, err := doctor.Scan(doctor.ScanOptions{
		Root:           root,
		Now:            now,
		ScannerVersion: version,
	})
	if err != nil {
		fmt.Fprintf(stderr, "assess doctor failed: %v\n", err)
		return 2
	}
	skillResult, err := skills.ScanMany(skills.ScanOptions{
		Target:         root,
		Now:            now,
		ScannerVersion: version,
		AllowDomains:   append([]string(nil), allowDomains...),
		EgressProfile:  *egressProfile,
		Suppressions:   suppressions,
	})
	if err != nil {
		if strings.Contains(err.Error(), "no skill or plugin manifests found") {
			skillResult = emptySkillScanResult(root, now)
		} else {
			fmt.Fprintf(stderr, "assess skill scan failed: %v\n", err)
			return 2
		}
	}
	watchResult, err := watchpkg.Scan(watchpkg.ScanOptions{
		Root:           root,
		StatePath:      *statePath,
		WriteState:     true,
		ScannerVersion: version,
		Now:            now,
		AllowDomains:   append([]string(nil), allowDomains...),
		EgressProfile:  *egressProfile,
		Suppressions:   suppressions,
	})
	if err != nil {
		fmt.Fprintf(stderr, "assess watch failed: %v\n", err)
		return 2
	}
	bundle := assessmentBundle{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Root:        root,
		Doctor:      doctorResult.Report,
		Skills:      skillResult.Report,
		Watch:       watchResult,
	}
	rendered, err := renderAssessmentFormat(*format, bundle)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write assessment: %v\n", err)
		return 2
	}
	if hasHighRiskFinding(doctorResult.Report.Findings) || hasHighRiskFinding(skillResult.Report.Findings) || watchHasHighRisk(watchResult) {
		return 1
	}
	return 0
}

func runDiffScanReport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("diff-scan-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baselinePath := flags.String("baseline", "", "baseline scan JSON report")
	currentPath := flags.String("current", "", "current scan JSON report")
	format := flags.String("format", "markdown", "diff format: markdown or json")
	output := flags.String("output", "", "write diff to file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "diff-scan-report received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	if strings.TrimSpace(*baselinePath) == "" || strings.TrimSpace(*currentPath) == "" {
		fmt.Fprintln(stderr, "diff-scan-report requires --baseline <json> and --current <json>")
		return 2
	}
	baseline, err := readScanReport(*baselinePath)
	if err != nil {
		fmt.Fprintf(stderr, "read baseline: %v\n", err)
		return 2
	}
	current, err := readScanReport(*currentPath)
	if err != nil {
		fmt.Fprintf(stderr, "read current: %v\n", err)
		return 2
	}
	diff := report.DiffScanReports(baseline, current)
	rendered, err := renderDiffFormat(*format, diff)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write diff: %v\n", err)
		return 2
	}
	if diff.HasAddedHighRisk() {
		return 1
	}
	return 0
}

func runSummarizeRegistryReport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("summarize-registry-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "registry JSON report path")
	format := flags.String("format", "markdown", "summary format: markdown")
	output := flags.String("output", "", "write summary to file")
	title := flags.String("title", "OpenClaw Public Skills Risk Report", "Markdown report title")
	topSkills := flags.Int("top-skills", 25, "maximum highest-risk skills to include")
	examples := flags.Int("examples", 25, "maximum evidence samples to include")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "summarize-registry-report received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	if strings.TrimSpace(*input) == "" {
		fmt.Fprintln(stderr, "summarize-registry-report requires --input <registry-json>")
		return 2
	}
	if strings.ToLower(strings.TrimSpace(*format)) != "markdown" {
		fmt.Fprintf(stderr, "unsupported registry summary format %q\n", *format)
		return 2
	}

	payload, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(stderr, "read registry report: %v\n", err)
		return 2
	}
	var result registry.RegistryScanReport
	if err := json.Unmarshal(payload, &result); err != nil {
		fmt.Fprintf(stderr, "parse registry report JSON: %v\n", err)
		return 2
	}

	rendered, err := report.RenderRegistryEcosystemMarkdown(result, report.RegistryEcosystemReportOptions{
		Title:             *title,
		TopSkillLimit:     *topSkills,
		ExampleSkillLimit: *examples,
	})
	if err != nil {
		fmt.Fprintf(stderr, "render registry summary: %v\n", err)
		return 2
	}
	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 2
	}
	if strings.TrimSpace(*output) != "" {
		fmt.Fprintf(stderr, "registry ecosystem report written to %s\n", *output)
	}
	return 0
}

func runRegistryReportPack(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("registry-report-pack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "registry JSON report path")
	outputDir := flags.String("output-dir", "", "directory for generated report pack")
	title := flags.String("title", "OpenClaw Public Skills Risk Report", "Markdown report title")
	topSkills := flags.Int("top-skills", 25, "maximum highest-risk skills to include")
	examples := flags.Int("examples", 25, "maximum evidence samples to include")
	archiveDir := flags.String("archive-dir", defaultRegistryArchiveDir, "also save registry report pack under this repo directory; use none to disable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "registry-report-pack received unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}
	if strings.TrimSpace(*input) == "" {
		fmt.Fprintln(stderr, "registry-report-pack requires --input <registry-json>")
		return 2
	}
	if strings.TrimSpace(*outputDir) == "" {
		fmt.Fprintln(stderr, "registry-report-pack requires --output-dir <dir>")
		return 2
	}

	payload, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(stderr, "read registry report: %v\n", err)
		return 2
	}
	var result registry.RegistryScanReport
	if err := json.Unmarshal(payload, &result); err != nil {
		fmt.Fprintf(stderr, "parse registry report JSON: %v\n", err)
		return 2
	}

	manifest, err := report.WriteRegistryReportPack(result, report.RegistryReportPackOptions{
		OutputDir:         *outputDir,
		Title:             *title,
		TopSkillLimit:     *topSkills,
		ExampleSkillLimit: *examples,
	})
	if err != nil {
		fmt.Fprintf(stderr, "write registry report pack: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "registry report pack written to %s (%d files)\n", manifest.OutputDir, len(manifest.Files))
	archivedDir, err := archiveRegistryReportPack(result, payload, manifest.OutputDir, *archiveDir)
	if err != nil {
		fmt.Fprintf(stderr, "archive registry report pack: %v\n", err)
		return 2
	}
	if archivedDir != "" {
		fmt.Fprintf(stderr, "registry report pack archived to %s\n", archivedDir)
	}
	return 0
}

func runSkillScan(args []string, stdout io.Writer, stderr io.Writer, now time.Time, many bool) int {
	command := "scan-skill"
	targetLabel := "a skill path or URL"
	if many {
		command = "scan-skills"
		targetLabel = "a skills directory"
	}

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "console", "report format: console, markdown, json, sarif")
	output := flags.String("output", "", "write report to file")
	var allowDomains multiStringFlag
	flags.Var(&allowDomains, "allow-domain", "additional allowed egress domain; may be repeated")
	egressProfile := flags.String("egress-profile", "balanced", "egress profile: balanced or audit")
	suppressionsPath := flags.String("suppressions", "", "JSON suppression file with reason and optional expiry")
	timeout := flags.Duration("timeout", 15*time.Second, "remote scanner request timeout")
	maxDownloadBytes := flags.Int64("max-download-bytes", 10<<20, "maximum remote skill download bytes")
	maxExtractedBytes := flags.Int64("max-extracted-bytes", 50<<20, "maximum extracted remote ZIP bytes")
	maxRelevantFileBytes := flags.Int64("max-file-bytes", 5<<20, "maximum relevant file bytes read by skill scanner")
	maxArchiveFiles := flags.Int("max-archive-files", 2048, "maximum files extracted from a remote ZIP")
	dependencyScan := flags.Bool("dependency-scan", false, "extract dependency inventory from supported manifests and lockfiles")
	vulnProvider := flags.String("vuln", "none", "vulnerability provider: none or osv")
	osvAPIBase := flags.String("osv-api-base", registry.DefaultOSVAPIBase, "OSV API base URL")
	cacheDir := flags.String("cache-dir", "", "cache directory for vulnerability enrichment")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if flags.NArg() != 1 {
		fmt.Fprintf(stderr, "%s requires %s\n", command, targetLabel)
		return 2
	}

	suppressions, suppressionsErr := loadSuppressionsFile(*suppressionsPath)
	if suppressionsErr != nil {
		fmt.Fprintf(stderr, "load suppressions: %v\n", suppressionsErr)
		return 2
	}

	options := skills.ScanOptions{
		Target:               flags.Arg(0),
		Now:                  now,
		ScannerVersion:       version,
		Timeout:              *timeout,
		MaxDownloadBytes:     *maxDownloadBytes,
		MaxExtractedBytes:    *maxExtractedBytes,
		MaxRelevantFileBytes: *maxRelevantFileBytes,
		MaxArchiveFiles:      *maxArchiveFiles,
		AllowDomains:         append([]string(nil), allowDomains...),
		EgressProfile:        *egressProfile,
		Suppressions:         suppressions,
	}

	var result skills.Result
	var err error
	if many {
		result, err = skills.ScanMany(options)
	} else {
		result, err = skills.Scan(options)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s failed: %v\n", command, err)
		return 2
	}

	if *dependencyScan || strings.EqualFold(strings.TrimSpace(*vulnProvider), "osv") {
		enriched, err := registry.ScanLocal(registry.ScanOptions{
			Registry:              "local",
			DependencyScan:        *dependencyScan,
			VulnerabilityProvider: *vulnProvider,
			OSVAPIBase:            *osvAPIBase,
			CacheDir:              *cacheDir,
			Now:                   now,
			ScannerVersion:        version,
			HTTPClient:            options.HTTPClient,
			Timeout:               options.Timeout,
			MaxDownloadBytes:      options.MaxDownloadBytes,
			MaxExtractedBytes:     options.MaxExtractedBytes,
			MaxRelevantFileBytes:  options.MaxRelevantFileBytes,
			MaxArchiveFiles:       options.MaxArchiveFiles,
			AllowDomains:          options.AllowDomains,
			EgressProfile:         options.EgressProfile,
			Suppressions:          options.Suppressions,
		}, flags.Arg(0), many)
		if err != nil {
			fmt.Fprintf(stderr, "%s enrichment failed: %v\n", command, err)
			return 2
		}
		applyLocalEnrichment(&result, enriched)
	}

	rendered, err := renderFormat(*format, result)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 2
	}

	if hasHighRiskFinding(result.Report.Findings) {
		return 1
	}
	return 0
}

func applyLocalEnrichment(result *skills.Result, enriched registry.RegistryScanReport) {
	for _, skill := range enriched.Skills {
		for _, dependency := range skill.Dependencies {
			result.Report.Dependencies = append(result.Report.Dependencies, doctor.Dependency{
				Ecosystem:    dependency.Ecosystem,
				Name:         dependency.Name,
				Version:      dependency.Version,
				ManifestPath: dependency.ManifestPath,
				Source:       dependency.Source,
				Direct:       dependency.Direct,
				Dev:          dependency.Dev,
			})
		}
		for _, vulnerability := range skill.Vulnerabilities {
			result.Report.Vulnerabilities = append(result.Report.Vulnerabilities, doctor.Vulnerability{
				ID:             vulnerability.ID,
				Aliases:        append([]string(nil), vulnerability.Aliases...),
				Ecosystem:      vulnerability.Ecosystem,
				PackageName:    vulnerability.PackageName,
				PackageVersion: vulnerability.PackageVersion,
				Severity:       vulnerability.Severity,
				SeverityType:   vulnerability.SeverityType,
				SeverityScore:  vulnerability.SeverityScore,
				Summary:        vulnerability.Summary,
				Published:      vulnerability.Published,
				Modified:       vulnerability.Modified,
				FixedVersions:  append([]string(nil), vulnerability.FixedVersions...),
				References:     append([]string(nil), vulnerability.References...),
			})
			result.Report.Findings = append(result.Report.Findings, vulnerabilityFinding(skill, vulnerability))
		}
	}
	result.Report.Summary = summarizeFindings(result.Report.Findings)
}

func vulnerabilityFinding(skill registry.RegistrySkillResult, vulnerability registry.RegistryVulnerability) doctor.Finding {
	severity := vulnerabilitySeverity(vulnerability.Severity)
	evidence := fmt.Sprintf("%s@%s %s affects %s/%s",
		vulnerability.PackageName,
		vulnerability.PackageVersion,
		displayValue(vulnerability.ID),
		displayValue(skill.Owner),
		displayValue(skill.Slug),
	)
	if strings.TrimSpace(vulnerability.Summary) != "" {
		evidence += ": " + vulnerability.Summary
	}
	return doctor.Finding{
		ID:          "finding-" + shortTextHash(strings.Join([]string{skills.RuleVulnerableDependency, skill.Slug, vulnerability.ID, vulnerability.PackageName, vulnerability.PackageVersion}, "|")),
		RuleID:      skills.RuleVulnerableDependency,
		Severity:    severity,
		Confidence:  0.92,
		Title:       "Skill depends on a package with known vulnerabilities",
		Evidence:    []string{evidence},
		Remediation: "Recommended policy: quarantine. Upgrade the vulnerable dependency to a fixed version or remove it before installation.",
	}
}

func vulnerabilitySeverity(label string) doctor.Severity {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return doctor.SeverityCritical
	case "high":
		return doctor.SeverityHigh
	case "medium", "moderate":
		return doctor.SeverityMedium
	case "low":
		return doctor.SeverityLow
	default:
		return doctor.SeverityInfo
	}
}

func summarizeFindings(findings []doctor.Finding) doctor.Summary {
	var summary doctor.Summary
	for _, finding := range findings {
		switch finding.Severity {
		case doctor.SeverityCritical:
			summary.Critical++
		case doctor.SeverityHigh:
			summary.High++
		case doctor.SeverityMedium:
			summary.Medium++
		case doctor.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}

func shortTextHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func runDoctor(args []string, stdout io.Writer, stderr io.Writer, env map[string]string, homeDir string, now time.Time) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "OpenClaw install path")
	openClawBin := flags.String("openclaw-bin", "", "optional OpenClaw binary for plugins list/inspect/doctor JSON diagnostics")
	format := flags.String("format", "console", "report format: console, markdown, json, sarif")
	output := flags.String("output", "", "write report to file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	result, err := scanInstall(*path, env, homeDir, now, *openClawBin)
	if err != nil {
		fmt.Fprintf(stderr, "doctor failed: %v\n", err)
		return 2
	}

	rendered, err := renderFormat(*format, result)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 2
	}

	if hasHighRiskFinding(result.Report.Findings) {
		return 1
	}
	return 0
}

func runExportReport(args []string, stdout io.Writer, stderr io.Writer, env map[string]string, homeDir string, now time.Time) int {
	flags := flag.NewFlagSet("export-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "OpenClaw install path")
	format := flags.String("format", "", "report format: markdown, json, sarif")
	output := flags.String("output", "", "write report to file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*format) == "" {
		fmt.Fprintln(stderr, "export-report requires --format markdown, json, or sarif")
		return 2
	}

	result, err := scanInstall(*path, env, homeDir, now, "")
	if err != nil {
		fmt.Fprintf(stderr, "export-report failed: %v\n", err)
		return 2
	}

	rendered, err := renderFormat(*format, result)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	if err := writeOutput(*output, rendered, stdout); err != nil {
		fmt.Fprintf(stderr, "write output: %v\n", err)
		return 2
	}
	return 0
}

func scanInstall(path string, env map[string]string, homeDir string, now time.Time, openClawBin string) (doctor.Result, error) {
	root, err := doctor.DiscoverRoot(doctor.DiscoverOptions{
		ExplicitPath: path,
		Env:          env,
		HomeDir:      homeDir,
	})
	if err != nil {
		return doctor.Result{}, err
	}
	diagnostics, err := collectOpenClawDiagnostics(openClawBin)
	if err != nil {
		return doctor.Result{}, err
	}

	return doctor.Scan(doctor.ScanOptions{
		Root:                root,
		Now:                 now,
		ScannerVersion:      version,
		OpenClawDiagnostics: diagnostics,
	})
}

func collectOpenClawDiagnostics(openClawBin string) ([]doctor.OpenClawPluginDiagnostic, error) {
	openClawBin = strings.TrimSpace(openClawBin)
	if openClawBin == "" {
		return nil, nil
	}

	var list struct {
		Plugins []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"plugins"`
	}
	if err := runOpenClawJSON(openClawBin, &list, "plugins", "list", "--json"); err != nil {
		return nil, fmt.Errorf("openclaw plugins list: %w", err)
	}

	diagnostics := []doctor.OpenClawPluginDiagnostic{}
	for _, plugin := range list.Plugins {
		if strings.TrimSpace(plugin.ID) == "" {
			continue
		}
		var inspect struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Manifest struct {
				Tools []string `json:"tools"`
			} `json:"manifest"`
			Runtime struct {
				Tools  []string `json:"tools"`
				Hooks  []string `json:"hooks"`
				Routes []string `json:"routes"`
			} `json:"runtime"`
		}
		if err := runOpenClawJSON(openClawBin, &inspect, "plugins", "inspect", plugin.ID, "--json"); err != nil {
			return nil, fmt.Errorf("openclaw plugins inspect %s: %w", plugin.ID, err)
		}
		diagnostics = append(diagnostics, doctor.OpenClawPluginDiagnostic{
			ID:            firstNonEmpty(inspect.ID, plugin.ID),
			Name:          firstNonEmpty(inspect.Name, plugin.Name),
			ManifestTools: inspect.Manifest.Tools,
			RuntimeTools:  inspect.Runtime.Tools,
			RuntimeHooks:  inspect.Runtime.Hooks,
			RuntimeRoutes: inspect.Runtime.Routes,
		})
	}

	var doctorOut struct {
		Findings []struct {
			PluginID string `json:"pluginId"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"findings"`
	}
	if err := runOpenClawJSON(openClawBin, &doctorOut, "plugins", "doctor", "--json"); err != nil {
		return nil, fmt.Errorf("openclaw plugins doctor: %w", err)
	}
	for _, finding := range doctorOut.Findings {
		message := strings.TrimSpace(strings.Join([]string{finding.Severity, finding.Message}, ": "))
		for i := range diagnostics {
			if diagnostics[i].ID == finding.PluginID || finding.PluginID == "" {
				diagnostics[i].DoctorFindings = append(diagnostics[i].DoctorFindings, message)
			}
		}
	}
	return diagnostics, nil
}

func runOpenClawJSON(openClawBin string, out any, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openClawBin, args...)
	payload, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("command timed out")
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	return nil
}

func renderFormat(format string, result doctor.Result) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "console":
		return report.RenderConsole(result)
	case "markdown", "md":
		return report.RenderMarkdown(result)
	case "json":
		return report.RenderJSON(result)
	case "sarif":
		return report.RenderSARIF(result)
	default:
		return "", fmt.Errorf("unsupported report format %q", format)
	}
}

func renderRegistryFormat(format string, result registry.RegistryScanReport) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "summary", "console", "text":
		return report.RenderRegistrySummary(result)
	case "json":
		return report.RenderRegistryJSON(result)
	case "sarif":
		return report.RenderRegistrySARIF(result)
	default:
		return "", fmt.Errorf("unsupported registry report format %q", format)
	}
}

func renderWatchFormat(format string, result watchpkg.Result) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", err
		}
		return string(append(payload, '\n')), nil
	case "console", "summary", "text":
		var b strings.Builder
		fmt.Fprintln(&b, "RunBrake OpenClaw Watch")
		fmt.Fprintf(&b, "Root: %s\n", result.Root)
		fmt.Fprintf(&b, "State: %s\n", result.StatePath)
		if len(result.Changes) == 0 {
			fmt.Fprintln(&b, "No new or changed OpenClaw skills/plugins detected.")
			return b.String(), nil
		}
		for _, change := range result.Changes {
			fmt.Fprintf(
				&b,
				"%s %s %s (%s): critical=%d high=%d medium=%d\n",
				strings.ToUpper(string(change.Status)),
				change.Kind,
				change.Name,
				change.Path,
				change.Summary.Critical,
				change.Summary.High,
				change.Summary.Medium,
			)
			for _, finding := range change.Findings {
				fmt.Fprintf(&b, "  %s %s %s\n", strings.ToUpper(string(finding.Severity)), finding.RuleID, finding.Title)
			}
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unsupported watch format %q", format)
	}
}

func renderAssessmentFormat(format string, bundle assessmentBundle) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		payload, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return "", err
		}
		return string(payload) + "\n", nil
	case "markdown", "md":
		var b strings.Builder
		fmt.Fprintln(&b, "# RunBrake Assessment")
		fmt.Fprintf(&b, "\n- OpenClaw root: `%s`\n", bundle.Root)
		fmt.Fprintf(&b, "- Generated at: `%s`\n\n", bundle.GeneratedAt)
		renderAssessmentReportSummary(&b, "Doctor", bundle.Doctor)
		renderAssessmentReportSummary(&b, "Installed Skill Scan", bundle.Skills)
		fmt.Fprintln(&b, "## Watch Changes")
		fmt.Fprintln(&b)
		if len(bundle.Watch.Changes) == 0 {
			fmt.Fprintln(&b, "No new or changed OpenClaw skill/plugin folders detected.")
			fmt.Fprintln(&b)
		} else {
			for _, change := range bundle.Watch.Changes {
				fmt.Fprintf(&b, "- `%s` %s `%s`: %d critical, %d high, %d medium\n", change.Status, change.Kind, change.Path, change.Summary.Critical, change.Summary.High, change.Summary.Medium)
				for _, finding := range change.Findings {
					fmt.Fprintf(&b, "  - `%s` %s\n", finding.RuleID, finding.Title)
				}
			}
			fmt.Fprintln(&b)
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unsupported assessment format %q", format)
	}
}

func renderAssessmentReportSummary(b *strings.Builder, title string, scan doctor.ScanReport) {
	fmt.Fprintf(b, "## %s\n\n", title)
	fmt.Fprintf(b, "Findings: %d critical, %d high, %d medium, %d low, %d info.\n\n",
		scan.Summary.Critical,
		scan.Summary.High,
		scan.Summary.Medium,
		scan.Summary.Low,
		scan.Summary.Info,
	)
	if len(scan.Findings) == 0 {
		fmt.Fprintln(b, "No findings.")
		fmt.Fprintln(b)
		return
	}
	for _, finding := range scan.Findings {
		fmt.Fprintf(b, "- `%s` %s %s\n", finding.RuleID, finding.Severity, finding.Title)
	}
	fmt.Fprintln(b)
}

func renderDiffFormat(format string, diff report.ScanReportDiff) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return report.RenderScanReportDiffJSON(diff)
	case "markdown", "md":
		return report.RenderScanReportDiffMarkdown(diff)
	default:
		return "", fmt.Errorf("unsupported scan diff format %q", format)
	}
}

func writeOutput(path string, rendered string, stdout io.Writer) error {
	if strings.TrimSpace(path) == "" {
		_, err := io.WriteString(stdout, rendered)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runbrake-output-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(rendered); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func archiveRegistryScanOutput(result registry.RegistryScanReport, format string, rendered string, archiveRoot string) (string, error) {
	runDir, enabled := registryArchiveRunDir(result, archiveRoot)
	if !enabled {
		return "", nil
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", err
	}

	fullJSON, err := report.RenderRegistryJSON(result)
	if err != nil {
		return "", err
	}
	if err := writeGzipFileAtomic(filepath.Join(runDir, "full-registry-report.json.gz"), []byte(fullJSON), 0o600); err != nil {
		return "", err
	}

	if name := registryRequestedOutputName(format); name != "" {
		if err := writeFileAtomic(filepath.Join(runDir, name), []byte(rendered), 0o600); err != nil {
			return "", err
		}
	}
	return runDir, nil
}

func archiveRegistryReportPack(result registry.RegistryScanReport, inputJSON []byte, sourceDir string, archiveRoot string) (string, error) {
	runDir, enabled := registryArchiveRunDir(result, archiveRoot)
	if !enabled {
		return "", nil
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", err
	}
	if err := writeGzipFileAtomic(filepath.Join(runDir, "full-registry-report.json.gz"), inputJSON, 0o600); err != nil {
		return "", err
	}

	packDir := filepath.Join(runDir, "report-pack")
	if samePath(sourceDir, packDir) {
		return runDir, nil
	}
	if err := os.RemoveAll(packDir); err != nil {
		return "", err
	}
	if err := copyDir(sourceDir, packDir); err != nil {
		return "", err
	}
	return runDir, nil
}

func registryArchiveRunDir(result registry.RegistryScanReport, archiveRoot string) (string, bool) {
	archiveRoot = strings.TrimSpace(archiveRoot)
	if archiveRoot == "" || strings.EqualFold(archiveRoot, "none") || strings.EqualFold(archiveRoot, "off") {
		return "", false
	}

	generated := "unknown-time"
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(result.GeneratedAt)); err == nil {
		generated = parsed.UTC().Format("20060102T150405Z")
	}
	id := safePathSegment(result.ID)
	if id == "" {
		id = "registry-scan"
	}
	return filepath.Join(archiveRoot, generated+"-"+id), true
}

func registryRequestedOutputName(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "summary", "console", "text":
		return "registry-summary.txt"
	case "sarif":
		return "registry-report.sarif"
	default:
		return ""
	}
}

func writeFileAtomic(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runbrake-archive-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func writeGzipFileAtomic(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runbrake-archive-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	gz, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if _, err := gz.Write(payload); err != nil {
		_ = gz.Close()
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func copyDir(src string, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeFileAtomic(target, data, 0o600)
	})
}

func samePath(left string, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftAbs == rightAbs
}

func safePathSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-.")
}

func hasHighRiskFinding(findings []doctor.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == doctor.SeverityCritical || finding.Severity == doctor.SeverityHigh {
			return true
		}
	}
	return false
}

func watchHasHighRisk(result watchpkg.Result) bool {
	for _, change := range result.Changes {
		if change.Summary.Critical > 0 || change.Summary.High > 0 {
			return true
		}
	}
	return false
}

func emptySkillScanResult(root string, now time.Time) skills.Result {
	generatedAt := now.UTC().Format(time.RFC3339)
	return skills.Result{
		Root: root,
		Report: doctor.ScanReport{
			ID:             "skill-scan-empty-" + safePathSegment(generatedAt),
			AgentID:        "skill-scan",
			ScannerVersion: version,
			GeneratedAt:    generatedAt,
			Findings:       []doctor.Finding{},
			ArtifactHashes: []string{},
		},
	}
}

type assessmentBundle struct {
	GeneratedAt string            `json:"generatedAt"`
	Root        string            `json:"root"`
	Doctor      doctor.ScanReport `json:"doctor"`
	Skills      doctor.ScanReport `json:"skills"`
	Watch       watchpkg.Result   `json:"watch"`
}

type multiStringFlag []string

func (values *multiStringFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *multiStringFlag) Set(value string) error {
	for _, part := range splitCSV(value) {
		*values = append(*values, part)
	}
	return nil
}

func loadSuppressionsFile(path string) ([]skills.Suppression, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrapped struct {
		Suppressions []skills.Suppression `json:"suppressions"`
	}
	if err := json.Unmarshal(payload, &wrapped); err == nil && wrapped.Suppressions != nil {
		return wrapped.Suppressions, nil
	}
	var suppressions []skills.Suppression
	if err := json.Unmarshal(payload, &suppressions); err != nil {
		return nil, err
	}
	return suppressions, nil
}

func readScanReport(path string) (doctor.ScanReport, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return doctor.ScanReport{}, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err == nil {
		if _, ok := envelope["skills"]; ok {
			var registryReport registry.RegistryScanReport
			if err := json.Unmarshal(payload, &registryReport); err != nil {
				return doctor.ScanReport{}, err
			}
			return flattenRegistryScanReport(registryReport), nil
		}
		if _, ok := envelope["report"]; ok {
			var result doctor.Result
			if err := json.Unmarshal(payload, &result); err != nil {
				return doctor.ScanReport{}, err
			}
			return result.Report, nil
		}
	}
	var scan doctor.ScanReport
	if err := json.Unmarshal(payload, &scan); err == nil && (scan.ID != "" || scan.AgentID != "" || len(scan.Findings) > 0 || len(scan.ArtifactHashes) > 0) {
		return scan, nil
	}
	return doctor.ScanReport{}, fmt.Errorf("unsupported scan report JSON shape")
}

func flattenRegistryScanReport(registryReport registry.RegistryScanReport) doctor.ScanReport {
	scan := doctor.ScanReport{
		ID:             registryReport.ID,
		AgentID:        "registry-scan",
		ScannerVersion: registryReport.ScannerVersion,
		GeneratedAt:    registryReport.GeneratedAt,
		Summary: doctor.Summary{
			Critical: registryReport.Summary.Critical,
			High:     registryReport.Summary.High,
			Medium:   registryReport.Summary.Medium,
			Low:      registryReport.Summary.Low,
			Info:     registryReport.Summary.Info,
		},
		Findings:       []doctor.Finding{},
		ArtifactHashes: []string{},
	}
	for _, skill := range registryReport.Skills {
		scan.Findings = append(scan.Findings, skill.Findings...)
		if strings.TrimSpace(skill.ArtifactHash) != "" {
			scan.ArtifactHashes = append(scan.ArtifactHashes, skill.ArtifactHash)
		}
	}
	return scan
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  runbrake assess [--path <openclaw-root>] [--format markdown|json] [--output <file>]")
	fmt.Fprintln(w, "  runbrake doctor [--path <openclaw-root>] [--openclaw-bin <path>] [--format console|markdown|json|sarif] [--output <file>]")
	fmt.Fprintln(w, "  runbrake export-report --format markdown|json|sarif [--path <openclaw-root>] [--output <file>]")
	fmt.Fprintln(w, "  runbrake scan-skill [--format console|markdown|json|sarif] [--allow-domain <domain>] [--egress-profile balanced|audit] [--suppressions <file>] [--dependency-scan] [--vuln none|osv] [--cache-dir <dir>] [--output <file>] <skill-path-or-url>")
	fmt.Fprintln(w, "  runbrake scan-skills [--format console|markdown|json|sarif] [--allow-domain <domain>] [--egress-profile balanced|audit] [--suppressions <file>] [--dependency-scan] [--vuln none|osv] [--cache-dir <dir>] [--output <file>] <skills-directory>")
	fmt.Fprintln(w, "  runbrake watch-openclaw --once [--path <openclaw-root>] [--state <file>] [--format console|json]")
	fmt.Fprintln(w, "  runbrake scan-registry openclaw [--source github|clawhub] [--limit <n>] [--workers <n>] [--dependency-scan] [--vuln none|osv] [--cache-dir <dir>] [--progress] [--fail-on none|low|medium|high|critical] [--slugs <slug,...>] [--format summary|json|sarif] [--output <file>] [--archive-dir <dir|none>]")
	fmt.Fprintln(w, "  runbrake summarize-registry-report --input <registry-json> [--output <file>] [--top-skills <n>] [--examples <n>]")
	fmt.Fprintln(w, "  runbrake registry-report-pack --input <registry-json> --output-dir <dir> [--archive-dir <dir|none>] [--top-skills <n>] [--examples <n>]")
	fmt.Fprintln(w, "  runbrake diff-scan-report --baseline <json> --current <json> [--format markdown|json] [--output <file>]")
}

func osEnviron() map[string]string {
	env := map[string]string{}
	for _, pair := range os.Environ() {
		key, value, ok := strings.Cut(pair, "=")
		if ok {
			env[key] = value
		}
	}
	return env
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type failThreshold string

const (
	failThresholdNone     failThreshold = "none"
	failThresholdLow      failThreshold = "low"
	failThresholdMedium   failThreshold = "medium"
	failThresholdHigh     failThreshold = "high"
	failThresholdCritical failThreshold = "critical"
)

func parseFailThreshold(value string) (failThreshold, error) {
	switch failThreshold(strings.ToLower(strings.TrimSpace(value))) {
	case failThresholdNone:
		return failThresholdNone, nil
	case failThresholdLow:
		return failThresholdLow, nil
	case failThresholdMedium:
		return failThresholdMedium, nil
	case failThresholdHigh, "":
		return failThresholdHigh, nil
	case failThresholdCritical:
		return failThresholdCritical, nil
	default:
		return "", fmt.Errorf("unsupported --fail-on threshold %q; use none, low, medium, high, or critical", value)
	}
}

func registryMeetsFailThreshold(result registry.RegistryScanReport, threshold failThreshold) bool {
	switch threshold {
	case failThresholdNone:
		return false
	case failThresholdLow:
		return result.Summary.Critical > 0 || result.Summary.High > 0 || result.Summary.Medium > 0 || result.Summary.Low > 0
	case failThresholdMedium:
		return result.Summary.Critical > 0 || result.Summary.High > 0 || result.Summary.Medium > 0
	case failThresholdHigh:
		return result.Summary.Critical > 0 || result.Summary.High > 0
	case failThresholdCritical:
		return result.Summary.Critical > 0
	default:
		return result.Summary.Critical > 0 || result.Summary.High > 0
	}
}

func printRegistryExitExplanation(stderr io.Writer, result registry.RegistryScanReport, output string, threshold failThreshold, shouldFail bool) {
	reportTarget := "stdout"
	if strings.TrimSpace(output) != "" {
		reportTarget = output
	}
	if shouldFail {
		fmt.Fprintf(stderr,
			"scan-registry completed with high-risk findings at fail-on threshold %s: %d critical, %d high, %d medium across %d risky skills; report: %s; returning exit code 1. exit code 2 means command failure.\n",
			threshold,
			result.Summary.Critical,
			result.Summary.High,
			result.Summary.Medium,
			result.Summary.Risky,
			reportTarget,
		)
		return
	}
	fmt.Fprintf(stderr,
		"scan-registry completed below fail-on threshold %s: %d risky skills, %d errors; report: %s; returning exit code 0. exit code 2 means command failure.\n",
		threshold,
		result.Summary.Risky,
		result.Summary.Errors,
		reportTarget,
	)
}

func printRegistryProgress(stderr io.Writer, event registry.RegistryProgressEvent) {
	switch event.Stage {
	case "skills":
		fmt.Fprintf(stderr, "progress: scanned %d/%d skills\n", event.Current, event.Total)
	case "osv-batches":
		fmt.Fprintf(stderr, "progress: osv queried %d/%d dependency batches\n", event.Current, event.Total)
	case "osv-details":
		fmt.Fprintf(stderr, "progress: osv fetched %d/%d advisory details\n", event.Current, event.Total)
	default:
		fmt.Fprintf(stderr, "progress: %s %d/%d\n", event.Stage, event.Current, event.Total)
	}
}

func legacyMain() {
	cfg := config.Default()
	fmt.Printf("%s %s\n", cfg.ProductName, version)
}
