package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/hermes"
	"github.com/runbrake/runbrake-oss/internal/skills"
)

type ChangeStatus string

const (
	StatusNew     ChangeStatus = "new"
	StatusChanged ChangeStatus = "changed"
)

type ScanOptions struct {
	Root           string
	Ecosystem      string
	StatePath      string
	WriteState     bool
	ScannerVersion string
	Now            time.Time
	AllowDomains   []string
	EgressProfile  string
	Suppressions   []skills.Suppression
}

type ArtifactChange struct {
	Status   ChangeStatus     `json:"status"`
	Kind     string           `json:"kind"`
	Name     string           `json:"name"`
	Path     string           `json:"path"`
	Hash     string           `json:"hash"`
	Summary  doctor.Summary   `json:"summary"`
	Findings []doctor.Finding `json:"findings"`
}

type Result struct {
	Root      string           `json:"root"`
	Ecosystem string           `json:"ecosystem"`
	StatePath string           `json:"statePath"`
	Changes   []ArtifactChange `json:"changes"`
}

type stateFile struct {
	Version   string                   `json:"version"`
	UpdatedAt string                   `json:"updatedAt"`
	Artifacts map[string]artifactState `json:"artifacts"`
}

type artifactState struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Hash string `json:"hash"`
}

func Scan(options ScanOptions) (Result, error) {
	root := strings.TrimSpace(options.Root)
	if root == "" {
		return Result{}, fmt.Errorf("watch root is required")
	}
	ecosystem := normalizeEcosystem(options.Ecosystem)
	if ecosystem != "openclaw" && ecosystem != "hermes" {
		return Result{}, fmt.Errorf("unsupported watch ecosystem %q", options.Ecosystem)
	}
	canonicalRoot, err := canonicalRoot(root, ecosystem)
	if err != nil {
		return Result{}, err
	}
	root = canonicalRoot
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	statePath := strings.TrimSpace(options.StatePath)
	if statePath == "" {
		statePath = filepath.Join(root, ".runbrake", "watch-state.json")
	}

	previous, err := readState(statePath)
	if err != nil {
		return Result{}, err
	}

	targets, err := discoverArtifactTargets(root, ecosystem)
	if err != nil {
		return Result{}, err
	}

	next := stateFile{
		Version:   "2026-04-28",
		UpdatedAt: now.Format(time.RFC3339),
		Artifacts: map[string]artifactState{},
	}
	result := Result{Root: root, Ecosystem: ecosystem, StatePath: statePath, Changes: []ArtifactChange{}}

	for _, target := range targets {
		scan, err := skills.Scan(skills.ScanOptions{
			Target:         target,
			Ecosystem:      ecosystem,
			Now:            now,
			ScannerVersion: options.ScannerVersion,
			AllowDomains:   options.AllowDomains,
			EgressProfile:  options.EgressProfile,
			Suppressions:   options.Suppressions,
		})
		if err != nil {
			return Result{}, fmt.Errorf("scan watched artifact %s: %w", target, err)
		}
		artifact, err := scannedArtifact(scan.Inventory)
		if err != nil {
			return Result{}, fmt.Errorf("read watched artifact %s: %w", target, err)
		}
		key, err := artifactPathKey(root, target)
		if err != nil {
			return Result{}, err
		}
		next.Artifacts[key] = artifactState{
			Kind: artifact.Kind,
			Name: artifact.Name,
			Hash: artifact.Hash,
		}

		status := changeStatus(previous.Artifacts[key], artifact.Hash)
		if status == "" {
			continue
		}
		result.Changes = append(result.Changes, ArtifactChange{
			Status:   status,
			Kind:     artifact.Kind,
			Name:     artifact.Name,
			Path:     key,
			Hash:     artifact.Hash,
			Summary:  scan.Report.Summary,
			Findings: scan.Report.Findings,
		})
	}
	sort.Slice(result.Changes, func(i int, j int) bool {
		return result.Changes[i].Path < result.Changes[j].Path
	})

	if options.WriteState {
		if err := writeState(statePath, next); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func ArtifactTargets(root string, ecosystem string) ([]string, error) {
	ecosystem = normalizeEcosystem(ecosystem)
	if ecosystem != "openclaw" && ecosystem != "hermes" {
		return nil, fmt.Errorf("unsupported watch ecosystem %q", ecosystem)
	}
	canonical, err := canonicalRoot(root, ecosystem)
	if err != nil {
		return nil, err
	}
	return discoverArtifactTargets(canonical, ecosystem)
}

func canonicalRoot(root string, ecosystem string) (string, error) {
	root = strings.TrimSpace(root)
	if ecosystem != "hermes" {
		return root, nil
	}
	discovery, err := discoverHermesHome(root)
	if err != nil {
		return "", err
	}
	return filepath.Dir(discovery.HomeDir), nil
}

func (result Result) HasCriticalRisk() bool {
	for _, change := range result.Changes {
		if change.Summary.Critical > 0 {
			return true
		}
	}
	return false
}

func RenderReceiptDigest(result Result) string {
	label := ecosystemLabel(result.Ecosystem)
	if len(result.Changes) == 0 {
		return fmt.Sprintf("RunBrake found no new or changed %s artifacts outside the install flow.", label)
	}

	newCount := 0
	changedCount := 0
	for _, change := range result.Changes {
		switch change.Status {
		case StatusNew:
			newCount++
		case StatusChanged:
			changedCount++
		}
	}

	var b strings.Builder
	if changedCount == 0 {
		fmt.Fprintf(&b, "RunBrake found %d new %s %s outside the install flow.", newCount, label, pluralize("artifact", newCount))
	} else if newCount == 0 {
		fmt.Fprintf(&b, "RunBrake found %d changed %s %s outside the install flow.", changedCount, label, pluralize("artifact", changedCount))
	} else {
		total := newCount + changedCount
		fmt.Fprintf(&b, "RunBrake found %d new or changed %s %s outside the install flow.", total, label, pluralize("artifact", total))
	}

	for _, change := range result.Changes {
		severity := highestSeverity(change)
		finding := topFinding(change.Findings)
		if finding.RuleID == "" {
			fmt.Fprintf(&b, "\n- %s %s %s: %s", strings.ToLower(string(change.Status)), change.Kind, change.Path, severity)
			continue
		}
		fmt.Fprintf(
			&b,
			"\n- %s %s %s: %s %s %s",
			strings.ToLower(string(change.Status)),
			change.Kind,
			change.Path,
			severity,
			finding.RuleID,
			finding.Title,
		)
	}
	return b.String()
}

func ecosystemLabel(ecosystem string) string {
	if normalizeEcosystem(ecosystem) == "hermes" {
		return "Hermes"
	}
	return "OpenClaw"
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func highestSeverity(change ArtifactChange) string {
	switch {
	case change.Summary.Critical > 0:
		return string(doctor.SeverityCritical)
	case change.Summary.High > 0:
		return string(doctor.SeverityHigh)
	case change.Summary.Medium > 0:
		return string(doctor.SeverityMedium)
	case change.Summary.Low > 0:
		return string(doctor.SeverityLow)
	default:
		return string(doctor.SeverityInfo)
	}
}

func topFinding(findings []doctor.Finding) doctor.Finding {
	if len(findings) == 0 {
		return doctor.Finding{}
	}
	top := findings[0]
	for _, finding := range findings[1:] {
		if severityRank(finding.Severity) > severityRank(top.Severity) {
			top = finding
		}
	}
	return top
}

func severityRank(severity doctor.Severity) int {
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

func discoverArtifactTargets(root string, ecosystem string) ([]string, error) {
	if ecosystem == "hermes" {
		return discoverHermesArtifactTargets(root)
	}
	bases := []string{
		filepath.Join(root, "skills"),
		filepath.Join(root, "plugins"),
		filepath.Join(root, "extensions"),
		filepath.Join(root, ".openclaw", "extensions"),
		filepath.Join(root, ".agents", "skills"),
	}
	targets := []string{}
	for _, base := range bases {
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				return nil
			}
			if hasManifest(path, ecosystem) {
				targets = append(targets, path)
				return filepath.SkipDir
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Strings(targets)
	return targets, nil
}

func discoverHermesArtifactTargets(root string) ([]string, error) {
	discovery, err := discoverHermesHome(root)
	if err != nil {
		return nil, err
	}
	bases := []string{}
	bases = append(bases, discovery.SkillDirs...)
	bases = append(bases, discovery.PluginDirs...)
	bases = append(bases, discovery.HookDirs...)
	bases = append(bases, discovery.ExternalSkillDirs...)
	return discoverTargetsFromBases(bases)
}

func discoverHermesHome(root string) (hermes.Discovery, error) {
	if filepath.Base(root) != ".hermes" {
		nested := filepath.Join(root, ".hermes")
		if _, statErr := os.Stat(nested); statErr == nil {
			if discovery, err := hermes.Discover(hermes.DiscoverOptions{ExplicitPath: nested}); err == nil {
				return discovery, nil
			}
		}
	}
	return hermes.Discover(hermes.DiscoverOptions{ExplicitPath: root})
}

func discoverTargetsFromBases(bases []string) ([]string, error) {
	targets := []string{}
	seenBases := map[string]bool{}
	for _, base := range bases {
		base = filepath.Clean(strings.TrimSpace(base))
		if base == "." || seenBases[base] {
			continue
		}
		seenBases[base] = true
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				return nil
			}
			if hasManifest(path, "hermes") {
				targets = append(targets, path)
				return filepath.SkipDir
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return sortedUnique(targets), nil
}

func hasManifest(path string, ecosystem string) bool {
	names := []string{"skill.json", "plugin.json", "openclaw.plugin.json", "SKILL.md", "skill.md"}
	if ecosystem == "hermes" {
		names = append(names, "plugin.yaml", "plugin.yml", "HOOK.yaml", "HOOK.yml")
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(path, name)); err == nil {
			return true
		}
	}
	return false
}

func scannedArtifact(inventory doctor.Inventory) (doctor.Artifact, error) {
	if len(inventory.Skills) > 0 {
		return inventory.Skills[0], nil
	}
	if len(inventory.Plugins) > 0 {
		return inventory.Plugins[0], nil
	}
	if len(inventory.Hooks) > 0 {
		return inventory.Hooks[0], nil
	}
	return doctor.Artifact{}, fmt.Errorf("scan returned no skill, plugin, or hook artifact")
}

func artifactPathKey(root string, target string) (string, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		rootAbs, rootErr := filepath.Abs(root)
		targetAbs, targetErr := filepath.Abs(target)
		if rootErr != nil || targetErr != nil {
			return "", err
		}
		rel, err = filepath.Rel(rootAbs, targetAbs)
		if err != nil {
			return "", err
		}
		target = targetAbs
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		abs, absErr := filepath.Abs(target)
		if absErr != nil {
			return "", absErr
		}
		return filepath.ToSlash(abs), nil
	}
	return filepath.ToSlash(rel), nil
}

func normalizeEcosystem(value string) string {
	ecosystem := strings.ToLower(strings.TrimSpace(value))
	if ecosystem == "" {
		return "openclaw"
	}
	return ecosystem
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = filepath.Clean(strings.TrimSpace(value))
		if value == "." || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func changeStatus(previous artifactState, hash string) ChangeStatus {
	if previous.Hash == "" {
		return StatusNew
	}
	if previous.Hash != hash {
		return StatusChanged
	}
	return ""
}

func readState(path string) (stateFile, error) {
	state := stateFile{Artifacts: map[string]artifactState{}}
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return stateFile{}, err
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return stateFile{}, fmt.Errorf("parse watch state: %w", err)
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]artifactState{}
	}
	return state, nil
}

func writeState(path string, state stateFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runbrake-watch-*")
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
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
