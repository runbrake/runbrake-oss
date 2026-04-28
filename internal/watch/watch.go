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
	"github.com/runbrake/runbrake-oss/internal/skills"
)

type ChangeStatus string

const (
	StatusNew     ChangeStatus = "new"
	StatusChanged ChangeStatus = "changed"
)

type ScanOptions struct {
	Root           string
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

	targets, err := discoverArtifactTargets(root)
	if err != nil {
		return Result{}, err
	}

	next := stateFile{
		Version:   "2026-04-28",
		UpdatedAt: now.Format(time.RFC3339),
		Artifacts: map[string]artifactState{},
	}
	result := Result{Root: root, StatePath: statePath, Changes: []ArtifactChange{}}

	for _, target := range targets {
		scan, err := skills.Scan(skills.ScanOptions{
			Target:         target,
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
		key, err := filepath.Rel(root, target)
		if err != nil {
			return Result{}, err
		}
		key = filepath.ToSlash(key)
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

func (result Result) HasCriticalRisk() bool {
	for _, change := range result.Changes {
		if change.Summary.Critical > 0 {
			return true
		}
	}
	return false
}

func discoverArtifactTargets(root string) ([]string, error) {
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
			if hasManifest(path) {
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

func hasManifest(path string) bool {
	for _, name := range []string{"skill.json", "plugin.json", "openclaw.plugin.json", "SKILL.md", "skill.md"} {
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
	return doctor.Artifact{}, fmt.Errorf("scan returned no skill or plugin artifact")
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
