package registry

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ScanLocal(options ScanOptions, root string, many bool) (RegistryScanReport, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return RegistryScanReport{}, fmt.Errorf("local scan root is required")
	}
	source := RegistrySource{
		Type:       SourceLocal,
		MirrorPath: root,
	}
	if options.Registry == "" {
		options.Registry = "local"
	}
	report := newReport(options, source)

	targets, err := localSkillTargets(root, many)
	if err != nil {
		return RegistryScanReport{}, err
	}
	report.Summary.Discovered = len(targets)
	for _, target := range targets {
		meta := skillMetadata{
			Slug:      filepath.Base(target),
			Source:    "local",
			SourceURL: "file:" + target,
		}
		aggregateSkill(&report, scanSkillDirectory(options, target, meta))
	}
	if err := enrichVulnerabilities(&report, options); err != nil {
		return RegistryScanReport{}, err
	}
	finishReport(&report)
	return report, nil
}

func localSkillTargets(root string, many bool) ([]string, error) {
	if !many {
		if hasLocalManifest(root) {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("no skill or plugin manifest found under %s", root)
	}
	targets := []string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		switch entry.Name() {
		case ".git", "node_modules", "dist", "coverage", ".cache":
			return filepath.SkipDir
		}
		if hasLocalManifest(path) {
			targets = append(targets, path)
			return filepath.SkipDir
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no skill or plugin manifests found under %s", root)
	}
	return targets, nil
}

func hasLocalManifest(path string) bool {
	for _, name := range []string{"skill.json", "plugin.json", "openclaw.plugin.json", "SKILL.md", "skill.md"} {
		if _, err := os.Stat(filepath.Join(path, name)); err == nil {
			return true
		}
	}
	return false
}
