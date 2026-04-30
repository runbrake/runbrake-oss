package registry

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/runbrake/runbrake-oss/internal/hermes"
)

const DefaultHermesAgentRepo = "https://github.com/NousResearch/hermes-agent.git"

type hermesDiscovery struct {
	category   string
	slug       string
	dir        string
	sourcePath string
	bundled    bool
}

func ScanHermes(options ScanOptions) (RegistryScanReport, error) {
	if strings.TrimSpace(options.MirrorPath) != "" {
		if strings.TrimSpace(options.SourceCommit) == "" {
			options.SourceCommit = gitCommit(options.MirrorPath)
		}
		return ScanHermesMirror(options)
	}

	sourceURL := strings.TrimSpace(options.SourceURL)
	if sourceURL == "" {
		sourceURL = DefaultHermesAgentRepo
		options.SourceURL = sourceURL
	}
	workDir := strings.TrimSpace(options.WorkDir)
	if workDir == "" {
		return RegistryScanReport{}, fmt.Errorf("github workdir is required when --mirror-path is not set")
	}

	if err := ensureGitMirror(workDir, sourceURL); err != nil {
		return RegistryScanReport{}, err
	}
	options.MirrorPath = workDir
	options.SourceCommit = gitCommit(workDir)
	return ScanHermesMirror(options)
}

func ScanHermesMirror(options ScanOptions) (RegistryScanReport, error) {
	mirrorPath := strings.TrimSpace(options.MirrorPath)
	if mirrorPath == "" {
		return RegistryScanReport{}, fmt.Errorf("Hermes GitHub mirror path is required")
	}

	source := RegistrySource{
		Type:       SourceHermesGitHub,
		URL:        firstNonEmpty(strings.TrimSpace(options.SourceURL), DefaultHermesAgentRepo),
		Commit:     strings.TrimSpace(options.SourceCommit),
		MirrorPath: mirrorPath,
	}
	report := newReport(options, source)

	discoveries, err := discoverHermesMirrorSkills(mirrorPath)
	if err != nil {
		return RegistryScanReport{}, err
	}
	report.Summary.Discovered = len(discoveries)

	candidates, skipped := filteredHermesDiscoveries(discoveries, options)
	report.Summary.Skipped = skipped
	skills := scanHermesDiscoveries(options, source, candidates)
	for _, skill := range skills {
		aggregateSkill(&report, skill)
	}
	if err := enrichVulnerabilities(&report, options); err != nil {
		return RegistryScanReport{}, err
	}

	finishReport(&report)
	return report, nil
}

func discoverHermesMirrorSkills(mirrorPath string) ([]hermesDiscovery, error) {
	root := filepath.Clean(mirrorPath)
	if info, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("stat Hermes GitHub mirror %s: %w", mirrorPath, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("Hermes GitHub mirror path %s is not a directory", mirrorPath)
	}

	var discoveries []hermesDiscovery
	for _, scanRoot := range []struct {
		dir     string
		bundled bool
	}{
		{dir: "skills", bundled: true},
		{dir: "optional-skills", bundled: false},
	} {
		base := filepath.Join(root, scanRoot.dir)
		if info, err := os.Stat(base); err != nil || !info.IsDir() {
			continue
		}
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", "node_modules", "dist", "coverage", ".cache", "vendor":
					return filepath.SkipDir
				default:
					return nil
				}
			}
			if entry.Name() != "SKILL.md" {
				return nil
			}
			rel, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if len(parts) < 2 {
				return nil
			}
			repoRel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			slug := strings.TrimSpace(parts[len(parts)-2])
			category := strings.TrimSpace(parts[0])
			if len(parts) == 2 {
				category = firstNonEmpty(hermesSkillCategory(path), "uncategorized")
			}
			if category == "" || slug == "" {
				return nil
			}
			discoveries = append(discoveries, hermesDiscovery{
				category:   category,
				slug:       slug,
				dir:        filepath.Dir(path),
				sourcePath: filepath.ToSlash(repoRel),
				bundled:    scanRoot.bundled,
			})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("discover Hermes %s skills: %w", scanRoot.dir, err)
		}
	}

	sort.SliceStable(discoveries, func(i, j int) bool {
		if discoveries[i].bundled != discoveries[j].bundled {
			return discoveries[i].bundled
		}
		if discoveries[i].category != discoveries[j].category {
			return discoveries[i].category < discoveries[j].category
		}
		return discoveries[i].slug < discoveries[j].slug
	})
	return discoveries, nil
}

func filteredHermesDiscoveries(discoveries []hermesDiscovery, options ScanOptions) ([]hermesDiscovery, int) {
	candidates := []hermesDiscovery{}
	skipped := 0
	slugFilter := normalizeSlugFilter(options.Slugs)
	for _, discovery := range discoveries {
		if !matchesSlugFilter(slugFilter, discovery.category, discovery.slug) {
			skipped++
			continue
		}
		if options.Limit > 0 && len(candidates) >= options.Limit {
			skipped++
			continue
		}
		candidates = append(candidates, discovery)
	}
	return candidates, skipped
}

func scanHermesDiscoveries(options ScanOptions, source RegistrySource, discoveries []hermesDiscovery) []RegistrySkillResult {
	if len(discoveries) == 0 {
		return []RegistrySkillResult{}
	}
	workers := options.Workers
	if workers <= 1 {
		skills := make([]RegistrySkillResult, 0, len(discoveries))
		for index, discovery := range discoveries {
			skills = append(skills, scanHermesDiscovery(options, source, discovery))
			emitProgress(options, "skills", index+1, len(discoveries))
		}
		return skills
	}
	if workers > len(discoveries) {
		workers = len(discoveries)
	}

	type job struct {
		index     int
		discovery hermesDiscovery
	}
	type result struct {
		index int
		skill RegistrySkillResult
	}

	jobs := make(chan job)
	results := make(chan result, len(discoveries))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				results <- result{
					index: item.index,
					skill: scanHermesDiscovery(options, source, item.discovery),
				}
			}
		}()
	}

	for index, discovery := range discoveries {
		jobs <- job{index: index, discovery: discovery}
	}
	close(jobs)
	wg.Wait()
	close(results)

	ordered := make([]RegistrySkillResult, len(discoveries))
	completed := 0
	for result := range results {
		ordered[result.index] = result.skill
		completed++
		emitProgress(options, "skills", completed, len(discoveries))
	}
	return ordered
}

func scanHermesDiscovery(options ScanOptions, source RegistrySource, discovery hermesDiscovery) RegistrySkillResult {
	bundled := discovery.bundled
	return scanSkillDirectory(options, discovery.dir, skillMetadata{
		Owner:        discovery.category,
		Slug:         discovery.slug,
		Source:       "hermes-agent",
		SourceURL:    source.URL,
		SourceCommit: source.Commit,
		SourcePath:   discovery.sourcePath,
		Category:     discovery.category,
		Bundled:      &bundled,
	})
}

func hermesSkillCategory(path string) string {
	meta, err := hermes.ParseSkillFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(meta.Category)
}
