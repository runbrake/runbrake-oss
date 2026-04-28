package registry

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const DefaultOpenClawSkillsRepo = "https://github.com/openclaw/skills.git"

type githubDiscovery struct {
	owner string
	slug  string
	dir   string
}

type githubMetadataFile struct {
	Owner         string                 `json:"owner"`
	Slug          string                 `json:"slug"`
	DisplayName   string                 `json:"displayName"`
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	CreatedAt     json.RawMessage        `json:"createdAt"`
	UpdatedAt     json.RawMessage        `json:"updatedAt"`
	PublishedAt   json.RawMessage        `json:"publishedAt"`
	Source        string                 `json:"source"`
	SourceURL     string                 `json:"sourceUrl"`
	SourceCommit  string                 `json:"sourceCommit"`
	Latest        githubLatestMetadata   `json:"latest"`
	LatestVersion githubLatestMetadata   `json:"latestVersion"`
	History       []githubLatestMetadata `json:"history"`
	Tags          map[string]string      `json:"tags"`
}

type githubLatestMetadata struct {
	Version     string          `json:"version"`
	Commit      string          `json:"commit"`
	Source      string          `json:"source"`
	SourceURL   string          `json:"sourceUrl"`
	PublishedAt json.RawMessage `json:"publishedAt"`
	CreatedAt   json.RawMessage `json:"createdAt"`
}

func ScanGitHub(options ScanOptions) (RegistryScanReport, error) {
	if strings.TrimSpace(options.MirrorPath) != "" {
		if strings.TrimSpace(options.SourceCommit) == "" {
			options.SourceCommit = gitCommit(options.MirrorPath)
		}
		return ScanGitHubMirror(options)
	}

	sourceURL := strings.TrimSpace(options.SourceURL)
	if sourceURL == "" {
		sourceURL = DefaultOpenClawSkillsRepo
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
	return ScanGitHubMirror(options)
}

func ScanGitHubMirror(options ScanOptions) (RegistryScanReport, error) {
	mirrorPath := strings.TrimSpace(options.MirrorPath)
	if mirrorPath == "" {
		return RegistryScanReport{}, fmt.Errorf("github mirror path is required")
	}

	source := RegistrySource{
		Type:       SourceGitHub,
		URL:        strings.TrimSpace(options.SourceURL),
		Commit:     strings.TrimSpace(options.SourceCommit),
		MirrorPath: mirrorPath,
	}
	report := newReport(options, source)

	discoveries, err := discoverGitHubMirrorSkills(mirrorPath)
	if err != nil {
		return RegistryScanReport{}, err
	}
	report.Summary.Discovered = len(discoveries)

	candidates, skipped := filteredGitHubDiscoveries(discoveries, options)
	report.Summary.Skipped = skipped
	skills := scanGitHubDiscoveries(options, source, candidates)
	for _, skill := range skills {
		aggregateSkill(&report, skill)
	}
	if err := enrichVulnerabilities(&report, options); err != nil {
		return RegistryScanReport{}, err
	}

	finishReport(&report)
	return report, nil
}

func filteredGitHubDiscoveries(discoveries []githubDiscovery, options ScanOptions) ([]githubDiscovery, int) {
	candidates := []githubDiscovery{}
	skipped := 0
	slugFilter := normalizeSlugFilter(options.Slugs)
	for _, discovery := range discoveries {
		if !matchesSlugFilter(slugFilter, discovery.owner, discovery.slug) {
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

func scanGitHubDiscoveries(options ScanOptions, source RegistrySource, discoveries []githubDiscovery) []RegistrySkillResult {
	if len(discoveries) == 0 {
		return []RegistrySkillResult{}
	}
	workers := options.Workers
	if workers <= 1 {
		skills := make([]RegistrySkillResult, 0, len(discoveries))
		for index, discovery := range discoveries {
			skills = append(skills, scanGitHubDiscovery(options, source, discovery))
			emitProgress(options, "skills", index+1, len(discoveries))
		}
		return skills
	}
	if workers > len(discoveries) {
		workers = len(discoveries)
	}

	type job struct {
		index     int
		discovery githubDiscovery
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
					skill: scanGitHubDiscovery(options, source, item.discovery),
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

func scanGitHubDiscovery(options ScanOptions, source RegistrySource, discovery githubDiscovery) RegistrySkillResult {
	meta := readGitHubMetadata(discovery, source)
	return scanSkillDirectory(options, discovery.dir, meta)
}

func ensureGitMirror(workDir string, sourceURL string) error {
	if info, err := os.Stat(workDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("github workdir %s is not a directory", workDir)
		}
		if err := runGit("", "git", "-C", workDir, "rev-parse", "--is-inside-work-tree"); err != nil {
			return fmt.Errorf("github workdir %s is not a git repository: %w", workDir, err)
		}
		if err := runGit("", "git", "-C", workDir, "fetch", "--depth=1", "origin", "HEAD"); err != nil {
			return err
		}
		return runGit("", "git", "-C", workDir, "checkout", "--detach", "FETCH_HEAD")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat github workdir %s: %w", workDir, err)
	}

	if err := os.MkdirAll(filepath.Dir(workDir), 0o755); err != nil {
		return fmt.Errorf("create github workdir parent: %w", err)
	}
	return runGit("", "git", "clone", "--depth=1", sourceURL, workDir)
}

func runGit(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func gitCommit(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	cmd := exec.Command("git", "-C", path, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func discoverGitHubMirrorSkills(mirrorPath string) ([]githubDiscovery, error) {
	root := filepath.Clean(mirrorPath)
	if info, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("stat github mirror %s: %w", mirrorPath, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("github mirror path %s is not a directory", mirrorPath)
	}

	skillsRoot := filepath.Join(root, "skills")
	if info, err := os.Stat(skillsRoot); err != nil || !info.IsDir() {
		skillsRoot = root
	}

	byDir := map[string]githubDiscovery{}
	if err := filepath.WalkDir(skillsRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "dist", "coverage", ".cache":
				return filepath.SkipDir
			default:
				return nil
			}
		}

		name := strings.ToLower(entry.Name())
		if name != "skill.md" {
			return nil
		}

		rel, err := filepath.Rel(skillsRoot, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 3 {
			return nil
		}
		owner := strings.TrimSpace(parts[0])
		slug := strings.TrimSpace(parts[1])
		if owner == "" || slug == "" {
			return nil
		}
		dir := filepath.Dir(path)
		if _, exists := byDir[dir]; !exists || entry.Name() == "SKILL.md" {
			byDir[dir] = githubDiscovery{
				owner: owner,
				slug:  slug,
				dir:   dir,
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("discover github mirror skills: %w", err)
	}

	discoveries := make([]githubDiscovery, 0, len(byDir))
	for _, discovery := range byDir {
		discoveries = append(discoveries, discovery)
	}
	sort.SliceStable(discoveries, func(i, j int) bool {
		if discoveries[i].owner != discoveries[j].owner {
			return discoveries[i].owner < discoveries[j].owner
		}
		return discoveries[i].slug < discoveries[j].slug
	})
	return discoveries, nil
}

func readGitHubMetadata(discovery githubDiscovery, source RegistrySource) skillMetadata {
	meta := skillMetadata{
		Owner:        discovery.owner,
		Slug:         discovery.slug,
		SourceURL:    source.URL,
		SourceCommit: source.Commit,
	}

	raw, err := os.ReadFile(filepath.Join(discovery.dir, "_meta.json"))
	if err != nil {
		return meta
	}

	var file githubMetadataFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return meta
	}

	meta.Owner = firstNonEmpty(file.Owner, meta.Owner)
	meta.Slug = firstNonEmpty(file.Slug, meta.Slug)
	meta.DisplayName = firstNonEmpty(file.DisplayName, file.Name)
	meta.Version = firstNonEmpty(file.Latest.Version, file.LatestVersion.Version, file.Version, file.Tags["latest"])
	meta.PublishedAt = firstNonEmpty(parseRegistryTimestamp(file.Latest.PublishedAt), parseRegistryTimestamp(file.LatestVersion.PublishedAt), parseRegistryTimestamp(file.PublishedAt), earliestHistoryTimestamp(file.History))
	meta.CreatedAt = firstNonEmpty(parseRegistryTimestamp(file.CreatedAt), earliestHistoryTimestamp(file.History))
	meta.UpdatedAt = firstNonEmpty(parseRegistryTimestamp(file.UpdatedAt), parseRegistryTimestamp(file.Latest.PublishedAt), parseRegistryTimestamp(file.LatestVersion.PublishedAt))
	meta.LatestVersionCreatedAt = firstNonEmpty(parseRegistryTimestamp(file.Latest.CreatedAt), parseRegistryTimestamp(file.LatestVersion.CreatedAt), parseRegistryTimestamp(file.Latest.PublishedAt), parseRegistryTimestamp(file.LatestVersion.PublishedAt))
	if len(file.History) > 0 {
		meta.VersionCount = len(file.History) + 1
	}
	meta.Source = firstNonEmpty(file.Source, file.Latest.Source)
	meta.SourceURL = firstNonEmpty(file.SourceURL, file.Latest.SourceURL, meta.SourceURL)
	meta.SourceCommit = firstNonEmpty(file.SourceCommit, file.Latest.Commit, file.LatestVersion.Commit, meta.SourceCommit)
	return meta
}

func earliestHistoryTimestamp(history []githubLatestMetadata) string {
	var earliest string
	for _, item := range history {
		candidate := firstNonEmpty(parseRegistryTimestamp(item.PublishedAt), parseRegistryTimestamp(item.CreatedAt))
		if candidate == "" {
			continue
		}
		if earliest == "" || candidate < earliest {
			earliest = candidate
		}
	}
	return earliest
}

func normalizeSlugFilter(slugs []string) map[string]bool {
	filter := map[string]bool{}
	for _, value := range slugs {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			filter[value] = true
		}
	}
	return filter
}

func matchesSlugFilter(filter map[string]bool, owner string, slug string) bool {
	if len(filter) == 0 {
		return true
	}
	owner = strings.ToLower(strings.TrimSpace(owner))
	slug = strings.ToLower(strings.TrimSpace(slug))
	return filter[slug] || filter[owner+"/"+slug]
}
