package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var exactPackageVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9A-Za-z][0-9A-Za-z._-]*)?([+-][0-9A-Za-z._-]+)?$`)
var pnpmPackagePattern = regexp.MustCompile(`^\s*/((?:@[^/]+/)?[^@\s]+)@([^:\s]+):\s*$`)
var yarnKeyPattern = regexp.MustCompile(`^"?((?:@[^/@]+/)?[^@"\s]+)@.*"?\s*:\s*$`)

func ExtractDependencies(root string) []RegistryDependency {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}

	var dependencies []RegistryDependency
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			if entry != nil && entry.IsDir() && shouldSkipDependencyDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		name := strings.ToLower(entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		switch name {
		case "package-lock.json":
			dependencies = append(dependencies, parsePackageLockDependencies(data, rel)...)
		case "pnpm-lock.yaml":
			dependencies = append(dependencies, parsePnpmLockDependencies(data, rel)...)
		case "yarn.lock":
			dependencies = append(dependencies, parseYarnLockDependencies(data, rel)...)
		case "package.json":
			dependencies = append(dependencies, parsePackageJSONDependencies(data, rel)...)
		case "requirements.txt":
			dependencies = append(dependencies, parseRequirementsDependencies(data, rel)...)
		case "poetry.lock", "uv.lock":
			dependencies = append(dependencies, parsePythonTOMLLockDependencies(data, rel)...)
		case "pipfile.lock":
			dependencies = append(dependencies, parsePipfileLockDependencies(data, rel)...)
		case "go.mod":
			dependencies = append(dependencies, parseGoModDependencies(data, rel)...)
		case "go.sum":
			dependencies = append(dependencies, parseGoSumDependencies(data, rel)...)
		case "cargo.lock":
			dependencies = append(dependencies, parseCargoLockDependencies(data, rel)...)
		}
		return nil
	})

	return dedupeDependencies(dependencies)
}

func shouldSkipDependencyDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", "coverage", ".cache", "vendor":
		return true
	default:
		return false
	}
}

type packageLockFile struct {
	Packages map[string]struct {
		Version              string            `json:"version"`
		Dev                  bool              `json:"dev"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

func parsePackageLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	var lock packageLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	out := []RegistryDependency{}
	directNames := map[string]bool{}
	devNames := map[string]bool{}
	if root, ok := lock.Packages[""]; ok {
		for name := range root.Dependencies {
			directNames[name] = true
		}
		for name := range root.PeerDependencies {
			directNames[name] = true
		}
		for name := range root.OptionalDependencies {
			directNames[name] = true
		}
		for name := range root.DevDependencies {
			directNames[name] = true
			devNames[name] = true
		}
	}
	for path, pkg := range lock.Packages {
		if path == "" || !strings.HasPrefix(path, "node_modules/") {
			continue
		}
		name := strings.TrimPrefix(path, "node_modules/")
		if strings.Contains(name, "/node_modules/") {
			continue
		}
		if name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "npm",
			Name:         name,
			Version:      pkg.Version,
			ManifestPath: manifestPath,
			Source:       "package-lock.json",
			Direct:       directNames[name],
			Dev:          pkg.Dev || devNames[name],
		})
	}
	if len(out) > 0 {
		return out
	}
	for name, pkg := range lock.Dependencies {
		if name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "npm",
			Name:         name,
			Version:      pkg.Version,
			ManifestPath: manifestPath,
			Source:       "package-lock.json",
			Direct:       true,
			Dev:          pkg.Dev,
		})
	}
	return out
}

func parsePnpmLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	for _, line := range strings.Split(string(data), "\n") {
		match := pnpmPackagePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		name := strings.TrimSpace(match[1])
		version := cleanExactVersion(match[2])
		if name == "" || version == "" {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "npm",
			Name:         name,
			Version:      version,
			ManifestPath: manifestPath,
			Source:       "pnpm-lock.yaml",
		})
	}
	return out
}

func parseYarnLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	currentNames := []string{}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			currentNames = nil
			continue
		}
		if !strings.HasPrefix(rawLine, " ") && strings.HasSuffix(line, ":") {
			currentNames = nil
			for _, key := range strings.Split(line, ",") {
				key = strings.TrimSpace(strings.Trim(key, `"`))
				match := yarnKeyPattern.FindStringSubmatch(key + ":")
				if len(match) == 2 {
					currentNames = append(currentNames, match[1])
				}
			}
			continue
		}
		if len(currentNames) == 0 || !strings.HasPrefix(line, "version ") {
			continue
		}
		version := cleanExactVersion(strings.TrimSpace(strings.TrimPrefix(line, "version ")))
		if version == "" {
			continue
		}
		for _, name := range currentNames {
			out = append(out, RegistryDependency{
				Ecosystem:    "npm",
				Name:         name,
				Version:      version,
				ManifestPath: manifestPath,
				Source:       "yarn.lock",
			})
		}
	}
	return out
}

type packageJSONFile struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePackageJSONDependencies(data []byte, manifestPath string) []RegistryDependency {
	var pkg packageJSONFile
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	out := []RegistryDependency{}
	addPackageJSONGroup := func(group map[string]string, dev bool) {
		for name, version := range group {
			version = cleanExactVersion(version)
			if name == "" || version == "" {
				continue
			}
			out = append(out, RegistryDependency{
				Ecosystem:    "npm",
				Name:         name,
				Version:      version,
				ManifestPath: manifestPath,
				Source:       "package.json",
				Direct:       true,
				Dev:          dev,
			})
		}
	}
	addPackageJSONGroup(pkg.Dependencies, false)
	addPackageJSONGroup(pkg.DevDependencies, true)
	addPackageJSONGroup(pkg.PeerDependencies, false)
	addPackageJSONGroup(pkg.OptionalDependencies, false)
	return out
}

func parseRequirementsDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "://") {
			continue
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		version = cleanExactVersion(version)
		if name == "" || version == "" {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "PyPI",
			Name:         name,
			Version:      version,
			ManifestPath: manifestPath,
			Source:       "requirements.txt",
			Direct:       true,
		})
	}
	return out
}

func parsePythonTOMLLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, RegistryDependency{
				Ecosystem:    "PyPI",
				Name:         name,
				Version:      version,
				ManifestPath: manifestPath,
				Source:       filepath.Base(manifestPath),
			})
		}
		name = ""
		version = ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			flush()
			continue
		}
		if value, ok := quotedTOMLValue(line, "name"); ok {
			name = value
		}
		if value, ok := quotedTOMLValue(line, "version"); ok {
			version = cleanExactVersion(value)
		}
	}
	flush()
	return out
}

func parsePipfileLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	var lock map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	out := []RegistryDependency{}
	for group, dependencies := range lock {
		for name, dependency := range dependencies {
			version := cleanExactVersion(dependency.Version)
			if name == "" || version == "" {
				continue
			}
			out = append(out, RegistryDependency{
				Ecosystem:    "PyPI",
				Name:         name,
				Version:      version,
				ManifestPath: manifestPath,
				Source:       "Pipfile.lock",
				Direct:       true,
				Dev:          group == "develop",
			})
		}
	}
	return out
}

func parseGoModDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.Split(line, "//")[0])
		if line == "" {
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inBlock {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "Go",
			Name:         parts[0],
			Version:      strings.TrimPrefix(parts[1], "v"),
			ManifestPath: manifestPath,
			Source:       "go.mod",
			Direct:       true,
		})
	}
	return out
}

func parseGoSumDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		version := strings.TrimSuffix(parts[1], "/go.mod")
		version = cleanExactVersion(strings.TrimPrefix(version, "v"))
		if parts[0] == "" || version == "" {
			continue
		}
		out = append(out, RegistryDependency{
			Ecosystem:    "Go",
			Name:         parts[0],
			Version:      version,
			ManifestPath: manifestPath,
			Source:       "go.sum",
		})
	}
	return out
}

func parseCargoLockDependencies(data []byte, manifestPath string) []RegistryDependency {
	out := []RegistryDependency{}
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, RegistryDependency{
				Ecosystem:    "crates.io",
				Name:         name,
				Version:      version,
				ManifestPath: manifestPath,
				Source:       "Cargo.lock",
				Direct:       true,
			})
		}
		name = ""
		version = ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			flush()
			continue
		}
		if value, ok := quotedTOMLValue(line, "name"); ok {
			name = value
		}
		if value, ok := quotedTOMLValue(line, "version"); ok {
			version = value
		}
	}
	flush()
	return out
}

func quotedTOMLValue(line string, key string) (string, bool) {
	prefix := key + " = "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	value = strings.Trim(value, `"`)
	return value, value != ""
}

func cleanExactVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, `"'`)
	version = strings.TrimLeft(version, "=")
	if strings.HasPrefix(version, "v") && len(version) > 1 && version[1] >= '0' && version[1] <= '9' {
		version = strings.TrimPrefix(version, "v")
	}
	if !exactPackageVersionPattern.MatchString(version) {
		return ""
	}
	return version
}

func dedupeDependencies(dependencies []RegistryDependency) []RegistryDependency {
	seen := map[string]RegistryDependency{}
	for _, dependency := range dependencies {
		dependency.Ecosystem = strings.TrimSpace(dependency.Ecosystem)
		dependency.Name = strings.TrimSpace(dependency.Name)
		dependency.Version = strings.TrimSpace(dependency.Version)
		if dependency.Ecosystem == "" || dependency.Name == "" || dependency.Version == "" {
			continue
		}
		key := dependency.Ecosystem + "|" + dependency.Name + "|" + dependency.Version
		if existing, ok := seen[key]; ok {
			if existing.ManifestPath == "" {
				existing.ManifestPath = dependency.ManifestPath
			}
			if existing.Source == "package.json" && dependency.Source == "package-lock.json" {
				existing.Source = dependency.Source
				existing.ManifestPath = dependency.ManifestPath
			}
			existing.Direct = existing.Direct || dependency.Direct
			existing.Dev = existing.Dev && dependency.Dev
			seen[key] = existing
			continue
		}
		seen[key] = dependency
	}
	out := make([]RegistryDependency, 0, len(seen))
	for _, dependency := range seen {
		out = append(out, dependency)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
