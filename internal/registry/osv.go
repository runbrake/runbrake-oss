package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultOSVAPIBase = "https://api.osv.dev"
	osvBatchLimit     = 1000
)

func enrichVulnerabilities(report *RegistryScanReport, options ScanOptions) error {
	provider := strings.ToLower(strings.TrimSpace(options.VulnerabilityProvider))
	if provider == "" || provider == "none" {
		return nil
	}
	if provider != "osv" {
		return fmt.Errorf("unsupported vulnerability provider %q", options.VulnerabilityProvider)
	}
	return enrichWithOSV(report, options)
}

func enrichWithOSV(report *RegistryScanReport, options ScanOptions) error {
	coordinates := uniqueDependencyCoordinates(report.Skills)
	if len(coordinates) == 0 {
		return nil
	}

	apiBase := strings.TrimSpace(options.OSVAPIBase)
	if apiBase == "" {
		apiBase = DefaultOSVAPIBase
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	vulnsByCoordinate := map[string][]RegistryVulnerability{}
	uniqueVulnIDs := map[string]bool{}
	for start := 0; start < len(coordinates); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(coordinates) {
			end = len(coordinates)
		}
		batch := coordinates[start:end]
		results, err := queryOSVBatchCached(client, apiBase, batch, options.CacheDir)
		if err != nil {
			return err
		}
		report.Summary.VulnerabilityQueryBatches++
		emitProgress(options, "osv-batches", start/osvBatchLimit+1, (len(coordinates)+osvBatchLimit-1)/osvBatchLimit)
		for i, result := range results {
			if i >= len(batch) {
				break
			}
			dependency := batch[i]
			for _, vuln := range result.Vulns {
				if strings.TrimSpace(vuln.ID) != "" {
					uniqueVulnIDs[vuln.ID] = true
				}
				vulnsByCoordinate[dependency.key()] = append(vulnsByCoordinate[dependency.key()], registryVulnerabilityFromOSV(dependency, vuln))
			}
		}
	}

	details, err := fetchOSVDetails(client, apiBase, uniqueVulnIDs, options)
	if err != nil {
		return err
	}
	for coordinate, vulns := range vulnsByCoordinate {
		for index, vuln := range vulns {
			if detail, ok := details[vuln.ID]; ok {
				vulns[index] = registryVulnerabilityFromOSV(RegistryDependency{
					Ecosystem: vuln.Ecosystem,
					Name:      vuln.PackageName,
					Version:   vuln.PackageVersion,
				}, detail)
			}
		}
		vulnsByCoordinate[coordinate] = vulns
	}

	for skillIndex := range report.Skills {
		for _, dependency := range report.Skills[skillIndex].Dependencies {
			report.Skills[skillIndex].Vulnerabilities = append(report.Skills[skillIndex].Vulnerabilities, vulnsByCoordinate[dependency.key()]...)
		}
		sort.SliceStable(report.Skills[skillIndex].Vulnerabilities, func(i, j int) bool {
			a := report.Skills[skillIndex].Vulnerabilities[i]
			b := report.Skills[skillIndex].Vulnerabilities[j]
			if severityLabelRank(a.Severity) != severityLabelRank(b.Severity) {
				return severityLabelRank(a.Severity) < severityLabelRank(b.Severity)
			}
			if a.PackageName != b.PackageName {
				return a.PackageName < b.PackageName
			}
			return a.ID < b.ID
		})
	}
	return nil
}

func uniqueDependencyCoordinates(skills []RegistrySkillResult) []RegistryDependency {
	seen := map[string]RegistryDependency{}
	for _, skill := range skills {
		for _, dependency := range skill.Dependencies {
			if dependency.Ecosystem == "" || dependency.Name == "" || dependency.Version == "" {
				continue
			}
			seen[dependency.key()] = dependency
		}
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

func (dependency RegistryDependency) key() string {
	return strings.Join([]string{dependency.Ecosystem, dependency.Name, dependency.Version}, "|")
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvVulnerabilityList `json:"results"`
}

type osvVulnerabilityList struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID        string        `json:"id"`
	Aliases   []string      `json:"aliases"`
	Summary   string        `json:"summary"`
	Published string        `json:"published"`
	Modified  string        `json:"modified"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func queryOSVBatch(client *http.Client, apiBase string, dependencies []RegistryDependency) ([]osvVulnerabilityList, error) {
	body, err := osvBatchRequestBody(dependencies)
	if err != nil {
		return nil, err
	}

	payload, err := postOSVBatch(client, apiBase, body)
	if err != nil {
		return nil, err
	}

	var response osvBatchResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("parse OSV batch response: %w", err)
	}
	return response.Results, nil
}

func queryOSVBatchCached(client *http.Client, apiBase string, dependencies []RegistryDependency, cacheDir string) ([]osvVulnerabilityList, error) {
	body, err := osvBatchRequestBody(dependencies)
	if err != nil {
		return nil, err
	}
	cachePath := osvBatchCachePath(cacheDir, body)
	if payload, ok := readCacheFile(cachePath); ok {
		var response osvBatchResponse
		if err := json.Unmarshal(payload, &response); err != nil {
			return nil, fmt.Errorf("parse cached OSV batch response: %w", err)
		}
		return response.Results, nil
	}

	payload, err := postOSVBatch(client, apiBase, body)
	if err != nil {
		return nil, err
	}
	if err := writeCacheFile(cachePath, payload); err != nil {
		return nil, err
	}

	var response osvBatchResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("parse OSV batch response: %w", err)
	}
	return response.Results, nil
}

func osvBatchRequestBody(dependencies []RegistryDependency) ([]byte, error) {
	request := osvBatchRequest{Queries: make([]osvQuery, 0, len(dependencies))}
	for _, dependency := range dependencies {
		request.Queries = append(request.Queries, osvQuery{
			Version: dependency.Version,
			Package: osvPackage{
				Name:      dependency.Name,
				Ecosystem: dependency.Ecosystem,
			},
		})
	}
	return json.Marshal(request)
}

func postOSVBatch(client *http.Client, apiBase string, body []byte) ([]byte, error) {
	rawURL, err := joinURL(apiBase, "/v1/querybatch")
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(rawURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	payload, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("read POST %s: %w", rawURL, readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("POST %s: status %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func fetchOSVDetails(client *http.Client, apiBase string, ids map[string]bool, options ScanOptions) (map[string]osvVulnerability, error) {
	if len(ids) == 0 {
		return map[string]osvVulnerability{}, nil
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		if strings.TrimSpace(id) != "" {
			ordered = append(ordered, id)
		}
	}
	sort.Strings(ordered)
	out := map[string]osvVulnerability{}
	for index, id := range ordered {
		payload, err := fetchOSVDetailPayload(client, apiBase, id, options.CacheDir)
		if err != nil {
			return nil, err
		}
		var vuln osvVulnerability
		if err := json.Unmarshal(payload, &vuln); err != nil {
			return nil, fmt.Errorf("parse OSV vulnerability %s: %w", id, err)
		}
		if vuln.ID == "" {
			vuln.ID = id
		}
		out[id] = vuln
		emitProgress(options, "osv-details", index+1, len(ordered))
	}
	return out, nil
}

func fetchOSVDetailPayload(client *http.Client, apiBase string, id string, cacheDir string) ([]byte, error) {
	cachePath := osvVulnCachePath(cacheDir, id)
	if payload, ok := readCacheFile(cachePath); ok {
		return payload, nil
	}

	rawURL, err := joinURL(apiBase, "/v1/vulns/"+url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	payload, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read GET %s: %w", rawURL, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close GET %s: %w", rawURL, closeErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: status %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if err := writeCacheFile(cachePath, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func registryVulnerabilityFromOSV(dependency RegistryDependency, vuln osvVulnerability) RegistryVulnerability {
	severityType, severityScore := primaryOSVSeverity(vuln.Severity)
	return RegistryVulnerability{
		ID:             vuln.ID,
		Aliases:        append([]string(nil), vuln.Aliases...),
		Ecosystem:      dependency.Ecosystem,
		PackageName:    dependency.Name,
		PackageVersion: dependency.Version,
		Severity:       severityLabelFromOSV(severityScore, vuln.DatabaseSpecific, vuln.EcosystemSpecific),
		SeverityType:   severityType,
		SeverityScore:  severityScore,
		Summary:        vuln.Summary,
		Published:      normalizeRegistryTimestamp(vuln.Published),
		Modified:       normalizeRegistryTimestamp(vuln.Modified),
		FixedVersions:  fixedVersions(vuln),
		References:     referenceURLs(vuln),
	}
}

func primaryOSVSeverity(severities []osvSeverity) (string, string) {
	if len(severities) == 0 {
		return "", ""
	}
	return severities[0].Type, severities[0].Score
}

func severityLabelFromOSV(score string, databaseSpecific map[string]any, ecosystemSpecific map[string]any) string {
	for _, source := range []map[string]any{databaseSpecific, ecosystemSpecific} {
		for _, key := range []string{"severity", "cvss_severity"} {
			if value, ok := source[key].(string); ok && value != "" {
				return normalizeSeverityLabel(value)
			}
		}
	}
	if numeric, ok := numericSeverityScore(score); ok {
		switch {
		case numeric >= 9:
			return "critical"
		case numeric >= 7:
			return "high"
		case numeric >= 4:
			return "medium"
		case numeric > 0:
			return "low"
		}
	}
	return "unknown"
}

func normalizeSeverityLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "critical", "high", "medium", "moderate", "low":
		if value == "moderate" {
			return "medium"
		}
		return value
	default:
		return "unknown"
	}
}

func numericSeverityScore(score string) (float64, bool) {
	score = strings.TrimSpace(score)
	if score == "" || strings.HasPrefix(score, "CVSS:") {
		return 0, false
	}
	value, err := strconv.ParseFloat(score, 64)
	return value, err == nil
}

func fixedVersions(vuln osvVulnerability) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, affected := range vuln.Affected {
		for _, rangeItem := range affected.Ranges {
			for _, event := range rangeItem.Events {
				if event.Fixed == "" || seen[event.Fixed] {
					continue
				}
				seen[event.Fixed] = true
				out = append(out, event.Fixed)
			}
		}
	}
	sort.Strings(out)
	return out
}

func referenceURLs(vuln osvVulnerability) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ref := range vuln.References {
		if ref.URL == "" || seen[ref.URL] {
			continue
		}
		seen[ref.URL] = true
		out = append(out, ref.URL)
	}
	sort.Strings(out)
	return out
}

func joinURL(apiBase string, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(apiBase, "/"))
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	return parsed.String(), nil
}

func osvBatchCachePath(cacheDir string, body []byte) string {
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return ""
	}
	sum := sha256.Sum256(body)
	return filepath.Join(cacheDir, "osv", "batches", fmt.Sprintf("%x.json", sum[:]))
}

func osvVulnCachePath(cacheDir string, id string) string {
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(cacheDir, "osv", "vulns", fmt.Sprintf("%x.json", sum[:]))
}

func readCacheFile(path string) ([]byte, bool) {
	if strings.TrimSpace(path) == "" {
		return nil, false
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func writeCacheFile(path string, payload []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create cache temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write cache temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close cache temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit cache file: %w", err)
	}
	return nil
}
