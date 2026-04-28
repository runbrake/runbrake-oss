package registry

import (
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
	"time"
)

const (
	defaultClawHubPageLimit = 100
	maxRetryAttempts        = 4
	DefaultClawHubAPIBase   = "https://clawhub.ai"
)

type clawHubListResponse struct {
	Items      []clawHubSkill `json:"items"`
	NextCursor *string        `json:"nextCursor"`
}

type clawHubSkill struct {
	Owner            string            `json:"owner"`
	OwnerDisplayName string            `json:"ownerDisplayName"`
	OwnerUserID      string            `json:"ownerUserId"`
	Slug             string            `json:"slug"`
	DisplayName      string            `json:"displayName"`
	Name             string            `json:"name"`
	Summary          string            `json:"summary"`
	Source           string            `json:"source"`
	SourceURL        string            `json:"sourceUrl"`
	Version          string            `json:"version"`
	Tags             map[string]string `json:"tags"`
	Stats            struct {
		Comments        int `json:"comments"`
		Downloads       int `json:"downloads"`
		InstallsAllTime int `json:"installsAllTime"`
		InstallsCurrent int `json:"installsCurrent"`
		Stars           int `json:"stars"`
		Versions        int `json:"versions"`
	} `json:"stats"`
	CreatedAt     json.RawMessage `json:"createdAt"`
	UpdatedAt     json.RawMessage `json:"updatedAt"`
	LatestVersion struct {
		Version   string          `json:"version"`
		CreatedAt json.RawMessage `json:"createdAt"`
		Changelog string          `json:"changelog"`
		License   string          `json:"license"`
	} `json:"latestVersion"`
	ModerationStatus   string
	ModerationWarnings bool
}

type clawHubSkillResponse struct {
	Skill         *clawHubSkill `json:"skill"`
	LatestVersion *struct {
		Version string `json:"version"`
	} `json:"latestVersion"`
	Owner *struct {
		Handle      string `json:"handle"`
		UserID      string `json:"userId"`
		DisplayName string `json:"displayName"`
		Image       string `json:"image"`
	} `json:"owner"`
	Moderation *struct {
		IsSuspicious     bool   `json:"isSuspicious"`
		IsMalwareBlocked bool   `json:"isMalwareBlocked"`
		Verdict          string `json:"verdict"`
	} `json:"moderation"`
}

type clawHubScanResponse struct {
	Status        string `json:"status"`
	HasWarnings   bool   `json:"hasWarnings"`
	CheckedAt     string `json:"checkedAt"`
	Model         string `json:"model"`
	SHA256Hash    string `json:"sha256hash"`
	VirusTotalURL string `json:"virustotalUrl"`
	Scanners      map[string]struct {
		Status     string  `json:"status"`
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Summary    string  `json:"summary"`
		CheckedAt  string  `json:"checkedAt"`
	} `json:"scanners"`
	Security struct {
		Status        string `json:"status"`
		HasWarnings   bool   `json:"hasWarnings"`
		CheckedAt     string `json:"checkedAt"`
		Model         string `json:"model"`
		SHA256Hash    string `json:"sha256hash"`
		VirusTotalURL string `json:"virustotalUrl"`
		Scanners      map[string]struct {
			Status     string  `json:"status"`
			Verdict    string  `json:"verdict"`
			Confidence float64 `json:"confidence"`
			Summary    string  `json:"summary"`
			CheckedAt  string  `json:"checkedAt"`
		} `json:"scanners"`
	} `json:"security"`
}

func ScanClawHubAPI(options ScanOptions) (RegistryScanReport, error) {
	apiBase := strings.TrimSpace(options.APIBase)
	if apiBase == "" {
		apiBase = DefaultClawHubAPIBase
	}

	source := RegistrySource{
		Type:    SourceClawHub,
		APIBase: strings.TrimRight(apiBase, "/"),
	}
	report := newReport(options, source)

	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	items, err := clawHubSkillItems(client, source.APIBase, options)
	if err != nil {
		return RegistryScanReport{}, err
	}
	report.Summary.Discovered = len(items)

	for index, item := range items {
		skill := scanClawHubSkill(client, source.APIBase, options, item)
		aggregateSkill(&report, skill)
		emitProgress(options, "skills", index+1, len(items))
	}
	if err := enrichVulnerabilities(&report, options); err != nil {
		return RegistryScanReport{}, err
	}

	finishReport(&report)
	return report, nil
}

func clawHubSkillItems(client *http.Client, apiBase string, options ScanOptions) ([]clawHubSkill, error) {
	if len(options.Slugs) > 0 {
		items := make([]clawHubSkill, 0, len(options.Slugs))
		for _, slug := range normalizeSlugFilterList(options.Slugs) {
			item, err := fetchClawHubSkillDetail(client, apiBase, slug)
			if err != nil {
				return nil, err
			}
			if item.Slug == "" {
				item.Slug = slug
			}
			items = append(items, item)
		}
		if options.Limit > 0 && len(items) > options.Limit {
			return items[:options.Limit], nil
		}
		return items, nil
	}

	return listClawHubSkills(client, apiBase, options.Limit)
}

func listClawHubSkills(client *http.Client, apiBase string, limit int) ([]clawHubSkill, error) {
	items := []clawHubSkill{}
	cursor := ""
	seenCursors := map[string]bool{}

	for {
		if limit > 0 && len(items) >= limit {
			break
		}

		pageLimit := defaultClawHubPageLimit
		if limit > 0 && limit-len(items) < pageLimit {
			pageLimit = limit - len(items)
		}

		values := url.Values{}
		values.Set("limit", strconv.Itoa(pageLimit))
		if cursor != "" {
			values.Set("cursor", cursor)
		}

		body, err := getWithRetry(client, buildClawHubURL(apiBase, "/api/v1/skills", values))
		if err != nil {
			return nil, err
		}

		var page clawHubListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse clawhub skills page: %w", err)
		}
		items = append(items, page.Items...)

		if page.NextCursor == nil || strings.TrimSpace(*page.NextCursor) == "" {
			break
		}
		cursor = strings.TrimSpace(*page.NextCursor)
		if seenCursors[cursor] {
			return nil, fmt.Errorf("clawhub pagination repeated cursor %q", cursor)
		}
		seenCursors[cursor] = true
	}

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func scanClawHubSkill(client *http.Client, apiBase string, options ScanOptions, item clawHubSkill) RegistrySkillResult {
	detail, detailErr := fetchClawHubSkillDetail(client, apiBase, item.Slug)
	if detailErr == nil {
		item = mergeClawHubSkill(item, detail)
	}

	meta := clawHubSkillMetadata(item, apiBase)
	result := RegistrySkillResult{
		Owner:       meta.Owner,
		Slug:        meta.Slug,
		DisplayName: meta.DisplayName,
		Version:     meta.Version,
		Source:      meta.Source,
		SourceURL:   meta.SourceURL,
		RiskLevel:   "unknown",
		Findings:    []Finding{},
	}

	fileBody, err := fetchClawHubSkillFile(client, apiBase, item.Slug)
	if err != nil {
		result.RiskLevel = "error"
		result.Error = appendError(appendError("", detailErr), err)
		return result
	}

	scanStatus, scanErr := fetchClawHubScanStatus(client, apiBase, item.Slug)

	tmpDir, err := os.MkdirTemp("", "runbrake-registry-skill-*")
	if err != nil {
		result.RiskLevel = "error"
		result.Error = appendError(result.Error, err)
		return result
	}
	defer os.RemoveAll(tmpDir)

	skillDir := filepath.Join(tmpDir, safePathSegment(meta.Slug))
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		result.RiskLevel = "error"
		result.Error = appendError(result.Error, err)
		return result
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), fileBody, 0o644); err != nil {
		result.RiskLevel = "error"
		result.Error = appendError(result.Error, err)
		return result
	}

	result = scanSkillDirectory(options, skillDir, meta)
	result.Path = skillURL(apiBase, item.Slug)
	result.RegistrySecurityStatus = scanStatus.Status
	if result.RegistrySecurityStatus == "" {
		result.RegistrySecurityStatus = item.ModerationStatus
	}
	result.RegistryHasWarnings = scanStatus.HasWarnings
	if !result.RegistryHasWarnings {
		result.RegistryHasWarnings = item.ModerationWarnings
	}
	result.RegistrySecurityCheckedAt = normalizeRegistryTimestamp(scanStatus.CheckedAt)
	result.RegistrySecurityModel = scanStatus.Model
	result.RegistrySecurityHash = scanStatus.SHA256Hash
	result.RegistryVirusTotalURL = scanStatus.VirusTotalURL
	result.RegistryScannerVerdicts = scanStatus.verdicts()
	result.Error = appendError(appendError(result.Error, detailErr), scanErr)
	if result.Error != "" && result.RiskLevel == "clean" {
		result.RiskLevel = "error"
	}
	return result
}

func clawHubSkillMetadata(item clawHubSkill, apiBase string) skillMetadata {
	return skillMetadata{
		Owner:                  strings.TrimSpace(item.Owner),
		OwnerDisplayName:       strings.TrimSpace(item.OwnerDisplayName),
		OwnerUserID:            strings.TrimSpace(item.OwnerUserID),
		Slug:                   strings.TrimSpace(item.Slug),
		DisplayName:            firstNonEmpty(item.DisplayName, item.Name),
		Version:                firstNonEmpty(item.LatestVersion.Version, item.Version, item.Tags["latest"]),
		PublishedAt:            firstNonEmpty(parseRegistryTimestamp(item.LatestVersion.CreatedAt), parseRegistryTimestamp(item.CreatedAt)),
		CreatedAt:              parseRegistryTimestamp(item.CreatedAt),
		UpdatedAt:              parseRegistryTimestamp(item.UpdatedAt),
		LatestVersionCreatedAt: parseRegistryTimestamp(item.LatestVersion.CreatedAt),
		Changelog:              item.LatestVersion.Changelog,
		License:                item.LatestVersion.License,
		VersionCount:           item.Stats.Versions,
		Downloads:              item.Stats.Downloads,
		InstallsCurrent:        item.Stats.InstallsCurrent,
		InstallsAllTime:        item.Stats.InstallsAllTime,
		Stars:                  item.Stats.Stars,
		Comments:               item.Stats.Comments,
		Source:                 item.Source,
		SourceURL:              firstNonEmpty(item.SourceURL, skillURL(apiBase, item.Slug)),
	}
}

func fetchClawHubSkillDetail(client *http.Client, apiBase string, slug string) (clawHubSkill, error) {
	body, err := getWithRetry(client, buildClawHubEscapedURL(apiBase, "/api/v1/skills/"+url.PathEscape(slug), nil))
	if err != nil {
		return clawHubSkill{}, err
	}

	var response clawHubSkillResponse
	if err := json.Unmarshal(body, &response); err == nil && response.Skill != nil {
		item := *response.Skill
		if item.Slug == "" {
			item.Slug = slug
		}
		if response.LatestVersion != nil && item.LatestVersion.Version == "" {
			item.LatestVersion.Version = response.LatestVersion.Version
		}
		if response.Owner != nil {
			item.Owner = firstNonEmpty(response.Owner.Handle, response.Owner.DisplayName, item.Owner)
			item.OwnerDisplayName = firstNonEmpty(response.Owner.DisplayName, item.OwnerDisplayName)
			item.OwnerUserID = firstNonEmpty(response.Owner.UserID, item.OwnerUserID)
		}
		if response.Moderation != nil {
			item.ModerationStatus = response.Moderation.Verdict
			item.ModerationWarnings = response.Moderation.IsSuspicious || response.Moderation.IsMalwareBlocked
		}
		return item, nil
	}

	var item clawHubSkill
	if err := json.Unmarshal(body, &item); err != nil {
		return clawHubSkill{}, fmt.Errorf("parse clawhub skill detail for %q: %w", slug, err)
	}
	if item.Slug == "" {
		item.Slug = slug
	}
	return item, nil
}

func fetchClawHubSkillFile(client *http.Client, apiBase string, slug string) ([]byte, error) {
	values := url.Values{}
	values.Set("path", "SKILL.md")
	return getWithRetry(client, buildClawHubEscapedURL(apiBase, "/api/v1/skills/"+url.PathEscape(slug)+"/file", values))
}

func fetchClawHubScanStatus(client *http.Client, apiBase string, slug string) (clawHubScanResponse, error) {
	body, err := getWithRetry(client, buildClawHubEscapedURL(apiBase, "/api/v1/skills/"+url.PathEscape(slug)+"/scan", nil))
	if err != nil {
		return clawHubScanResponse{}, err
	}

	var response clawHubScanResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return clawHubScanResponse{}, fmt.Errorf("parse clawhub scan status for %q: %w", slug, err)
	}
	if response.Security.Status != "" {
		response.Status = response.Security.Status
		response.HasWarnings = response.Security.HasWarnings
		response.CheckedAt = response.Security.CheckedAt
		response.Model = response.Security.Model
		response.SHA256Hash = response.Security.SHA256Hash
		response.VirusTotalURL = response.Security.VirusTotalURL
		response.Scanners = response.Security.Scanners
	}
	return response, nil
}

func (response clawHubScanResponse) verdicts() []RegistryScannerVerdict {
	out := make([]RegistryScannerVerdict, 0, len(response.Scanners))
	for name, scanner := range response.Scanners {
		out = append(out, RegistryScannerVerdict{
			Scanner:    name,
			Status:     scanner.Status,
			Verdict:    scanner.Verdict,
			Confidence: scanner.Confidence,
			Summary:    scanner.Summary,
			CheckedAt:  normalizeRegistryTimestamp(scanner.CheckedAt),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Scanner < out[j].Scanner
	})
	return out
}

func mergeClawHubSkill(base clawHubSkill, detail clawHubSkill) clawHubSkill {
	if detail.Slug != "" {
		base.Slug = detail.Slug
	}
	base.Owner = firstNonEmpty(detail.Owner, base.Owner)
	base.OwnerDisplayName = firstNonEmpty(detail.OwnerDisplayName, base.OwnerDisplayName)
	base.OwnerUserID = firstNonEmpty(detail.OwnerUserID, base.OwnerUserID)
	base.DisplayName = firstNonEmpty(detail.DisplayName, base.DisplayName)
	base.Name = firstNonEmpty(detail.Name, base.Name)
	base.Summary = firstNonEmpty(detail.Summary, base.Summary)
	base.Source = firstNonEmpty(detail.Source, base.Source)
	base.SourceURL = firstNonEmpty(detail.SourceURL, base.SourceURL)
	base.Version = firstNonEmpty(detail.Version, base.Version)
	if detail.Tags != nil {
		base.Tags = detail.Tags
	}
	if detail.LatestVersion.Version != "" {
		base.LatestVersion.Version = detail.LatestVersion.Version
	}
	if len(detail.LatestVersion.CreatedAt) > 0 {
		base.LatestVersion.CreatedAt = detail.LatestVersion.CreatedAt
	}
	base.LatestVersion.Changelog = firstNonEmpty(detail.LatestVersion.Changelog, base.LatestVersion.Changelog)
	base.LatestVersion.License = firstNonEmpty(detail.LatestVersion.License, base.LatestVersion.License)
	if len(detail.CreatedAt) > 0 {
		base.CreatedAt = detail.CreatedAt
	}
	if len(detail.UpdatedAt) > 0 {
		base.UpdatedAt = detail.UpdatedAt
	}
	if detail.Stats.Downloads != 0 {
		base.Stats.Downloads = detail.Stats.Downloads
	}
	if detail.Stats.Versions != 0 {
		base.Stats.Versions = detail.Stats.Versions
	}
	if detail.Stats.Stars != 0 {
		base.Stats.Stars = detail.Stats.Stars
	}
	if detail.Stats.Comments != 0 {
		base.Stats.Comments = detail.Stats.Comments
	}
	if detail.Stats.InstallsCurrent != 0 {
		base.Stats.InstallsCurrent = detail.Stats.InstallsCurrent
	}
	if detail.Stats.InstallsAllTime != 0 {
		base.Stats.InstallsAllTime = detail.Stats.InstallsAllTime
	}
	base.ModerationStatus = firstNonEmpty(detail.ModerationStatus, base.ModerationStatus)
	base.ModerationWarnings = detail.ModerationWarnings || base.ModerationWarnings
	return base
}

func normalizeSlugFilterList(slugs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range slugs {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func safePathSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "skill"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "skill"
	}
	return b.String()
}

func getWithRetry(client *http.Client, rawURL string) ([]byte, error) {
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		resp, err := client.Get(rawURL)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", rawURL, err)
		}

		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read GET %s: %w", rawURL, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close GET %s: %w", rawURL, closeErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetryAttempts-1 {
			if delay := retryAfterDelay(resp.Header.Get("Retry-After")); delay > 0 {
				time.Sleep(delay)
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("GET %s: status %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return body, nil
	}
	return nil, fmt.Errorf("GET %s: exhausted retries", rawURL)
}

func retryAfterDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		delay := time.Until(at)
		if delay > 0 {
			return delay
		}
	}
	return 0
}

func buildClawHubURL(apiBase string, path string, values url.Values) string {
	base, err := url.Parse(strings.TrimRight(apiBase, "/"))
	if err != nil {
		return strings.TrimRight(apiBase, "/") + path
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	if values != nil {
		base.RawQuery = values.Encode()
	}
	return base.String()
}

func buildClawHubEscapedURL(apiBase string, escapedPath string, values url.Values) string {
	base, err := url.Parse(strings.TrimRight(apiBase, "/"))
	if err != nil {
		raw := strings.TrimRight(apiBase, "/") + escapedPath
		if values != nil && len(values) > 0 {
			raw += "?" + values.Encode()
		}
		return raw
	}

	prefix := strings.TrimRight(base.EscapedPath(), "/")
	rawPath := prefix + escapedPath
	path, unescapeErr := url.PathUnescape(rawPath)
	if unescapeErr != nil {
		base.Path = strings.TrimRight(base.Path, "/") + escapedPath
	} else {
		base.Path = path
		base.RawPath = rawPath
	}
	if values != nil {
		base.RawQuery = values.Encode()
	}
	return base.String()
}

func skillURL(apiBase string, slug string) string {
	return buildClawHubEscapedURL(apiBase, "/skills/"+url.PathEscape(slug), nil)
}
