package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/redaction"
)

const defaultScannerVersion = "0.1.0"
const minimumSafeOpenClawVersion = "1.4.0"

type openClawConfig struct {
	AgentID         string        `json:"agentId"`
	Version         string        `json:"version"`
	Gateway         gatewayConfig `json:"gateway"`
	Tools           []string      `json:"tools"`
	OAuthScopes     []string      `json:"oauthScopes"`
	Logs            []string      `json:"logs"`
	BackgroundTasks []string      `json:"backgroundTasks"`
	StandingOrders  []string      `json:"standingOrders"`
	MemoryFiles     []string      `json:"memoryFiles"`
}

type gatewayConfig struct {
	BindHost       string   `json:"bindHost"`
	Port           int      `json:"port"`
	Auth           string   `json:"auth"`
	AuthEnabled    *bool    `json:"authEnabled"`
	AllowRemote    bool     `json:"allowRemote"`
	AllowedOrigins []string `json:"allowedOrigins"`
	Tunnels        []string `json:"tunnels"`
}

type artifactManifest struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Source        string            `json:"source"`
	InstallMethod string            `json:"installMethod"`
	Publisher     string            `json:"publisher"`
	Permissions   []string          `json:"permissions"`
	Tools         []string          `json:"tools"`
	OAuthScopes   []string          `json:"oauthScopes"`
	RawFields     map[string]string `json:"-"`
}

func Scan(options ScanOptions) (Result, error) {
	if options.Root == "" {
		return Result{}, fmt.Errorf("scan root is required")
	}

	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	scannerVersion := options.ScannerVersion
	if scannerVersion == "" {
		scannerVersion = defaultScannerVersion
	}

	configPath := filepath.Join(options.Root, "openclaw.json")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return Result{}, fmt.Errorf("read OpenClaw config: %w", err)
	}

	var cfg openClawConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return Result{}, fmt.Errorf("parse OpenClaw config: %w", err)
	}

	if cfg.AgentID == "" {
		cfg.AgentID = "agent-local"
	}

	result := Result{
		Root:            options.Root,
		OpenClawVersion: cfg.Version,
		Report: ScanReport{
			ID:             "scan-" + shortHash(cfg.AgentID+"|"+now.UTC().Format(time.RFC3339)),
			AgentID:        cfg.AgentID,
			ScannerVersion: scannerVersion,
			GeneratedAt:    now.UTC().Format(time.RFC3339),
			Findings:       []Finding{},
			ArtifactHashes: []string{},
		},
	}

	skills, err := discoverArtifacts(options.Root, "skills", "skill.json", "skill")
	if err != nil {
		return Result{}, err
	}
	plugins, err := discoverArtifacts(options.Root, "plugins", "plugin.json", "plugin")
	if err != nil {
		return Result{}, err
	}
	result.Inventory = Inventory{Skills: skills, Plugins: plugins}

	for _, artifact := range append(slices.Clone(skills), plugins...) {
		result.Report.ArtifactHashes = append(result.Report.ArtifactHashes, artifact.Hash)
	}
	sort.Strings(result.Report.ArtifactHashes)

	findings := []Finding{}
	add := func(ruleID string, severity Severity, confidence float64, title string, evidence []string, remediation string) {
		evidence = cleanEvidence(evidence)
		findings = append(findings, Finding{
			ID:          "finding-" + shortHash(ruleID+"|"+strings.Join(evidence, "|")),
			RuleID:      ruleID,
			Severity:    severity,
			Confidence:  confidence,
			Title:       title,
			Evidence:    evidence,
			Remediation: remediation,
		})
	}

	if isRemoteHost(cfg.Gateway.BindHost) && isMissingAuth(cfg.Gateway) {
		add(
			"RB-GATEWAY-EXPOSED",
			SeverityCritical,
			0.98,
			"OpenClaw gateway is exposed without authentication",
			[]string{fmt.Sprintf("gateway bind host %s:%d with auth %s", cfg.Gateway.BindHost, cfg.Gateway.Port, authLabel(cfg.Gateway))},
			"Bind the gateway to 127.0.0.1 and require a local token before enabling remote access.",
		)
	}

	if isMissingAuth(cfg.Gateway) {
		add(
			"RB-AUTH-MISSING",
			SeverityHigh,
			0.95,
			"OpenClaw gateway authentication is disabled or missing",
			[]string{"gateway authentication is " + authLabel(cfg.Gateway)},
			"Enable token-based gateway authentication and rotate any previously exposed local credentials.",
		)
	}

	if cfg.Gateway.AllowRemote || slices.Contains(cfg.Gateway.AllowedOrigins, "*") {
		add(
			"RB-GATEWAY-REMOTE",
			SeverityMedium,
			0.88,
			"OpenClaw gateway allows unsafe remote access",
			[]string{fmt.Sprintf("allowRemote=%t allowedOrigins=%s", cfg.Gateway.AllowRemote, strings.Join(cfg.Gateway.AllowedOrigins, ","))},
			"Restrict remote origins to trusted hosts and keep the gateway local unless a reviewed tunnel is required.",
		)
	}

	tunnelEvidence := tunnelIndicators(cfg, options.Root)
	if len(tunnelEvidence) > 0 {
		add(
			"RB-GATEWAY-TUNNEL",
			SeverityMedium,
			0.87,
			"OpenClaw gateway appears to use a public tunnel",
			tunnelEvidence,
			"Disable public tunnels or front them with strong authentication, allowlists, and audit logging.",
		)
	}

	if versionLessThan(cfg.Version, minimumSafeOpenClawVersion) {
		add(
			"RB-VERSION-STALE",
			SeverityLow,
			0.82,
			"OpenClaw version is behind the bundled advisory baseline",
			[]string{fmt.Sprintf("OpenClaw version %s is older than baseline %s", cfg.Version, minimumSafeOpenClawVersion)},
			"Upgrade OpenClaw to the current stable release and rerun the doctor.",
		)
	}

	toolEvidence := dangerousToolEvidence(cfg, result.Inventory)
	if len(toolEvidence) > 0 {
		add(
			"RB-TOOL-BROAD-PERMISSIONS",
			SeverityHigh,
			0.9,
			"Installed configuration grants broad tool permissions",
			toolEvidence,
			"Remove unused dangerous tools or require approval policies for shell, write, send, and payment-like actions.",
		)
	}

	oauthEvidence := broadOAuthEvidence(cfg, result.Inventory)
	if len(oauthEvidence) > 0 {
		add(
			"RB-OAUTH-BROAD-SCOPES",
			SeverityHigh,
			0.91,
			"OpenClaw install requests broad OAuth scopes",
			oauthEvidence,
			"Replace broad OAuth scopes with least-privilege scopes and rotate grants that were issued broadly.",
		)
	}

	secretEvidence, err := secretEvidence(options.Root, cfg, append(slices.Clone(skills), plugins...))
	if err != nil {
		return Result{}, err
	}
	if len(secretEvidence) > 0 {
		add(
			"RB-SECRET-PLAINTEXT",
			SeverityHigh,
			0.95,
			"Plaintext secret detected in local OpenClaw files",
			secretEvidence,
			"Move secrets into a dedicated secret manager and rotate exposed credentials.",
		)
	}

	if unsafeConfigPermissions(configPath) {
		add(
			"RB-CONFIG-PERMISSIONS",
			SeverityHigh,
			0.86,
			"OpenClaw config file is group or world writable",
			[]string{"openclaw.json allows group or world writes"},
			"Restrict the config file to the current user, for example chmod 600 openclaw.json.",
		)
	}

	addPersistenceFindings(&findings, add, options.Root, cfg)

	sortFindings(findings)
	result.Report.Findings = findings
	result.Report.Summary = summarize(findings)
	return result, nil
}

func discoverArtifacts(root string, dir string, manifestName string, kind string) ([]Artifact, error) {
	base := filepath.Join(root, dir)
	if _, err := os.Stat(base); errorsIsNotExist(err) {
		return []Artifact{}, nil
	}

	artifacts := []Artifact{}
	if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != manifestName {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var manifest artifactManifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return fmt.Errorf("parse %s manifest %s: %w", kind, path, err)
		}

		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		artifacts = append(artifacts, Artifact{
			Kind:           kind,
			Name:           manifest.Name,
			Version:        manifest.Version,
			Source:         manifest.Source,
			InstallMethod:  manifest.InstallMethod,
			ManifestPath:   filepath.ToSlash(rel),
			Hash:           "sha256:" + hashBytes(raw),
			Permissions:    sortedUnique(manifest.Permissions),
			Tools:          sortedUnique(manifest.Tools),
			OAuthScopes:    sortedUnique(manifest.OAuthScopes),
			ManifestFields: stringFields(fields),
		})
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Name < artifacts[j].Name
	})
	return artifacts, nil
}

func cleanEvidence(evidence []string) []string {
	cleaned := make([]string, 0, len(evidence))
	for _, item := range evidence {
		item = strings.TrimSpace(redaction.Redact(item))
		if item != "" {
			cleaned = append(cleaned, item)
		}
	}
	return sortedUnique(cleaned)
}

func isRemoteHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	return host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1"
}

func isMissingAuth(gateway gatewayConfig) bool {
	if gateway.AuthEnabled != nil && !*gateway.AuthEnabled {
		return true
	}
	auth := strings.TrimSpace(strings.ToLower(gateway.Auth))
	return auth == "" || auth == "none" || auth == "disabled"
}

func authLabel(gateway gatewayConfig) string {
	if gateway.Auth == "" {
		return "missing"
	}
	return gateway.Auth
}

func tunnelIndicators(cfg openClawConfig, root string) []string {
	evidence := []string{}
	for _, tunnel := range cfg.Gateway.Tunnels {
		evidence = append(evidence, "gateway tunnel configured: "+tunnel)
	}

	for _, logPath := range cfg.Logs {
		data, err := readRootFile(root, logPath)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, indicator := range []string{"ngrok", "cloudflared", "localhost.run"} {
			if strings.Contains(lower, indicator) {
				evidence = append(evidence, filepath.ToSlash(logPath)+" mentions "+indicator)
			}
		}
	}
	return sortedUnique(evidence)
}

func dangerousToolEvidence(cfg openClawConfig, inventory Inventory) []string {
	dangerous := map[string]string{
		"shell":         "shell execution",
		"file_write":    "file write",
		"browser":       "browser control",
		"email_send":    "email send",
		"github_write":  "GitHub write",
		"drive_write":   "Drive write",
		"payment":       "payment-like action",
		"payments":      "payment-like action",
		"payment_send":  "payment-like action",
		"stripe_charge": "payment-like action",
	}

	evidence := []string{}
	for _, tool := range cfg.Tools {
		if label, ok := dangerous[strings.ToLower(tool)]; ok {
			evidence = append(evidence, "config grants "+label+" via "+tool)
		}
	}

	for _, artifact := range append(slices.Clone(inventory.Skills), inventory.Plugins...) {
		for _, value := range append(slices.Clone(artifact.Permissions), artifact.Tools...) {
			if label, ok := dangerous[strings.ToLower(value)]; ok {
				evidence = append(evidence, artifact.Kind+" "+artifact.Name+" grants "+label+" via "+value)
			}
		}
	}

	return sortedUnique(evidence)
}

func broadOAuthEvidence(cfg openClawConfig, inventory Inventory) []string {
	evidence := []string{}
	for _, scope := range cfg.OAuthScopes {
		if isBroadScope(scope) {
			evidence = append(evidence, "config requests broad OAuth scope "+scope)
		}
	}

	for _, artifact := range append(slices.Clone(inventory.Skills), inventory.Plugins...) {
		for _, scope := range artifact.OAuthScopes {
			if isBroadScope(scope) {
				evidence = append(evidence, artifact.Kind+" "+artifact.Name+" requests broad OAuth scope "+scope)
			}
		}
	}
	return sortedUnique(evidence)
}

func isBroadScope(scope string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	broadMarkers := []string{
		"mail.google.com",
		"auth/drive",
		"gmail.modify",
		"gmail.send",
		"repo",
		"admin",
		"chat:write",
		"files:write",
		"payments",
	}
	for _, marker := range broadMarkers {
		if scope == marker || strings.Contains(scope, marker) {
			return true
		}
	}
	return false
}

func secretEvidence(root string, cfg openClawConfig, artifacts []Artifact) ([]string, error) {
	paths := []string{"openclaw.json"}
	paths = append(paths, cfg.Logs...)
	for _, artifact := range artifacts {
		paths = append(paths, artifact.ManifestPath)
	}

	evidence := []string{}
	for _, rel := range sortedUnique(paths) {
		data, err := readRootFile(root, rel)
		if err != nil {
			continue
		}
		for _, match := range redaction.FindSecrets(filepath.ToSlash(rel), string(data)) {
			evidence = append(evidence, match.Evidence)
		}
	}
	return sortedUnique(evidence), nil
}

func unsafeConfigPermissions(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o022 != 0
}

func addPersistenceFindings(findings *[]Finding, add func(string, Severity, float64, string, []string, string), root string, cfg openClawConfig) {
	if entries := listDirEvidence(root, "cron", "cron entry"); len(entries) > 0 {
		add("RB-PERSISTENCE-CRON", SeverityMedium, 0.88, "OpenClaw install has cron persistence", entries, "Remove unreviewed cron entries and move scheduled work behind explicit approval.")
	}

	if entries := listDirEvidence(root, "launch-agents", "launch agent"); len(entries) > 0 {
		add("RB-PERSISTENCE-LAUNCH-AGENT", SeverityMedium, 0.88, "OpenClaw install has launch-agent persistence", entries, "Remove unreviewed launch agents and document required startup behavior.")
	}

	if len(cfg.BackgroundTasks) > 0 {
		add("RB-PERSISTENCE-BACKGROUND", SeverityMedium, 0.86, "OpenClaw background tasks are configured", prefixEvidence("background task configured: ", cfg.BackgroundTasks), "Review background tasks and require human approval for sensitive recurring actions.")
	}

	if len(cfg.StandingOrders) > 0 {
		add("RB-PERSISTENCE-STANDING-ORDER", SeverityMedium, 0.84, "OpenClaw standing orders are configured", prefixEvidence("standing order configured: ", cfg.StandingOrders), "Move standing orders into reviewed policy and expire high-risk instructions.")
	}

	memoryEvidence := []string{}
	for _, rel := range cfg.MemoryFiles {
		data, err := readRootFile(root, rel)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "standing order") || strings.Contains(lower, "always ") || strings.Contains(lower, "background") {
			memoryEvidence = append(memoryEvidence, filepath.ToSlash(rel)+" contains persistent instructions")
		}
	}
	if len(memoryEvidence) > 0 {
		add("RB-PERSISTENCE-MEMORY", SeverityMedium, 0.82, "OpenClaw memory files contain persistent instructions", memoryEvidence, "Review memory/config persistence and remove instructions that bypass fresh approval.")
	}
}

func listDirEvidence(root string, dir string, label string) []string {
	base := filepath.Join(root, dir)
	evidence := []string{}
	_ = filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil {
			evidence = append(evidence, label+" file "+filepath.ToSlash(rel))
		}
		return nil
	})
	return sortedUnique(evidence)
}

func prefixEvidence(prefix string, values []string) []string {
	evidence := make([]string, 0, len(values))
	for _, value := range values {
		evidence = append(evidence, prefix+value)
	}
	return evidence
}

func readRootFile(root string, rel string) ([]byte, error) {
	cleanRel := filepath.Clean(rel)
	if filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) || cleanRel == ".." {
		return nil, fmt.Errorf("path escapes root: %s", rel)
	}
	return os.ReadFile(filepath.Join(root, cleanRel))
}

func summarize(findings []Finding) Summary {
	var summary Summary
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}
	return summary
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

func versionLessThan(got string, baseline string) bool {
	g, okG := parseVersion(got)
	b, okB := parseVersion(baseline)
	if !okG || !okB {
		return false
	}
	for i := 0; i < len(g) && i < len(b); i++ {
		if g[i] < b[i] {
			return true
		}
		if g[i] > b[i] {
			return false
		}
	}
	return false
}

func parseVersion(version string) ([]int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return nil, false
	}
	out := make([]int, 3)
	for i := 0; i < len(out) && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringFields(fields map[string]any) map[string]string {
	out := map[string]string{}
	for key, value := range fields {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case float64:
			out[key] = fmt.Sprintf("%v", typed)
		case bool:
			out[key] = fmt.Sprintf("%t", typed)
		}
	}
	return out
}

func shortHash(input string) string {
	return hashBytes([]byte(input))[:16]
}

func hashBytes(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
