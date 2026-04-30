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

	"github.com/runbrake/runbrake-oss/internal/hermes"
	"github.com/runbrake/runbrake-oss/internal/redaction"
)

const defaultScannerVersion = "0.1.0"
const minimumSafeOpenClawVersion = "1.4.0"

type openClawConfig struct {
	AgentID         string        `json:"agentId"`
	Version         string        `json:"version"`
	Gateway         gatewayConfig `json:"gateway"`
	Agents          agentsConfig  `json:"agents"`
	Tools           []string      `json:"tools"`
	OAuthScopes     []string      `json:"oauthScopes"`
	Logs            []string      `json:"logs"`
	BackgroundTasks []string      `json:"backgroundTasks"`
	StandingOrders  []string      `json:"standingOrders"`
	MemoryFiles     []string      `json:"memoryFiles"`
}

type agentsConfig struct {
	Defaults agentSkillConfig            `json:"defaults"`
	Profiles map[string]agentSkillConfig `json:"profiles"`
}

type agentSkillConfig struct {
	Skills []string `json:"skills"`
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
	ecosystem := normalizeEcosystem(options.Ecosystem)
	if ecosystem == "hermes" {
		return scanHermes(options)
	}
	if ecosystem != "openclaw" {
		return Result{}, fmt.Errorf("unsupported doctor ecosystem %q", options.Ecosystem)
	}
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
		Ecosystem:       "openclaw",
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
	addOpenClawSkillPostureFindings(add, options.Root, cfg)
	addOpenClawPluginDiagnosticFindings(add, options.OpenClawDiagnostics)

	sortFindings(findings)
	result.Report.Findings = findings
	result.Report.Summary = summarize(findings)
	return result, nil
}

func scanHermes(options ScanOptions) (Result, error) {
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

	discovery, err := hermes.Discover(hermes.DiscoverOptions{ExplicitPath: options.Root})
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Root:      discovery.HomeDir,
		Ecosystem: "hermes",
		Report: ScanReport{
			ID:             "scan-" + shortHash("hermes|"+discovery.HomeDir+"|"+now.UTC().Format(time.RFC3339)),
			AgentID:        "hermes-local",
			ScannerVersion: scannerVersion,
			GeneratedAt:    now.UTC().Format(time.RFC3339),
			Findings:       []Finding{},
			ArtifactHashes: []string{},
		},
	}

	localSkills, err := discoverHermesSkillArtifacts(discovery.HomeDir, discovery.SkillDirs, "local")
	if err != nil {
		return Result{}, err
	}
	externalSkills, err := discoverHermesSkillArtifacts(discovery.HomeDir, discovery.ExternalSkillDirs, "external")
	if err != nil {
		return Result{}, err
	}
	plugins, err := discoverHermesArtifacts(discovery.HomeDir, discovery.PluginDirs, "plugin.yaml", "plugin", "local")
	if err != nil {
		return Result{}, err
	}
	hooks, err := discoverHermesArtifacts(discovery.HomeDir, discovery.HookDirs, "HOOK.yaml", "hook", "local")
	if err != nil {
		return Result{}, err
	}
	result.Inventory = Inventory{
		Skills:  append(localSkills, externalSkills...),
		Plugins: plugins,
		Hooks:   hooks,
	}

	for _, artifact := range append(append(append([]Artifact{}, result.Inventory.Skills...), result.Inventory.Plugins...), result.Inventory.Hooks...) {
		if artifact.Hash != "" {
			result.Report.ArtifactHashes = append(result.Report.ArtifactHashes, artifact.Hash)
		}
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

	if discovery.InlineShellEnabled {
		add(
			"RB-HERMES-INLINE-SHELL-ENABLED",
			SeverityMedium,
			0.9,
			"Hermes inline shell expansion is enabled",
			[]string{configEvidence(discovery, "skills.inline_shell=true")},
			"Disable inline shell expansion unless the Hermes home and installed skills are reviewed and pinned.",
		)
	}
	if evidence := hermesSkillShadowEvidence(localSkills, externalSkills); len(evidence) > 0 {
		add(
			"RB-HERMES-EXTERNAL-SKILL-SHADOW",
			SeverityMedium,
			0.88,
			"Hermes external skill shadows a local skill name",
			evidence,
			"Rename or remove duplicate skills so the intended Hermes skill source is unambiguous.",
		)
	}
	if hookEvidence := hermesHookEvidence(discovery, hooks); len(hookEvidence) > 0 {
		add(
			"RB-HERMES-GATEWAY-HOOKS",
			SeverityMedium,
			0.86,
			"Hermes gateway hooks are installed",
			hookEvidence,
			"Review installed Hermes gateway hooks and keep only hooks required for local policy enforcement.",
		)
	}
	if evidence := broadHermesToolsetEvidence(discovery.Toolsets); len(evidence) > 0 {
		add(
			"RB-HERMES-BROAD-TOOLSET",
			SeverityMedium,
			0.86,
			"Hermes config enables broad toolsets",
			evidence,
			"Replace broad Hermes toolsets with specific least-privilege toolsets for the skills you intend to run.",
		)
	}

	sortFindings(findings)
	result.Report.Findings = findings
	result.Report.Summary = summarize(findings)
	return result, nil
}

func addOpenClawPluginDiagnosticFindings(add func(string, Severity, float64, string, []string, string), diagnostics []OpenClawPluginDiagnostic) {
	for _, diagnostic := range diagnostics {
		extra := runtimeBeyondManifest(diagnostic.RuntimeTools, diagnostic.ManifestTools)
		for _, hook := range diagnostic.RuntimeHooks {
			extra = append(extra, "hook:"+hook)
		}
		for _, route := range diagnostic.RuntimeRoutes {
			extra = append(extra, "route:"+route)
		}
		if len(extra) > 0 {
			add("RB-PLUGIN-RUNTIME-MISMATCH", SeverityHigh, 0.88, "OpenClaw plugin runtime capabilities exceed manifest evidence", []string{fmt.Sprintf("plugin %s runtime evidence: %s", pluginDiagnosticName(diagnostic), strings.Join(sortedUnique(extra), ", "))}, "Review plugin inspect output and ensure runtime tools, hooks, and routes are declared and approved before use.")
		}
		if len(diagnostic.DoctorFindings) > 0 {
			add("RB-PLUGIN-DOCTOR-WARNING", SeverityMedium, 0.86, "OpenClaw plugin doctor reported warnings", prefixEvidence("plugin "+pluginDiagnosticName(diagnostic)+": ", diagnostic.DoctorFindings), "Resolve OpenClaw plugin doctor warnings before trusting the plugin in production.")
		}
	}
}

func runtimeBeyondManifest(runtime []string, manifest []string) []string {
	allowed := map[string]bool{}
	for _, value := range manifest {
		allowed[strings.TrimSpace(value)] = true
	}
	out := []string{}
	for _, value := range runtime {
		value = strings.TrimSpace(value)
		if value != "" && !allowed[value] {
			out = append(out, "tool:"+value)
		}
	}
	return out
}

func pluginDiagnosticName(diagnostic OpenClawPluginDiagnostic) string {
	if strings.TrimSpace(diagnostic.Name) != "" {
		return diagnostic.Name
	}
	if strings.TrimSpace(diagnostic.ID) != "" {
		return diagnostic.ID
	}
	return "unknown"
}

type skillLocation struct {
	Name string
	Path string
	Base string
}

func addOpenClawSkillPostureFindings(add func(string, Severity, float64, string, []string, string), root string, cfg openClawConfig) {
	locations := discoverSkillLocations(root)
	byName := map[string][]skillLocation{}
	for _, location := range locations {
		byName[location.Name] = append(byName[location.Name], location)
	}
	for name, matches := range byName {
		if len(matches) < 2 {
			continue
		}
		evidence := []string{}
		hasWorkspace := false
		hasManaged := false
		for _, match := range matches {
			evidence = append(evidence, fmt.Sprintf("%s at %s", name, match.Path))
			if match.Base == "skills" || match.Base == ".agents/skills" {
				hasWorkspace = true
			}
			if match.Base == ".openclaw/skills" {
				hasManaged = true
			}
		}
		add("RB-SKILL-PRECEDENCE-SHADOW", SeverityMedium, 0.86, "OpenClaw skill name appears in multiple precedence locations", evidence, "Remove duplicate skill names or pin the intended higher-precedence skill explicitly.")
		if hasWorkspace && hasManaged {
			add("RB-SKILL-WORKSPACE-OVERRIDE", SeverityMedium, 0.84, "Workspace skill overrides a managed OpenClaw skill", evidence, "Review the workspace override before running agents and move trusted skills into an approved location.")
		}
	}

	if len(cfg.Agents.Defaults.Skills) == 0 {
		add("RB-AGENT-SKILL-ALLOWLIST-MISSING", SeverityMedium, 0.82, "OpenClaw agent default skill allowlist is missing", []string{"agents.defaults.skills is empty or missing"}, "Set an explicit least-privilege skill allowlist for agent defaults.")
		return
	}
	for _, skill := range cfg.Agents.Defaults.Skills {
		if strings.TrimSpace(skill) == "*" {
			add("RB-AGENT-SKILL-WILDCARD", SeverityMedium, 0.84, "OpenClaw agent default skill allowlist is wildcarded", []string{"agents.defaults.skills contains *"}, "Replace wildcard skill access with explicit reviewed skill names.")
			return
		}
	}
}

func discoverSkillLocations(root string) []skillLocation {
	bases := []string{"skills", ".openclaw/skills", ".agents/skills"}
	locations := []skillLocation{}
	for _, base := range bases {
		abs := filepath.Join(root, filepath.FromSlash(base))
		if _, err := os.Stat(abs); errorsIsNotExist(err) {
			continue
		}
		_ = filepath.WalkDir(abs, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || !entry.IsDir() {
				return nil
			}
			manifestPath := filepath.Join(path, "skill.json")
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				return nil
			}
			var manifest artifactManifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				return nil
			}
			name := strings.TrimSpace(manifest.Name)
			if name == "" {
				name = filepath.Base(path)
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			locations = append(locations, skillLocation{
				Name: name,
				Path: filepath.ToSlash(rel),
				Base: base,
			})
			return filepath.SkipDir
		})
	}
	return locations
}

func discoverHermesSkillArtifacts(root string, dirs []string, installMethod string) ([]Artifact, error) {
	return discoverHermesArtifacts(root, dirs, "SKILL.md", "skill", installMethod)
}

func discoverHermesArtifacts(root string, dirs []string, manifestName string, kind string, installMethod string) ([]Artifact, error) {
	artifacts := []Artifact{}
	for _, base := range dirs {
		if _, err := os.Stat(base); errorsIsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
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
			name := extractHermesName(raw, filepath.Base(filepath.Dir(path)))
			artifacts = append(artifacts, Artifact{
				Kind:          kind,
				Ecosystem:     "hermes",
				Name:          name,
				Source:        installMethod,
				InstallMethod: installMethod,
				ManifestPath:  hermesManifestPath(root, path),
				Hash:          "sha256:" + hashBytes(raw),
			})
			return filepath.SkipDir
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].Name != artifacts[j].Name {
			return artifacts[i].Name < artifacts[j].Name
		}
		return artifacts[i].ManifestPath < artifacts[j].ManifestPath
	})
	return artifacts, nil
}

func extractHermesName(raw []byte, fallback string) string {
	manifest := string(raw)
	if strings.HasPrefix(manifest, "---") {
		rest := strings.TrimPrefix(manifest, "---")
		if idx := strings.Index(rest, "---"); idx >= 0 {
			manifest = rest[:idx]
		}
	}
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		key, value, ok := strings.Cut(trimmed, ":")
		if ok && strings.TrimSpace(key) == "name" {
			if name := strings.Trim(strings.TrimSpace(value), `"'`); name != "" {
				return name
			}
		}
	}
	return fallback
}

func hermesManifestPath(root string, manifestPath string) string {
	rel, err := filepath.Rel(root, manifestPath)
	if err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Clean(manifestPath))
}

func configEvidence(discovery hermes.Discovery, detail string) string {
	if discovery.ConfigPath == "" {
		return detail
	}
	return fmt.Sprintf("%s in %s", detail, hermesManifestPath(discovery.HomeDir, discovery.ConfigPath))
}

func hermesSkillShadowEvidence(localSkills []Artifact, externalSkills []Artifact) []string {
	localByName := map[string][]Artifact{}
	for _, skill := range localSkills {
		localByName[skill.Name] = append(localByName[skill.Name], skill)
	}
	evidence := []string{}
	for _, external := range externalSkills {
		for _, local := range localByName[external.Name] {
			evidence = append(evidence, fmt.Sprintf("skill %s local %s shadows external %s", external.Name, local.ManifestPath, external.ManifestPath))
		}
	}
	return sortedUnique(evidence)
}

func artifactEvidence(label string, artifacts []Artifact) []string {
	evidence := []string{}
	for _, artifact := range artifacts {
		evidence = append(evidence, fmt.Sprintf("%s %s at %s", label, artifact.Name, artifact.ManifestPath))
	}
	return sortedUnique(evidence)
}

func hermesHookEvidence(discovery hermes.Discovery, hooks []Artifact) []string {
	evidence := artifactEvidence("hook", hooks)
	if discovery.ShellHookConfigured {
		evidence = append(evidence, configEvidence(discovery, "hooks configured"))
	}
	return sortedUnique(evidence)
}

func broadHermesToolsetEvidence(toolsets []string) []string {
	evidence := []string{}
	for _, toolset := range toolsets {
		normalized := strings.ToLower(strings.TrimSpace(toolset))
		if normalized == "hermes-cli" || normalized == "all" || normalized == "*" {
			evidence = append(evidence, "config toolset "+toolset)
		}
	}
	return sortedUnique(evidence)
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

func normalizeEcosystem(ecosystem string) string {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if ecosystem == "" {
		return "openclaw"
	}
	return ecosystem
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
