package skills

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/redaction"
)

const defaultScannerVersion = "0.2.0"

const (
	defaultRemoteTimeout        = 15 * time.Second
	defaultMaxDownloadBytes     = 10 << 20
	defaultMaxExtractedBytes    = 50 << 20
	defaultMaxRelevantFileBytes = 5 << 20
	defaultMaxArchiveFiles      = 2048
	egressProfileAudit          = "audit"
)

var urlPattern = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
var quotedStringPattern = regexp.MustCompile(`["']([^"']{1,200})["']`)

func Scan(options ScanOptions) (Result, error) {
	if strings.TrimSpace(options.Target) == "" {
		return Result{}, fmt.Errorf("skill scan target is required")
	}

	if isRemoteTarget(options.Target) {
		originalTarget := strings.TrimSpace(options.Target)
		now := options.Now
		if now.IsZero() {
			now = time.Now().UTC()
			options.Now = now
		}
		root, cleanup, err := materializeRemoteTarget(options)
		if err != nil {
			return Result{}, err
		}
		defer cleanup()

		options.Target = root
		result, err := scanTargets([]string{root}, options, "remote-skill-scan")
		if err != nil {
			return Result{}, err
		}
		result.Root = originalTarget
		result.Report.ID = "skill-scan-" + shortHash(originalTarget+"|"+now.UTC().Format(time.RFC3339))
		return result, nil
	}

	return scanTargets([]string{options.Target}, options, "skill-scan")
}

func ScanMany(options ScanOptions) (Result, error) {
	if strings.TrimSpace(options.Target) == "" {
		return Result{}, fmt.Errorf("skill scan target is required")
	}
	if isRemoteTarget(options.Target) {
		return Result{}, fmt.Errorf("scan-skills expects a local directory")
	}

	targets, err := childSkillTargets(options.Target)
	if err != nil {
		return Result{}, err
	}
	if len(targets) == 0 {
		return Result{}, fmt.Errorf("no skill or plugin manifests found under %s", options.Target)
	}
	return scanTargets(targets, options, "skill-scan")
}

func scanTargets(targets []string, options ScanOptions, agentID string) (Result, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scannerVersion := options.ScannerVersion
	if scannerVersion == "" {
		scannerVersion = defaultScannerVersion
	}

	result := Result{
		Root: strings.TrimSpace(options.Target),
		Report: doctor.ScanReport{
			ID:             "skill-scan-" + shortHash(strings.Join(targets, "|")+"|"+now.UTC().Format(time.RFC3339)),
			AgentID:        agentID,
			ScannerVersion: scannerVersion,
			GeneratedAt:    now.UTC().Format(time.RFC3339),
			Findings:       []doctor.Finding{},
			ArtifactHashes: []string{},
		},
	}

	for _, target := range targets {
		artifact, files, pkg, err := loadArtifact(target, options)
		if err != nil {
			return Result{}, err
		}

		if artifact.Kind == "plugin" {
			result.Inventory.Plugins = append(result.Inventory.Plugins, artifact)
		} else {
			result.Inventory.Skills = append(result.Inventory.Skills, artifact)
		}
		result.Report.ArtifactHashes = append(result.Report.ArtifactHashes, artifact.Hash)
		result.Report.Findings = append(result.Report.Findings, scanArtifact(artifact, files, pkg, options)...)
	}

	sortArtifacts(result.Inventory.Skills)
	sortArtifacts(result.Inventory.Plugins)
	result.Report.ArtifactHashes = sortedUnique(result.Report.ArtifactHashes)
	sortFindings(result.Report.Findings)
	result.Report.Findings = applySuppressions(result.Report.Findings, result.Inventory, options.Suppressions, now)
	result.Report.Summary = summarize(result.Report.Findings)
	return result, nil
}

func loadArtifact(root string, options ScanOptions) (doctor.Artifact, []scannedFile, packageJSON, error) {
	manifestPath, kind, err := findManifest(root)
	if err != nil {
		return doctor.Artifact{}, nil, packageJSON{}, err
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return doctor.Artifact{}, nil, packageJSON{}, err
	}

	var meta manifest
	if isMarkdownManifest(manifestPath) {
		meta = parseSkillMarkdown(raw)
	} else {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return doctor.Artifact{}, nil, packageJSON{}, fmt.Errorf("parse %s: %w", manifestPath, err)
		}
	}

	files, err := readRelevantFiles(root, options)
	if err != nil {
		return doctor.Artifact{}, nil, packageJSON{}, err
	}

	pkg := packageJSON{}
	pkgPath := filepath.Join(root, "package.json")
	if pkgBytes, err := os.ReadFile(pkgPath); err == nil {
		_ = json.Unmarshal(pkgBytes, &pkg)
	}

	fields := map[string]any{}
	if isMarkdownManifest(manifestPath) {
		for key, value := range parseFrontmatter(raw) {
			fields[key] = value
		}
	} else {
		_ = json.Unmarshal(raw, &fields)
	}
	rel, err := filepath.Rel(root, manifestPath)
	if err != nil {
		return doctor.Artifact{}, nil, packageJSON{}, err
	}

	name := firstNonEmpty(string(meta.Name), string(meta.ID), pkg.Name, filepath.Base(root))
	version := firstNonEmpty(string(meta.Version), pkg.Version)

	artifact := doctor.Artifact{
		Kind:           kind,
		Name:           name,
		Version:        version,
		Source:         string(meta.Source),
		InstallMethod:  string(meta.InstallMethod),
		ManifestPath:   filepath.ToSlash(rel),
		Hash:           "sha256:" + hashFiles(files),
		Permissions:    sortedUnique([]string(meta.Permissions)),
		Tools:          sortedUnique([]string(meta.Tools)),
		OAuthScopes:    sortedUnique([]string(meta.OAuthScopes)),
		ManifestFields: stringFields(fields),
	}
	return artifact, files, pkg, nil
}

func scanArtifact(artifact doctor.Artifact, files []scannedFile, pkg packageJSON, options ScanOptions) []doctor.Finding {
	findings := []doctor.Finding{}
	add := func(ruleID string, evidence []string) {
		rule, ok := ruleByID(ruleID)
		if !ok {
			return
		}
		evidence = qualifyFileEvidence(artifact, evidence)
		cleaned := cleanEvidence(evidence)
		if len(cleaned) == 0 {
			return
		}
		findings = append(findings, doctor.Finding{
			ID:          "finding-" + shortHash(ruleID+"|"+artifact.Name+"|"+strings.Join(cleaned, "|")),
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Confidence:  rule.Confidence,
			Title:       rule.Title,
			Evidence:    cleaned,
			Remediation: fmt.Sprintf("Recommended policy: %s. %s", rule.RecommendedPolicy, rule.Remediation),
		})
	}

	if evidence := shellEvidence(artifact, files); len(evidence) > 0 {
		add(RuleShellExecution, evidence)
	}
	if evidence := fileWriteEvidence(artifact); len(evidence) > 0 {
		add(RuleFileWrite, evidence)
	}
	if evidence := broadOAuthEvidence(artifact); len(evidence) > 0 {
		add(RuleBroadOAuth, evidence)
	}
	if evidence := plaintextSecretEvidence(files); len(evidence) > 0 {
		add(RulePlaintextSecret, evidence)
	}
	if evidence := dangerousInstallEvidence(pkg); len(evidence) > 0 {
		add(RuleDangerousInstall, evidence)
	}
	if evidence := hiddenUnicodeEvidence(files); len(evidence) > 0 {
		add(RuleHiddenUnicode, evidence)
	}
	if evidence := promptInjectionEvidence(files); len(evidence) > 0 {
		add(RulePromptInjection, evidence)
	}
	if evidence := obfuscatedCommandEvidence(files, pkg); len(evidence) > 0 {
		add(RuleObfuscatedCommand, evidence)
	}
	if evidence := base64Evidence(files, pkg); len(evidence) > 0 {
		add(RuleBase64Decode, evidence)
	}
	if evidence := remoteScriptEvidence(files, pkg); len(evidence) > 0 {
		add(RuleRemoteScriptExecution, evidence)
	}
	if evidence := unknownEgressEvidence(artifact, files, pkg, options); len(evidence) > 0 {
		add(RuleUnknownEgress, evidence)
	}
	if evidence := constructedEgressEvidence(files, pkg); len(evidence) > 0 {
		add(RuleConstructedEgress, evidence)
	}
	if evidence := similarNameEvidence(pkg); len(evidence) > 0 {
		add(RuleSimilarNamePackage, evidence)
	}

	sortFindings(findings)
	return findings
}

func findManifest(root string) (string, string, error) {
	for _, candidate := range []struct {
		name string
		kind string
	}{
		{name: "skill.json", kind: "skill"},
		{name: "plugin.json", kind: "plugin"},
		{name: "openclaw.plugin.json", kind: "plugin"},
		{name: "SKILL.md", kind: "skill"},
		{name: "skill.md", kind: "skill"},
	} {
		path := filepath.Join(root, candidate.name)
		if _, err := os.Stat(path); err == nil {
			return path, candidate.kind, nil
		}
	}
	return "", "", fmt.Errorf("no skill.json, plugin.json, or openclaw.plugin.json found in %s", root)
}

func childSkillTargets(root string) ([]string, error) {
	if _, _, err := findManifest(root); err == nil {
		return []string{root}, nil
	}

	targets := []string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if path == root {
			return nil
		}
		switch entry.Name() {
		case ".git", "node_modules", "dist", "coverage", ".cache":
			return filepath.SkipDir
		}
		if _, _, err := findManifest(path); err == nil {
			targets = append(targets, path)
			return filepath.SkipDir
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(targets)
	return targets, nil
}

func isMarkdownManifest(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "skill.md"
}

func parseSkillMarkdown(raw []byte) manifest {
	frontmatter := parseFrontmatter(raw)
	return manifest{
		Name:        flexibleString(frontmatter["name"]),
		Version:     flexibleString(frontmatter["version"]),
		Source:      flexibleString(frontmatter["source"]),
		Permissions: flexibleStringList(splitCSVLike(frontmatter["permissions"])),
		Tools:       flexibleStringList(splitCSVLike(frontmatter["tools"])),
		OAuthScopes: flexibleStringList(splitCSVLike(firstNonEmpty(frontmatter["oauthScopes"], frontmatter["oauth_scopes"]))),
	}
}

func parseFrontmatter(raw []byte) map[string]string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return map[string]string{}
	}

	fields := map[string]string{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || strings.HasPrefix(key, "#") || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
			continue
		}
		fields[key] = strings.Trim(value, `"'`)
	}
	return fields
}

func splitCSVLike(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	value = strings.Trim(value, "[]")
	parts := strings.Split(value, ",")
	out := []string{}
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readRelevantFiles(root string, options ScanOptions) ([]scannedFile, error) {
	files := []scannedFile{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
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
		if !isRelevantFile(entry.Name()) {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			return fmt.Errorf("symlink relevant file is not allowed: %s", filepath.ToSlash(rel))
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		maxFileBytes := resolvedMaxRelevantFileBytes(options)
		if info.Size() > maxFileBytes {
			return fmt.Errorf("relevant file %s exceeds max file bytes %d", filepath.ToSlash(rel), maxFileBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, scannedFile{
			Rel:  filepath.ToSlash(rel),
			Data: data,
			Text: string(data),
		})
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
	return files, nil
}

func isRelevantFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".md", ".txt", ".sh", ".bash", ".zsh", ".js", ".ts", ".tsx", ".mjs", ".cjs", ".yaml", ".yml", ".toml":
		return true
	default:
		return false
	}
}

func shellEvidence(artifact doctor.Artifact, files []scannedFile) []string {
	evidence := []string{}
	for _, value := range append(slices.Clone(artifact.Permissions), artifact.Tools...) {
		if isShellPermission(value) {
			evidence = append(evidence, fmt.Sprintf("%s %s grants shell execution via %s", artifact.Kind, artifact.Name, value))
		}
	}
	for _, file := range files {
		lower := strings.ToLower(file.Text)
		if strings.Contains(lower, " | sh") || strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "bash -c") || strings.Contains(lower, "sh -c") {
			evidence = append(evidence, file.Rel+" contains shell execution syntax")
		}
	}
	return sortedUnique(evidence)
}

func isShellPermission(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "shell" || value == "bash" || value == "terminal" || value == "exec" || value == "command_exec"
}

func fileWriteEvidence(artifact doctor.Artifact) []string {
	evidence := []string{}
	for _, value := range append(slices.Clone(artifact.Permissions), artifact.Tools...) {
		lower := strings.ToLower(strings.TrimSpace(value))
		if lower == "file_write" || lower == "write_file" || lower == "drive_write" || lower == "github_write" {
			evidence = append(evidence, fmt.Sprintf("%s %s grants write permission via %s", artifact.Kind, artifact.Name, value))
		}
	}
	return sortedUnique(evidence)
}

func broadOAuthEvidence(artifact doctor.Artifact) []string {
	evidence := []string{}
	for _, scope := range artifact.OAuthScopes {
		if isBroadScope(scope) {
			evidence = append(evidence, fmt.Sprintf("%s %s requests broad OAuth scope %s", artifact.Kind, artifact.Name, scope))
		}
	}
	return sortedUnique(evidence)
}

func plaintextSecretEvidence(files []scannedFile) []string {
	evidence := []string{}
	for _, file := range files {
		for _, match := range redaction.FindSecrets(file.Rel, file.Text) {
			evidence = append(evidence, match.Evidence)
		}
	}
	return sortedUnique(evidence)
}

func isBroadScope(scope string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	for _, marker := range []string{"mail.google.com", "auth/drive", "gmail.modify", "gmail.send", "repo", "admin", "chat:write", "files:write", "payments"} {
		if scope == marker || strings.Contains(scope, marker) {
			return true
		}
	}
	return false
}

func dangerousInstallEvidence(pkg packageJSON) []string {
	evidence := []string{}
	for name, command := range pkg.Scripts {
		lowerName := strings.ToLower(strings.TrimSpace(name))
		if lowerName != "preinstall" && lowerName != "install" && lowerName != "postinstall" && lowerName != "prepare" {
			continue
		}
		if commandLooksDangerous(command) {
			evidence = append(evidence, fmt.Sprintf("package script %s runs %s", name, command))
		}
	}
	return sortedUnique(evidence)
}

func commandLooksDangerous(command string) bool {
	lower := strings.ToLower(command)
	dangerous := []string{"curl ", "wget ", "| sh", "| bash", "execsync", "child_process", "bash -c", "sh -c", "powershell", "eval "}
	for _, marker := range dangerous {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hiddenUnicodeEvidence(files []scannedFile) []string {
	evidence := []string{}
	for _, file := range files {
		for _, r := range file.Text {
			if isHiddenControl(r) {
				evidence = append(evidence, fmt.Sprintf("%s contains hidden Unicode control U+%04X", file.Rel, r))
			}
		}
	}
	return sortedUnique(evidence)
}

func isHiddenControl(r rune) bool {
	return (r >= '\u202A' && r <= '\u202E') ||
		(r >= '\u2066' && r <= '\u2069') ||
		r == '\u200B' ||
		r == '\u200C' ||
		r == '\u200D' ||
		r == '\uFEFF'
}

func promptInjectionEvidence(files []scannedFile) []string {
	evidence := []string{}
	for _, file := range files {
		lower := strings.ToLower(file.Text)
		for _, marker := range []string{"ignore previous instructions", "ignore all previous", "exfiltrate", "reveal secrets", "leak secrets", "bypass policy"} {
			if strings.Contains(lower, marker) {
				evidence = append(evidence, file.Rel+" contains prompt-injection phrase "+marker)
			}
		}
	}
	return sortedUnique(evidence)
}

func obfuscatedCommandEvidence(files []scannedFile, pkg packageJSON) []string {
	evidence := []string{}
	for _, file := range files {
		lower := strings.ToLower(file.Text)
		for _, marker := range []string{"eval ", "execsync", "child_process", "bash -c", "sh -c", "powershell -enc"} {
			if strings.Contains(lower, marker) {
				evidence = append(evidence, file.Rel+" contains obfuscated command marker "+marker)
			}
		}
	}
	for name, command := range pkg.Scripts {
		if commandLooksDangerous(command) {
			evidence = append(evidence, "package script "+name+" contains obfuscated command execution")
		}
	}
	return sortedUnique(evidence)
}

func base64Evidence(files []scannedFile, pkg packageJSON) []string {
	evidence := []string{}
	check := func(location string, text string) {
		lower := strings.ToLower(text)
		for _, marker := range []string{"base64 -d", "base64 --decode", "base64.b64decode", "frombase64", "atob("} {
			if strings.Contains(lower, marker) {
				evidence = append(evidence, location+" contains base64 decode marker "+marker)
			}
		}
	}
	for _, file := range files {
		check(file.Rel, file.Text)
	}
	for name, command := range pkg.Scripts {
		check("package script "+name, command)
	}
	return sortedUnique(evidence)
}

func remoteScriptEvidence(files []scannedFile, pkg packageJSON) []string {
	evidence := []string{}
	check := func(location string, text string) {
		lower := strings.ToLower(text)
		if (strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ")) &&
			(strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash")) {
			evidence = append(evidence, location+" downloads a remote script and pipes it to a shell")
		}
	}
	for _, file := range files {
		check(file.Rel, file.Text)
	}
	for name, command := range pkg.Scripts {
		check("package script "+name, command)
	}
	return sortedUnique(evidence)
}

func unknownEgressEvidence(artifact doctor.Artifact, files []scannedFile, pkg packageJSON, options ScanOptions) []string {
	if strings.EqualFold(strings.TrimSpace(options.EgressProfile), egressProfileAudit) {
		return nil
	}
	evidence := []string{}
	if domain := unknownDomain(artifact.Source, options.AllowDomains); domain != "" {
		evidence = append(evidence, fmt.Sprintf("%s %s source references unknown domain %s", artifact.Kind, artifact.Name, domain))
	}
	for _, file := range files {
		for _, rawURL := range extractedURLs(file.Text) {
			if domain := unknownDomain(rawURL, options.AllowDomains); domain != "" {
				evidence = append(evidence, file.Rel+" references unknown egress domain "+domain)
			}
		}
	}
	for name, command := range pkg.Scripts {
		for _, rawURL := range extractedURLs(command) {
			if domain := unknownDomain(rawURL, options.AllowDomains); domain != "" {
				evidence = append(evidence, "package script "+name+" references unknown egress domain "+domain)
			}
		}
	}
	return sortedUnique(evidence)
}

func extractedURLs(text string) []string {
	urls := append([]string(nil), urlPattern.FindAllString(text, -1)...)
	for _, match := range quotedStringPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(match[1])
		if err != nil {
			continue
		}
		urls = append(urls, urlPattern.FindAllString(string(decoded), -1)...)
	}
	return sortedUnique(urls)
}

func constructedEgressEvidence(files []scannedFile, pkg packageJSON) []string {
	evidence := []string{}
	check := func(location, text string) {
		lower := strings.ToLower(text)
		if strings.Contains(lower, ".join(\".\")") || strings.Contains(lower, ".join('.')") {
			evidence = append(evidence, location+" dynamically joins domain labels")
		}
		if strings.Contains(lower, `"https://" +`) || strings.Contains(lower, `'https://' +`) ||
			strings.Contains(lower, "`https://${") || strings.Contains(lower, "new url(") {
			evidence = append(evidence, location+" dynamically constructs a URL")
		}
		for _, rawURL := range extractedURLs(text) {
			if domain := unknownDomain(rawURL, nil); domain != "" && strings.Contains(lower, "atob(") {
				evidence = append(evidence, location+" decodes hidden URL domain "+domain)
			}
		}
	}
	for _, file := range files {
		check(file.Rel, file.Text)
	}
	for name, command := range pkg.Scripts {
		check("package script "+name, command)
	}
	return sortedUnique(evidence)
}

func unknownDomain(raw string, allowDomains []string) string {
	raw = strings.Trim(strings.TrimSpace(raw), `"'.,;:!?)>]}`)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return ""
	}
	allowlist := []string{
		"github.com",
		"raw.githubusercontent.com",
		"registry.npmjs.org",
		"npmjs.com",
		"www.npmjs.com",
		"openai.com",
		"api.openai.com",
		"openclaw.ai",
		"clawhub.ai",
		"clawhub.com",
		"googleapis.com",
		"www.googleapis.com",
	}
	for _, allowed := range allowlist {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return ""
		}
	}
	for _, allowed := range allowDomains {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		allowed = strings.TrimPrefix(allowed, ".")
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return ""
		}
	}
	return host
}

func qualifyFileEvidence(artifact doctor.Artifact, evidence []string) []string {
	prefix := strings.TrimSpace(artifact.Kind+" "+artifact.Name) + ": "
	out := make([]string, 0, len(evidence))
	for _, item := range evidence {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" || strings.HasPrefix(trimmed, artifact.Kind+" "+artifact.Name) || strings.Contains(trimmed, ": ") {
			out = append(out, item)
			continue
		}
		out = append(out, prefix+item)
	}
	return out
}

func similarNameEvidence(pkg packageJSON) []string {
	popular := []string{"lodash", "express", "axios", "react", "typescript", "openai", "next", "vite", "eslint", "prettier"}
	evidence := []string{}
	for dep := range allDependencies(pkg) {
		base := unscopedPackageName(dep)
		for _, target := range popular {
			if base == target {
				continue
			}
			if levenshtein(base, target) <= 2 {
				evidence = append(evidence, fmt.Sprintf("dependency %s is similar to popular package %s", dep, target))
				break
			}
		}
	}
	return sortedUnique(evidence)
}

func allDependencies(pkg packageJSON) map[string]string {
	out := map[string]string{}
	for _, group := range []flexibleStringMap{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name, version := range group {
			out[name] = version
		}
	}
	return out
}

func unscopedPackageName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return name
}

func materializeRemoteTarget(options ScanOptions) (string, func(), error) {
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: resolvedTimeout(options)}
	}
	resp, err := client.Get(options.Target)
	if err != nil {
		return "", func() {}, fmt.Errorf("fetch remote skill: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", func() {}, fmt.Errorf("fetch remote skill: HTTP %d", resp.StatusCode)
	}
	maxDownloadBytes := resolvedMaxDownloadBytes(options)
	data, err := readLimited(resp.Body, maxDownloadBytes, "remote skill exceeds max download bytes")
	if err != nil {
		return "", func() {}, err
	}

	root, err := os.MkdirTemp("", "runbrake-skill-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }

	if looksLikeZip(options.Target, resp.Header.Get("Content-Type"), data) {
		if err := unzipBytes(data, root, options); err != nil {
			cleanup()
			return "", func() {}, err
		}
		return root, cleanup, nil
	}

	if json.Valid(data) {
		if err := os.WriteFile(filepath.Join(root, "skill.json"), data, 0o600); err != nil {
			cleanup()
			return "", func() {}, err
		}
		return root, cleanup, nil
	}

	cleanup()
	return "", func() {}, fmt.Errorf("remote skill must be a zip archive or JSON manifest")
}

func looksLikeZip(target string, contentType string, data []byte) bool {
	return strings.HasSuffix(strings.ToLower(target), ".zip") ||
		strings.Contains(strings.ToLower(contentType), "zip") ||
		bytes.HasPrefix(data, []byte("PK\x03\x04"))
}

func unzipBytes(data []byte, dst string, options ScanOptions) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	maxFiles := resolvedMaxArchiveFiles(options)
	maxExtractedBytes := resolvedMaxExtractedBytes(options)
	var extractedBytes int64
	var files int
	for _, file := range reader.File {
		if file.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("zip symlink entries are not allowed: %s", file.Name)
		}
		cleanName := filepath.Clean(file.Name)
		if filepath.IsAbs(cleanName) || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) {
			return fmt.Errorf("zip entry escapes target: %s", file.Name)
		}
		target := filepath.Join(dst, cleanName)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		files++
		if files > maxFiles {
			return fmt.Errorf("zip contains too many files: %d exceeds %d", files, maxFiles)
		}
		extractedBytes += int64(file.UncompressedSize64)
		if extractedBytes > maxExtractedBytes {
			return fmt.Errorf("zip extracted content exceeds max bytes %d", maxExtractedBytes)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			_ = src.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(src, int64(file.UncompressedSize64)+1))
		closeErr := out.Close()
		srcErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if srcErr != nil {
			return srcErr
		}
	}
	return nil
}

func readLimited(reader io.Reader, maxBytes int64, message string) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxDownloadBytes
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s: %d", message, maxBytes)
	}
	return data, nil
}

func isRemoteTarget(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func hashFiles(files []scannedFile) string {
	hash := sha256.New()
	for _, file := range files {
		_, _ = hash.Write([]byte(file.Rel))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(file.Data)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
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

func applySuppressions(findings []doctor.Finding, inventory doctor.Inventory, suppressions []Suppression, now time.Time) []doctor.Finding {
	if len(findings) == 0 || len(suppressions) == 0 {
		return findings
	}
	artifactNames := map[string]bool{}
	for _, artifact := range inventory.Skills {
		artifactNames[artifact.Name] = true
	}
	for _, artifact := range inventory.Plugins {
		artifactNames[artifact.Name] = true
	}
	out := make([]doctor.Finding, 0, len(findings))
	for _, finding := range findings {
		if findingSuppressed(finding, artifactNames, suppressions, now) {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func findingSuppressed(finding doctor.Finding, artifactNames map[string]bool, suppressions []Suppression, now time.Time) bool {
	for _, suppression := range suppressions {
		if strings.TrimSpace(suppression.RuleID) != "" && suppression.RuleID != finding.RuleID {
			continue
		}
		if suppressionExpired(suppression, now) {
			continue
		}
		if strings.TrimSpace(suppression.ArtifactName) != "" && !findingEvidenceMentionsArtifact(finding, suppression.ArtifactName, artifactNames) {
			continue
		}
		if strings.TrimSpace(suppression.EvidenceContains) != "" && !findingEvidenceContains(finding, suppression.EvidenceContains) {
			continue
		}
		if strings.TrimSpace(suppression.Reason) == "" {
			continue
		}
		return true
	}
	return false
}

func suppressionExpired(suppression Suppression, now time.Time) bool {
	if strings.TrimSpace(suppression.ExpiresAt) == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(suppression.ExpiresAt))
	if err != nil {
		return false
	}
	return !now.Before(expiresAt)
}

func findingEvidenceMentionsArtifact(finding doctor.Finding, artifactName string, artifactNames map[string]bool) bool {
	artifactName = strings.TrimSpace(artifactName)
	if artifactName == "" {
		return true
	}
	if !artifactNames[artifactName] {
		return false
	}
	needleSkill := "skill " + artifactName + ":"
	needlePlugin := "plugin " + artifactName + ":"
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence, needleSkill) || strings.Contains(evidence, needlePlugin) || strings.Contains(evidence, artifactName) {
			return true
		}
	}
	return false
}

func findingEvidenceContains(finding doctor.Finding, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return true
	}
	for _, evidence := range finding.Evidence {
		if strings.Contains(strings.ToLower(evidence), value) {
			return true
		}
	}
	return false
}

func resolvedTimeout(options ScanOptions) time.Duration {
	if options.Timeout > 0 {
		return options.Timeout
	}
	return defaultRemoteTimeout
}

func resolvedMaxDownloadBytes(options ScanOptions) int64 {
	if options.MaxDownloadBytes > 0 {
		return options.MaxDownloadBytes
	}
	return defaultMaxDownloadBytes
}

func resolvedMaxExtractedBytes(options ScanOptions) int64 {
	if options.MaxExtractedBytes > 0 {
		return options.MaxExtractedBytes
	}
	return defaultMaxExtractedBytes
}

func resolvedMaxRelevantFileBytes(options ScanOptions) int64 {
	if options.MaxRelevantFileBytes > 0 {
		return options.MaxRelevantFileBytes
	}
	return defaultMaxRelevantFileBytes
}

func resolvedMaxArchiveFiles(options ScanOptions) int {
	if options.MaxArchiveFiles > 0 {
		return options.MaxArchiveFiles
	}
	return defaultMaxArchiveFiles
}

func summarize(findings []doctor.Finding) doctor.Summary {
	var summary doctor.Summary
	for _, finding := range findings {
		switch finding.Severity {
		case doctor.SeverityCritical:
			summary.Critical++
		case doctor.SeverityHigh:
			summary.High++
		case doctor.SeverityMedium:
			summary.Medium++
		case doctor.SeverityLow:
			summary.Low++
		case doctor.SeverityInfo:
			summary.Info++
		}
	}
	return summary
}

func sortFindings(findings []doctor.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ID < findings[j].ID
	})
}

func severityRank(severity doctor.Severity) int {
	switch severity {
	case doctor.SeverityCritical:
		return 0
	case doctor.SeverityHigh:
		return 1
	case doctor.SeverityMedium:
		return 2
	case doctor.SeverityLow:
		return 3
	default:
		return 4
	}
}

func sortArtifacts(artifacts []doctor.Artifact) {
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].Name != artifacts[j].Name {
			return artifacts[i].Name < artifacts[j].Name
		}
		return artifacts[i].Hash < artifacts[j].Hash
	})
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func levenshtein(a string, b string) int {
	if !utf8.ValidString(a) || !utf8.ValidString(b) {
		return 100
	}
	ar := []rune(a)
	br := []rune(b)
	dp := make([][]int, len(ar)+1)
	for i := range dp {
		dp[i] = make([]int, len(br)+1)
		dp[i][0] = i
	}
	for j := range br {
		dp[0][j+1] = j + 1
	}
	for i := 1; i <= len(ar); i++ {
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}
			dp[i][j] = minInt(
				dp[i-1][j]+1,
				dp[i][j-1]+1,
				dp[i-1][j-1]+cost,
			)
		}
	}
	return dp[len(ar)][len(br)]
}

func minInt(values ...int) int {
	out := values[0]
	for _, value := range values[1:] {
		if value < out {
			out = value
		}
	}
	return out
}
