package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

type SecretMatch struct {
	Path     string
	Kind     string
	Evidence string
}

type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{kind: "private_key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{kind: "oauth_token", re: regexp.MustCompile(`Bearer\s+[A-Za-z0-9._~+/=-]{16,}`)},
	{kind: "api_key", re: regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`)},
	{kind: "aws_access_key", re: regexp.MustCompile(`\bA(KIA|SIA)[A-Z0-9]{16}\b`)},
	{kind: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`)},
	{kind: "stripe_key", re: regexp.MustCompile(`\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b`)},
	{kind: "github_token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
	{kind: "npm_token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}\b`)},
	{kind: "pypi_token", re: regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{32,}\b`)},
	{kind: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b`)},
	{kind: "oauth_token", re: regexp.MustCompile(`ya29\.[A-Za-z0-9._-]{16,}`)},
	{kind: "oauth_token", re: regexp.MustCompile(`ghp_[A-Za-z0-9_]{16,}`)},
	{kind: "session_cookie", re: regexp.MustCompile(`(?i)(session|cookie)[_-]?(token|secret)?["'=:\s]+[A-Za-z0-9._~+/=-]{20,}`)},
	{kind: "database_url", re: regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[^\s"']+`)},
}

func Redact(input string) string {
	output := input
	for _, pattern := range secretPatterns {
		kind := pattern.kind
		output = pattern.re.ReplaceAllStringFunc(output, func(match string) string {
			return marker(kind, match)
		})
	}
	return output
}

func FindSecrets(path string, input string) []SecretMatch {
	matches := []SecretMatch{}
	seen := map[string]bool{}

	for _, rawLine := range strings.Split(input, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		redacted := Redact(line)
		if redacted == line {
			continue
		}

		key := path + "\x00" + redacted
		if seen[key] {
			continue
		}
		seen[key] = true

		matches = append(matches, SecretMatch{
			Path:     path,
			Kind:     firstKind(line),
			Evidence: path + " contains " + redacted,
		})
	}

	return matches
}

func firstKind(input string) string {
	for _, pattern := range secretPatterns {
		if pattern.re.MatchString(input) {
			return pattern.kind
		}
	}
	return "secret"
}

func marker(kind string, raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "[REDACTED:" + kind + ":" + hex.EncodeToString(sum[:])[:8] + "]"
}
