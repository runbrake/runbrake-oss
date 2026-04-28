package redaction

import (
	"strings"
	"testing"
)

func TestRedactSecretsReplacesValuesWithStableMarkers(t *testing.T) {
	input := `apiKey="sk-test-1234567890abcdefSECRET" token="ya29.secretFixtureToken123456789" Authorization: Bearer ghp_secretFixtureToken123456789`

	redacted := Redact(input)

	for _, raw := range []string{
		"sk-test-1234567890abcdefSECRET",
		"ya29.secretFixtureToken123456789",
		"ghp_secretFixtureToken123456789",
	} {
		if strings.Contains(redacted, raw) {
			t.Fatalf("redacted output leaked %q in %q", raw, redacted)
		}
	}

	if !strings.Contains(redacted, "[REDACTED:api_key:") {
		t.Fatalf("missing api_key marker in %q", redacted)
	}

	if !strings.Contains(redacted, "[REDACTED:oauth_token:") {
		t.Fatalf("missing oauth_token marker in %q", redacted)
	}
}

func TestFindSecretsReturnsRedactedEvidence(t *testing.T) {
	matches := FindSecrets("config.json", `{"oauthToken":"ya29.secretFixtureToken123456789"}`)

	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}

	if matches[0].Path != "config.json" {
		t.Fatalf("Path = %q, want config.json", matches[0].Path)
	}

	if strings.Contains(matches[0].Evidence, "ya29.secretFixtureToken123456789") {
		t.Fatalf("evidence leaked raw secret: %q", matches[0].Evidence)
	}
}
