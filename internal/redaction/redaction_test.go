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

func TestRedactCoversCommonProviderTokens(t *testing.T) {
	awsKey := "AK" + "IAIOSFODNN7EXAMPLE"
	slackToken := "xo" + "xb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
	stripeKey := "rk_" + "live_1234567890abcdefghijklmnopqrstuv"
	githubToken := "github" + "_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890"
	npmToken := "npm" + "_abcdefghijklmnopqrstuvwxyz1234567890"
	pypiToken := "pypi" + "-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVm"
	jwtToken := "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sgnaturefixture1234567890"

	input := strings.Join([]string{
		`aws_access_key_id = "` + awsKey + `"`,
		`slack = "` + slackToken + `"`,
		`stripe = "` + stripeKey + `"`,
		`github = "` + githubToken + `"`,
		`npm = "` + npmToken + `"`,
		`pypi = "` + pypiToken + `"`,
		`jwt = "` + jwtToken + `"`,
	}, "\n")

	redacted := Redact(input)

	for _, raw := range []string{
		awsKey,
		slackToken,
		stripeKey,
		githubToken,
		npmToken,
		pypiToken,
		jwtToken,
	} {
		if strings.Contains(redacted, raw) {
			t.Fatalf("redacted output leaked %q in %q", raw, redacted)
		}
	}

	for _, marker := range []string{
		"[REDACTED:aws_access_key:",
		"[REDACTED:slack_token:",
		"[REDACTED:stripe_key:",
		"[REDACTED:github_token:",
		"[REDACTED:npm_token:",
		"[REDACTED:pypi_token:",
		"[REDACTED:jwt:",
	} {
		if !strings.Contains(redacted, marker) {
			t.Fatalf("redacted output missing marker %s in %q", marker, redacted)
		}
	}
}
