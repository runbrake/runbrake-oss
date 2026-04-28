package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var fixedScanTime = time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

func TestScanSafeFixtureProducesCleanInventory(t *testing.T) {
	result := scanFixture(t, "safe-local")

	if len(result.Report.Findings) != 0 {
		t.Fatalf("safe fixture findings = %v, want none", result.Report.Findings)
	}

	if result.OpenClawVersion != "1.4.2" {
		t.Fatalf("OpenClawVersion = %q, want 1.4.2", result.OpenClawVersion)
	}

	if len(result.Inventory.Skills) != 1 {
		t.Fatalf("skill inventory count = %d, want 1", len(result.Inventory.Skills))
	}

	if len(result.Inventory.Plugins) != 1 {
		t.Fatalf("plugin inventory count = %d, want 1", len(result.Inventory.Plugins))
	}

	if len(result.Report.ArtifactHashes) != 2 {
		t.Fatalf("artifact hashes = %v, want one skill and one plugin hash", result.Report.ArtifactHashes)
	}
}

func TestScanFixturesDetectPhaseOneRisks(t *testing.T) {
	tests := []struct {
		fixture string
		want    []string
	}{
		{
			fixture: "exposed-gateway",
			want: []string{
				"RB-GATEWAY-EXPOSED",
				"RB-AUTH-MISSING",
				"RB-GATEWAY-TUNNEL",
				"RB-VERSION-STALE",
				"RB-TOOL-BROAD-PERMISSIONS",
			},
		},
		{
			fixture: "broad-oauth",
			want: []string{
				"RB-OAUTH-BROAD-SCOPES",
				"RB-TOOL-BROAD-PERMISSIONS",
			},
		},
		{
			fixture: "secrets",
			want: []string{
				"RB-SECRET-PLAINTEXT",
				"RB-CONFIG-PERMISSIONS",
			},
		},
		{
			fixture: "persistence",
			want: []string{
				"RB-PERSISTENCE-CRON",
				"RB-PERSISTENCE-LAUNCH-AGENT",
				"RB-PERSISTENCE-BACKGROUND",
				"RB-PERSISTENCE-STANDING-ORDER",
				"RB-PERSISTENCE-MEMORY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			root := fixturePath(tt.fixture)
			if tt.fixture == "secrets" {
				root = copyFixture(t, tt.fixture)
				if err := os.Chmod(filepath.Join(root, "openclaw.json"), 0o666); err != nil {
					t.Fatalf("chmod secret fixture config: %v", err)
				}
			}

			result, err := Scan(ScanOptions{
				Root:           root,
				Now:            fixedScanTime,
				ScannerVersion: "test",
			})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}

			got := findingRuleIDs(result.Report.Findings)
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Fatalf("rule IDs = %v, missing %s", got, want)
				}
			}
		})
	}
}

func TestScanRedactsSecretFixtureValues(t *testing.T) {
	result := scanFixture(t, "secrets")

	payload, err := json.Marshal(result.Report.Findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}

	rendered := string(payload)
	for _, raw := range []string{
		"sk-test-1234567890abcdefSECRET",
		"ya29.secretFixtureToken123456789",
		"ghp_secretFixtureToken123456789",
	} {
		if strings.Contains(rendered, raw) {
			t.Fatalf("findings leaked raw secret %q in %s", raw, rendered)
		}
	}

	if !strings.Contains(rendered, "[REDACTED:") {
		t.Fatalf("findings did not include redaction markers: %s", rendered)
	}
}

func TestDiscoverRootUsesExplicitEnvAndDefaults(t *testing.T) {
	explicit := fixturePath("safe-local")
	root, err := DiscoverRoot(DiscoverOptions{
		ExplicitPath: explicit,
		Env:          map[string]string{},
		HomeDir:      t.TempDir(),
	})
	if err != nil {
		t.Fatalf("explicit DiscoverRoot() error = %v", err)
	}
	if root != explicit {
		t.Fatalf("explicit root = %q, want %q", root, explicit)
	}

	envRoot := fixturePath("broad-oauth")
	root, err = DiscoverRoot(DiscoverOptions{
		Env:     map[string]string{"OPENCLAW_HOME": envRoot},
		HomeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("env DiscoverRoot() error = %v", err)
	}
	if root != envRoot {
		t.Fatalf("env root = %q, want %q", root, envRoot)
	}

	home := t.TempDir()
	defaultRoot := filepath.Join(home, ".openclaw")
	copyDir(t, fixturePath("safe-local"), defaultRoot)

	root, err = DiscoverRoot(DiscoverOptions{
		Env:     map[string]string{},
		HomeDir: home,
	})
	if err != nil {
		t.Fatalf("default DiscoverRoot() error = %v", err)
	}
	if root != defaultRoot {
		t.Fatalf("default root = %q, want %q", root, defaultRoot)
	}
}

func scanFixture(t *testing.T, name string) Result {
	t.Helper()

	root := fixturePath(name)
	if name == "secrets" {
		root = copyFixture(t, name)
		if err := os.Chmod(filepath.Join(root, "openclaw.json"), 0o666); err != nil {
			t.Fatalf("chmod secret fixture config: %v", err)
		}
	}

	result, err := Scan(ScanOptions{
		Root:           root,
		Now:            fixedScanTime,
		ScannerVersion: "test",
	})
	if err != nil {
		t.Fatalf("Scan(%s) error = %v", name, err)
	}
	return result
}

func fixturePath(name string) string {
	return filepath.Join("testdata", "fixtures", name)
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()

	dst := filepath.Join(t.TempDir(), name)
	copyDir(t, fixturePath(name), dst)
	return dst
}

func copyDir(t *testing.T, src string, dst string) {
	t.Helper()

	if err := filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	}); err != nil {
		t.Fatalf("copy fixture %s: %v", src, err)
	}
}

func findingRuleIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}
