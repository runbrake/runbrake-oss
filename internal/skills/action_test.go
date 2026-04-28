package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubActionEmitsSARIFWithoutRunBrakeCredentials(t *testing.T) {
	actionPath := filepath.Join("..", "..", ".github", "actions", "runbrake-skill-scan", "action.yml")
	data, err := os.ReadFile(actionPath)
	if err != nil {
		t.Fatalf("read action fixture: %v", err)
	}

	action := string(data)
	for _, want := range []string{
		"release-base-url",
		"curl -fsSLO",
		"shasum -a 256 -c -",
		"echo \"$install_dir\" >> \"$GITHUB_PATH\"",
		"runbrake scan-skills",
		"--format sarif",
		"runbrake-skill-scan.sarif",
		"github/codeql-action/upload-sarif",
	} {
		if !strings.Contains(action, want) {
			t.Fatalf("action fixture missing %q:\n%s", want, action)
		}
	}

	for _, forbidden := range []string{
		"RUNBRAKE_API_KEY",
		"RUNBRAKE_TOKEN",
		"runbrake.com/api",
		"go run ./cmd/runbrake",
		"go install github.com/runbrake/runbrake-oss",
	} {
		if strings.Contains(action, forbidden) {
			t.Fatalf("action fixture unexpectedly requires RunBrake account credential %q:\n%s", forbidden, action)
		}
	}
}
