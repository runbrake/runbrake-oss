package doctor

import (
	"errors"
	"os"
	"path/filepath"
)

func DiscoverRoot(options DiscoverOptions) (string, error) {
	candidates := []string{}

	if options.ExplicitPath != "" {
		candidates = append(candidates, options.ExplicitPath)
	} else {
		for _, name := range []string{"OPENCLAW_HOME", "OPENCLAW_CONFIG_HOME"} {
			if value := options.Env[name]; value != "" {
				candidates = append(candidates, value)
			}
		}

		home := options.HomeDir
		if home == "" {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				return "", err
			}
		}

		candidates = append(candidates,
			filepath.Join(home, ".openclaw"),
			filepath.Join(home, ".config", "openclaw"),
		)
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		if hasOpenClawConfig(candidate) {
			return candidate, nil
		}
	}

	return "", errors.New("no OpenClaw install found; pass --path or set OPENCLAW_HOME")
}

func hasOpenClawConfig(root string) bool {
	info, err := os.Stat(filepath.Join(root, "openclaw.json"))
	return err == nil && !info.IsDir()
}
