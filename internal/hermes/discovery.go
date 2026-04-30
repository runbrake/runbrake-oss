package hermes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type DiscoverOptions struct {
	ExplicitPath string
	Env          map[string]string
	HomeDir      string
}

type Discovery struct {
	HomeDir             string
	ConfigPath          string
	SkillDirs           []string
	ExternalSkillDirs   []string
	PluginDirs          []string
	HookDirs            []string
	ShellHookConfigured bool
	InlineShellEnabled  bool
	Toolsets            []string
}

func Discover(options DiscoverOptions) (Discovery, error) {
	home, err := discoverHome(options)
	if err != nil {
		return Discovery{}, err
	}

	result := Discovery{HomeDir: home}
	if dirExists(filepath.Join(home, "skills")) {
		result.SkillDirs = append(result.SkillDirs, filepath.Join(home, "skills"))
	}
	if dirExists(filepath.Join(home, "plugins")) {
		result.PluginDirs = append(result.PluginDirs, filepath.Join(home, "plugins"))
	}
	if dirExists(filepath.Join(home, "hooks")) {
		result.HookDirs = append(result.HookDirs, filepath.Join(home, "hooks"))
	}

	configPath := firstExistingFile(
		filepath.Join(home, "config.yaml"),
		filepath.Join(home, "config.yml"),
	)
	if configPath != "" {
		result.ConfigPath = configPath
		cfg, err := parseConfig(configPath)
		if err != nil {
			return Discovery{}, err
		}
		result.InlineShellEnabled = cfg.inlineShell
		result.ShellHookConfigured = cfg.shellHookConfigured
		result.Toolsets = sortedUnique(cfg.toolsets)
		for _, dir := range cfg.externalSkillDirs {
			if filepath.IsAbs(dir) {
				result.ExternalSkillDirs = append(result.ExternalSkillDirs, filepath.Clean(dir))
			} else {
				result.ExternalSkillDirs = append(result.ExternalSkillDirs, filepath.Clean(filepath.Join(home, dir)))
			}
		}
	}

	if result.ConfigPath == "" && len(result.SkillDirs) == 0 && len(result.PluginDirs) == 0 && len(result.HookDirs) == 0 {
		return Discovery{}, fmt.Errorf("no Hermes config or known directories found in %s", home)
	}

	return result, nil
}

func discoverHome(options DiscoverOptions) (string, error) {
	if strings.TrimSpace(options.ExplicitPath) != "" {
		return cleanAbs(options.ExplicitPath), nil
	}
	if value := strings.TrimSpace(options.Env["HERMES_HOME"]); value != "" {
		return cleanAbs(value), nil
	}
	home := options.HomeDir
	if strings.TrimSpace(home) == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	return cleanAbs(filepath.Join(home, ".hermes")), nil
}

func cleanAbs(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return cleaned
	}
	return absolute
}

type configValues struct {
	inlineShell          bool
	externalSkillDirs    []string
	shellHookConfigured  bool
	toolsets             []string
	pendingListContainer string
}

func parseConfig(path string) (configValues, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return configValues{}, err
	}

	cfg := configValues{}
	section := ""
	for _, rawLine := range strings.Split(string(payload), "\n") {
		line := trimComment(rawLine)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := leadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSuffix(trimmed, ":")
			section = key
			cfg.pendingListContainer = key
			if key == "hooks" {
				cfg.shellHookConfigured = true
			}
			continue
		}

		if strings.HasPrefix(trimmed, "- ") {
			value := cleanScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			switch cfg.pendingListContainer {
			case "skills.external_dirs":
				cfg.externalSkillDirs = append(cfg.externalSkillDirs, value)
			case "toolsets":
				cfg.toolsets = append(cfg.toolsets, value)
			case "hooks":
				cfg.shellHookConfigured = true
			}
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		fullKey := key
		if section != "" && indent > 0 {
			fullKey = section + "." + key
		}

		switch fullKey {
		case "skills.inline_shell":
			cfg.inlineShell = parseBool(value)
		case "skills.external_dirs":
			cfg.pendingListContainer = "skills.external_dirs"
			cfg.externalSkillDirs = append(cfg.externalSkillDirs, parseInlineList(value)...)
		case "toolsets":
			cfg.pendingListContainer = "toolsets"
			cfg.toolsets = append(cfg.toolsets, parseInlineList(value)...)
		case "hooks", "hooks.shell", "hooks.shell_hook", "hooks.pre_tool_call":
			cfg.shellHookConfigured = true
			cfg.pendingListContainer = "hooks"
		}
	}

	return cfg, nil
}

func firstExistingFile(paths ...string) string {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func trimComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func parseBool(value string) bool {
	switch strings.ToLower(cleanScalar(value)) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

func parseInlineList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return []string{cleanScalar(value)}
	}
	value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		if cleaned := cleanScalar(part); cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}

func cleanScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
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
	return out
}
