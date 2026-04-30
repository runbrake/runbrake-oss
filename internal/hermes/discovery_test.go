package hermes

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDiscoverHomeFindsHermesConfigSkillsPluginsAndHooks(t *testing.T) {
	root := filepath.Join("testdata", "home")
	result, err := Discover(DiscoverOptions{ExplicitPath: filepath.Join(root, ".hermes")})
	if err != nil {
		t.Fatal(err)
	}
	absRoot, err := filepath.Abs(filepath.Join(root, ".hermes"))
	if err != nil {
		t.Fatal(err)
	}
	if result.HomeDir != absRoot {
		t.Fatalf("HomeDir = %q, want absolute path %q", result.HomeDir, absRoot)
	}
	assertContainsPath(t, result.SkillDirs, filepath.Join(absRoot, "skills"))
	assertContainsPath(t, result.PluginDirs, filepath.Join(absRoot, "plugins"))
	assertContainsPath(t, result.HookDirs, filepath.Join(absRoot, "hooks"))
	assertContainsPath(t, result.ExternalSkillDirs, filepath.Clean(filepath.Join(absRoot, "../../shared-skills")))
	for _, dir := range result.ExternalSkillDirs {
		if !filepath.IsAbs(dir) {
			t.Fatalf("external skill dir = %q, want absolute path", dir)
		}
	}
	if !result.InlineShellEnabled {
		t.Fatalf("expected inline shell setting to be detected")
	}
}

func TestDiscoverPrecedenceUsesExplicitPathBeforeEnvAndHome(t *testing.T) {
	home := t.TempDir()
	explicit := makeHermesHome(t, t.TempDir(), "explicit")
	envHome := makeHermesHome(t, t.TempDir(), "env")
	defaultHome := makeHermesHome(t, home, ".hermes")

	result, err := Discover(DiscoverOptions{
		ExplicitPath: explicit,
		Env:          map[string]string{"HERMES_HOME": envHome},
		HomeDir:      home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(result.HomeDir) != filepath.Clean(explicit) {
		t.Fatalf("HomeDir = %q, want explicit path %q; default fixture %q should not win", result.HomeDir, explicit, defaultHome)
	}
}

func TestDiscoverPrecedenceUsesHermesHomeBeforeHomeDirFallback(t *testing.T) {
	home := t.TempDir()
	envHome := makeHermesHome(t, t.TempDir(), "env")
	defaultHome := makeHermesHome(t, home, ".hermes")

	result, err := Discover(DiscoverOptions{
		Env:     map[string]string{"HERMES_HOME": envHome},
		HomeDir: home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(result.HomeDir) != filepath.Clean(envHome) {
		t.Fatalf("HomeDir = %q, want HERMES_HOME %q; default fixture %q should not win", result.HomeDir, envHome, defaultHome)
	}
}

func TestDiscoverPrecedenceFallsBackToHomeDirHermes(t *testing.T) {
	home := t.TempDir()
	defaultHome := makeHermesHome(t, home, ".hermes")

	result, err := Discover(DiscoverOptions{
		Env:     map[string]string{},
		HomeDir: home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(result.HomeDir) != filepath.Clean(defaultHome) {
		t.Fatalf("HomeDir = %q, want HomeDir fallback %q", result.HomeDir, defaultHome)
	}
}

func TestDiscoverAcceptsKnownDirsWhenConfigIsMissing(t *testing.T) {
	root := makeHermesHome(t, t.TempDir(), ".hermes")

	result, err := Discover(DiscoverOptions{ExplicitPath: root})
	if err != nil {
		t.Fatal(err)
	}
	if result.ConfigPath != "" {
		t.Fatalf("ConfigPath = %q, want empty for config-less Hermes home", result.ConfigPath)
	}
	assertContainsPath(t, result.SkillDirs, filepath.Join(root, "skills"))
	assertContainsPath(t, result.PluginDirs, filepath.Join(root, "plugins"))
	assertContainsPath(t, result.HookDirs, filepath.Join(root, "hooks"))
}

func makeHermesHome(t *testing.T, parent string, name string) string {
	t.Helper()

	root := filepath.Join(parent, name)
	for _, dir := range []string{"skills", "plugins", "hooks"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir Hermes dir: %v", err)
		}
	}
	return root
}

func assertContainsPath(t *testing.T, got []string, want string) {
	t.Helper()

	want = filepath.Clean(want)
	cleaned := make([]string, 0, len(got))
	for _, path := range got {
		cleaned = append(cleaned, filepath.Clean(path))
	}
	if !slices.Contains(cleaned, want) {
		t.Fatalf("paths = %v, missing %s", cleaned, want)
	}
}
