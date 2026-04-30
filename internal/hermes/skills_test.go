package hermes

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseSkillFrontmatterExtractsHermesMetadata(t *testing.T) {
	meta, err := ParseSkillFile(filepath.Join("testdata", "home", ".hermes", "skills", "devops", "deploy-k8s", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "deploy-k8s" {
		t.Fatalf("name = %q", meta.Name)
	}
	assertContains(t, meta.RequiresToolsets, "terminal")
	assertContains(t, meta.RequiredEnv, "KUBECONFIG")
	if !meta.UsesInlineShell {
		t.Fatalf("expected inline shell snippet")
	}
}

func TestParseSkillFrontmatterExtractsDocumentedMetadataFields(t *testing.T) {
	root := filepath.Join(t.TempDir(), "complex-skill")
	for _, dir := range []string{"scripts", "references", "templates"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(root, "scripts", "deploy.sh"):              "#!/bin/sh\n",
		filepath.Join(root, "references", "runbook.md"):          "# Runbook\n",
		filepath.Join(root, "templates", "deployment.yaml.tmpl"): "kind: Deployment\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	skill := `---
name: complex-skill
description: Complex Hermes metadata fixture
version: 1.2.3
platforms: [macos, linux]
metadata:
  hermes:
    category: devops
    requires_toolsets: [terminal]
    requires_tools: [kubectl]
    fallback_for_toolsets: [browser]
    fallback_for_tools: [web_search]
    config:
      - key: deploy.namespace
required_environment_variables:
  - name: KUBECONFIG
required_credential_files:
  - path: ~/.kube/config
---

# Complex Skill
`
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(skill), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}

	meta, err := ParseSkillFile(filepath.Join(root, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}

	if meta.Version != "1.2.3" {
		t.Fatalf("version = %q", meta.Version)
	}
	if meta.Category != "devops" {
		t.Fatalf("category = %q", meta.Category)
	}
	for _, want := range []string{"macos", "linux"} {
		assertContains(t, meta.Platforms, want)
	}
	assertContains(t, meta.RequiresTools, "kubectl")
	assertContains(t, meta.FallbackForToolsets, "browser")
	assertContains(t, meta.FallbackForTools, "web_search")
	assertContains(t, meta.ConfigKeys, "deploy.namespace")
	assertContains(t, meta.RequiredEnv, "KUBECONFIG")
	assertContains(t, meta.RequiredCredentialFiles, "~/.kube/config")
	assertContains(t, meta.ScriptPaths, "scripts/deploy.sh")
	assertContains(t, meta.ReferencePaths, "references/runbook.md")
	assertContains(t, meta.TemplatePaths, "templates/deployment.yaml.tmpl")
}

func assertContains(t *testing.T, got []string, want string) {
	t.Helper()

	if !slices.Contains(got, want) {
		t.Fatalf("values = %v, missing %s", got, want)
	}
}
