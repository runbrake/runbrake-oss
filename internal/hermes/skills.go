package hermes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SkillMetadata struct {
	Name                    string
	Description             string
	Version                 string
	Platforms               []string
	Category                string
	RequiresToolsets        []string
	RequiresTools           []string
	FallbackForToolsets     []string
	FallbackForTools        []string
	ConfigKeys              []string
	RequiredEnv             []string
	RequiredCredentialFiles []string
	UsesInlineShell         bool
	ScriptPaths             []string
	ReferencePaths          []string
	TemplatePaths           []string
}

func ParseSkillFile(path string) (SkillMetadata, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return SkillMetadata{}, err
	}

	frontmatter, body := splitMarkdownFrontmatter(string(payload))
	meta := parseSkillFrontmatter(frontmatter)
	meta.UsesInlineShell = strings.Contains(body, "!`")

	root := filepath.Dir(path)
	meta.ScriptPaths = discoverRelativeFiles(root, "scripts")
	meta.ReferencePaths = discoverRelativeFiles(root, "references")
	meta.TemplatePaths = discoverRelativeFiles(root, "templates")

	if meta.Name == "" {
		meta.Name = filepath.Base(root)
	}
	return meta, nil
}

func splitMarkdownFrontmatter(text string) (string, string) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", text
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			return strings.Join(lines[1:i], "\n"), strings.Join(lines[i+1:], "\n")
		}
	}
	return "", text
}

func parseSkillFrontmatter(frontmatter string) SkillMetadata {
	meta := SkillMetadata{}
	container := ""
	for _, rawLine := range strings.Split(frontmatter, "\n") {
		line := trimComment(rawLine)
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := leadingSpaces(line)
		trimmed := strings.TrimSpace(line)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			container = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if indent == 2 && container == "metadata" && strings.HasSuffix(trimmed, ":") {
			container = "metadata." + strings.TrimSuffix(trimmed, ":")
			continue
		}
		if indent == 4 && container == "metadata.hermes" && strings.HasSuffix(trimmed, ":") {
			container = "metadata.hermes." + strings.TrimSuffix(trimmed, ":")
			continue
		}

		if strings.HasPrefix(trimmed, "- ") {
			parseSkillListItem(&meta, container, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		fullKey := key
		if indent > 0 && container != "" {
			fullKey = container + "." + key
		} else if indent == 0 {
			container = key
		}

		parseSkillScalar(&meta, fullKey, value)
	}

	meta.Platforms = sortedUnique(meta.Platforms)
	meta.RequiresToolsets = sortedUnique(meta.RequiresToolsets)
	meta.RequiresTools = sortedUnique(meta.RequiresTools)
	meta.FallbackForToolsets = sortedUnique(meta.FallbackForToolsets)
	meta.FallbackForTools = sortedUnique(meta.FallbackForTools)
	meta.ConfigKeys = sortedUnique(meta.ConfigKeys)
	meta.RequiredEnv = sortedUnique(meta.RequiredEnv)
	meta.RequiredCredentialFiles = sortedUnique(meta.RequiredCredentialFiles)
	return meta
}

func parseSkillScalar(meta *SkillMetadata, key string, value string) {
	switch key {
	case "name":
		meta.Name = cleanScalar(value)
	case "description":
		meta.Description = cleanScalar(value)
	case "version":
		meta.Version = cleanScalar(value)
	case "platforms":
		meta.Platforms = append(meta.Platforms, parseInlineList(value)...)
	case "metadata.hermes.category", "category":
		meta.Category = cleanScalar(value)
	case "metadata.hermes.requires_toolsets", "requires_toolsets":
		meta.RequiresToolsets = append(meta.RequiresToolsets, parseInlineList(value)...)
	case "metadata.hermes.requires_tools", "requires_tools":
		meta.RequiresTools = append(meta.RequiresTools, parseInlineList(value)...)
	case "metadata.hermes.fallback_for_toolsets", "fallback_for_toolsets":
		meta.FallbackForToolsets = append(meta.FallbackForToolsets, parseInlineList(value)...)
	case "metadata.hermes.fallback_for_tools", "fallback_for_tools":
		meta.FallbackForTools = append(meta.FallbackForTools, parseInlineList(value)...)
	case "metadata.hermes.config.key":
		meta.ConfigKeys = append(meta.ConfigKeys, cleanScalar(value))
	case "required_environment_variables", "env", "required_env":
		meta.RequiredEnv = append(meta.RequiredEnv, parseInlineList(value)...)
	case "required_credential_files", "credential_files":
		meta.RequiredCredentialFiles = append(meta.RequiredCredentialFiles, parseInlineList(value)...)
	}
}

func parseSkillListItem(meta *SkillMetadata, container string, item string) {
	key, value, hasKey := strings.Cut(item, ":")
	switch container {
	case "platforms":
		meta.Platforms = append(meta.Platforms, cleanScalar(item))
	case "metadata.hermes.requires_toolsets", "requires_toolsets":
		meta.RequiresToolsets = append(meta.RequiresToolsets, cleanScalar(item))
	case "metadata.hermes.requires_tools", "requires_tools":
		meta.RequiresTools = append(meta.RequiresTools, cleanScalar(item))
	case "metadata.hermes.fallback_for_toolsets", "fallback_for_toolsets":
		meta.FallbackForToolsets = append(meta.FallbackForToolsets, cleanScalar(item))
	case "metadata.hermes.fallback_for_tools", "fallback_for_tools":
		meta.FallbackForTools = append(meta.FallbackForTools, cleanScalar(item))
	case "metadata.hermes.config":
		if hasKey && strings.TrimSpace(key) == "key" {
			meta.ConfigKeys = append(meta.ConfigKeys, cleanScalar(value))
		}
	case "required_environment_variables", "env", "required_env":
		if hasKey {
			if strings.TrimSpace(key) == "name" || strings.TrimSpace(key) == "key" {
				meta.RequiredEnv = append(meta.RequiredEnv, cleanScalar(value))
			}
		} else {
			meta.RequiredEnv = append(meta.RequiredEnv, cleanScalar(item))
		}
	case "required_credential_files", "credential_files":
		if hasKey {
			if strings.TrimSpace(key) == "path" || strings.TrimSpace(key) == "file" || strings.TrimSpace(key) == "name" {
				meta.RequiredCredentialFiles = append(meta.RequiredCredentialFiles, cleanScalar(value))
			}
		} else {
			meta.RequiredCredentialFiles = append(meta.RequiredCredentialFiles, cleanScalar(item))
		}
	}
}

func discoverRelativeFiles(root string, dirName string) []string {
	base := filepath.Join(root, dirName)
	if !dirExists(base) {
		return nil
	}
	out := []string{}
	_ = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return sortedUnique(out)
}

func ParseSkillFileForScanner(path string) (SkillMetadata, error) {
	meta, err := ParseSkillFile(path)
	if err != nil {
		return SkillMetadata{}, fmt.Errorf("parse Hermes skill %s: %w", path, err)
	}
	return meta, nil
}
