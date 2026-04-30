package skills

import "github.com/runbrake/runbrake-oss/internal/doctor"

const (
	RuleShellExecution        = "RB-SKILL-SHELL-EXECUTION"
	RuleFileWrite             = "RB-SKILL-FILE-WRITE"
	RuleBroadOAuth            = "RB-SKILL-BROAD-OAUTH"
	RuleDangerousInstall      = "RB-SKILL-DANGEROUS-INSTALL-SCRIPT"
	RuleHiddenUnicode         = "RB-SKILL-HIDDEN-UNICODE"
	RulePromptInjection       = "RB-SKILL-PROMPT-INJECTION-BAIT"
	RuleObfuscatedCommand     = "RB-SKILL-OBFUSCATED-COMMAND"
	RuleBase64Decode          = "RB-SKILL-BASE64-DECODE"
	RuleRemoteScriptExecution = "RB-SKILL-REMOTE-SCRIPT-EXECUTION"
	RuleUnknownEgress         = "RB-SKILL-UNKNOWN-EGRESS"
	RuleConstructedEgress     = "RB-SKILL-CONSTRUCTED-EGRESS"
	RuleVulnerableDependency  = "RB-SKILL-VULNERABLE-DEPENDENCY"
	RuleSimilarNamePackage    = "RB-SKILL-SIMILAR-NAME-PACKAGE"
	RulePlaintextSecret       = "RB-SKILL-PLAINTEXT-SECRET"
	RuleHermesInlineShell     = "RB-HERMES-INLINE-SHELL"
	RuleHermesRequiredSecret  = "RB-HERMES-REQUIRED-SECRET"
	RuleHermesTerminal        = "RB-HERMES-TERMINAL-REQUIRED"
	RuleHermesBrowserOrWeb    = "RB-HERMES-BROWSER-OR-WEB-REQUIRED"
	RuleHermesGatewayHook     = "RB-HERMES-GATEWAY-HOOK"
	RuleHermesPreToolHook     = "RB-HERMES-PRE-TOOL-BLOCKING-HOOK"
	RuleHermesPluginExposure  = "RB-HERMES-PLUGIN-TOOL-EXPOSURE"
)

func RuleRegistry() []Rule {
	return []Rule{
		{
			ID:                RuleRemoteScriptExecution,
			Severity:          doctor.SeverityCritical,
			Confidence:        0.96,
			Title:             "Skill executes a remote script",
			Remediation:       "Remove remote script execution from install and runtime instructions; pin reviewed artifacts by hash instead.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleDangerousInstall,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.93,
			Title:             "Skill package has a dangerous dependency install script",
			Remediation:       "Remove lifecycle scripts that execute shell, network downloads, or child processes during dependency installation.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleShellExecution,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.9,
			Title:             "Skill can execute shell commands",
			Remediation:       "Remove shell permission or require explicit approval with command and destination review.",
			RecommendedPolicy: "deny destructive shell",
		},
		{
			ID:                RulePlaintextSecret,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.94,
			Title:             "Skill package contains plaintext secrets",
			Remediation:       "Remove embedded credentials from the skill package and rotate any exposed token before installation.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleBroadOAuth,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.91,
			Title:             "Skill requests broad OAuth scopes",
			Remediation:       "Replace broad OAuth grants with least-privilege scopes and rotate grants issued to the skill.",
			RecommendedPolicy: "approval required for send/write",
		},
		{
			ID:                RuleBase64Decode,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.88,
			Title:             "Skill decodes base64 payloads before execution",
			Remediation:       "Replace encoded commands with plain reviewed scripts or remove the behavior.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleObfuscatedCommand,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.86,
			Title:             "Skill contains obfuscated command execution",
			Remediation:       "Remove eval, encoded command, or child-process execution paths that hide behavior from reviewers.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleFileWrite,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.86,
			Title:             "Skill can write files or shared documents",
			Remediation:       "Limit write permissions to reviewed paths and require approval for document, Drive, or repository writes.",
			RecommendedPolicy: "approval required for send/write",
		},
		{
			ID:                RuleHiddenUnicode,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.92,
			Title:             "Skill contains hidden Unicode controls",
			Remediation:       "Remove bidirectional or zero-width controls from skill instructions and manifests before installation.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RulePromptInjection,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.84,
			Title:             "Skill contains prompt-injection bait",
			Remediation:       "Remove instructions that tell the agent to ignore higher-priority instructions, exfiltrate data, or reveal secrets.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleUnknownEgress,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.8,
			Title:             "Skill references unknown network egress domains",
			Remediation:       "Replace unknown domains with reviewed allowlisted endpoints or require approval before outbound network access.",
			RecommendedPolicy: "approval required for network egress",
		},
		{
			ID:                RuleConstructedEgress,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.82,
			Title:             "Skill constructs network egress destinations dynamically",
			Remediation:       "Replace dynamically assembled network destinations with documented, reviewable allowlisted domains.",
			RecommendedPolicy: "approval required for network egress",
		},
		{
			ID:                RuleVulnerableDependency,
			Severity:          doctor.SeverityHigh,
			Confidence:        0.92,
			Title:             "Skill depends on a package with known vulnerabilities",
			Remediation:       "Upgrade the vulnerable dependency to a fixed version or remove it before installation.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleSimilarNamePackage,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.78,
			Title:             "Skill depends on a package name similar to a popular package",
			Remediation:       "Verify the package publisher and replace typo-squatted dependencies with the intended package.",
			RecommendedPolicy: "quarantine",
		},
		{
			ID:                RuleHermesInlineShell,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.88,
			Title:             "Hermes skill uses inline shell",
			Remediation:       "Review inline shell snippets and require approval for terminal execution in Hermes policy.",
			RecommendedPolicy: "approval required for terminal",
		},
		{
			ID:                RuleHermesRequiredSecret,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.86,
			Title:             "Hermes artifact requires secret material",
			Remediation:       "Document required secrets and keep credentials outside skill/plugin source control.",
			RecommendedPolicy: "approval required for secret access",
		},
		{
			ID:                RuleHermesTerminal,
			Severity:          doctor.SeverityLow,
			Confidence:        0.84,
			Title:             "Hermes artifact requires terminal access",
			Remediation:       "Review terminal-requiring skills before enabling them in shared Hermes homes.",
			RecommendedPolicy: "approval required for terminal",
		},
		{
			ID:                RuleHermesBrowserOrWeb,
			Severity:          doctor.SeverityLow,
			Confidence:        0.8,
			Title:             "Hermes artifact requires browser or web access",
			Remediation:       "Review browser or web tool usage and restrict network destinations where possible.",
			RecommendedPolicy: "approval required for network egress",
		},
		{
			ID:                RuleHermesGatewayHook,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.84,
			Title:             "Hermes gateway hook is installed",
			Remediation:       "Review hook handler code and keep hook behavior auditable.",
			RecommendedPolicy: "inventory",
		},
		{
			ID:                RuleHermesPreToolHook,
			Severity:          doctor.SeverityInfo,
			Confidence:        0.82,
			Title:             "Hermes pre-tool hook can influence tool calls",
			Remediation:       "Inventory pre_tool_call hooks and pair blocking behavior with reviewed policy code.",
			RecommendedPolicy: "inventory",
		},
		{
			ID:                RuleHermesPluginExposure,
			Severity:          doctor.SeverityMedium,
			Confidence:        0.8,
			Title:             "Hermes plugin exposes runtime hooks or tools",
			Remediation:       "Review plugin registration and restrict exposed hooks or tools to least privilege.",
			RecommendedPolicy: "approval required for plugin runtime",
		},
	}
}

func ruleByID(id string) (Rule, bool) {
	for _, rule := range RuleRegistry() {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
