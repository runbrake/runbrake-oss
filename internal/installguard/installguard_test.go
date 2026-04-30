package installguard

import (
	"strings"
	"testing"
	"time"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/policy"
)

var fixedInstallDecisionTime = time.Date(2026, 4, 28, 15, 0, 0, 0, time.UTC)

func TestEvaluateCriticalInstallShadowsWhenPolicyIsShadowOnly(t *testing.T) {
	set := policy.DefaultPolicySet()
	set.ShadowOnly = true

	decision, err := Evaluate(set, sampleInstallEvent(), doctor.ScanReport{
		Findings: []doctor.Finding{{
			ID:          "finding-critical",
			RuleID:      "RB-SKILL-REMOTE-SCRIPT-EXECUTION",
			Severity:    doctor.SeverityCritical,
			Confidence:  0.98,
			Title:       "Skill executes a remote script",
			Evidence:    []string{"SKILL.md downloads a remote script"},
			Remediation: "Quarantine before install.",
		}},
	}, fixedInstallDecisionTime)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.Action != policy.ActionShadow {
		t.Fatalf("Action = %q, want shadow", decision.Action)
	}
	if decision.PolicyID != PolicyInstallCriticalFinding {
		t.Fatalf("PolicyID = %q, want %s", decision.PolicyID, PolicyInstallCriticalFinding)
	}
	if decision.FailMode != policy.FailModeClosed {
		t.Fatalf("FailMode = %q, want closed", decision.FailMode)
	}
	if !strings.Contains(strings.Join(decision.Reasons, " "), "would have returned deny") {
		t.Fatalf("decision reasons missing shadow explanation: %#v", decision.Reasons)
	}
}

func TestEvaluateCriticalInstallDeniesWhenPolicyEnforces(t *testing.T) {
	set := policy.DefaultPolicySet()
	set.ShadowOnly = false

	decision, err := Evaluate(set, sampleInstallEvent(), doctor.ScanReport{
		Findings: []doctor.Finding{{
			ID:          "finding-critical",
			RuleID:      "RB-SKILL-REMOTE-SCRIPT-EXECUTION",
			Severity:    doctor.SeverityCritical,
			Confidence:  0.98,
			Title:       "Skill executes a remote script",
			Evidence:    []string{"SKILL.md downloads a remote script"},
			Remediation: "Quarantine before install.",
		}},
	}, fixedInstallDecisionTime)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.Action != policy.ActionDeny {
		t.Fatalf("Action = %q, want deny", decision.Action)
	}
	if decision.FailMode != policy.FailModeClosed {
		t.Fatalf("FailMode = %q, want closed", decision.FailMode)
	}
}

func TestEvaluateSafeInstallAllows(t *testing.T) {
	decision, err := Evaluate(policy.DefaultPolicySet(), sampleInstallEvent(), doctor.ScanReport{}, fixedInstallDecisionTime)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.Action != policy.ActionAllow {
		t.Fatalf("Action = %q, want allow", decision.Action)
	}
	if decision.PolicyID != PolicyInstallDefaultAllow {
		t.Fatalf("PolicyID = %q, want %s", decision.PolicyID, PolicyInstallDefaultAllow)
	}
}

func sampleInstallEvent() InstallEvent {
	return InstallEvent{
		ID:           "install-001",
		Kind:         "plugin",
		Name:         "shell-helper",
		Version:      "1.0.0",
		Source:       "clawhub:shell-helper",
		ArtifactPath: "/tmp/shell-helper",
		ArtifactHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		AgentID:      "agent-local-dev",
		UserID:       "user-dev",
		ObservedAt:   "2026-04-28T15:00:00Z",
	}
}
