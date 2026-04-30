package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/runbrake/runbrake-oss/internal/installguard"
	"github.com/runbrake/runbrake-oss/internal/policy"
)

func TestPolicyDecisionAuditEventIsSignedAndVerifiable(t *testing.T) {
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	event := policy.ToolCallEvent{
		ID:             "event-001",
		OrganizationID: "org-local",
		AgentID:        "agent-local-dev",
		UserID:         "user-dev",
		Skill:          "google-workspace@1.4.2",
		Tool:           "gmail.send",
		Phase:          "before",
		ObservedAt:     now.Format(time.RFC3339),
		Arguments: map[string]string{
			"authorization": "[REDACTED:oauth_token:12345678]",
		},
		PayloadClassifications: []string{"customer_email"},
		DestinationDomains:     []string{"vendor.example"},
	}
	decision := policy.PolicyDecision{
		ID:         "decision-001",
		EventID:    event.ID,
		PolicyID:   "policy-external-email-approval",
		Action:     policy.ActionShadow,
		DecidedAt:  now.Format(time.RFC3339),
		Reasons:    []string{"shadow mode: would have requested approval"},
		Redactions: []string{"arguments.authorization"},
		FailMode:   policy.FailModeOpen,
	}
	signer := NewSigner("test-audit-key")

	auditEvent, err := NewPolicyDecisionEvent(event, decision, "", signer, now)
	if err != nil {
		t.Fatalf("NewPolicyDecisionEvent returned error: %v", err)
	}

	if auditEvent.EventType != "policy.decision.shadow" {
		t.Fatalf("EventType = %q, want policy.decision.shadow", auditEvent.EventType)
	}
	if !strings.HasPrefix(auditEvent.EvidenceHash, "sha256:") {
		t.Fatalf("EvidenceHash = %q, want sha256 prefix", auditEvent.EvidenceHash)
	}
	if !strings.HasPrefix(auditEvent.Signature, "hmac-sha256:") {
		t.Fatalf("Signature = %q, want hmac-sha256 prefix", auditEvent.Signature)
	}
	if !signer.Verify(auditEvent) {
		t.Fatalf("audit signature did not verify: %+v", auditEvent)
	}
}

func TestAuditEventDoesNotExposeRawSecretValues(t *testing.T) {
	now := time.Date(2026, 4, 28, 13, 5, 0, 0, time.UTC)
	event := policy.ToolCallEvent{
		ID:                     "event-secret",
		AgentID:                "agent-local-dev",
		UserID:                 "user-dev",
		Skill:                  "shell@1.0.0",
		Tool:                   "shell.exec",
		Phase:                  "before",
		ObservedAt:             now.Format(time.RFC3339),
		Arguments:              map[string]string{"token": "sk-prod_1234567890abcdef"},
		PayloadClassifications: []string{"secret"},
		DestinationDomains:     []string{},
	}
	redacted, _, err := policy.RedactToolCallEvent(event, nil)
	if err != nil {
		t.Fatalf("RedactToolCallEvent returned error: %v", err)
	}
	decision := policy.PolicyDecision{
		ID:         "decision-secret",
		EventID:    event.ID,
		PolicyID:   "policy-secret",
		Action:     policy.ActionShadow,
		DecidedAt:  now.Format(time.RFC3339),
		Reasons:    []string{"matched policy rule policy-secret"},
		Redactions: []string{"arguments.token"},
		FailMode:   policy.FailModeOpen,
	}

	auditEvent, err := NewPolicyDecisionEvent(redacted, decision, "", NewSigner("test-audit-key"), now)
	if err != nil {
		t.Fatalf("NewPolicyDecisionEvent returned error: %v", err)
	}
	payload, err := json.Marshal(auditEvent)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}

	if strings.Contains(string(payload), "sk-prod_1234567890abcdef") {
		t.Fatalf("audit event leaked raw secret: %s", string(payload))
	}
}

func TestInstallDecisionAuditEventSignsMetadataOnlyEvidence(t *testing.T) {
	now := time.Date(2026, 4, 28, 15, 10, 0, 0, time.UTC)
	event := installguard.InstallEvent{
		ID:           "install-001",
		Kind:         installguard.InstallKindPlugin,
		Name:         "shell-helper",
		Source:       "clawhub:shell-helper",
		ArtifactPath: "/tmp/openclaw-install/shell-helper",
		ArtifactHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		AgentID:      "agent-local-dev",
		UserID:       "user-dev",
		ObservedAt:   "2026-04-28T15:10:00Z",
	}
	decision := policy.PolicyDecision{
		ID:         "decision-install",
		EventID:    "install-001",
		PolicyID:   installguard.PolicyInstallCriticalFinding,
		Action:     policy.ActionDeny,
		DecidedAt:  now.Format(time.RFC3339),
		Reasons:    []string{"plugin install matched critical rule RB-SKILL-REMOTE-SCRIPT-EXECUTION"},
		Redactions: []string{},
		FailMode:   policy.FailModeClosed,
	}
	signer := NewSigner("test-install-audit-key")

	auditEvent, err := NewInstallDecisionEvent(event, decision, "", signer, now)
	if err != nil {
		t.Fatalf("NewInstallDecisionEvent returned error: %v", err)
	}

	if auditEvent.EventType != "install.decision.deny" {
		t.Fatalf("EventType = %q, want install.decision.deny", auditEvent.EventType)
	}
	if auditEvent.Subject != "plugin:shell-helper" {
		t.Fatalf("Subject = %q, want plugin:shell-helper", auditEvent.Subject)
	}
	if !signer.Verify(auditEvent) {
		t.Fatalf("audit event signature did not verify: %+v", auditEvent)
	}
	payload, err := json.Marshal(auditEvent)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	if strings.Contains(string(payload), "openclaw-install") {
		t.Fatalf("audit event leaked local artifact path: %s", string(payload))
	}
}
