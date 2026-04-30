package policy

import (
	"strings"
	"testing"
	"time"
)

var fixedDecisionTime = time.Date(2026, 4, 28, 12, 30, 0, 0, time.UTC)

func TestPolicyEvaluatesFirstMatchingRuleAsShadowDecision(t *testing.T) {
	set, err := Parse([]byte(`{
		"version": "2026-04-28",
		"shadowOnly": true,
		"defaultAction": "allow",
		"defaultFailMode": "open",
		"rules": [
			{
				"id": "policy-external-email-approval",
				"description": "external customer email requires approval",
				"action": "approve",
				"failMode": "closed",
				"match": {
					"tool": "gmail.send",
					"environment": "prod",
					"destinationDomains": ["vendor.example"],
					"payloadClassifications": ["customer_email"],
					"arguments": {
						"recipient": "@vendor\\.example$"
					}
				}
			},
			{
				"id": "policy-gmail-deny-fallback",
				"action": "deny",
				"match": {
					"tool": "gmail.send"
				}
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	decision, err := Evaluate(set, ToolCallEvent{
		ID:                     "event-001",
		AgentID:                "agent-local-dev",
		UserID:                 "user-dev",
		Skill:                  "google-workspace@1.4.2",
		Tool:                   "gmail.send",
		Phase:                  "before",
		ObservedAt:             fixedDecisionTime.Format(time.RFC3339),
		Environment:            "prod",
		DestinationDomains:     []string{"vendor.example"},
		PayloadClassifications: []string{"customer_email"},
		Arguments: map[string]string{
			"recipient":     "finance@vendor.example",
			"authorization": "Bearer ya29.supersecrettokenvalue",
		},
	}, fixedDecisionTime)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.PolicyID != "policy-external-email-approval" {
		t.Fatalf("PolicyID = %q, want first matching rule", decision.PolicyID)
	}
	if decision.Action != ActionShadow {
		t.Fatalf("Action = %q, want shadow", decision.Action)
	}
	if decision.FailMode != FailModeClosed {
		t.Fatalf("FailMode = %q, want closed", decision.FailMode)
	}
	if !strings.Contains(strings.Join(decision.Reasons, " "), "would have returned approve") {
		t.Fatalf("decision reasons missing shadow explanation: %#v", decision.Reasons)
	}
	if len(decision.Redactions) != 1 || decision.Redactions[0] != "arguments.authorization" {
		t.Fatalf("Redactions = %#v, want authorization argument redacted", decision.Redactions)
	}
}

func TestPolicyDefaultsToAllowWhenNoRuleMatches(t *testing.T) {
	decision, err := Evaluate(DefaultPolicySet(), ToolCallEvent{
		ID:                     "event-allow",
		AgentID:                "agent-local-dev",
		UserID:                 "user-dev",
		Skill:                  "calendar@1.0.0",
		Tool:                   "calendar.read",
		Phase:                  "before",
		ObservedAt:             fixedDecisionTime.Format(time.RFC3339),
		PayloadClassifications: []string{"calendar_metadata"},
		DestinationDomains:     []string{"calendar.example"},
	}, fixedDecisionTime)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if decision.Action != ActionAllow {
		t.Fatalf("Action = %q, want allow", decision.Action)
	}
	if decision.PolicyID != defaultPolicyID {
		t.Fatalf("PolicyID = %q, want default policy", decision.PolicyID)
	}
}

func TestPolicyRejectsInvalidArgumentRegex(t *testing.T) {
	_, err := Parse([]byte(`{
		"version": "2026-04-28",
		"shadowOnly": true,
		"rules": [
			{
				"id": "policy-bad-regex",
				"action": "deny",
				"match": {
					"arguments": {
						"command": "["
					}
				}
			}
		]
	}`))
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid regex error")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("Parse error = %v, want invalid regex", err)
	}
}

func TestRedactToolCallEventAppliesBuiltInAndCustomPatterns(t *testing.T) {
	event := ToolCallEvent{
		ID:      "event-redact",
		AgentID: "agent-local-dev",
		UserID:  "user-dev",
		Skill:   "shell@1.0.0",
		Tool:    "shell.exec",
		Phase:   "before",
		Arguments: map[string]string{
			"apiKey":      "sk-prod_1234567890abcdef",
			"customer_id": "customer SSN 123-45-6789",
		},
		PayloadClassifications: []string{"secret"},
		DestinationDomains:     []string{},
	}

	redacted, redactions, err := RedactToolCallEvent(event, []CustomRedaction{
		{Name: "ssn", Pattern: `\d{3}-\d{2}-\d{4}`},
	})
	if err != nil {
		t.Fatalf("RedactToolCallEvent returned error: %v", err)
	}

	rendered := redacted.Arguments["apiKey"] + " " + redacted.Arguments["customer_id"]
	for _, raw := range []string{"sk-prod_1234567890abcdef", "123-45-6789"} {
		if strings.Contains(rendered, raw) {
			t.Fatalf("redacted event leaked %q in %q", raw, rendered)
		}
	}
	if len(redactions) != 2 {
		t.Fatalf("redactions = %#v, want two redacted arguments", redactions)
	}
}
