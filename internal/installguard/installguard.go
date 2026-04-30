package installguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/policy"
)

const (
	PolicyInstallCriticalFinding = "policy-install-critical-finding"
	PolicyInstallDefaultAllow    = "policy-install-default-allow"
)

type InstallKind string

const (
	InstallKindSkill  InstallKind = "skill"
	InstallKindPlugin InstallKind = "plugin"
)

type InstallEvent struct {
	ID               string      `json:"id"`
	Kind             InstallKind `json:"kind"`
	Name             string      `json:"name,omitempty"`
	Version          string      `json:"version,omitempty"`
	Source           string      `json:"source,omitempty"`
	ArtifactPath     string      `json:"artifactPath,omitempty"`
	ArtifactHash     string      `json:"artifactHash,omitempty"`
	OrganizationID   string      `json:"organizationId,omitempty"`
	AgentID          string      `json:"agentId,omitempty"`
	UserID           string      `json:"userId,omitempty"`
	ObservedAt       string      `json:"observedAt"`
	OpenClawFindings []string    `json:"openclawFindings,omitempty"`
}

func Evaluate(set policy.PolicySet, event InstallEvent, report doctor.ScanReport, now time.Time) (policy.PolicyDecision, error) {
	if err := validateEvent(event); err != nil {
		return policy.PolicyDecision{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if set.Version == "" {
		set = policy.DefaultPolicySet()
	}

	if critical := firstFindingWithSeverity(report.Findings, doctor.SeverityCritical); critical != nil {
		action := policy.ActionDeny
		reasons := []string{
			fmt.Sprintf("%s install matched critical rule %s: %s", event.Kind, critical.RuleID, critical.Title),
		}
		if set.ShadowOnly {
			reasons = append(reasons, "shadow mode: install would have returned deny")
			action = policy.ActionShadow
		}
		return policy.PolicyDecision{
			ID:         decisionID(event.ID, PolicyInstallCriticalFinding, action, now),
			EventID:    event.ID,
			PolicyID:   PolicyInstallCriticalFinding,
			Action:     action,
			DecidedAt:  now.Format(time.RFC3339),
			Reasons:    reasons,
			Redactions: []string{},
			FailMode:   policy.FailModeClosed,
		}, nil
	}

	failMode := set.DefaultFailMode
	if failMode == "" {
		failMode = policy.FailModeOpen
	}
	return policy.PolicyDecision{
		ID:         decisionID(event.ID, PolicyInstallDefaultAllow, policy.ActionAllow, now),
		EventID:    event.ID,
		PolicyID:   PolicyInstallDefaultAllow,
		Action:     policy.ActionAllow,
		DecidedAt:  now.Format(time.RFC3339),
		Reasons:    []string{fmt.Sprintf("%s install scan completed below critical threshold", event.Kind)},
		Redactions: []string{},
		FailMode:   failMode,
	}, nil
}

func validateEvent(event InstallEvent) error {
	if strings.TrimSpace(event.ID) == "" {
		return fmt.Errorf("install event requires id")
	}
	switch event.Kind {
	case InstallKindSkill, InstallKindPlugin:
		return nil
	default:
		return fmt.Errorf("install event kind must be skill or plugin")
	}
}

func firstFindingWithSeverity(findings []doctor.Finding, severity doctor.Severity) *doctor.Finding {
	for i := range findings {
		if findings[i].Severity == severity {
			return &findings[i]
		}
	}
	return nil
}

func decisionID(eventID string, policyID string, action policy.Action, now time.Time) string {
	sum := sha256.Sum256([]byte(eventID + "\x00" + policyID + "\x00" + string(action) + "\x00" + now.Format(time.RFC3339Nano)))
	return "decision-" + hex.EncodeToString(sum[:])[:16]
}
