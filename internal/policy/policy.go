package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/redaction"
)

const defaultPolicyID = "policy-default-allow"

func DefaultPolicySet() PolicySet {
	return PolicySet{
		Version:         "2026-04-28",
		ShadowOnly:      true,
		DefaultAction:   ActionAllow,
		DefaultFailMode: FailModeOpen,
		Rules:           []Rule{},
	}
}

func Parse(data []byte) (PolicySet, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var set PolicySet
	if err := decoder.Decode(&set); err != nil {
		return PolicySet{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := normalizeAndValidate(&set); err != nil {
		return PolicySet{}, err
	}
	return set, nil
}

func Evaluate(set PolicySet, event ToolCallEvent, now time.Time) (PolicyDecision, error) {
	if err := normalizeAndValidate(&set); err != nil {
		return PolicyDecision{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	sanitized, redactions, err := RedactToolCallEvent(event, set.CustomRedactions)
	if err != nil {
		return PolicyDecision{}, err
	}

	for _, rule := range set.Rules {
		matched, err := ruleMatches(rule, sanitized)
		if err != nil {
			return PolicyDecision{}, err
		}
		if !matched {
			continue
		}

		action := rule.Action
		reasons := []string{ruleReason(rule)}
		if set.ShadowOnly && shadowedAction(action) {
			reasons = append(reasons, fmt.Sprintf("shadow mode: rule %s would have returned %s", rule.ID, action))
			action = ActionShadow
		}

		failMode := rule.FailMode
		if failMode == "" {
			failMode = set.DefaultFailMode
		}

		return PolicyDecision{
			ID:         decisionID(sanitized.ID, rule.ID, action, now),
			EventID:    sanitized.ID,
			PolicyID:   rule.ID,
			Action:     action,
			DecidedAt:  now.Format(time.RFC3339),
			Reasons:    reasons,
			Redactions: redactions,
			FailMode:   failMode,
		}, nil
	}

	action := set.DefaultAction
	reasons := []string{"no policy rule matched; default action " + string(set.DefaultAction)}
	if set.ShadowOnly && shadowedAction(action) {
		reasons = append(reasons, fmt.Sprintf("shadow mode: default action would have returned %s", action))
		action = ActionShadow
	}

	return PolicyDecision{
		ID:         decisionID(sanitized.ID, defaultPolicyID, action, now),
		EventID:    sanitized.ID,
		PolicyID:   defaultPolicyID,
		Action:     action,
		DecidedAt:  now.Format(time.RFC3339),
		Reasons:    reasons,
		Redactions: redactions,
		FailMode:   set.DefaultFailMode,
	}, nil
}

func RedactToolCallEvent(event ToolCallEvent, custom []CustomRedaction) (ToolCallEvent, []string, error) {
	sanitized := event
	if event.Arguments == nil {
		return sanitized, []string{}, nil
	}

	customPatterns := make([]compiledCustomRedaction, 0, len(custom))
	for _, item := range custom {
		re, err := regexp.Compile(item.Pattern)
		if err != nil {
			return ToolCallEvent{}, nil, fmt.Errorf("custom redaction %q has invalid pattern: %w", item.Name, err)
		}
		customPatterns = append(customPatterns, compiledCustomRedaction{name: item.Name, re: re})
	}

	sanitized.Arguments = make(map[string]string, len(event.Arguments))
	redactions := []string{}
	keys := make([]string, 0, len(event.Arguments))
	for key := range event.Arguments {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := event.Arguments[key]
		redacted := redaction.Redact(value)
		for _, customPattern := range customPatterns {
			redacted = customPattern.re.ReplaceAllStringFunc(redacted, func(match string) string {
				return customMarker(customPattern.name, match)
			})
		}
		sanitized.Arguments[key] = redacted
		if redacted != value {
			redactions = append(redactions, "arguments."+key)
		}
	}

	return sanitized, redactions, nil
}

type compiledCustomRedaction struct {
	name string
	re   *regexp.Regexp
}

func normalizeAndValidate(set *PolicySet) error {
	if strings.TrimSpace(set.Version) == "" {
		return fmt.Errorf("policy version is required")
	}
	if set.DefaultAction == "" {
		set.DefaultAction = ActionAllow
	}
	if set.DefaultFailMode == "" {
		set.DefaultFailMode = FailModeOpen
	}
	if !validAction(set.DefaultAction) {
		return fmt.Errorf("unsupported defaultAction %q", set.DefaultAction)
	}
	if !validFailMode(set.DefaultFailMode) {
		return fmt.Errorf("unsupported defaultFailMode %q", set.DefaultFailMode)
	}
	for _, custom := range set.CustomRedactions {
		if strings.TrimSpace(custom.Name) == "" {
			return fmt.Errorf("custom redaction name is required")
		}
		if _, err := regexp.Compile(custom.Pattern); err != nil {
			return fmt.Errorf("custom redaction %q has invalid pattern: %w", custom.Name, err)
		}
	}
	seen := map[string]bool{}
	for _, rule := range set.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("policy rule id is required")
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate policy rule id %q", rule.ID)
		}
		seen[rule.ID] = true
		if !validAction(rule.Action) {
			return fmt.Errorf("rule %s has unsupported action %q", rule.ID, rule.Action)
		}
		if rule.FailMode != "" && !validFailMode(rule.FailMode) {
			return fmt.Errorf("rule %s has unsupported failMode %q", rule.ID, rule.FailMode)
		}
		for name, pattern := range rule.Match.Arguments {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("rule %s argument %s has invalid regex: %w", rule.ID, name, err)
			}
		}
	}
	return nil
}

func ruleMatches(rule Rule, event ToolCallEvent) (bool, error) {
	match := rule.Match
	if match.Tool != "" && match.Tool != event.Tool {
		return false, nil
	}
	if match.Skill != "" && match.Skill != event.Skill {
		return false, nil
	}
	if match.AgentID != "" && match.AgentID != event.AgentID {
		return false, nil
	}
	if match.UserID != "" && match.UserID != event.UserID {
		return false, nil
	}
	if match.Environment != "" && match.Environment != event.Environment {
		return false, nil
	}
	if len(match.DestinationDomains) > 0 && !containsAny(event.DestinationDomains, match.DestinationDomains) {
		return false, nil
	}
	if len(match.PayloadClassifications) > 0 && !containsAny(event.PayloadClassifications, match.PayloadClassifications) {
		return false, nil
	}
	for key, pattern := range match.Arguments {
		value, ok := event.Arguments[key]
		if !ok {
			return false, nil
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		if !re.MatchString(value) {
			return false, nil
		}
	}
	return true, nil
}

func containsAny(values []string, required []string) bool {
	set := map[string]bool{}
	for _, value := range values {
		set[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range required {
		if set[strings.ToLower(strings.TrimSpace(value))] {
			return true
		}
	}
	return false
}

func ruleReason(rule Rule) string {
	if strings.TrimSpace(rule.Description) != "" {
		return rule.Description
	}
	return "matched policy rule " + rule.ID
}

func shadowedAction(action Action) bool {
	return action == ActionDeny || action == ActionApprove || action == ActionQuarantine || action == ActionKillSwitch
}

func validAction(action Action) bool {
	switch action {
	case ActionAllow, ActionDeny, ActionRedact, ActionApprove, ActionShadow, ActionQuarantine, ActionKillSwitch:
		return true
	default:
		return false
	}
}

func validFailMode(mode FailMode) bool {
	return mode == FailModeOpen || mode == FailModeClosed
}

func decisionID(eventID string, policyID string, action Action, now time.Time) string {
	sum := sha256.Sum256([]byte(eventID + "\x00" + policyID + "\x00" + string(action) + "\x00" + now.Format(time.RFC3339Nano)))
	return "decision-" + hex.EncodeToString(sum[:])[:16]
}

func customMarker(name string, raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "[REDACTED:" + name + ":" + hex.EncodeToString(sum[:])[:8] + "]"
}
