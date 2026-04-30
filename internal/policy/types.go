package policy

type Action string

const (
	ActionAllow      Action = "allow"
	ActionDeny       Action = "deny"
	ActionRedact     Action = "redact"
	ActionApprove    Action = "approve"
	ActionShadow     Action = "shadow"
	ActionQuarantine Action = "quarantine"
	ActionKillSwitch Action = "kill_switch"
)

type FailMode string

const (
	FailModeOpen   FailMode = "open"
	FailModeClosed FailMode = "closed"
)

type ToolCallEvent struct {
	ID                     string            `json:"id"`
	OrganizationID         string            `json:"organizationId,omitempty"`
	AgentID                string            `json:"agentId"`
	UserID                 string            `json:"userId"`
	Skill                  string            `json:"skill"`
	Tool                   string            `json:"tool"`
	Phase                  string            `json:"phase"`
	ObservedAt             string            `json:"observedAt"`
	Environment            string            `json:"environment,omitempty"`
	Arguments              map[string]string `json:"arguments,omitempty"`
	PayloadClassifications []string          `json:"payloadClassifications"`
	DestinationDomains     []string          `json:"destinationDomains"`
}

type PolicyDecision struct {
	ID         string   `json:"id"`
	EventID    string   `json:"eventId"`
	PolicyID   string   `json:"policyId"`
	Action     Action   `json:"action"`
	DecidedAt  string   `json:"decidedAt"`
	Reasons    []string `json:"reasons"`
	Redactions []string `json:"redactions"`
	FailMode   FailMode `json:"failMode"`
}

type PolicySet struct {
	Version          string            `json:"version"`
	ShadowOnly       bool              `json:"shadowOnly"`
	DefaultAction    Action            `json:"defaultAction,omitempty"`
	DefaultFailMode  FailMode          `json:"defaultFailMode,omitempty"`
	CustomRedactions []CustomRedaction `json:"customRedactions,omitempty"`
	Rules            []Rule            `json:"rules"`
}

type CustomRedaction struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type Rule struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Action      Action    `json:"action"`
	FailMode    FailMode  `json:"failMode,omitempty"`
	Match       RuleMatch `json:"match"`
}

type RuleMatch struct {
	Tool                   string            `json:"tool,omitempty"`
	Skill                  string            `json:"skill,omitempty"`
	AgentID                string            `json:"agentId,omitempty"`
	UserID                 string            `json:"userId,omitempty"`
	Environment            string            `json:"environment,omitempty"`
	DestinationDomains     []string          `json:"destinationDomains,omitempty"`
	PayloadClassifications []string          `json:"payloadClassifications,omitempty"`
	Arguments              map[string]string `json:"arguments,omitempty"`
}
