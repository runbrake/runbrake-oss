package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/audit"
	"github.com/runbrake/runbrake-oss/internal/doctor"
	"github.com/runbrake/runbrake-oss/internal/installguard"
	"github.com/runbrake/runbrake-oss/internal/policy"
	"github.com/runbrake/runbrake-oss/internal/redaction"
	"github.com/runbrake/runbrake-oss/internal/skills"
)

type HealthStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

type HandlerOptions struct {
	Version string
	Policy  policy.PolicySet
	Signer  audit.Signer
	Now     func() time.Time
}

type DecisionResponse struct {
	Decision   policy.PolicyDecision `json:"decision"`
	AuditEvent audit.Event           `json:"auditEvent"`
	Receipt    CheckReceipt          `json:"receipt"`
}

type CheckReceipt struct {
	ID           string   `json:"id"`
	EventID      string   `json:"eventId"`
	Surface      string   `json:"surface"`
	Ecosystem    string   `json:"ecosystem"`
	Status       string   `json:"status"`
	Severity     string   `json:"severity"`
	Headline     string   `json:"headline"`
	Detail       string   `json:"detail"`
	PolicyID     string   `json:"policyId,omitempty"`
	AuditEventID string   `json:"auditEventId,omitempty"`
	EvidenceHash string   `json:"evidenceHash,omitempty"`
	RuleIDs      []string `json:"ruleIds"`
	ObservedAt   string   `json:"observedAt"`
}

type RuntimeObservation struct {
	ID                     string            `json:"id"`
	Source                 string            `json:"source"`
	OrganizationID         string            `json:"organizationId,omitempty"`
	AgentID                string            `json:"agentId"`
	UserID                 string            `json:"userId,omitempty"`
	Skill                  string            `json:"skill,omitempty"`
	Tool                   string            `json:"tool"`
	Phase                  string            `json:"phase"`
	ObservedAt             string            `json:"observedAt"`
	Environment            string            `json:"environment,omitempty"`
	DestinationDomains     []string          `json:"destinationDomains"`
	PayloadClassifications []string          `json:"payloadClassifications"`
	ArgumentKeys           []string          `json:"argumentKeys"`
	ArgumentEvidence       map[string]string `json:"argumentEvidence"`
}

type RuntimeObservationResponse struct {
	Observation RuntimeObservation `json:"observation"`
	AuditEvent  audit.Event        `json:"auditEvent"`
	Receipt     CheckReceipt       `json:"receipt"`
}

func Health(version string) HealthStatus {
	return HealthStatus{
		Name:    "runbrake-sidecar",
		Status:  "ok",
		Version: version,
	}
}

func NewHandler(options HandlerOptions) http.Handler {
	if options.Policy.Version == "" {
		options.Policy = policy.DefaultPolicySet()
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, Health(options.Version))
	})
	mux.HandleFunc("/v1/policy/decision", func(w http.ResponseWriter, r *http.Request) {
		handlePolicyDecision(w, r, options)
	})
	mux.HandleFunc("/v1/install/decision", func(w http.ResponseWriter, r *http.Request) {
		handleInstallDecision(w, r, options)
	})
	mux.HandleFunc("/v1/runtime/observation", func(w http.ResponseWriter, r *http.Request) {
		handleRuntimeObservation(w, r, options)
	})
	return mux
}

func handlePolicyDecision(w http.ResponseWriter, r *http.Request, options HandlerOptions) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var event policy.ToolCallEvent
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "parse tool call event: "+err.Error())
		return
	}
	if event.ID == "" || event.AgentID == "" || event.UserID == "" || event.Tool == "" {
		writeError(w, http.StatusBadRequest, "tool call event requires id, agentId, userId, and tool")
		return
	}

	now := options.Now()
	decision, err := policy.Evaluate(options.Policy, event, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "evaluate policy: "+err.Error())
		return
	}

	redactedEvent, _, err := policy.RedactToolCallEvent(event, options.Policy.CustomRedactions)
	if err != nil {
		writeError(w, http.StatusBadRequest, "redact event: "+err.Error())
		return
	}
	auditEvent, err := audit.NewPolicyDecisionEvent(redactedEvent, decision, "", options.Signer, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create audit event: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, DecisionResponse{
		Decision:   decision,
		AuditEvent: auditEvent,
		Receipt:    policyReceipt(redactedEvent, decision, auditEvent),
	})
}

func handleInstallDecision(w http.ResponseWriter, r *http.Request, options HandlerOptions) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var event installguard.InstallEvent
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "parse install event: "+err.Error())
		return
	}

	now := options.Now()
	report := doctor.ScanReport{}
	if event.ArtifactPath != "" {
		result, err := skills.Scan(skills.ScanOptions{
			Target:         event.ArtifactPath,
			Now:            now,
			ScannerVersion: options.Version,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "scan install artifact: "+err.Error())
			return
		}
		report = result.Report
	}

	decision, err := installguard.Evaluate(options.Policy, event, report, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "evaluate install: "+err.Error())
		return
	}

	auditEvent, err := audit.NewInstallDecisionEvent(event, decision, "", options.Signer, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create audit event: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, DecisionResponse{
		Decision:   decision,
		AuditEvent: auditEvent,
		Receipt:    installReceipt(event, decision, auditEvent),
	})
}

func handleRuntimeObservation(w http.ResponseWriter, r *http.Request, options HandlerOptions) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var observation RuntimeObservation
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		writeError(w, http.StatusBadRequest, "parse runtime observation: "+err.Error())
		return
	}
	if observation.ID == "" || observation.Source == "" || observation.AgentID == "" || observation.Tool == "" {
		writeError(w, http.StatusBadRequest, "runtime observation requires id, source, agentId, and tool")
		return
	}
	if observation.Phase != "before" && observation.Phase != "after" {
		writeError(w, http.StatusBadRequest, "runtime observation phase must be before or after")
		return
	}
	observation.ArgumentEvidence = redactEvidenceMap(observation.ArgumentEvidence)
	if observation.DestinationDomains == nil {
		observation.DestinationDomains = []string{}
	}
	if observation.PayloadClassifications == nil {
		observation.PayloadClassifications = []string{}
	}
	if observation.ArgumentKeys == nil {
		observation.ArgumentKeys = []string{}
	}

	now := options.Now()
	auditEvent, err := audit.NewRuntimeObservationEvent(audit.RuntimeObservationEvidence{
		ID:               observation.ID,
		OrganizationID:   observation.OrganizationID,
		AgentID:          observation.AgentID,
		UserID:           observation.UserID,
		Skill:            observation.Skill,
		Tool:             observation.Tool,
		Source:           observation.Source,
		ObservedAt:       observation.ObservedAt,
		ArgumentEvidence: observation.ArgumentEvidence,
	}, "", options.Signer, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create audit event: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, RuntimeObservationResponse{
		Observation: observation,
		AuditEvent:  auditEvent,
		Receipt:     runtimeObservationReceipt(observation, auditEvent),
	})
}

func policyReceipt(event policy.ToolCallEvent, decision policy.PolicyDecision, auditEvent audit.Event) CheckReceipt {
	status := receiptStatus(decision.Action)
	return CheckReceipt{
		ID:           receiptID("runtime", event.ID, string(status), auditEvent.ID),
		EventID:      event.ID,
		Surface:      "runtime",
		Ecosystem:    ecosystemFromAgent(event.AgentID, event.Skill, ""),
		Status:       status,
		Severity:     receiptSeverity(status),
		Headline:     fmt.Sprintf("RunBrake checked %s", event.Tool),
		Detail:       receiptDetail(decision.Reasons, string(decision.Action)),
		PolicyID:     decision.PolicyID,
		AuditEventID: auditEvent.ID,
		EvidenceHash: auditEvent.EvidenceHash,
		RuleIDs:      []string{},
		ObservedAt:   auditEvent.OccurredAt,
	}
}

func installReceipt(event installguard.InstallEvent, decision policy.PolicyDecision, auditEvent audit.Event) CheckReceipt {
	status := receiptStatus(decision.Action)
	name := event.Name
	if name == "" {
		name = event.Source
	}
	if name == "" {
		name = event.ID
	}
	return CheckReceipt{
		ID:           receiptID("install", event.ID, string(status), auditEvent.ID),
		EventID:      event.ID,
		Surface:      "install",
		Ecosystem:    ecosystemFromAgent(event.AgentID, name, ""),
		Status:       status,
		Severity:     receiptSeverity(status),
		Headline:     fmt.Sprintf("RunBrake checked install %s", name),
		Detail:       receiptDetail(decision.Reasons, string(decision.Action)),
		PolicyID:     decision.PolicyID,
		AuditEventID: auditEvent.ID,
		EvidenceHash: auditEvent.EvidenceHash,
		RuleIDs:      []string{},
		ObservedAt:   auditEvent.OccurredAt,
	}
}

func runtimeObservationReceipt(observation RuntimeObservation, auditEvent audit.Event) CheckReceipt {
	return CheckReceipt{
		ID:           receiptID("runtime", observation.ID, "observed", auditEvent.ID),
		EventID:      observation.ID,
		Surface:      "runtime",
		Ecosystem:    ecosystemFromAgent(observation.AgentID, observation.Skill, observation.Source),
		Status:       "observed",
		Severity:     "info",
		Headline:     fmt.Sprintf("RunBrake observed %s", observation.Tool),
		Detail:       "runtime observation recorded with redacted local evidence",
		AuditEventID: auditEvent.ID,
		EvidenceHash: auditEvent.EvidenceHash,
		RuleIDs:      []string{},
		ObservedAt:   auditEvent.OccurredAt,
	}
}

func receiptStatus(action policy.Action) string {
	switch action {
	case policy.ActionAllow:
		return "allowed"
	case policy.ActionShadow:
		return "shadowed"
	case policy.ActionRedact:
		return "redacted"
	case policy.ActionApprove:
		return "approval_required"
	case policy.ActionDeny:
		return "blocked"
	case policy.ActionQuarantine:
		return "quarantined"
	case policy.ActionKillSwitch:
		return "kill_switch"
	default:
		return "observed"
	}
}

func receiptSeverity(status string) string {
	switch status {
	case "blocked", "quarantined", "kill_switch":
		return "critical"
	case "shadowed", "approval_required":
		return "medium"
	case "redacted":
		return "low"
	default:
		return "info"
	}
}

func receiptDetail(reasons []string, fallback string) string {
	for _, reason := range reasons {
		if strings.TrimSpace(reason) != "" {
			return reason
		}
	}
	return fallback
}

func ecosystemFromAgent(agentID string, skill string, source string) string {
	joined := strings.ToLower(agentID + " " + skill + " " + source)
	if strings.Contains(joined, "hermes") {
		return "hermes"
	}
	return "openclaw"
}

func receiptID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "receipt-" + hex.EncodeToString(sum[:])[:16]
}

func redactEvidenceMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = redaction.Redact(value)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func Serve(addr string, options HandlerOptions) error {
	if addr == "" {
		return fmt.Errorf("sidecar address is required")
	}
	return http.ListenAndServe(addr, NewHandler(options))
}
