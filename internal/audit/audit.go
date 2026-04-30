package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/runbrake/runbrake-oss/internal/installguard"
	"github.com/runbrake/runbrake-oss/internal/policy"
)

type Event struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organizationId"`
	AgentID        string  `json:"agentId"`
	EventType      string  `json:"eventType"`
	OccurredAt     string  `json:"occurredAt"`
	Actor          string  `json:"actor"`
	Subject        string  `json:"subject"`
	EvidenceHash   string  `json:"evidenceHash"`
	PreviousHash   *string `json:"previousHash"`
	Signature      string  `json:"signature"`
}

type Signer struct {
	key []byte
}

func NewSigner(key string) Signer {
	if key == "" {
		key = "runbrake-local-sidecar-audit-key"
	}
	return Signer{key: []byte(key)}
}

func NewPolicyDecisionEvent(event policy.ToolCallEvent, decision policy.PolicyDecision, previousHash string, signer Signer, now time.Time) (Event, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	organizationID := event.OrganizationID
	if organizationID == "" {
		organizationID = "local"
	}

	evidenceHash, err := HashEvidence(event, decision)
	if err != nil {
		return Event{}, err
	}

	auditEvent := Event{
		ID:             auditEventID(decision.ID, now),
		OrganizationID: organizationID,
		AgentID:        event.AgentID,
		EventType:      "policy.decision." + string(decision.Action),
		OccurredAt:     now.Format(time.RFC3339),
		Actor:          event.AgentID,
		Subject:        event.Tool,
		EvidenceHash:   evidenceHash,
		PreviousHash:   previousHashPtr(previousHash),
	}

	signature, err := signer.Sign(auditEvent)
	if err != nil {
		return Event{}, err
	}
	auditEvent.Signature = signature
	return auditEvent, nil
}

func NewInstallDecisionEvent(event installguard.InstallEvent, decision policy.PolicyDecision, previousHash string, signer Signer, now time.Time) (Event, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	organizationID := event.OrganizationID
	if organizationID == "" {
		organizationID = "local"
	}
	agentID := event.AgentID
	if agentID == "" {
		agentID = "openclaw-install"
	}

	evidenceHash, err := HashInstallEvidence(event, decision)
	if err != nil {
		return Event{}, err
	}

	auditEvent := Event{
		ID:             auditEventID(decision.ID, now),
		OrganizationID: organizationID,
		AgentID:        agentID,
		EventType:      "install.decision." + string(decision.Action),
		OccurredAt:     now.Format(time.RFC3339),
		Actor:          agentID,
		Subject:        installSubject(event),
		EvidenceHash:   evidenceHash,
		PreviousHash:   previousHashPtr(previousHash),
	}

	signature, err := signer.Sign(auditEvent)
	if err != nil {
		return Event{}, err
	}
	auditEvent.Signature = signature
	return auditEvent, nil
}

type RuntimeObservationEvidence struct {
	ID               string            `json:"id"`
	OrganizationID   string            `json:"organizationId,omitempty"`
	AgentID          string            `json:"agentId"`
	UserID           string            `json:"userId,omitempty"`
	Skill            string            `json:"skill,omitempty"`
	Tool             string            `json:"tool"`
	Source           string            `json:"source"`
	ObservedAt       string            `json:"observedAt"`
	ArgumentEvidence map[string]string `json:"argumentEvidence,omitempty"`
}

func NewRuntimeObservationEvent(event RuntimeObservationEvidence, previousHash string, signer Signer, now time.Time) (Event, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	organizationID := event.OrganizationID
	if organizationID == "" {
		organizationID = "local"
	}

	evidenceHash, err := HashRuntimeObservationEvidence(event)
	if err != nil {
		return Event{}, err
	}

	auditEvent := Event{
		ID:             auditEventID(event.ID, now),
		OrganizationID: organizationID,
		AgentID:        event.AgentID,
		EventType:      "runtime_observation_recorded",
		OccurredAt:     now.Format(time.RFC3339),
		Actor:          event.AgentID,
		Subject:        event.Tool,
		EvidenceHash:   evidenceHash,
		PreviousHash:   previousHashPtr(previousHash),
	}

	signature, err := signer.Sign(auditEvent)
	if err != nil {
		return Event{}, err
	}
	auditEvent.Signature = signature
	return auditEvent, nil
}

func HashEvidence(event policy.ToolCallEvent, decision policy.PolicyDecision) (string, error) {
	payload, err := json.Marshal(struct {
		Event    policy.ToolCallEvent  `json:"event"`
		Decision policy.PolicyDecision `json:"decision"`
	}{
		Event:    event,
		Decision: decision,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func HashInstallEvidence(event installguard.InstallEvent, decision policy.PolicyDecision) (string, error) {
	payload, err := json.Marshal(struct {
		Event    installguard.InstallEvent `json:"event"`
		Decision policy.PolicyDecision     `json:"decision"`
	}{
		Event:    event,
		Decision: decision,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func HashRuntimeObservationEvidence(event RuntimeObservationEvidence) (string, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (signer Signer) Sign(event Event) (string, error) {
	if len(signer.key) == 0 {
		return "", fmt.Errorf("audit signer key is required")
	}
	payload, err := signingPayload(event)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, signer.key)
	if _, err := mac.Write(payload); err != nil {
		return "", err
	}
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (signer Signer) Verify(event Event) bool {
	expected, err := signer.Sign(Event{
		ID:             event.ID,
		OrganizationID: event.OrganizationID,
		AgentID:        event.AgentID,
		EventType:      event.EventType,
		OccurredAt:     event.OccurredAt,
		Actor:          event.Actor,
		Subject:        event.Subject,
		EvidenceHash:   event.EvidenceHash,
		PreviousHash:   event.PreviousHash,
	})
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(event.Signature))
}

func signingPayload(event Event) ([]byte, error) {
	unsigned := event
	unsigned.Signature = ""
	return json.Marshal(unsigned)
}

func auditEventID(decisionID string, now time.Time) string {
	sum := sha256.Sum256([]byte(decisionID + "\x00" + now.Format(time.RFC3339Nano)))
	return "audit-" + hex.EncodeToString(sum[:])[:16]
}

func previousHashPtr(previousHash string) *string {
	if previousHash == "" {
		return nil
	}
	return &previousHash
}

func installSubject(event installguard.InstallEvent) string {
	name := event.Name
	if name == "" {
		name = event.Source
	}
	if name == "" {
		name = event.ID
	}
	return string(event.Kind) + ":" + name
}
