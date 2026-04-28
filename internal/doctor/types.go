package doctor

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Title       string   `json:"title"`
	Evidence    []string `json:"evidence"`
	Remediation string   `json:"remediation"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanReport struct {
	ID             string    `json:"id"`
	AgentID        string    `json:"agentId"`
	ScannerVersion string    `json:"scannerVersion"`
	GeneratedAt    string    `json:"generatedAt"`
	Summary        Summary   `json:"summary"`
	Findings       []Finding `json:"findings"`
	ArtifactHashes []string  `json:"artifactHashes"`
}

type Artifact struct {
	Kind           string            `json:"kind"`
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Source         string            `json:"source"`
	InstallMethod  string            `json:"installMethod"`
	ManifestPath   string            `json:"manifestPath"`
	Hash           string            `json:"hash"`
	Permissions    []string          `json:"permissions"`
	Tools          []string          `json:"tools"`
	OAuthScopes    []string          `json:"oauthScopes"`
	ManifestFields map[string]string `json:"manifestFields,omitempty"`
}

type Inventory struct {
	Skills  []Artifact `json:"skills"`
	Plugins []Artifact `json:"plugins"`
}

type Result struct {
	Root            string     `json:"root"`
	OpenClawVersion string     `json:"openClawVersion"`
	Inventory       Inventory  `json:"inventory"`
	Report          ScanReport `json:"report"`
}

type ScanOptions struct {
	Root           string
	Now            time.Time
	ScannerVersion string
}

type DiscoverOptions struct {
	ExplicitPath string
	Env          map[string]string
	HomeDir      string
}
