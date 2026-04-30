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
	ID              string          `json:"id"`
	AgentID         string          `json:"agentId"`
	ScannerVersion  string          `json:"scannerVersion"`
	GeneratedAt     string          `json:"generatedAt"`
	Summary         Summary         `json:"summary"`
	Findings        []Finding       `json:"findings"`
	ArtifactHashes  []string        `json:"artifactHashes"`
	Dependencies    []Dependency    `json:"dependencies,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Dependency struct {
	Ecosystem    string `json:"ecosystem"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	ManifestPath string `json:"manifestPath,omitempty"`
	Source       string `json:"source,omitempty"`
	Direct       bool   `json:"direct,omitempty"`
	Dev          bool   `json:"dev,omitempty"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases,omitempty"`
	Ecosystem      string   `json:"ecosystem"`
	PackageName    string   `json:"packageName"`
	PackageVersion string   `json:"packageVersion,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	SeverityType   string   `json:"severityType,omitempty"`
	SeverityScore  string   `json:"severityScore,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Published      string   `json:"published,omitempty"`
	Modified       string   `json:"modified,omitempty"`
	FixedVersions  []string `json:"fixedVersions,omitempty"`
	References     []string `json:"references,omitempty"`
}

type Artifact struct {
	Kind           string            `json:"kind"`
	Ecosystem      string            `json:"ecosystem,omitempty"`
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
	Hooks   []Artifact `json:"hooks,omitempty"`
}

type Result struct {
	Root            string     `json:"root"`
	Ecosystem       string     `json:"ecosystem,omitempty"`
	OpenClawVersion string     `json:"openClawVersion"`
	Inventory       Inventory  `json:"inventory"`
	Report          ScanReport `json:"report"`
}

type ScanOptions struct {
	Root                string
	Ecosystem           string
	Now                 time.Time
	ScannerVersion      string
	OpenClawDiagnostics []OpenClawPluginDiagnostic
}

type OpenClawPluginDiagnostic struct {
	ID             string
	Name           string
	ManifestTools  []string
	RuntimeTools   []string
	RuntimeHooks   []string
	RuntimeRoutes  []string
	DoctorFindings []string
}

type DiscoverOptions struct {
	ExplicitPath string
	Env          map[string]string
	HomeDir      string
}
