package skills

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/runbrake/runbrake-oss/internal/doctor"
)

type Finding = doctor.Finding
type Result = doctor.Result

type ScanOptions struct {
	Target               string
	Now                  time.Time
	ScannerVersion       string
	HTTPClient           *http.Client
	Timeout              time.Duration
	MaxDownloadBytes     int64
	MaxExtractedBytes    int64
	MaxRelevantFileBytes int64
	MaxArchiveFiles      int
	AllowDomains         []string
	EgressProfile        string
	Suppressions         []Suppression
}

type Suppression struct {
	RuleID           string `json:"ruleId"`
	ArtifactName     string `json:"artifactName,omitempty"`
	EvidenceContains string `json:"evidenceContains,omitempty"`
	Reason           string `json:"reason"`
	ExpiresAt        string `json:"expiresAt,omitempty"`
}

type Rule struct {
	ID                string
	Severity          doctor.Severity
	Confidence        float64
	Title             string
	Remediation       string
	RecommendedPolicy string
}

type manifest struct {
	ID            flexibleString     `json:"id"`
	Name          flexibleString     `json:"name"`
	Version       flexibleString     `json:"version"`
	Source        flexibleString     `json:"source"`
	InstallMethod flexibleString     `json:"installMethod"`
	Publisher     flexibleString     `json:"publisher"`
	Permissions   flexibleStringList `json:"permissions"`
	Tools         flexibleStringList `json:"tools"`
	OAuthScopes   flexibleStringList `json:"oauthScopes"`
}

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              flexibleStringMap `json:"scripts"`
	Dependencies         flexibleStringMap `json:"dependencies"`
	DevDependencies      flexibleStringMap `json:"devDependencies"`
	PeerDependencies     flexibleStringMap `json:"peerDependencies"`
	OptionalDependencies flexibleStringMap `json:"optionalDependencies"`
}

type scannedFile struct {
	Rel  string
	Data []byte
	Text string
}

type flexibleString string

func (value *flexibleString) UnmarshalJSON(data []byte) error {
	values := flattenStringishJSON(data)
	if len(values) == 0 {
		*value = ""
		return nil
	}
	*value = flexibleString(values[0])
	return nil
}

type flexibleStringList []string

func (values *flexibleStringList) UnmarshalJSON(data []byte) error {
	*values = flexibleStringList(flattenStringishJSON(data))
	return nil
}

type flexibleStringMap map[string]string

func (values *flexibleStringMap) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		var list []json.RawMessage
		if listErr := json.Unmarshal(data, &list); listErr != nil {
			return err
		}
		out := map[string]string{}
		for _, item := range list {
			for _, value := range flattenStringishJSON(item) {
				if value != "" {
					out[value] = ""
				}
			}
		}
		*values = out
		return nil
	}

	out := map[string]string{}
	for key, value := range raw {
		flattened := flattenStringishJSON(value)
		if len(flattened) == 0 {
			out[key] = ""
			continue
		}
		out[key] = strings.Join(flattened, " ")
	}
	*values = out
	return nil
}

func flattenStringishJSON(data []byte) []string {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil
	}
	out := []string{}
	collectStringish(value, &out)
	return sortedUnique(out)
}

func collectStringish(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		for _, item := range splitCSVLike(typed) {
			*out = append(*out, item)
		}
	case []any:
		for _, item := range typed {
			collectStringish(item, out)
		}
	case map[string]any:
		for key, item := range typed {
			if strings.TrimSpace(key) != "" {
				*out = append(*out, strings.TrimSpace(key))
			}
			collectStringish(item, out)
		}
	}
}
