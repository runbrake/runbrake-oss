package registry

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

func parseRegistryTimestamp(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return normalizeRegistryTimestamp(text)
	}

	var number int64
	if err := json.Unmarshal(raw, &number); err == nil {
		return unixMaybeMillisToRFC3339(number)
	}

	var floatValue float64
	if err := json.Unmarshal(raw, &floatValue); err == nil {
		return unixMaybeMillisToRFC3339(int64(floatValue))
	}
	return ""
}

func normalizeRegistryTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		return unixMaybeMillisToRFC3339(number)
	}
	return value
}

func unixMaybeMillisToRFC3339(value int64) string {
	if value <= 0 {
		return ""
	}
	if value > 10_000_000_000 {
		return time.UnixMilli(value).UTC().Format(time.RFC3339)
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}
