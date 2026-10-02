package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var responseStatusPattern = regexp.MustCompile(`(?i)\b(?:api returned|http)\s+([1-5][0-9]{2})\b`)

func responseErrorStatus(raw string) int {
	// Only the transport prefix establishes a status. Numbers and quoted
	// HTTP messages in a response body must not change retry decisions.
	prefix, _, _ := strings.Cut(raw, "{")
	match := responseStatusPattern.FindStringSubmatch(prefix)
	if len(match) != 2 {
		return 0
	}
	status, _ := strconv.Atoi(match[1])
	return status
}

// SafeErrorDiagnostic describes an upstream failure for operator logs using
// only a class, response status, and known protocol code. It never returns
// response messages, headers, request identifiers, URLs, or arbitrary values.
func SafeErrorDiagnostic(err error) string {
	if err == nil {
		return "class=none http_status=0 code=none"
	}
	raw := err.Error()
	return fmt.Sprintf("class=%s http_status=%d code=%s", ClassifyErrorString(raw).Class,
		responseErrorStatus(raw), diagnosticErrorCode(raw))
}

func diagnosticErrorCode(raw string) string {
	start := strings.IndexByte(raw, '{')
	if start < 0 {
		return "unknown"
	}
	type fields struct {
		Code   json.RawMessage `json:"code"`
		Type   string          `json:"type"`
		Status string          `json:"status"`
	}
	var body struct {
		fields
		Error fields `json:"error"`
	}
	if err := json.NewDecoder(strings.NewReader(raw[start:])).Decode(&body); err != nil {
		return "unknown"
	}
	for _, values := range []fields{body.Error, body.fields} {
		var code string
		_ = json.Unmarshal(values.Code, &code)
		for _, candidate := range []string{code, values.Type, values.Status} {
			switch strings.ToLower(candidate) {
			case "rate_limit_exceeded", "rate_limit_error", "resource_exhausted",
				"insufficient_quota", "quota_exceeded", "usage_limit_reached",
				"overloaded_error", "context_length_exceeded", "invalid_api_key",
				"unauthenticated", "permission_denied", "billing_not_active",
				"tokens", "requests":
				return strings.ToLower(candidate)
			}
		}
	}
	return "unknown"
}
