package llm

import "testing"

func TestPauseClassificationUsesResponseStatus(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want ErrorClass
	}{
		{"unrelated request identifier", `API returned 500: {"error":{"message":"internal error","request_id":"req_529123"}}`, ErrorClassGeneric},
		{"unrelated port", `dial tcp 127.0.0.1:5290: connection refused`, ErrorClassGeneric},
		{"longer status number", `API returned 5290: invalid status`, ErrorClassGeneric},
		{"temporary resource limit", `API returned 429: {"error":{"status":"RESOURCE_EXHAUSTED","message":"Resource has been exhausted (e.g. check quota)."}}`, ErrorClassRateLimit},
		{"explicit depleted credits", `API returned 429: {"error":{"code":"insufficient_quota","message":"No credits left"}}`, ErrorClassQuotaExhausted},
		{"actual capacity response", `API returned 529: {"error":{"type":"overloaded_error"}}`, ErrorClassOverloaded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyErrorString(tt.err); got.Class != tt.want {
				t.Fatalf("class = %s, want %s", got.Class, tt.want)
			}
		})
	}
}
