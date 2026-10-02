package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestSafeErrorDiagnostic(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"rate", `rate limited: API returned 429: {"error":{"code":"rate_limit_exceeded","message":"secret-value https://private.invalid/","request_id":"secret-value"}}`, "class=rate_limit http_status=429 code=rate_limit_exceeded"},
		{"capacity", `API returned 529: {"error":{"type":"overloaded_error","message":"secret-value"}}`, "class=overloaded http_status=529 code=overloaded_error"},
		{"resource limit", `API returned 429: {"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"check quota secret-value"}}`, "class=rate_limit http_status=429 code=resource_exhausted"},
		{"unknown code", `API returned 429: {"error":{"code":"secret-value","type":"secret-value","status":"secret-value"}}`, "class=rate_limit http_status=429 code=unknown"},
		{"top level", `HTTP 402: {"code":"insufficient_quota","message":"secret-value"}`, "class=quota_exhausted http_status=402 code=insufficient_quota"},
		{"malformed body", `API returned 429: {secret-value`, "class=rate_limit http_status=429 code=unknown"},
		{"body status distractor", `API returned 500: {"error":{"message":"HTTP 529 secret-value"}}`, "class=generic http_status=500 code=unknown"},
		{"identifier distractor", `dial tcp 127.0.0.1:5290: secret-value`, "class=generic http_status=0 code=unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeErrorDiagnostic(errors.New(tt.raw))
			if got != tt.want {
				t.Fatalf("diagnostic = %q, want %q", got, tt.want)
			}
		})
	}
	if got := SafeErrorDiagnostic(nil); got != "class=none http_status=0 code=none" {
		t.Fatalf("nil diagnostic = %q", got)
	}
}

func TestUpstreamWaitHasOneRequestPerAgentAttempt(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusPaymentRequired, 529} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable"}}`))
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			client := NewClient(&config.Config{LLM: "test", APIBase: srv.URL, APIKey: "test"})
			client.SetContext(ctx)
			_, _, err := client.ChatWithUsage([]Message{{Role: "user", Content: "test"}})
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected upstream failure immediately, got %v", err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests = %d, want 1", got)
			}
			if got := ClassifyError(err).Class; got == ErrorClassGeneric || got == ErrorClassAuth {
				t.Fatalf("lost upstream wait class: %s (%s)", got, strings.TrimSpace(err.Error()))
			}
		})
	}
}
