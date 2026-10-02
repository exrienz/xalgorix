package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestProviderWaitDiagnosticsStayInOperatorLogs(t *testing.T) {
	for _, tt := range []struct {
		name, code, reason string
		status             int
	}{
		{"rate", "rate_limit_exceeded", "provider_rate_limited", 429},
		{"capacity", "overloaded_error", "provider_overloaded", 529},
		{"credits", "insufficient_quota", "provider_quota_exhausted", 402},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const secret = "test-secret-must-not-be-logged"
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
					"code": tt.code, "message": secret + " https://private.invalid/", "request_id": secret,
				}})
			}))
			defer srv.Close()
			var logs bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(writer)
			cfg := &config.Config{LLM: "test", APIBase: srv.URL, APIKey: secret, MaxRateLimitWaitSec: 1}
			events := make(chan Event, 256)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			a := NewAgent(cfg, "wait-diagnostic-test", events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0},
				WithLLMClient(llm.NewClient(cfg)), withParentContext(ctx),
				withRateLimitBackoff(func(int) time.Duration { return 500 * time.Millisecond }))
			a.Run([]string{"example.test"}, "Run security assessment")
			close(events)
			paused := false
			for event := range events {
				paused = paused || event.Type == "paused" && event.AbortReason == tt.reason && event.Aborted
				for _, private := range []string{secret, "private.invalid", "http_status=", "code=" + tt.code, "wait_limit="} {
					if strings.Contains(event.Content, private) {
						t.Fatalf("operator diagnostic leaked into event: %q", event.Content)
					}
				}
			}
			if !paused || requests.Load() != 2 || a.state.CumulativeRateLimitWait != time.Second {
				t.Fatalf("lost bounded pause: paused=%v requests=%d spent=%s", paused, requests.Load(), a.state.CumulativeRateLimitWait)
			}
			for _, want := range []string{"http_status=", "code=" + tt.code, "wait_limit=1s", "wait_remaining=0s", "budget exhausted", "state preserved for resume"} {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("missing operator diagnostic %q", want)
				}
			}
			if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), "private.invalid") {
				t.Fatal("response values leaked into operator logs")
			}
		})
	}
}

func TestProviderWaitRecoveryDiagnostic(t *testing.T) {
	var requests atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"error":{"code":"rate_limit_exceeded"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"<function=finish><parameter=summary>Test routine</parameter></function>"}}]}`))
	}))
	defer srv.Close()
	var logs bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(writer)
	cfg := &config.Config{LLM: "test", APIBase: srv.URL, APIKey: "test", MaxRateLimitWaitSec: 1}
	events := make(chan Event, 256)
	a := NewAgent(cfg, "wait-recovery-test", events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0},
		WithLLMClient(llm.NewClient(cfg)), withParentContext(ctx),
		withRateLimitBackoff(func(int) time.Duration { return time.Millisecond }))
	a.Run([]string{"example.test"}, "Run security assessment")
	close(events)
	for event := range events {
		if strings.Contains(event.Content, "wait_attempts=") || event.Type == "paused" {
			t.Fatalf("unexpected customer event: %q", event.Content)
		}
	}
	if !strings.Contains(logs.String(), "recovered: wait_attempts=1 cumulative_wait=1ms") {
		t.Fatal("missing recovery diagnostic")
	}
	if a.state.CumulativeRateLimitWait != time.Millisecond || a.state.ConsecutiveRateLimits != 0 {
		t.Fatalf("recovery changed spent budget or failed to reset attempts: %s / %d", a.state.CumulativeRateLimitWait, a.state.ConsecutiveRateLimits)
	}
}
