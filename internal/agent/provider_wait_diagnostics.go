package agent

import (
	"fmt"
	"log"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

func (a *Agent) providerWaitBudgetDiagnostic(limit time.Duration) string {
	if limit <= 0 {
		return "wait_limit=unlimited wait_remaining=unlimited"
	}
	remaining := max(time.Duration(0), limit-a.state.CumulativeRateLimitWait)
	return fmt.Sprintf("wait_limit=%s wait_remaining=%s", limit, remaining)
}

func (a *Agent) logProviderWait(err error, backoff, limit time.Duration) {
	log.Printf("[agent:%s] Upstream LLM wait (%s): retry_in=%s attempt=%d cumulative_wait=%s %s",
		a.ID, llm.SafeErrorDiagnostic(err), backoff, a.state.ConsecutiveRateLimits,
		a.state.CumulativeRateLimitWait, a.providerWaitBudgetDiagnostic(limit))
}

func (a *Agent) pauseForProviderWait(err error, reason string, limit time.Duration, tokens int) {
	log.Printf("[agent:%s] Upstream LLM wait budget exhausted (%s): attempt=%d cumulative_wait=%s %s; state preserved for resume",
		a.ID, llm.SafeErrorDiagnostic(err), a.state.ConsecutiveRateLimits,
		a.state.CumulativeRateLimitWait, a.providerWaitBudgetDiagnostic(limit))
	a.emit(Event{Type: "paused", Content: "Scan paused: upstream provider temporarily unavailable; existing findings preserved.",
		TotalTokens: tokens, Aborted: true, AbortReason: reason})
}
