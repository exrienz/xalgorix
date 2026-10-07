package web

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// processEvent is the single choke point every agent event flows through on
// its way to clients and the persisted event history. Model prose that carries
// provider-internal control delimiters must be redacted there, regardless of
// which sub-path produced the event (root loop, delegated specialists, tool
// results, error echoes).
func TestProcessEvent_ScrubsProviderControlTokens(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("scrub-control", t.TempDir())
	defer sctx.Close()

	inst := &ScanInstance{ID: "inst-scrub", Status: "running", Targets: "example.com"}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	sess := &scanSession{
		id:         "scrub-control",
		target:     "https://example.com",
		scanDir:    t.TempDir(),
		record:     &ScanRecord{ID: "scrub-control", Target: "https://example.com", Status: "running"},
		sctx:       sctx,
		server:     s,
		instanceID: inst.ID,
	}

	s.processEvent(agent.Event{
		Type:    "message",
		Content: "Reading config]<]minimax[>[done",
	}, sess)

	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if len(inst.events) != 1 {
		t.Fatalf("buffered events = %d, want 1", len(inst.events))
	}
	if got := inst.events[0].Content; strings.Contains(strings.ToLower(got), "minimax") || strings.Contains(got, "<]") {
		t.Fatalf("event content leaked provider control token: %q", got)
	}
	if got := inst.events[0].Content; got != "Reading configdone" {
		t.Fatalf("unexpected scrubbed content: %q", got)
	}
}
