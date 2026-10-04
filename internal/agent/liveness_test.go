package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestSaturatedResultGuardTerminatesWithTypedPartialOutcome(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveSameResult = RepeatResultHardSkip
	state.ConsecutiveSameResultNudges = 7
	result := hookStuckNudge(state, map[string]string{"tool_name": "http_request"})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	events := make(chan Event, 1)
	a := &Agent{ctx: ctx, cancel: cancel, events: events}
	if result.StopReason != "stuck_loop_limit" || !a.stopForHook(result) {
		t.Fatalf("saturated guard must terminate, got %+v", result)
	}
	event := <-events
	if event.Type != "finished" || !event.Aborted || event.AbortReason != "stuck_loop_limit" || ctx.Err() == nil {
		t.Fatalf("guard lost its partial outcome: %+v, context=%v", event, ctx.Err())
	}
}

func TestActiveIdleCheckpointExcludesDowntimeAndKeepsSpentRecovery(t *testing.T) {
	dir := t.TempDir()
	savedAt := time.Now().Add(-24 * time.Hour)
	saved := budgetCheckpoint{Version: 1, ScanID: "idle-clock", UpdatedAt: savedAt, ProgressAt: savedAt.Add(-40 * time.Minute)}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "execution-budget.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{scanBudget: newScanBudget(), cfg: &config.Config{MaxNonProgressSec: 3600}}
	if err := a.scanBudget.loadCheckpoint(dir, "idle-clock"); err != nil {
		t.Fatal(err)
	}
	remaining := a.semanticIdleRemaining()
	if remaining < 19*time.Minute || remaining > 20*time.Minute {
		t.Fatalf("restart charged downtime or granted a new recovery budget: %s", remaining)
	}
}

func TestRunInterruptsAndResumesPlanBeforeBoundingBlockedRequest(t *testing.T) {
	dir := t.TempDir()
	requests := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		requests <- string(body)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	sctx := scanctx.New("run-continuity", dir)
	t.Cleanup(sctx.Close)
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "saved-done", Phase: 6, VulnClass: "sqli", Status: TaskCompleted})
	state.Plan.add(&Task{ID: "saved-next", Phase: 7, VulnClass: "xss", Status: TaskActive})
	state.PlanBuilt = true
	state.ReconCoverage.HTTPProbed = true
	prior := &Agent{scanCtx: sctx, state: state, scanBudget: newScanBudget()}
	if err := prior.saveExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for run := 0; run < 2; run++ {
		cfg := &config.Config{LLM: "test-model", APIBase: srv.URL, APIKey: "test-key"}
		if run == 1 {
			cfg.MaxNonProgressSec = 1
			ctx = context.Background()
		}
		events := make(chan Event, 256)
		a := NewAgent(cfg, "continuation-test", events, scopeguard.Config{BindAddr: "127.0.0.1"}, sctx, withParentContext(ctx))
		a.discoveryMode = true
		done := make(chan struct{})
		t.Cleanup(func() {
			a.Stop()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("agent did not stop during test cleanup")
			}
		})
		go func() { a.Run([]string{"https://example.invalid"}, "continue assessment"); close(done) }()
		select {
		case body := <-requests:
			if !strings.Contains(body, "saved-done") || !strings.Contains(body, "saved-next") {
				t.Fatal("resumed request omitted executable task identities")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("agent did not reach the controlled request")
		}
		if run == 0 {
			cancel()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation or semantic idle deadline failed to interrupt request")
		}
		close(events)
		var terminal Event
		for event := range events {
			if event.Type == "finished" {
				terminal = event
			}
		}
		if run == 0 && (!terminal.Resumable || terminal.Aborted || a.terminalOutcome.Load() != nil) {
			t.Fatalf("external shutdown terminalized executable work: %+v", terminal)
		}
		if run == 1 && (!terminal.Aborted || terminal.AbortReason != "stuck_loop_limit" || terminal.Resumable) {
			t.Fatalf("blocked request escaped active recovery deadline: %+v", terminal)
		}
		if a.state.Plan.Get("saved-done").Status != TaskCompleted || !a.state.ReconCoverage.HTTPProbed {
			t.Fatal("run/restart discarded completed plan or reconnaissance evidence")
		}
		a.Stop()
	}
}

func TestAlternatingPlanErrorsCannotEvadeRecovery(t *testing.T) {
	state := NewScanState()
	state.Plan = AutoPlan([]string{"/users"}, nil)
	a := &Agent{state: state, scanBudget: newScanBudget()}
	hooks := NewHookRegistry()
	RegisterDefaultHooks(hooks)
	for i := 0; i < planValidationRecoveryLimit; i++ {
		state.Iteration = i
		id := "test-sqli"
		if i%2 != 0 {
			id = "test-xss"
		}
		result, err := a.updatePlanTool(map[string]string{"task_id": id, "status": "skipped"})
		if err != nil || result.Error == "" {
			t.Fatalf("expected rejected update: %+v %v", result, err)
		}
		outcome := hooks.Fire(OnToolResult, state, map[string]string{"tool_name": "update_plan", "error": result.Error})
		if outcome.StopReason != "" {
			t.Fatalf("plan recovery stopped before feedback could be delivered: %+v", outcome)
		}
		check := a.semanticLivenessCheck()
		if i < planValidationRecoveryLimit-1 && check.StopReason != "" {
			t.Fatalf("plan recovery stopped before the turn limit: %+v", check)
		}
		if i == planValidationRecoveryLimit-1 && check.StopReason != "stuck_loop_limit" {
			t.Fatalf("alternating validation turns were not bounded: %+v", check)
		}
	}
}

func TestPlanValidationBatchWaitsForFeedbackAndLaterProgress(t *testing.T) {
	state := NewScanState()
	state.Plan = NewPlan()
	task := &Task{ID: "test-xss", Phase: 6, VulnClass: "xss", Endpoint: "/users", Status: TaskActive}
	state.Plan.add(task)
	state.PlanValidationErrors = planValidationRecoveryLimit - 1
	state.LastPlanValidationErrorIteration = 8
	state.PlanValidationErrorIterationSeen = true
	state.Iteration = 9
	a := &Agent{state: state, scanBudget: newScanBudget()}
	args := map[string]string{"tool_name": "update_plan", "error": "invalid transition"}
	for i := 0; i < 26; i++ {
		if result := hookPlanValidationTracker(state, args); result.StopReason != "" {
			t.Fatalf("batch stopped before feedback was delivered: %+v", result)
		}
	}
	if state.PlanValidationErrors != planValidationRecoveryLimit {
		t.Fatalf("one response counted as %d recovery attempts", state.PlanValidationErrors)
	}
	// A valid result later in the same response must still be able to rescue it.
	task.Status = TaskCompleted
	if result := hookPlanValidationTracker(state, map[string]string{"tool_name": "update_plan"}); result.StopReason != "" {
		t.Fatalf("completed work was rejected: %+v", result)
	}
	if result := a.semanticLivenessCheck(); result.StopReason != "" || state.PlanValidationErrors != 0 {
		t.Fatalf("completed work did not reset the recovery deadline: %+v", result)
	}
}

func TestRepeatedPlanSkipFeedbackKeepsTaskAndGuidance(t *testing.T) {
	seen := false
	firstError := tools.Result{Error: fmt.Sprintf("task %q (%s)%s", "first", "xss", planSkipNoteGuidance)}
	secondError := tools.Result{Error: strings.Replace(firstError.Error, `"first"`, `"second"`, 1)}
	first := formatBatchToolResult("update_plan", firstError, &seen)
	second := formatBatchToolResult("update_plan", secondError, &seen)
	if !seen || !strings.Contains(first, "blocked_unreachable") || !strings.Contains(second, `task "second" (xss)`) ||
		!strings.Contains(second, "concrete surface fact") || len(second) >= len(first) {
		t.Fatalf("batch feedback lost task identity or actionable guidance: first=%q second=%q", first, second)
	}
	other := tools.Result{Error: "unknown task ID"}
	if got := formatBatchToolResult("update_plan", other, &seen); got != formatToolResult("update_plan", other) {
		t.Fatalf("unrelated rejection was shortened: %q", got)
	}
	other.Error = `task "third" (xss) cannot be skipped without a justification note. Additional task-specific evidence is required.`
	if got := formatBatchToolResult("update_plan", other, &seen); got != formatToolResult("update_plan", other) {
		t.Fatalf("task-specific rejection was shortened: %q", got)
	}
}

func TestPlanRecoveryResetsOnlyForNewCompletedWork(t *testing.T) {
	state := NewScanState()
	state.Plan = NewPlan()
	task := &Task{ID: "first", Phase: 6, VulnClass: "sqli", Endpoint: "/search", Status: TaskCompleted}
	state.Plan.add(task)
	args := map[string]string{"tool_name": "update_plan", "error": "invalid transition"}
	state.Iteration = 1
	hookPlanValidationTracker(state, args)
	for i := 0; i < 10; i++ {
		task.Status = TaskActive
		state.Iteration++
		hookPlanValidationTracker(state, args)
		task.ID = fmt.Sprintf("replacement-%d", i)
		task.Status = TaskCompleted
		state.Iteration++
		hookPlanValidationTracker(state, args)
	}
	if state.PlanValidationErrors != 21 {
		t.Fatalf("regression/replacement reset recovery: %d", state.PlanValidationErrors)
	}
	state.ReconCoverage.HTTPProbed = true
	state.Iteration++
	hookPlanValidationTracker(state, args)
	if state.PlanValidationErrors != 1 {
		t.Fatalf("new validated recon did not reset recovery: %d", state.PlanValidationErrors)
	}
}

func TestDelegatedPlanHasOnlyAssignedCoverage(t *testing.T) {
	state := NewScanState()
	state.DelegatedAgent = true
	state.LaneScoped = true
	state.AssignedClasses = []string{"sqli"}
	state.DiscoveredEndpoints = []string{"/search?q=a"}
	a := &Agent{state: state}
	result, err := a.buildPlanTool(map[string]string{"tasks": `[{"id":"assigned","phase":6,"vuln_class":"sqli","endpoint":"/search?q=a"}]`})
	if err != nil || result.Error != "" {
		t.Fatalf("assigned plan rejected: %+v %v", result, err)
	}
	for _, plan := range []*Plan{state.Plan, AutoPlanFromState(state)} {
		if plan.IsEmpty() {
			t.Fatal("assigned coverage was discarded")
		}
		for _, task := range plan.Tasks {
			if task.VulnClass != "sqli" {
				t.Fatalf("specialist inherited unrelated task: %+v", task)
			}
		}
	}
	result, _ = a.buildPlanTool(map[string]string{"tasks": `[{"id":"foreign","phase":7,"vuln_class":"xss"}]`})
	if result.Error == "" {
		t.Fatal("explicit lane accepted unrelated coverage")
	}
}

func TestToolWaitHonorsRemainingDurationBudget(t *testing.T) {
	sctx := scanctx.New("duration-test", t.TempDir())
	t.Cleanup(sctx.Close)
	registry := tools.NewRegistry()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	registry.Register(&tools.Tool{Name: "slow", Execute: func(map[string]string) (tools.Result, error) {
		<-release
		return tools.Result{Output: "late"}, nil
	}})
	budget := newScanBudget()
	budget.start()
	budget.startedAt = time.Now().Add(-950 * time.Millisecond)
	a := &Agent{cfg: &config.Config{MaxDurationSec: 1}, ctx: context.Background(), scanCtx: sctx, registry: registry, scanBudget: budget}
	start := time.Now()
	result, err := a.executeToolAsync("slow", nil)
	if !errors.Is(err, context.DeadlineExceeded) || result.Error == "" || time.Since(start) > time.Second {
		t.Fatalf("tool wait exceeded remaining scan duration: %+v %v after %s", result, err, time.Since(start))
	}
	if sctx.Ctx.Err() == nil {
		t.Fatal("duration expiry did not cancel scan-owned work")
	}
}

func TestSemanticLivenessBoundsChangingSuccessfulCalls(t *testing.T) {
	a := &Agent{state: NewScanState(), scanBudget: newScanBudget()}
	for i := 0; i < semanticNonProgressLimit; i++ {
		a.state.Iteration = i
		a.state.LastToolName = fmt.Sprintf("successful-read-%d", i)
		a.scanBudget.addTokens(100)
		a.updateAssessmentProgress()
		result := a.semanticLivenessCheck()
		if i == semanticNonProgressLimit-1 && result.StopReason != "stuck_loop_limit" {
			t.Fatalf("changing success output bypassed semantic liveness: %+v", result)
		}
	}
	a.state.ReconCoverage.HTTPProbed = true
	a.updateAssessmentProgress()
	if result := a.semanticLivenessCheck(); result.StopReason != "" || a.state.ProgressIdleIterations != 0 || a.AssessmentProgress() != 1 {
		t.Fatalf("validated recon did not reset the stalled-work counter: %+v", result)
	}
	for i := 0; i < 10; i++ {
		a.state.ReconCoverage.HTTPProbed = false
		a.updateAssessmentProgress()
		a.state.ReconCoverage.HTTPProbed = true
		a.updateAssessmentProgress()
		a.semanticLivenessCheck()
	}
	if a.AssessmentProgress() != 1 || a.state.ProgressIdleIterations != 10 {
		t.Fatal("replayed evidence or state regression was counted as new work")
	}
}
