package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func childScopeFixture(status string) (*ScanRecord, *ScanInstance) {
	child := &ScanRecord{
		ID: "child-record", InstanceID: "coordinator", Target: "a.example.invalid", ParentTarget: "example.invalid",
		ScanMode: "wildcard", Status: status, StartedAt: "2026-01-01T00:00:00Z", CurrentPhase: 3, Phases: []int{1, 3},
		Iterations: 2, ToolCalls: 3, TotalTokens: 100, AssessmentProgress: 4, WorkStarted: true,
		PlanPresent: true, PlanTasksTotal: 5, PlanTasksCompleted: 1, PlanTasksSkipped: 1, PlanTasksUnfinished: 3,
		UsageBySession: map[string]sessionUsage{"child-record": {Tokens: 100, Progress: 4}},
		Vulns:          []VulnSummary{{ID: "XALG-1", SourceScanID: "child-record", Title: "Child finding", Target: "a.example.invalid", Severity: "high"}},
		Events:         []WSEvent{{Type: "message", Content: "Child evidence", Target: "a.example.invalid"}},
	}
	if status != "running" {
		child.FinishedAt = "2026-01-01T01:00:00Z"
		child.Completion = "partial"
		child.StopReason = "stuck_loop_limit"
	}
	parent := &ScanInstance{
		ID: "coordinator", Targets: "example.invalid", ScanMode: "wildcard", Status: "running", CurrentPhase: 21,
		Iterations: 40, ToolCalls: 50, TotalTokens: 1000, AssessmentProgress: 20, WorkStarted: true,
		PlanPresent: true, PlanTasksTotal: 20, PlanTasksCompleted: 10, PlanTasksSkipped: 2, PlanTasksUnfinished: 8,
		UsageBySession: map[string]sessionUsage{"sibling-record": {Tokens: 900, Progress: 16}},
		Vulns:          []VulnSummary{{ID: "XALG-1", SourceScanID: "sibling-record", Title: "Sibling finding", Target: "b.example.invalid", Severity: "medium"}},
		events:         []WSEvent{{Type: "message", Content: "Sibling evidence", Target: "b.example.invalid"}},
	}
	return child, parent
}

func TestChildRecordDoesNotInheritCoordinatorSnapshot(t *testing.T) {
	for _, status := range []string{"running", "finished", "stopped", "failed"} {
		for _, includeEvents := range []bool{false, true} {
			t.Run(status+"/events="+map[bool]string{false: "false", true: "true"}[includeEvents], func(t *testing.T) {
				child, parent := childScopeFixture(status)
				before, _ := json.Marshal(child)
				s := newTestServer(t, nil)
				s.instances[parent.ID] = parent
				s.applyInstanceSnapshot(child, includeEvents)
				after, _ := json.Marshal(child)
				if string(before) != string(after) {
					t.Errorf("child inherited coordinator state: status=%s findings=%d tokens=%d progress=%d phase=%d plan=%d events=%v",
						child.Status, len(child.Vulns), child.TotalTokens, child.AssessmentProgress, child.CurrentPhase, child.PlanTasksTotal, child.Events)
				}
			})
		}
	}
}

func TestChildDetailRetainsOwnEvidenceAndOutcome(t *testing.T) {
	for _, status := range []string{"running", "finished", "stopped", "failed"} {
		t.Run(status, func(t *testing.T) {
			child, parent := childScopeFixture(status)
			s := newTestServer(t, nil)
			s.instances[parent.ID] = parent
			writeScanRecord(t, s.dataDir, "child", *child)
			path := filepath.Join(s.dataDir, "child", "scan.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/"+child.ID, nil))
			var got ScanRecord
			if rr.Code != http.StatusOK {
				t.Fatalf("detail status=%d", rr.Code)
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.ID != child.ID || got.InstanceID != child.InstanceID || got.Target != child.Target || got.ParentTarget != child.ParentTarget ||
				got.Status != child.Status || got.StartedAt != child.StartedAt || got.FinishedAt != child.FinishedAt ||
				got.Completion != child.Completion || got.StopReason != child.StopReason {
				t.Errorf("child detail changed identity or outcome: %s/%s/%s", got.Status, got.Completion, got.StopReason)
			}
			if !reflect.DeepEqual(got.Vulns, child.Vulns) || !reflect.DeepEqual(got.Events, child.Events) || !reflect.DeepEqual(got.UsageBySession, child.UsageBySession) {
				t.Error("child detail returned findings, events, or usage from another session")
			}
			if got.TotalTokens != child.TotalTokens || got.Iterations != child.Iterations || got.ToolCalls != child.ToolCalls ||
				got.AssessmentProgress != child.AssessmentProgress || got.CurrentPhase != child.CurrentPhase ||
				got.PlanTasksTotal != child.PlanTasksTotal || got.PlanTasksCompleted != child.PlanTasksCompleted ||
				got.PlanTasksSkipped != child.PlanTasksSkipped || got.PlanTasksUnfinished != child.PlanTasksUnfinished {
				t.Error("child detail returned coordinator counters or plan")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatal("reading child detail changed its saved record")
			}
		})
	}
}

func TestParentSnapshotAndChildAggregationRemainAvailable(t *testing.T) {
	child, inst := childScopeFixture("finished")
	s := newTestServer(t, nil)
	s.instances[inst.ID] = inst
	parent := ScanRecord{ID: "parent-record", InstanceID: inst.ID, Target: inst.Targets, ScanMode: "wildcard", Status: "running", StartedAt: child.StartedAt}
	writeScanRecord(t, s.dataDir, "parent", parent)
	writeScanRecord(t, s.dataDir, "child", *child)
	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/"+parent.ID, nil))
	var got ScanRecord
	if rr.Code != http.StatusOK {
		t.Fatalf("parent detail status=%d", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TotalTokens != inst.TotalTokens || got.AssessmentProgress != inst.AssessmentProgress || got.CurrentPhase != inst.CurrentPhase || !reflect.DeepEqual(got.Events, inst.events) {
		t.Error("parent lost its live snapshot")
	}
	if len(got.Vulns) != 2 || got.SubScanCompleted != 1 || len(got.SubScans) != 1 || got.SubScans[0].ID != child.ID || got.SubScans[0].TotalTokens != child.TotalTokens {
		t.Fatal("parent lost aggregate findings or independent child usage")
	}
	rows := s.cachedScanList()
	if len(rows) != 1 || rows[0].ID != parent.ID || rows[0].VulnCount != 2 || rows[0].TotalTokens != inst.TotalTokens || rows[0].SubScanCompleted != 1 {
		t.Fatal("parent list aggregation regressed or exposed a child as a top-level scan")
	}
}
