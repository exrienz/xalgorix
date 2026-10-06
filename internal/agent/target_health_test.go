package agent

import (
	"errors"
	"testing"
)

func TestConfirmTargetUnresponsiveRequiresFreshFailuresOnAllTargets(t *testing.T) {
	called := 0
	down := func(string) (int, error) {
		called++
		return 503, nil
	}
	if !confirmTargetUnresponsive([]string{"example.test", "https://other.test/path"}, down) || called != 6 {
		t.Fatalf("two confirmed failures per target required, calls=%d", called)
	}
	called = 0
	if confirmTargetUnresponsive([]string{"example.test", "https://other.test"}, func(target string) (int, error) {
		called++
		if target == "https://other.test" {
			return 200, nil
		}
		return 503, nil
	}) {
		t.Fatal("a reachable target must keep the scan running")
	}
	if called != 5 {
		t.Fatalf("expected one successful check to veto stop, calls=%d", called)
	}
	if confirmTargetUnresponsive([]string{"*.example.test"}, down) {
		t.Fatal("wildcard target cannot be confirmed by one host probe")
	}
	if confirmTargetUnresponsive([]string{"example.test"}, func(string) (int, error) {
		return 403, nil
	}) {
		t.Fatal("ambiguous edge response must not cancel the scan")
	}
	if confirmTargetUnresponsive([]string{"example.test"}, func(string) (int, error) {
		return 0, errors.New("proxy-required mode is not initialized")
	}) {
		t.Fatal("local proxy errors must not be treated as target outage")
	}
}
