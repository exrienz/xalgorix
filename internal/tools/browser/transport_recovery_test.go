package browser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

type failedBrowserTransport struct{ err error }

func (f failedBrowserTransport) Event() <-chan *cdp.Event { return nil }
func (f failedBrowserTransport) Call(context.Context, string, string, interface{}) ([]byte, error) {
	return nil, f.err
}

func TestDisconnectedBrowserDoesNotLeaveDeadCachedSession(t *testing.T) {
	for _, failure := range []error{io.EOF, net.ErrClosed} {
		t.Run(failure.Error(), func(t *testing.T) {
			ctxID := "transport-" + t.Name()
			store := getBrowserStoreByID(ctxID)
			store.browser = rod.New().Client(failedBrowserTransport{failure})
			store.requiredProxy = true
			store.sessionDir = t.TempDir()
			store.savedSessions["account"] = []*proto.NetworkCookie{{Name: "session", Value: "test", Domain: "example.invalid"}}
			t.Cleanup(func() { CleanupContext(ctxID) })
			var gotErr error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("transport failure escaped as a tool panic: %v", recovered)
					}
				}()
				_, gotErr = browserActionWithContext(ctxID, map[string]string{"command": "launch"})
			}()
			if gotErr == nil {
				t.Error("failed browser action was not returned as an error")
			}
			if store.browser != nil || store.page != nil || len(store.pages) != 0 {
				t.Error("dead browser remains cached and will be reused by the next launch")
			}
			result, err := browserActionWithContext(ctxID, map[string]string{"command": "list_sessions"})
			if err != nil || !strings.Contains(result.Output, "account") || store.sessionDir == "" {
				t.Fatalf("saved authentication session lost: %v / %s", err, result.Output)
			}
		})
	}
}

func TestBrowserRequestFailureDoesNotDiscardUsableSession(t *testing.T) {
	ctxID := "request-failure-control"
	store := getBrowserStoreByID(ctxID)
	store.browser = rod.New().Client(failedBrowserTransport{errors.New("invalid browser request")})
	store.requiredProxy = true
	t.Cleanup(func() { CleanupContext(ctxID) })
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Error("unrelated tool failure must retain its existing failure path")
			}
		}()
		_, _ = browserActionWithContext(ctxID, map[string]string{"command": "launch"})
	}()
	if store.browser == nil {
		t.Fatal("non-transport failure discarded a usable browser session")
	}
}

func TestFirstClassRouteDiscoveryRecoversTransport(t *testing.T) {
	ctxID := t.Name()
	s := getBrowserStoreByID(ctxID)
	s.browser = rod.New().Client(failedBrowserTransport{io.EOF})
	s.requiredProxy = true
	t.Cleanup(func() { CleanupContext(ctxID) })
	_, err := discoverClientRoutesAtURL(ctxID, "https://example.invalid/", "")
	if !errors.Is(err, errBrowserDisconnected) || s.browser != nil {
		t.Fatalf("discovery retained a disconnected browser: %v", err)
	}
}

func TestBrowserTransportClassificationUsesErrorIdentity(t *testing.T) {
	for _, failure := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, syscall.ECONNRESET, syscall.EPIPE, syscall.ECONNABORTED} {
		if !isBrowserTransportError(fmt.Errorf("wrapped: %w", failure)) {
			t.Errorf("wrapped transport error not recognized: %v", failure)
		}
	}
	for _, failure := range []error{nil, context.Canceled, context.DeadlineExceeded,
		errors.New("EOF"), errors.New("use of closed network connection"), errors.New("JavaScript: ECONNRESET")} {
		if isBrowserTransportError(failure) {
			t.Errorf("unrelated error classified as a disconnect: %v", failure)
		}
	}
}

type recordingBrowserTransport struct {
	mu      sync.Mutex
	err     error
	methods []string
}

func (c *recordingBrowserTransport) Event() <-chan *cdp.Event { return nil }
func (c *recordingBrowserTransport) Call(_ context.Context, _, method string, _ interface{}) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods = append(c.methods, method)
	return nil, c.err
}

func TestIgnoredBrowserTransportErrorCannotReportSuccessOrReplay(t *testing.T) {
	ctxID := t.Name()
	s := getBrowserStoreByID(ctxID)
	client := &recordingBrowserTransport{err: &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, Err: net.ErrClosed}}
	s.transport = &browserTransport{CDPClient: client}
	s.browser = rod.New().Client(s.transport)
	s.page = s.browser.PageFromSession("test")
	s.pages["tab_1"] = s.page
	s.currentTab = "tab_1"
	t.Cleanup(func() { CleanupContext(ctxID) })
	result, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
		_, _ = s.browser.Call(context.Background(), "", "Page.navigate", nil)
		return tools.Result{Output: "Navigation succeeded", Metadata: map[string]any{"success": true}}, nil
	})
	if !errors.Is(err, errBrowserDisconnected) || result.Output != "" || len(result.Metadata) != 0 {
		t.Fatalf("ignored disconnect produced a success result: %+v / %v", result, err)
	}
	if strings.Contains(err.Error(), "192.0.2.1") || strings.Contains(err.Error(), "1234") {
		t.Fatal("transport diagnostic exposed a connection address")
	}
	if s.browser != nil || s.transport != nil || s.page != nil || len(s.pages) != 0 || s.currentTab != "" {
		t.Fatal("disconnected browser/tab/transport state retained")
	}
	calls := 0
	for _, method := range client.methods {
		if method == "Page.navigate" {
			calls++
		}
	}
	if calls != 1 {
		t.Fatalf("interrupted action replayed: %d calls", calls)
	}
}

func TestPriorObservedDisconnectDoesNotExecuteNextAction(t *testing.T) {
	ctxID := t.Name()
	s := getBrowserStoreByID(ctxID)
	s.transport = &browserTransport{CDPClient: failedBrowserTransport{net.ErrClosed}}
	s.transport.failed.Store(true)
	s.browser = rod.New().Client(s.transport)
	t.Cleanup(func() { CleanupContext(ctxID) })
	called := false
	_, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
		called = true
		return tools.Result{}, nil
	})
	if called || !errors.Is(err, errBrowserDisconnected) || s.browser != nil {
		t.Fatalf("action ran against a known dead connection: called=%v err=%v", called, err)
	}
}

func TestOrdinaryBrowserErrorsPreserveConnection(t *testing.T) {
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, errors.New("JavaScript: EOF")} {
		t.Run(failure.Error(), func(t *testing.T) {
			ctxID := t.Name()
			s := getBrowserStoreByID(ctxID)
			s.transport = &browserTransport{CDPClient: failedBrowserTransport{failure}}
			original := rod.New().Client(s.transport)
			s.browser = original
			t.Cleanup(func() { CleanupContext(ctxID) })
			_, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
				_, err := s.browser.Call(context.Background(), "", "Runtime.evaluate", nil)
				return tools.Result{}, err
			})
			if !errors.Is(err, failure) || s.browser != original || s.transport.failed.Load() {
				t.Fatalf("ordinary failure discarded the connection: %v", err)
			}
		})
	}
}

func TestConcurrentBrowserActionCannotLoseReplacement(t *testing.T) {
	ctxID := t.Name()
	s := getBrowserStoreByID(ctxID)
	s.browser = rod.New().Client(failedBrowserTransport{io.EOF})
	replacement := rod.New().Client(failedBrowserTransport{errors.New("request failure")})
	t.Cleanup(func() { CleanupContext(ctxID) })
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
			close(entered)
			<-release
			panic(io.EOF)
		})
		firstDone <- err
	}()
	<-entered
	go func() {
		_, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
			s.mu.Lock()
			s.browser = replacement
			s.mu.Unlock()
			return tools.Result{}, nil
		})
		secondDone <- err
	}()
	close(release)
	if err := <-firstDone; !errors.Is(err, errBrowserDisconnected) {
		t.Fatalf("failed action did not recover: %v", err)
	}
	if err := <-secondDone; err != nil || s.browser != replacement {
		t.Fatalf("failed action discarded a concurrent replacement: %v", err)
	}
}

func TestContextCleanupWaitsForActionWithoutBlockingOtherContexts(t *testing.T) {
	ctxID := t.Name()
	t.Cleanup(func() { CleanupContext(ctxID) })
	entered := make(chan struct{})
	release := make(chan struct{})
	actionDone := make(chan struct{})
	cleanupDone := make(chan struct{})
	go func() {
		_, _ = withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
			close(entered)
			<-release
			_ = getBrowserStoreByID(ctxID)
			return tools.Result{}, nil
		})
		close(actionDone)
	}()
	<-entered
	go func() { CleanupContext(ctxID); close(cleanupDone) }()
	otherDone := make(chan error, 1)
	go func() {
		otherID := ctxID + "-other"
		_, err := browserActionWithContext(otherID, map[string]string{"command": "list_sessions"})
		CleanupContext(otherID)
		otherDone <- err
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Errorf("independent action failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cleanup blocked the global store registry")
	}
	close(release)
	select {
	case <-actionDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup deadlocked the ongoing action")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after the ongoing action")
	}
}

type waitingBrowserTransport struct{ started chan struct{} }

func (c waitingBrowserTransport) Event() <-chan *cdp.Event { return nil }
func (c waitingBrowserTransport) Call(ctx context.Context, _, method string, _ interface{}) ([]byte, error) {
	if method == "Browser.close" {
		return nil, net.ErrClosed
	}
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestScanCancellationUnblocksBrowserActionAndCleanup(t *testing.T) {
	ctxID := t.Name()
	sc := scanctx.New(ctxID, t.TempDir())
	scanctx.Activate(sc)
	t.Cleanup(func() { CleanupContext(ctxID); sc.Close(); scanctx.Deactivate(ctxID) })
	s := getBrowserStoreByID(ctxID)
	started := make(chan struct{})
	s.browser = rod.New().Context(browserWaitContext(ctxID)).Client(waitingBrowserTransport{started})
	actionDone := make(chan error, 1)
	cleanupDone := make(chan struct{})
	go func() {
		_, err := withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
			_, err := proto.TargetCreateTarget{URL: "about:blank"}.Call(s.browser)
			return tools.Result{}, err
		})
		actionDone <- err
	}()
	<-started
	sc.Cancel()
	go func() { CleanupContext(ctxID); close(cleanupDone) }()
	select {
	case err := <-actionDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scan cancellation did not release the browser action")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("scan cancellation did not allow browser cleanup")
	}
}
