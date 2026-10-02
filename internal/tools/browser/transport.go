package browser

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/go-rod/rod"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

var errBrowserDisconnected = errors.New("browser connection closed; launch a new browser and load a saved session if needed. The interrupted action was not retried; check whether it took effect before repeating it")

// browserTransport observes connection failures even when a helper intentionally
// ignores a navigation or page-info error. Target JavaScript text is not used.
type browserTransport struct {
	rod.CDPClient
	failed atomic.Bool
}

func (c *browserTransport) Call(ctx context.Context, sessionID, method string, params interface{}) ([]byte, error) {
	response, err := c.CDPClient.Call(ctx, sessionID, method, params)
	if isBrowserTransportError(err) {
		c.failed.Store(true)
	}
	return response, err
}

func isBrowserTransportError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED)
}

// Serialize actions and cleanup for each context. Recheck membership after
// locking so a caller queued behind context cleanup cannot mutate the old store.
func lockBrowserAction(ctxID string) *browserStore {
	for {
		s := getBrowserStoreByID(ctxID)
		s.actionMu.Lock()
		browserStoresMu.RLock()
		current := browserStores[ctxID] == s
		browserStoresMu.RUnlock()
		if current {
			return s
		}
		s.actionMu.Unlock()
	}
}

func withBrowserTransportRecovery(ctxID string, action func() (tools.Result, error)) (result tools.Result, err error) {
	s := lockBrowserAction(ctxID)
	defer s.actionMu.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(error)
			if !ok || !isBrowserTransportError(failure) {
				panic(recovered)
			}
			err = failure
		}
		if isBrowserTransportError(err) || (s.transport != nil && s.transport.failed.Load()) {
			s.mu.Lock()
			resetBrowserConnectionLocked(ctxID, s)
			s.mu.Unlock()
			log.Print("[browser] Disconnected browser released; saved sessions retained; interrupted action not replayed")
			result = tools.Result{}
			err = errBrowserDisconnected
		}
	}()
	if s.transport != nil && s.transport.failed.Load() {
		return tools.Result{}, errBrowserDisconnected
	}
	return action()
}
