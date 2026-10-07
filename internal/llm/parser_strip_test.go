package llm

import (
	"strings"
	"testing"
)

// Model prose must never carry provider-internal channel delimiters into
// display or history surfaces. Real-world artifact shape observed in event
// logs: an identifier wrapped in "<]"…"[>" glued to flanking brackets.
func TestStripProviderControlTokens(t *testing.T) {
	if got := StripProviderControlTokens("echo]<]minimax[>[Reading /reservation/user1"); got != "echoReading /reservation/user1" {
		t.Fatalf("StripProviderControlTokens = %q", got)
	}
	// Whitespace and case variants must match.
	if got := StripProviderControlTokens("a <] MiniMax [> b"); got != "a  b" {
		t.Fatalf("StripProviderControlTokens spaced = %q", got)
	}
	// The redaction is generic: any identifier inside the delimiters goes.
	if got := StripProviderControlTokens("x<]someprovider[>y"); got != "xy" {
		t.Fatalf("StripProviderControlTokens generic = %q", got)
	}
	// Ordinary prose (including tool-call XML, angle brackets, brackets in
	// sentences) must pass through untouched.
	touched := "clean prose about <function> calls, list[0], a]< b"
	if got := StripProviderControlTokens(touched); got != touched {
		t.Fatalf("StripProviderControlTokens false positive: %q", got)
	}
	if got := StripProviderControlTokens(""); got != "" {
		t.Fatalf("StripProviderControlTokens empty = %q", got)
	}
}

// Display prose (the source of "message" events) must come out clean even
// when the artifact rides along inside a response.
func TestCleanContentStripsProviderControlTokens(t *testing.T) {
	got := CleanContent("Analysis continues.<]minimax[>Now checking /api/v1")
	if strings.Contains(strings.ToLower(got), "minimax") || strings.Contains(got, "<]") {
		t.Fatalf("CleanContent leaked control token: %q", got)
	}
	if !strings.Contains(got, "Analysis continues.") || !strings.Contains(got, "Now checking /api/v1") {
		t.Fatalf("CleanContent dropped surrounding prose: %q", got)
	}
}

// The canonical assistant-turn rebuilder must also strip the artifact so it
// is never fed back into the model's own history.
func TestStripToolResidueStripsProviderControlTokens(t *testing.T) {
	got := StripToolResidue("prose]<]minimax[>[tail <function=x></function>")
	if strings.Contains(strings.ToLower(got), "minimax") || strings.Contains(got, "<]") {
		t.Fatalf("StripToolResidue leaked control token: %q", got)
	}
}
