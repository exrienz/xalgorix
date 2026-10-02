package browser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func discoverClientRoutesAtURL(ctxID, rawURL, proxy string) (tools.Result, error) {
	return withBrowserTransportRecovery(ctxID, func() (tools.Result, error) {
		return discoverClientRoutesAtURLAction(ctxID, rawURL, proxy)
	})
}

func discoverClientRoutesAtURLAction(ctxID, rawURL, proxy string) (tools.Result, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return tools.Result{Error: "discover_client_routes requires an absolute HTTP(S) page URL"}, nil
	}

	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		launched, err := launchBrowser(ctxID, u.String(), proxy)
		if err != nil || launched.Error != "" {
			return launched, err
		}
	} else {
		navigated, err := navigateTo(ctxID, u.String())
		if err != nil || navigated.Error != "" {
			return navigated, err
		}
	}
	discovery, err := discoverClientRoutes(ctxID)
	if err != nil || discovery.Error != "" {
		return discovery, err
	}
	return automaticallyVerifyPrioritizedPathXSS(ctxID, discovery), nil
}

const maxAutomaticPathXSSCandidates = 3

// automaticallyVerifyPrioritizedPathXSS closes the gap between client-route
// discovery and execution proof. When the inspected live assets carry
// AngularJS signals, the first-class discovery tool safely checks a small,
// deterministic set of the highest-priority public dynamic prefixes instead
// of relying on the model to copy the right route into a later tool call.
//
// This remains bounded and low impact: only same-origin routes extracted from
// target-served assets are considered, only GET navigation is used, privileged
// or ambiguous routes are excluded by the generic priority threshold, and the
// loop stops on the first browser-observed execution signal.
func automaticallyVerifyPrioritizedPathXSS(ctxID string, discovery tools.Result) tools.Result {
	angular, _ := discovery.Metadata["angularjs_signals"].(bool)
	routes, _ := discovery.Metadata["routes"].([]discoveredClientRoute)
	candidates := automaticPathXSSCandidates(routes)
	discovery.Metadata["path_xss_auto_checked"] = []string{}
	discovery.Metadata["path_xss_auto_confirmed"] = false
	if !angular || len(candidates) == 0 {
		return discovery
	}

	checked := make([]string, 0, len(candidates))
	var checkSummaries []string
	for _, route := range candidates {
		checked = append(checked, route.CandidateURL)
		verification, err := verifyPathTemplateXSS(ctxID, route.CandidateURL)
		if err != nil {
			checkSummaries = append(checkSummaries, fmt.Sprintf("%s: verifier error: %v", route.CandidateURL, err))
			continue
		}
		if verification.Error != "" {
			checkSummaries = append(checkSummaries, fmt.Sprintf("%s: verifier error: %s", route.CandidateURL, verification.Error))
			continue
		}
		confirmed, _ := verification.Metadata["xss_confirmed"].(bool)
		if confirmed {
			discovery.Metadata["path_xss_auto_checked"] = checked
			discovery.Metadata["path_xss_auto_confirmed"] = true
			discovery.Metadata["path_xss_confirmed_route"] = route.CandidateURL
			discovery.Metadata["path_xss_verification"] = verification.Metadata
			discovery.Output = "AUTOMATED PATH-XSS CONFIRMED on the highest-priority target-served public route. " + verification.Output + "\n\n" + discovery.Output
			return discovery
		}
		checkSummaries = append(checkSummaries, fmt.Sprintf("%s: no execution signal", route.CandidateURL))
	}

	discovery.Metadata["path_xss_auto_checked"] = checked
	discovery.Output = fmt.Sprintf("Automated path-XSS check found no execution signal on %d highest-priority public route(s): %s. This is a bounded negative result, not proof that every client route is safe.\n\n%s", len(checked), strings.Join(checkSummaries, "; "), discovery.Output)
	return discovery
}

func automaticPathXSSCandidates(routes []discoveredClientRoute) []discoveredClientRoute {
	var candidates []discoveredClientRoute
	seen := make(map[string]bool)
	for _, route := range routes {
		if len(candidates) >= maxAutomaticPathXSSCandidates {
			break
		}
		candidate := strings.TrimSpace(route.CandidateURL)
		if candidate == "" || seen[candidate] || clientRouteTestPriority(route.Pattern) > 0 {
			continue
		}
		seen[candidate] = true
		candidates = append(candidates, route)
	}
	return candidates
}

const discoverClientRoutesScript = `() => (async () => {
	const maxScripts = 12;
	const maxScriptBytes = 2500000;
	const maxTotalBytes = 8000000;
	const maxRoutes = 200;
	const origin = window.location.origin;
	const pageURL = window.location.href;
	const routes = new Map();
	let bytesRead = 0;
	let scriptsFetched = 0;
	let scriptsSkipped = 0;
	let truncated = false;
	let angularSignals = /ng-(?:app|controller|cloak)|angular(?:\.min)?\.js|angular\.module/i.test(
		document.documentElement.outerHTML.slice(0, 500000)
	);

	function sourceLabel(raw) {
		try {
			const u = new URL(raw, pageURL);
			return u.pathname;
		} catch (_) {
			return "inline";
		}
	}

	function addRoutes(text, source) {
		if (!text || routes.size >= maxRoutes) return;
		if (/angular\.module|angular-route|ngRoute|ngSanitize/i.test(text)) angularSignals = true;
		const routePattern = /(?:["']?(?:path|route)["']?)\s*[:=]\s*(["'])(\/[^"'\\]{1,240})\1/g;
		let match;
		while ((match = routePattern.exec(text)) !== null && routes.size < maxRoutes) {
			const pattern = match[2].replace(/\\\//g, "/");
			if (!pattern.startsWith("/") || pattern.startsWith("//")) continue;
			const segments = pattern.split("/").filter(Boolean);
			const literal = [];
			let dynamic = false;
			for (const segment of segments) {
				if (segment.startsWith(":") || segment.startsWith("*") || /\{[^}]+\}/.test(segment)) {
					dynamic = true;
					break;
				}
				literal.push(segment);
			}
			if (!dynamic || literal.length === 0) continue;
			const candidatePath = "/" + literal.join("/") + "/";
			if (!routes.has(pattern)) {
				routes.set(pattern, {
					pattern,
					candidate_url: origin + candidatePath,
					source: sourceLabel(source)
				});
			}
		}
	}

	for (const script of Array.from(document.scripts)) {
		if (!script.src && script.textContent) {
			addRoutes(script.textContent.slice(0, 500000), "inline");
		}
	}

	const scriptURLs = [];
	const seen = new Set();
	for (const script of Array.from(document.scripts)) {
		if (!script.src) continue;
		try {
			const u = new URL(script.src, pageURL);
			if (u.origin !== origin || !/^https?:$/.test(u.protocol) || seen.has(u.href)) continue;
			seen.add(u.href);
			scriptURLs.push(u.href);
		} catch (_) {}
	}

	for (const scriptURL of scriptURLs.slice(0, maxScripts)) {
		const remaining = Math.min(maxScriptBytes, maxTotalBytes - bytesRead);
		if (remaining <= 0) {
			truncated = true;
			break;
		}
		try {
			const response = await fetch(scriptURL, {credentials: "include", cache: "no-store"});
			if (!response.ok) {
				scriptsSkipped++;
				continue;
			}
			const declared = Number(response.headers.get("content-length") || "0");
			if (declared > remaining) {
				scriptsSkipped++;
				truncated = true;
				continue;
			}
			let text = "";
			let currentBytes = 0;
			if (response.body && response.body.getReader) {
				const reader = response.body.getReader();
				const decoder = new TextDecoder();
				while (true) {
					const item = await reader.read();
					if (item.done) break;
					if (currentBytes + item.value.byteLength > remaining) {
						const take = Math.max(0, remaining - currentBytes);
						if (take > 0) text += decoder.decode(item.value.slice(0, take), {stream: true});
						currentBytes += take;
						truncated = true;
						await reader.cancel();
						break;
					}
					currentBytes += item.value.byteLength;
					text += decoder.decode(item.value, {stream: true});
				}
				text += decoder.decode();
			} else {
				text = await response.text();
				currentBytes = new TextEncoder().encode(text).byteLength;
				if (currentBytes > remaining) {
					text = text.slice(0, remaining);
					currentBytes = remaining;
					truncated = true;
				}
			}
			bytesRead += currentBytes;
			scriptsFetched++;
			addRoutes(text, scriptURL);
		} catch (_) {
			scriptsSkipped++;
		}
	}

	if (scriptURLs.length > maxScripts) truncated = true;
	return JSON.stringify({
		page_url: pageURL,
		origin,
		angularjs_signals: angularSignals,
		scripts_seen: scriptURLs.length,
		scripts_fetched: scriptsFetched,
		scripts_skipped: scriptsSkipped,
		bytes_read: bytesRead,
		truncated,
		routes: Array.from(routes.values())
	});
})()`

type discoveredClientRoute struct {
	Pattern      string `json:"pattern"`
	CandidateURL string `json:"candidate_url"`
	Source       string `json:"source"`
}

type clientRouteDiscovery struct {
	PageURL          string                  `json:"page_url"`
	Origin           string                  `json:"origin"`
	AngularJSSignals bool                    `json:"angularjs_signals"`
	ScriptsSeen      int                     `json:"scripts_seen"`
	ScriptsFetched   int                     `json:"scripts_fetched"`
	ScriptsSkipped   int                     `json:"scripts_skipped"`
	BytesRead        int                     `json:"bytes_read"`
	Truncated        bool                    `json:"truncated"`
	Routes           []discoveredClientRoute `json:"routes"`
}

// discoverClientRoutes extracts dynamic client route templates from the live
// page and a bounded set of same-origin scripts. It intentionally does not use
// source maps, third-party scripts, product fingerprints, or advisory data: the
// returned candidates are grounded in assets the target served during this
// scan. The action is discovery-only and never injects a payload.
func discoverClientRoutes(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s == nil || s.page == nil {
		return tools.Result{Error: "browser not launched — launch the target page before discovering client routes"}, nil
	}

	result, err := s.page.Timeout(30 * time.Second).Eval(discoverClientRoutesScript)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("client route discovery failed: %v", err)}, nil
	}
	var discovery clientRouteDiscovery
	if err := json.Unmarshal([]byte(result.Value.String()), &discovery); err != nil {
		return tools.Result{Error: fmt.Sprintf("client route discovery returned invalid data: %v", err)}, nil
	}

	sort.Slice(discovery.Routes, func(i, j int) bool {
		left, right := clientRouteTestPriority(discovery.Routes[i].Pattern), clientRouteTestPriority(discovery.Routes[j].Pattern)
		if left != right {
			return left < right
		}
		return discovery.Routes[i].Pattern < discovery.Routes[j].Pattern
	})

	var output strings.Builder
	fmt.Fprintf(&output, "Discovered %d dynamic client route(s) from %d/%d bounded same-origin script(s) (%d bytes).", len(discovery.Routes), discovery.ScriptsFetched, discovery.ScriptsSeen, discovery.BytesRead)
	if discovery.Truncated {
		output.WriteString(" Discovery reached a safety bound; results are partial.")
	}
	if len(discovery.Routes) == 0 {
		output.WriteString(" No path-template candidates were observed in the inspected live assets.")
	} else {
		output.WriteString("\n\nRoute templates and safe candidate prefixes:")
		outputRoutes := discovery.Routes
		if len(outputRoutes) > 80 {
			outputRoutes = outputRoutes[:80]
		}
		for _, route := range outputRoutes {
			fmt.Fprintf(&output, "\n- %s -> %s (source %s)", route.Pattern, route.CandidateURL, route.Source)
		}
		if omitted := len(discovery.Routes) - len(outputRoutes); omitted > 0 {
			fmt.Fprintf(&output, "\n- ... %d lower-priority dynamic route(s) omitted from text output (retained in metadata)", omitted)
		}
		if discovery.AngularJSSignals {
			output.WriteString("\n\nAngularJS signals were observed. Test plausible public dynamic prefixes with browser_action command=verify_path_template_xss; confirmation still requires browser-observed execution.")
		}
	}

	return tools.Result{
		Output: output.String(),
		Metadata: map[string]any{
			"page_url":          discovery.PageURL,
			"origin":            discovery.Origin,
			"angularjs_signals": discovery.AngularJSSignals,
			"scripts_seen":      discovery.ScriptsSeen,
			"scripts_fetched":   discovery.ScriptsFetched,
			"scripts_skipped":   discovery.ScriptsSkipped,
			"bytes_read":        discovery.BytesRead,
			"truncated":         discovery.Truncated,
			"routes":            discovery.Routes,
		},
	}, nil
}

// clientRouteTestPriority orders routes by likely anonymous reachability and
// low side-effect risk. It is intentionally semantic rather than
// product-specific: invitation, sharing, login, preview, and snapshot flows are
// common public entry points, while administrative/configuration paths usually
// require a session. The caller must still establish reachability and execute a
// deterministic verifier before reporting anything.
func clientRouteTestPriority(pattern string) int {
	lower := strings.ToLower(pattern)
	score := strings.Count(lower, "/") + 2*strings.Count(lower, ":")
	for _, public := range []string{"invite", "share", "shared", "login", "signup", "register", "reset", "callback", "preview", "snapshot", "public"} {
		if strings.Contains(lower, public) {
			score -= 8
		}
	}
	for _, privileged := range []string{"admin", "settings", "config", "edit", "delete"} {
		if strings.Contains(lower, privileged) {
			score += 8
		}
	}
	return score
}
