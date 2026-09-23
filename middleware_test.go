package echo

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	echolib "github.com/labstack/echo/v4"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const xssVector = "q=<script>alert(1)</script>"

func init() {
	echolib.New().Logger.SetOutput(io.Discard)
}

type probe struct {
	called   bool
	headers  http.Header
	body     []byte
	method   string
	path     string
	rawQuery string
}

func newTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = false
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

func newTestMiddleware(t *testing.T, mutate func(*guardcore.SecurityConfig), opts ...Option) (echolib.MiddlewareFunc, *guardcore.Engine) {
	t.Helper()
	engine := newTestEngine(t, mutate)
	guard, err := New(engine, opts...)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	return guard, engine
}

func serve(t *testing.T, guard echolib.MiddlewareFunc, r *http.Request) (*httptest.ResponseRecorder, *probe) {
	t.Helper()
	p := &probe{}
	router := echolib.New()
	router.Use(guard)
	router.Any("/*", func(c echolib.Context) error {
		p.called = true
		p.headers = c.Response().Header().Clone()
		p.body, _ = io.ReadAll(c.Request().Body)
		p.method = c.Request().Method
		p.path = c.Request().URL.Path
		p.rawQuery = c.Request().URL.RawQuery
		return nil
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec, p
}

func newShimContext(r *http.Request) echolib.Context {
	return echolib.New().NewContext(r, httptest.NewRecorder())
}

func TestMiddlewareNilEngineRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil engine must be rejected")
	}
}

func TestMiddlewareAllowsRequestUnmutated(t *testing.T) {
	guard, _ := newTestMiddleware(t, nil)
	r := httptest.NewRequest("GET", "/api/users?v=1", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("clean request must reach the handler, got %d called=%v", rec.Code, p.called)
	}
	if p.method != "GET" || p.path != "/api/users" || p.rawQuery != "v=1" {
		t.Fatalf("handler must see the original request, got %s %s?%s", p.method, p.path, p.rawQuery)
	}
	if len(p.headers) != 0 {
		t.Fatalf("adapter must not add headers on pass, got %v", p.headers)
	}
}

func TestMiddlewareBlocksBannedIPExactly(t *testing.T) {
	guard, engine := newTestMiddleware(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, guard, r)
	if rec.Code != 403 {
		t.Fatalf("banned IP must be 403, got %d", rec.Code)
	}
	if rec.Body.String() != guardcore.IPBanBlockedMessage {
		t.Fatalf("body must be the error factory body %q, got %q", guardcore.IPBanBlockedMessage, rec.Body.String())
	}
	if p.called {
		t.Fatal("blocked request must not reach the handler")
	}
	if len(rec.Header()) != 0 {
		t.Fatalf("verdict headers were empty, adapter must translate exactly, got %v", rec.Header())
	}
}

func TestMiddlewareCustomErrorMessage(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[403] = "denied by policy"
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	rec, _ := serve(t, guard, r)
	if rec.Code != 403 || rec.Body.String() != "denied by policy" {
		t.Fatalf("custom message must be translated verbatim, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareTranslatesRedirectVerdictHeaders(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnforceHTTPS = true
	})
	r := httptest.NewRequest("GET", "http://example.com/api", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 301 || p.called {
		t.Fatalf("http request must redirect with 301, got %d called=%v", rec.Code, p.called)
	}
	if location := rec.Header().Get("Location"); location != "https://example.com/api" {
		t.Fatalf("Location header must come from the verdict, got %q", location)
	}
}

func TestMiddlewarePOSTBodyScannedAndReplayed(t *testing.T) {
	var firstRead, secondRead []byte
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			firstRead, _ = req.Body()
			secondRead, _ = req.Body()
			if bytes.Contains(firstRead, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	})
	benign := httptest.NewRequest("POST", "/submit", strings.NewReader("hello world"))
	rec, p := serve(t, guard, benign)
	if rec.Code != 200 || !p.called || string(p.body) != "hello world" {
		t.Fatalf("benign body must pass and be replayed to the handler, got %d handler-body=%q", rec.Code, p.body)
	}
	if !bytes.Equal(firstRead, secondRead) {
		t.Fatalf("Body() must be idempotent, got %q then %q", firstRead, secondRead)
	}
	evilm := httptest.NewRequest("POST", "/submit", strings.NewReader("evil payload"))
	rec, p = serve(t, guard, evilm)
	if rec.Code != 403 || rec.Body.String() != "malicious body" || p.called {
		t.Fatalf("body content must block, got %d %q called=%v", rec.Code, rec.Body.String(), p.called)
	}
}

func TestMiddlewareBoundedBodyOnlyScansPrefix(t *testing.T) {
	var seenLen int
	var seen []byte
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			seen, _ = req.Body()
			seenLen = len(seen)
			if bytes.Contains(seen, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	}, WithMaxBodyBytes(16))
	payload := strings.Repeat("x", 20) + "evil" + strings.Repeat("y", 40)
	oversize := httptest.NewRequest("POST", "/submit", strings.NewReader(payload))
	rec, p := serve(t, guard, oversize)
	if rec.Code != 200 || !p.called {
		t.Fatalf("marker beyond the bounded prefix must pass, got %d called=%v", rec.Code, p.called)
	}
	if seenLen != 16 {
		t.Fatalf("engine must only see the bounded prefix, got %d bytes", seenLen)
	}
	if string(p.body) != payload {
		t.Fatal("handler must still receive the full body")
	}
	inline := httptest.NewRequest("POST", "/submit", strings.NewReader("evil"+strings.Repeat("x", 60)))
	rec, p = serve(t, guard, inline)
	if rec.Code != 403 || p.called {
		t.Fatalf("marker inside the prefix must block, got %d called=%v", rec.Code, p.called)
	}
}

func TestRequestShimBoundedPrefixAndReplay(t *testing.T) {
	body := strings.Repeat("A", 12) + "TAIL"
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	shim := newRequestShim(newShimContext(r), 8)
	prefix, err := shim.ReadBodyPrefix(4)
	if err != nil || string(prefix) != "AAAA" {
		t.Fatalf("prefix read must return 4 bytes, got %q err=%v", prefix, err)
	}
	if extended, _ := shim.ReadBodyPrefix(8); string(extended) != strings.Repeat("A", 8) {
		t.Fatalf("prefix must extend contiguously, got %q", extended)
	}
	cached, err := shim.Body()
	if err != nil || len(cached) != 8 {
		t.Fatalf("Body() must be bounded by MaxBodyBytes, got %d bytes err=%v", len(cached), err)
	}
	replayed, err := io.ReadAll(r.Body)
	if err != nil || string(replayed) != body {
		t.Fatalf("replay must restore the full body, got %d bytes err=%v", len(replayed), err)
	}
}

func TestRequestShimWithoutEngineReadStreamsUntouched(t *testing.T) {
	body := "stream-me"
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	newRequestShim(newShimContext(r), 64)
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != body {
		t.Fatalf("un-read body must stream through untouched, got %q err=%v", got, err)
	}
}

func TestRequestShimEchoContextConversion(t *testing.T) {
	r := httptest.NewRequest("post", "/api/items?tag=first&tag=second&page=2", strings.NewReader("payload"))
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.4")
	r.Host = "example.com:8080"
	r.RemoteAddr = "192.0.2.44:51234"
	shim := newRequestShim(newShimContext(r), DefaultMaxBodyBytes)
	if shim.URLPath() != "/api/items" {
		t.Fatalf("path conversion mismatch, got %q", shim.URLPath())
	}
	if shim.URLScheme() != "http" {
		t.Fatalf("scheme conversion mismatch, got %q", shim.URLScheme())
	}
	if full := shim.URLFull(); full != "http://example.com:8080/api/items?tag=first&tag=second&page=2" {
		t.Fatalf("full URL conversion mismatch, got %q", full)
	}
	if replaced := shim.URLReplaceScheme("https"); replaced != "https://example.com:8080/api/items?tag=first&tag=second&page=2" {
		t.Fatalf("scheme replacement mismatch, got %q", replaced)
	}
	if shim.Method() != "POST" {
		t.Fatalf("method must be uppercased, got %q", shim.Method())
	}
	if host := shim.ClientHost(); host != "192.0.2.44" {
		t.Fatalf("client host must come from RemoteAddr, got %q", host)
	}
	headers := shim.Headers()
	if value, ok := headers.Get("X-Forwarded-For"); !ok || value != "203.0.113.9" {
		t.Fatalf("only the first header value must be adapted, got %q ok=%v", value, ok)
	}
	if host, ok := headers.Get("Host"); !ok || host != "example.com:8080" {
		t.Fatalf("Host header must be adapted from the request, got %q ok=%v", host, ok)
	}
	params := shim.QueryParams()
	if params["tag"] != "first" || params["page"] != "2" || len(params) != 2 {
		t.Fatalf("query params must take the first value per key, got %v", params)
	}
	if shim.State().GuardRouteID != "" {
		t.Fatalf("route id must stay empty without the context key, got %q", shim.State().GuardRouteID)
	}
	routed := r.WithContext(WithRouteID(r.Context(), "open"))
	if id := newRequestShim(newShimContext(routed), DefaultMaxBodyBytes).State().GuardRouteID; id != "open" {
		t.Fatalf("route id must be copied from the context, got %q", id)
	}
	portless := httptest.NewRequest("GET", "/api", nil)
	portless.RemoteAddr = "203.0.113.9"
	if host := newRequestShim(newShimContext(portless), DefaultMaxBodyBytes).ClientHost(); host != "203.0.113.9" {
		t.Fatalf("RemoteAddr without a port must pass through, got %q", host)
	}
}

func TestMiddlewareRouteBypassAll(t *testing.T) {
	guard, engine := newTestMiddleware(t, nil)
	engine.Routes.Register("open", func(rc *guardcore.RouteConfig) {
		rc.BypassedChecks = []string{"all"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	r = r.WithContext(WithRouteID(r.Context(), "open"))
	rec, p := serve(t, guard, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("bypass-all route must reach the handler even for banned IPs, got %d called=%v", rec.Code, p.called)
	}
	plain := httptest.NewRequest("GET", "/api", nil)
	plain.RemoteAddr = "203.0.113.7:4711"
	rec, p = serve(t, guard, plain)
	if rec.Code != 403 || p.called {
		t.Fatalf("without the route id the ban must hold, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewareExclusionScoping(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.ExcludePaths = []string{"/public"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := httptest.NewRequest("GET", "/public/data", nil)
	banned.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, guard, banned)
	if rec.Code != 403 || p.called {
		t.Fatalf("ip ban stays enforced on excluded paths, got %d called=%v", rec.Code, p.called)
	}
	excluded := httptest.NewRequest("GET", "/public?"+xssVector, nil)
	rec, p = serve(t, guard, excluded)
	if rec.Code != 200 || !p.called {
		t.Fatalf("suspicious detection must be skipped in exclusion scope, got %d called=%v", rec.Code, p.called)
	}
	scoped := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, guard, scoped)
	if rec.Code != 400 || p.called {
		t.Fatalf("same vector outside exclusions must be blocked, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewarePassiveModePassesThrough(t *testing.T) {
	var hookPayloads []map[string]any
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.PassiveMode = true
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			hookPayloads = append(hookPayloads, payload)
		}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := httptest.NewRequest("GET", "/api", nil)
	banned.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, guard, banned)
	if rec.Code != 200 || !p.called {
		t.Fatalf("passive mode must pass through even for banned IPs, got %d called=%v", rec.Code, p.called)
	}
	vector := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, guard, vector)
	if rec.Code != 200 || !p.called {
		t.Fatalf("passive mode must pass through detection, got %d called=%v", rec.Code, p.called)
	}
	if len(hookPayloads) != 1 || hookPayloads[0]["passive_mode"] != true || hookPayloads[0]["check_name"] != "suspicious_activity" {
		t.Fatalf("passive block hook must fire once with passive payload, got %v", hookPayloads)
	}
}

func TestMiddlewareWhitelistHonored(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.Whitelist = []string{"203.0.113.7"}
	})
	allowed := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	allowed.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, guard, allowed)
	if rec.Code != 200 || !p.called {
		t.Fatalf("whitelisted IP must pass, got %d called=%v", rec.Code, p.called)
	}
	other := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, guard, other)
	if rec.Code != 403 || p.called {
		t.Fatalf("non-whitelisted IP must be denied by ip security, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewareCustomCheckPanicFailsClosed(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 500 || p.called {
		t.Fatalf("fail-secure must translate to 500 without reaching the handler, got %d called=%v", rec.Code, p.called)
	}
	if rec.Body.String() != "Security check failed" {
		t.Fatalf("fail-secure body mismatch, got %q", rec.Body.String())
	}
}

func TestMiddlewareFailClosedHonorsCustomMessage(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[500] = "upstream refused"
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 500 || rec.Body.String() != "upstream refused" || p.called {
		t.Fatalf("fail-closed must honor the custom 500 message, got %d %q called=%v", rec.Code, rec.Body.String(), p.called)
	}
}

func TestMiddlewareWithLoggerReceivesFailClosed(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	m := &middleware{engine: &guardcore.Engine{}, maxBytes: DefaultMaxBodyBytes, logger: logger}
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, m.wrap, r)
	if rec.Code != 500 || p.called {
		t.Fatalf("malfunctioning engine must fail closed, got %d called=%v", rec.Code, p.called)
	}
	if rec.Body.String() != failClosedMessage {
		t.Fatalf("fail-closed body mismatch, got %q", rec.Body.String())
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") || !strings.Contains(buf.String(), "engine panic:") {
		t.Fatalf("custom logger must receive the malfunction detail, got %q", buf.String())
	}
}

func TestMiddlewareInvalidOptionsIgnored(t *testing.T) {
	engine := newTestEngine(t, nil)
	guard, err := New(engine, WithMaxBodyBytes(-1), WithLogger(nil))
	if err != nil {
		t.Fatalf("invalid option values must be ignored, got %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("middleware with defaults must pass clean traffic, got %d called=%v", rec.Code, p.called)
	}
}
