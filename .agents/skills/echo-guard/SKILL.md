---
name: echo-guard
description: Use when wiring guard-core-go security into a Go Echo service, or when working in github.com/rennf93/echo-guard: build the middleware with guardecho.New(engine, opts...) (package echo, alias it to avoid clashing with github.com/labstack/echo/v4), tune WithMaxBodyBytes (default 262144) and WithLogger, attach route identity with WithRouteID on the request context (c.SetRequest), understand requestShim adaptation of echo.Context to guardcore.Request including the bounded body prefix scan, idempotent Body(), and replay so handlers still receive the full stream, exact verdict translation into c.Response() writes with the chain stopped by not calling next(c) (Echo has no Abort call), fail-closed 500 on engine malfunction, and Redis-backed integration tests via REDIS_HOST and go test -tags integration.
---

# echo-guard

Echo middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). Translates `echo.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Echo responses (status, headers, body, then stop the chain). Contains no security logic itself. Module: `github.com/rennf93/echo-guard`, Go `1.25.0`, no release tag yet.

## Quick Reference

| Identifier | Kind | Notes |
| --- | --- | --- |
| `guardecho.New(engine, opts...)` | func | Returns `(echo.MiddlewareFunc, error)`; errors on nil engine |
| `guardecho.WithMaxBodyBytes(n)` | Option | Bounds engine body scan; ignored when `n <= 0`; default 262144 |
| `guardecho.WithLogger(l)` | Option | Fail-closed logger; ignored when nil; default `log.Default()` |
| `guardecho.WithRouteID(ctx, id)` | func | Returns a context carrying the route ID for `engine.Routes` lookups |
| `guardecho.DefaultMaxBodyBytes` | const | `262144` bytes (256 KiB) |

Behavior contract: the engine sees at most `MaxBodyBytes` of the body prefix; payloads beyond the bound are not scanned; the handler still receives the full body via replay. A verdict short-circuits the handler (the middleware writes it and returns nil without calling `next(c)`). An engine error or panic produces a 500 via `engine.CreateErrorResponse(500, "Security check failed")`. On a clean pass the adapter adds no headers and returns `next(c)`.

## Installation

```sh
go get github.com/rennf93/echo-guard@main github.com/rennf93/guard-core-go/v4@v4.0.4
```

The package name is `echo`, which collides with `github.com/labstack/echo/v4`, so import the adapter with an alias:

```go
import (
    echolib "github.com/labstack/echo/v4"
    guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
    guardecho "github.com/rennf93/echo-guard"
)
```

## Setup

```go
cfg := guardcore.DefaultSecurityConfig()
engine, err := guardcore.NewEngine(cfg)
if err != nil { log.Fatal(err) }
if err := engine.Initialize(); err != nil { log.Fatal(err) }

guard, err := guardecho.New(engine) // or guardecho.New(engine, guardecho.WithMaxBodyBytes(65536))
if err != nil { log.Fatal(err) }

router := echolib.New()
router.Use(guard)
router.GET("/", func(c echolib.Context) error { return c.String(200, "ok") })
log.Fatal(router.Start(":8080"))
```

`Initialize` is required by the core. Redis connectivity is a guard-core-go concern; this adapter never talks to Redis directly.

## guardecho.New

```go
func New(engine *guardcore.Engine, opts ...Option) (echo.MiddlewareFunc, error)
```

- Rejects a nil engine with `errors.New("engine must not be nil")`.
- Returns an `echo.MiddlewareFunc`, so it composes with `router.Use` and route groups anywhere in the Echo chain.
- The middleware builds a `requestShim` from `c.Request()`, calls `engine.Check`, then either applies the verdict and returns nil (stopping the chain) or returns `next(c)`.
- Engine calls are wrapped in a recover: a panic from `engine.Check` (for example inside a user `CustomRequestCheck`) becomes an error and takes the fail-closed path.

## Options: WithMaxBodyBytes and WithLogger

```go
func WithMaxBodyBytes(maxBodyBytes int64) Option
func WithLogger(logger *log.Logger) Option
```

- `WithMaxBodyBytes` sets the byte bound scanned by the engine. Non-positive values are ignored and the default `DefaultMaxBodyBytes` (262144) applies. The bound also caps `ReadBodyPrefix`.
- `WithLogger` replaces the logger used on engine malfunction. Nil is ignored; the default is `log.Default()`. The message logged is `guardcore echo: engine malfunction, failing closed: <err>`.
- Invalid option values never cause an error from `New`; they are silently ignored.

## WithRouteID and Route Matching

```go
func WithRouteID(ctx context.Context, routeID string) context.Context
```

- Stores the route ID under a private context key. `requestShim` copies it to `guardcore.RequestState.GuardRouteID`.
- Route policy itself lives in the core: register with `engine.Routes.Register("name", func(rc *guardcore.RouteConfig) { rc.BypassedChecks = []string{"all"} })`.
- In Echo the guard runs as middleware, so attach the ID in a middleware registered before it: `c.SetRequest(c.Request().WithContext(guardecho.WithRouteID(c.Request().Context(), "name")))`. Without a route ID in context the request is evaluated under default policy.

## Request Adaptation: requestShim and Body Replay

`requestShim` implements `guardcore.Request` over `c.Request()` and is the whole adaptation surface.

- `URLPath`, `URLScheme` (https when `req.TLS != nil`), `URLFull`, `URLReplaceScheme`, `Method` (uppercased, defaults to GET), `ClientHost` (via `net.SplitHostPort` on `RemoteAddr`, not Echo's `c.RealIP()`).
- `Headers`: first value per header name only, plus an explicit `Host` from `req.Host`.
- `QueryParams`: first parsed value per key.
- `Body()` returns the cached prefix (bounded by `MaxBodyBytes`) and is idempotent.
- `ReadBodyPrefix(maxBytes)` extends the cache contiguously up to the bound; negative values clamp to 0, values above the bound clamp to `MaxBodyBytes`.
- `newRequestShim` replaces `c.Request().Body` with a `replayBody`. Reads first return bytes the engine consumed from the cache, then stream the untouched remainder from the source. `Close` closes the original body.

## Footguns

- Package name collision: `github.com/rennf93/echo-guard` and `github.com/labstack/echo/v4` are both package `echo`; always alias the adapter (for example `guardecho`).
- The engine only scans the first `MaxBodyBytes` bytes. A malicious marker beyond the bound is not detected and the request passes; verify bounds when a route accepts large payloads.
- `WithMaxBodyBytes(-1)` and `WithLogger(nil)` are silently ignored, not errors. Guard against typos that drop real configuration.
- Client identity comes from `RemoteAddr`, never `c.RealIP()`. Do not "fix" this in the adapter; proxy trust is core configuration territory.
- Aborting is not calling `next(c)`. Echo has no `Abort()` on the context; write the verdict to `c.Response()` and return nil, never return the verdict as an error (the Echo error handler would replace the body).
- Integration tests SKIP when `REDIS_HOST` is unset. `go test -tags integration ./...` can look green while Redis-backed coverage never ran.
- A panic inside a core custom check is converted to a 500. That is intentional fail-closed behavior, not a crash.
- Verdict headers, status, and body come from the core verbatim. Do not add or rewrite response headers in this adapter.
- Do not push to `main` (protected) and do not push `v*` tags; a tag push triggers the Release Gate workflow.

## Related Projects

- [guard-core-go](https://github.com/rennf93/guard-core-go): the engine this adapter wraps. All detection, rate limiting, bans, configuration, and Redis integration live there; import it as `guardcore "github.com/rennf93/guard-core-go/v4/guardcore"`.
- [nethttp-guard](https://github.com/rennf93/nethttp-guard): the sibling net/http adapter with the same surface and behavior contract.
- [gin-guard](https://github.com/rennf93/gin-guard): the sibling Gin adapter with the same surface and behavior contract.
