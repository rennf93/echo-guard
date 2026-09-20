# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

echo-guard is an Echo middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). It translates `echo.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Echo responses. It contains NO security logic of its own.

- Module: `github.com/rennf93/echo-guard`, Go directive `go 1.25.0`, MIT license.
- Single Go package `echo` at the repo root. Source files: `middleware.go`, `request.go`. Tests: `middleware_test.go`, `integration_test.go`. There are no subpackage directories.
- Release state: no tags exist yet. The repo ships untagged; depend on it via a commit reference until the first tag is cut. State this honestly; there is no changelog beyond git history.
- The public surface is small and deliberate: `New`, `Option`, `WithMaxBodyBytes`, `WithLogger`, `WithRouteID`, and the `DefaultMaxBodyBytes` constant (262144).

## Ecosystem Position

This repo is the ADAPTER layer of the guard-core ecosystem:

- `guard-core-go` is the engine. All detection (suspicious activity, IP bans, rate limits, HTTPS enforcement), verdict construction, and error response factories live there.
- This repo wires Go Echo types to that engine and nothing more. It consumes `github.com/rennf93/guard-core-go v0.1.0` as a normal module dependency (see `go.mod`); no `replace` directive is used or needed. For cross-repo work on the core, add a temporary local `replace` in your own checkout and drop it before committing.
- Because the middleware is an `echo.MiddlewareFunc`, it composes with `e.Use` and runs anywhere in an Echo handler chain. Echo has no explicit abort call: a verdict is written to `c.Response()` and the chain stops because the middleware returns nil without calling `next(c)`.
- Direct dependencies: `github.com/labstack/echo/v4 v4.15.4` (the framework this adapter exists for; a framework import is allowed here, unlike in the core) and `github.com/rennf93/guard-core-go v0.1.0`. Notable indirect floors: the core's transitives (`redis/go-redis/v9 v9.7.3`, `dlclark/regexp2 v1.12.0`, `golang.org/x/text v0.39.0`) plus echo's own (`golang.org/x/crypto v0.53.0`, `golang.org/x/net v0.56.0`). govulncheck reports zero vulnerabilities reachable from this module's code; the module-level findings in `x/crypto/ssh` and `x/crypto/openpgp` are never called here, so no floor bump was needed (unlike gin-guard's quic-go bump for GO-2026-5676).

## Boundary Rules

- This adapter MUST NOT implement detection rules, rate limiting, ban storage, IP parsing heuristics, or any verdict logic. Every verdict comes from `engine.Check(req)` in `middleware.go`.
- This adapter MUST NOT reimplement client-IP trust policy. Client identity comes from `c.Request().RemoteAddr` via `net.SplitHostPort` in `ClientHost`. Echo's `c.RealIP()` is intentionally not used: trusting proxy headers is policy, and the adapter passes `RemoteAddr` to the core exactly like the net/http sibling adapter does.
- Verdict translation MUST be exact. `applyResponse` in `middleware.go` sets each verdict header with `c.Response().Header().Set`, writes the verdict status code, and writes the body verbatim. Aborting is Echo's middleware contract: the middleware returns nil without calling `next(c)`, so no later handler runs. On a clean pass the adapter adds no headers, mutates nothing except the replay body wrapper, and returns `next(c)`.
- The adapter MUST fail closed. If `engine.Check` returns an error or panics, the middleware logs via its logger and responds with `engine.CreateErrorResponse(500, "Security check failed")`. The handler is not called. A custom 500 body comes from `cfg.CustomErrorResponses[500]`, not from adapter code.
- The adapter MUST bound what the engine reads from the body. `request.go` caches at most `maxBytes` (default `DefaultMaxBodyBytes` = 262144) via `fillCacheLocked`. `Body()` and `ReadBodyPrefix` never return more than that prefix. Payload bytes beyond the bound are not scanned, and the full body still reaches the handler untouched through the `replayBody` wrapper installed on `c.Request().Body`.
- Route identity comes only from the request context. `WithRouteID(ctx, id)` sets a private context key; `newRequestShim` copies it into `guardcore.RequestState.GuardRouteID`. In Echo, attach it by replacing the request with `c.SetRequest(c.Request().WithContext(...))` in a middleware registered before the guard. Route configuration itself (`engine.Routes.Register`, bypassed checks) lives in the core, not here.
- Header normalization (first value wins, explicit `Host` header, uppercased method defaulting to GET when empty) is adaptation, not policy.

## Quick Start

```sh
git clone https://github.com/rennf93/echo-guard
cd echo-guard
go build ./...
go test ./...
```

Redis is only needed for integration tests. To run the full suite including them:

```sh
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

Minimal usage (from README.md):

```go
import (
    echolib "github.com/labstack/echo/v4"
    guardcore "github.com/rennf93/guard-core-go/guardcore"
    guardecho "github.com/rennf93/echo-guard"
)

cfg := guardcore.DefaultSecurityConfig()
engine, err := guardcore.NewEngine(cfg)
if err != nil { log.Fatal(err) }
if err := engine.Initialize(); err != nil { log.Fatal(err) }

guard, err := guardecho.New(engine)
if err != nil { log.Fatal(err) }

router := echolib.New()
router.Use(guard)
router.GET("/api", func(c echolib.Context) error { return c.String(200, "ok") })
log.Fatal(router.Start(":8080"))
```

Note the import alias: the module path ends in `echo-guard` but the package name is `echo`, which collides with `github.com/labstack/echo/v4` (also package `echo`), so an explicit alias such as `guardecho "github.com/rennf93/echo-guard"` is the idiomatic import.

## Development Commands

There is no Makefile. Every command below comes from the CI workflows or the README.

| Command | Purpose | Verified in |
| --- | --- | --- |
| `go build ./...` | Compile the single root package | standard go command for this layout |
| `gofmt -l .` | List unformatted files; CI fails if any are listed | `.github/workflows/ci.yml` step "gofmt check" |
| `gofmt -w .` | Rewrite files that gofmt would list | standard gofmt fix for the check above |
| `go vet ./...` | Static analysis | `.github/workflows/ci.yml`, `scheduled-lint.yml` |
| `go test ./...` | Unit tests (no Redis needed; `middleware_test.go` disables Redis) | `.github/workflows/ci.yml` step "go test (unit)" |
| `REDIS_HOST=127.0.0.1 go test -tags integration ./...` | Unit plus Redis-backed integration tests | `.github/workflows/ci.yml` step "go test (integration, redis)", README.md |
| `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...` | Vulnerability scan | `.github/workflows/ci.yml` and `scheduled-lint.yml` |

CI runs the test job on a Go matrix of `1.25.x` and `1.26.x` (fail-fast disabled) with `GOTOOLCHAIN: auto`, plus a separate `govulncheck` job on stable Go. The integration step runs against a `redis:7-alpine` service container on port 6379 with `REDIS_HOST=127.0.0.1`.

## Project Structure

```
.
├── middleware.go        # New, Option, WithMaxBodyBytes, WithLogger, verdict application, fail-closed path
├── request.go           # requestShim (implements guardcore.Request), WithRouteID, DefaultMaxBodyBytes, replayBody
├── middleware_test.go   # unit tests, real echo.Echo, Redis disabled
├── integration_test.go  # //go:build integration, Redis-backed, skips when REDIS_HOST is unset
├── go.mod / go.sum      # module github.com/rennf93/echo-guard, requires echo v4.15.4 and guard-core-go v0.1.0
├── README.md            # usage, options, integration test instructions
├── LICENSE              # MIT
└── .github/
    ├── workflows/ci.yml           # push/PR: gofmt, vet, unit, integration, govulncheck
    ├── workflows/release.yml      # tag push gate: same tests, plus module tag consumable check
    ├── workflows/scheduled-lint.yml  # weekly cron vet + govulncheck
    ├── workflows/code-ql.yml      # CodeQL go analysis on push/PR/weekly
    └── dependabot.yml             # weekly gomod and github-actions updates
```

## Technology Stack

- Go, directive `go 1.25.0`; CI matrix tests 1.25.x and 1.26.x.
- `github.com/rennf93/guard-core-go v0.1.0` (direct require in `go.mod`), providing `guardcore.Engine`, `guardcore.Request`, `guardcore.Response`, `guardcore.SecurityConfig`.
- `github.com/labstack/echo/v4 v4.15.4` (direct require in `go.mod`), providing `echo.MiddlewareFunc` and `echo.Context` for the bridging surface.
- Redis 7 for integration tests (CI service container `redis:7-alpine`); runtime Redis usage is a guard-core-go concern, not this adapter's.
- GitHub Actions: CI on push and pull_request, Release Gate on `v*` tag push, weekly Scheduled Lint, CodeQL (go), Dependabot for gomod and actions, all with minimal permissions and pinned action SHAs.

## Testing Guidelines

- Unit tests live in `middleware_test.go` and run with plain `go test ./...`. The helper `newTestEngine` builds a config with `EnableRedis = false` so no Redis is required.
- Tests drive a real `echo.Echo` (see the `serve` helper): the guard is registered with `router.Use`, a wildcard `router.Any("/*")` probe route records whether it was reached, the response headers it saw, and the method, path, query, and body it received. `newShimContext` builds a bare `echolib.Context` via `e.NewContext(r, httptest.NewRecorder())` for direct `requestShim` tests.
- Integration tests in `integration_test.go` carry the `//go:build integration` build tag. They skip (not fail) when `REDIS_HOST` is unset. They use `cfg.RedisURL = "redis://" + host + ":6379"`, `cfg.RedisPrefix = "guard_core_echo_test:"`, `cfg.RedisFailOpen = false`, and clean up the `banned_ips:*` and `rate_limit:rate:*` key patterns in `t.Cleanup` before closing the engine.
- Invariants the tests enforce; keep them true when changing code:
  - A blocked request must never reach the handler; a clean pass must reach it with the original method, path, and query, and no adapter-added headers.
  - Verdicts translate exactly: status, body (including `guardcore.IPBanBlockedMessage` and custom messages), and headers such as the 301 `Location` come from the verdict.
  - `Body()` is idempotent for the engine, the bounded prefix is the only part scanned, and the handler still receives the full body via replay.
  - Engine malfunction and panics inside `CustomRequestCheck` fail closed with a 500 and the fail-closed message.
- `TestRequestShimEchoContextConversion` pins the bridging contract itself: path, scheme, full URL, scheme replacement, uppercased method, `RemoteAddr` host extraction, first-value header normalization with explicit `Host`, first-value query params, and `WithRouteID` context propagation.
- Match the existing style: table-free plain tests, `t.Helper()` helpers, `t.Fatalf` with got/want context.

## Code Quality Standards

- `gofmt -l .` must produce no output and `go vet ./...` must pass; CI rejects otherwise.
- `govulncheck ./...` must report zero vulnerabilities reachable from this module's code (CI job plus weekly scheduled run). If a bump of an echo transitive is needed, record it as an explicit indirect floor in `go.mod` with the GO id in the commit message.
- Commits use conventional commits with scopes seen in ecosystem history: `feat(echo):`, `test(echo):`, `fix(deps):`, `ci:`, `chore:`, `docs:`.
- Keep the public API frozen unless a change is deliberate: two files, one package, six exported identifiers. Prefer table-free helper-based tests like the existing ones.
- Error handling convention: construction returns errors (`New` rejects a nil engine); request-time failures fail closed, never panic upward.

## Best Practices

- Never push to `main` and never push tags from routine work. A `v*` tag push triggers the Release Gate workflow, which re-runs the full matrix and verifies the module tag resolves from a clean consumer module.
- Work on a branch, open a PR against `main`, and keep the diff scoped. Do not merge your own PR without review.
- Do not add a `replace` directive for guard-core-go in a commit; it is consumed as a normal module dependency.
- Do not commit generated files, `.DS_Store`, or stray artifacts. Stage explicit paths only.
- When touching `request.go`, preserve the mutex-guarded cache and replay invariants: prefix reads extend contiguously, `Body()` returns the bounded cache, replay restores bytes the engine consumed and streams the rest untouched.
- When touching `middleware.go`, preserve exact verdict translation, the return-nil-without-`next(c)` abort behavior after a verdict is written, and the fail-closed 500 path.
- Do not vendor dependencies; `.gitignore` excludes `vendor/`.

## Related Projects

- [guard-core-go](https://github.com/rennf93/guard-core-go): the engine this adapter wraps. All security logic, configuration, verdicts, and Redis integration live there. Import it as `guardcore "github.com/rennf93/guard-core-go/guardcore"`.
- [nethttp-guard](https://github.com/rennf93/nethttp-guard): the sibling net/http adapter with the same surface and behavior contract.
- [gin-guard](https://github.com/rennf93/gin-guard): the sibling Gin adapter with the same surface and behavior contract; keep the adapters behaviorally aligned.
