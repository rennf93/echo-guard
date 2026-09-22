# Usage

## Constructor

```go
func New(engine *guardcore.Engine, opts ...Option) (echo.MiddlewareFunc, error)
```

`New` returns an `echo.MiddlewareFunc`, so the guard composes with `e.Use`
(or `group.Use`) anywhere in a middleware chain. It rejects a nil engine
with an error; invalid option values are silently ignored so a bad flag can
never weaken security.

## Options

| Option | Default | Purpose |
|---|---|---|
| `WithMaxBodyBytes(int64)` | `DefaultMaxBodyBytes` (262144) | Body prefix handed to the engine for inspection |
| `WithLogger(*log.Logger)` | `log.Default()` | Receive fail-closed diagnostics (prefix `guardcore echo: ...`) |

```go
guard, err := guardecho.New(engine,
    guardecho.WithMaxBodyBytes(64*1024),
    guardecho.WithLogger(log.New(os.Stderr, "guardecho ", log.LstdFlags)),
)
```

## Route IDs

Per-route configuration lives in the engine's `RouteRegistry`. Attach a route
ID to the request context in a middleware registered before the guard: Echo
runs middleware in registration order, so a group-level middleware would run
after the guard and the engine would never see the ID.

```go
engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
    rc.RequiredHeaders = guardcore.RequiredHeaders{
        {Name: "X-Admin-Token", Value: "secret"},
    }
})

routeIDs := map[string]string{
    "/admin/banned": "admin",
    "/admin/ban":    "admin",
    "/admin/unban":  "admin",
}

// Keys are echo route patterns (c.Path()), so parameterized routes map
// cleanly.
router.Use(func(next echolib.HandlerFunc) echolib.HandlerFunc {
    return func(c echolib.Context) error {
        if routeID, ok := routeIDs[c.Path()]; ok {
            c.SetRequest(c.Request().WithContext(guardecho.WithRouteID(c.Request().Context(), routeID)))
        }
        return next(c)
    }
})
router.Use(guard) // the mapper must run before the guard
```

## Verdicts

When the engine returns a block verdict, the middleware writes the verdict
status code, headers, and body to `c.Response()` and returns nil without
calling `next(c)`, so no later handler runs:

| Situation | Status | Body |
|---|---|---|
| Banned IP | 403 | `IP address banned` |
| Suspicious content | 400 | `Suspicious activity detected` |
| Rate limit exceeded | 429 | `Too many requests` |

Bodies can be overridden globally through `SecurityConfig.CustomErrorResponses`.

## Fail-closed behavior

If the engine check panics, the middleware recovers, logs through the
`WithLogger` sink, and responds `500 Security check failed` rather than
letting the request through.
