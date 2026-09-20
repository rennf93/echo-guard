# echo-guard

Echo middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). Translates `echo.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Echo responses (status, headers, body, then stop the chain). Works with any `echo.Echo` or `echo.Group` chain via `e.Use`.

## Install

The adapter has no release tag yet; pin a commit (or track `main`) until the first tag is published:

```
go get github.com/rennf93/echo-guard@main github.com/rennf93/guard-core-go@v0.1.0
```

The package name is `echo`, which collides with `github.com/labstack/echo/v4` (also package `echo`), so import the adapter with an explicit alias such as `guardecho`.

## Usage

```go
package main

import (
	"log"

	echolib "github.com/labstack/echo/v4"
	guardcore "github.com/rennf93/guard-core-go/guardcore"
	guardecho "github.com/rennf93/echo-guard"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}

	guard, err := guardecho.New(engine)
	if err != nil {
		log.Fatal(err)
	}

	router := echolib.New()
	router.Use(guard)
	router.GET("/", func(c echolib.Context) error {
		return c.String(200, "ok")
	})

	log.Fatal(router.Start(":8080"))
}
```

Options: `guardecho.WithMaxBodyBytes(n)` bounds the body bytes the engine scans (default 262144), `guardecho.WithLogger(l)` swaps the fail-closed logger. Route-level configuration uses `engine.Routes.Register` plus `guardecho.WithRouteID(ctx, id)` on the request context (set the wrapped request with `c.SetRequest` in a middleware registered before the guard).

Echo's middleware contract has no explicit abort call: a verdict is written to `c.Response()` and the chain stops by not calling `next(c)`. Engine malfunctions fail closed with a 500. Detection covers at most the first `MaxBodyBytes` of the body; payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.

## Development

The middleware consumes the core as a normal module dependency (`github.com/rennf93/guard-core-go v0.1.0`); no `replace` directive is used or needed. For cross-repo work on the core itself, add a temporary local `replace` line in your own checkout and drop it before committing.

Integration tests run against real Redis:

```
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

## License

MIT
