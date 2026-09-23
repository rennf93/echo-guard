# echo-guard

`echo-guard` is the official Echo adapter for
[guard-core-go](https://github.com/rennf93/guard-core-go), the Go port of the
guard-core security engine. It wraps any `echo.Echo` or `echo.Group` with the
full engine pipeline: penetration detection, rate limiting, IP banning, and
verdict responses.

All security logic lives in the engine; this package is a thin shim that
translates `echo.Context` into `guardcore.Request`, runs the engine, and
writes the block verdict (status, headers, body) when one arrives; the chain
stops because the middleware returns without calling `next`.

## Installation

```bash
go get github.com/rennf93/echo-guard@main github.com/rennf93/guard-core-go@v0.1.0
```

Requires Go 1.25 or later.

The package name is `echo`, which collides with `github.com/labstack/echo/v4`
(also package `echo`), so import the adapter with an explicit alias such as
`guardecho`.

## Quick start

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

## What the shim handles

- Client identity: `net.SplitHostPort` on `c.Request().RemoteAddr`. Echo's
  `c.RealIP()` is intentionally not used: trusting proxy headers is policy,
  and trusted-proxy resolution is performed by the engine
  (`SecurityConfig.TrustedProxies`)
- Headers: first value per key, plus the `Host` header
- Body: the first `maxBodyBytes` bytes are shown to the engine, and the body
  is made replayable so your handler still receives it after inspection
- Route IDs: read from the request context (see [Usage](usage.md))
- Chain control: Echo has no explicit abort call; a verdict is written to
  `c.Response()` and the middleware returns nil without calling `next(c)`
- Fail-closed: engine panics become `500` with a fixed, non-leaky message

See [Configuration](configuration.md) for engine tuning and the
[examples](https://github.com/rennf93/echo-guard/tree/master/examples) for
runnable apps.
