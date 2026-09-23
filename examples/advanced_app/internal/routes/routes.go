// Package routes holds the HTTP handlers of the advanced example, split by
// concern the way the Python advanced example splits routers. The guard
// middleware and the route-ID mapper are attached by cmd/server before these
// handlers run.
package routes

import (
	"io"
	"log"
	"net/http"

	echolib "github.com/labstack/echo/v4"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

// App carries the engine into handlers that need operational access (the
// admin routes drive the ban manager directly).
type App struct {
	Engine *guardcore.Engine
}

// Register builds the full route table on the given router. The /admin/*
// group is registered on the engine's RouteRegistry with a RequiredHeaders
// guard (see cmd/server/main.go): the engine itself rejects calls missing the
// admin token with a 400 before these handlers run.
func Register(e *echolib.Echo, app *App) {
	e.GET("/", app.info)
	e.GET("/health", app.health)
	e.GET("/ready", app.ready)
	e.POST("/echo", app.echo)
	e.GET("/rate/burst", app.burst)
	e.GET("/test/xss", app.attackEcho)
	e.GET("/test/sqli", app.attackEcho)

	admin := e.Group("/admin")
	admin.GET("/banned", app.bannedCount)
	admin.POST("/ban", app.ban)
	admin.POST("/unban", app.unban)
}

// health and ready are excluded from the pipeline (config.ExcludePaths), so
// probes and orchestrator health checks never trip the guard.
func (a *App) health(c echolib.Context) error {
	return c.JSON(http.StatusOK, echolib.Map{"status": "ok"})
}

func (a *App) ready(c echolib.Context) error {
	// Extend this with real dependency probes (Redis PING, cloud range
	// warmup) for your deployment.
	return c.JSON(http.StatusOK, echolib.Map{"status": "ready"})
}

func (a *App) info(c echolib.Context) error {
	return c.JSON(http.StatusOK, echolib.Map{
		"app":     "echo-guard advanced example",
		"routes":  []string{"/health", "/ready", "/echo", "/rate/burst", "/admin/*", "/test/*"},
		"engine":  "guardcore",
		"version": "1.0.0",
	})
}

// echo proves the adapter's body contract: the engine scans a bounded prefix
// and the replay wrapper hands the handler the full, untouched body.
func (a *App) echo(c echolib.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echolib.Map{"error": "unreadable body"})
	}
	return c.JSON(http.StatusOK, echolib.Map{
		"echo":   true,
		"method": c.Request().Method,
		"path":   c.Request().URL.Path,
		"bytes":  len(body),
	})
}

// burst is limited by config.EndpointRateLimits (5 requests per 60 seconds),
// which this port enforces by exact request path.
func (a *App) burst(c echolib.Context) error {
	return c.JSON(http.StatusOK, echolib.Map{
		"endpoint": "/rate/burst",
		"limit":    "5 requests per 60 seconds",
	})
}

// The /admin/* routes are registered on the engine's RouteRegistry with a
// RequiredHeaders guard (see cmd/server/main.go): the engine itself rejects
// calls missing the admin token with a 400 before these handlers run.

func (a *App) bannedCount(c echolib.Context) error {
	return c.JSON(http.StatusOK, echolib.Map{
		"banned_ips":      a.Engine.Ban.BannedIPCount(),
		"banned_networks": a.Engine.Ban.BannedNetworkCount(),
	})
}

func (a *App) ban(c echolib.Context) error {
	var body struct {
		IP      string `json:"ip"`
		Seconds int    `json:"seconds"`
		Reason  string `json:"reason"`
	}
	if err := c.Bind(&body); err != nil || body.IP == "" {
		return c.JSON(http.StatusBadRequest, echolib.Map{
			"error": `body must be {"ip": ..., "seconds": ..., "reason": ...}`,
		})
	}
	if body.Seconds <= 0 {
		body.Seconds = 300
	}
	if body.Reason == "" {
		body.Reason = "manual ban via admin route"
	}
	created, err := a.Engine.Ban.Ban(body.IP, body.Seconds, body.Reason)
	if err != nil {
		log.Printf("admin ban %s failed: %v", body.IP, err)
		return c.JSON(http.StatusInternalServerError, echolib.Map{"error": "ban failed"})
	}
	return c.JSON(http.StatusOK, echolib.Map{
		"ip": body.IP, "seconds": body.Seconds, "created": created,
	})
}

func (a *App) unban(c echolib.Context) error {
	var body struct {
		IP string `json:"ip"`
	}
	if err := c.Bind(&body); err != nil || body.IP == "" {
		return c.JSON(http.StatusBadRequest, echolib.Map{"error": `body must be {"ip": ...}`})
	}
	if err := a.Engine.Ban.Unban(body.IP); err != nil {
		log.Printf("admin unban %s failed: %v", body.IP, err)
		return c.JSON(http.StatusInternalServerError, echolib.Map{"error": "unban failed"})
	}
	return c.JSON(http.StatusOK, echolib.Map{"ip": body.IP, "status": "unbanned"})
}

// attackEcho handlers intentionally echo hostile payloads; the guard blocks
// the request before the handler runs, so reaching this code means detection
// was bypassed (defense in depth: do not log or store the payload).
// Payloads ride in query parameters because this port does not scan request
// bodies yet (see the engine port's roadmap notes).
func (a *App) attackEcho(c echolib.Context) error {
	return c.JSON(http.StatusOK, echolib.Map{"detected": false})
}
