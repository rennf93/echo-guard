// Command server assembles the advanced example: tuned engine config, the
// engine's route registry, echo route groups, the echo-guard middleware, and
// graceful shutdown.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	echolib "github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	guardecho "github.com/rennf93/echo-guard"
	guardcore "github.com/rennf93/guard-core-go/guardcore"

	"github.com/rennf93/echo-guard/examples/advanced_app/internal/config"
	"github.com/rennf93/echo-guard/examples/advanced_app/internal/routes"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// Route registry: route IDs are attached to requests by the route-ID
	// mapper below and resolved by the engine's route_config check.
	//
	// Note on ported surface: this Go port enforces the following
	// route-scoped knobs: RequireHTTPS, MaxRequestSize,
	// AllowedContentTypes, RequiredHeaders, and authentication. Per-route
	// rate limits are NOT read by the pipeline yet; use
	// SecurityConfig.EndpointRateLimits (as done for /rate/burst) instead.
	adminToken := config.EnvOr("ADMIN_TOKEN", "admin-token-change-me")
	engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
		rc.RequiredHeaders = guardcore.RequiredHeaders{
			{Name: "X-Admin-Token", Value: adminToken},
		}
	})

	guard, err := guardecho.New(engine,
		guardecho.WithMaxBodyBytes(1<<20),
		guardecho.WithLogger(log.New(os.Stderr, "guardecho ", log.LstdFlags)),
	)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	// Route IDs reach the engine through the request context
	// (guardecho.WithRouteID), which the adapter copies into
	// RequestState.GuardRouteID. The mapper must therefore be registered
	// before the guard: echo runs middleware in registration order, so a
	// group-level middleware would run after the guard and the engine would
	// never see the route ID. Keys are echo route patterns (c.Path()), so
	// parameterized routes map cleanly.
	routeIDs := map[string]string{
		"/admin/banned": "admin",
		"/admin/ban":    "admin",
		"/admin/unban":  "admin",
	}

	router := echolib.New()
	router.HideBanner = true
	// Recovery stays outermost so handler panics are contained; the mapper
	// and the guard follow so blocked requests never reach another handler.
	router.Use(echomiddleware.Recover())
	router.Use(attachRouteIDs(routeIDs))
	router.Use(guard)
	routes.Register(router, &routes.App{Engine: engine})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Println("advanced example listening on :8080")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// attachRouteIDs tags requests with the engine route ID of the matched echo
// route pattern before the guard runs.
func attachRouteIDs(routeIDs map[string]string) echolib.MiddlewareFunc {
	return func(next echolib.HandlerFunc) echolib.HandlerFunc {
		return func(c echolib.Context) error {
			if routeID, ok := routeIDs[c.Path()]; ok {
				c.SetRequest(c.Request().WithContext(guardecho.WithRouteID(c.Request().Context(), routeID)))
			}
			return next(c)
		}
	}
}
