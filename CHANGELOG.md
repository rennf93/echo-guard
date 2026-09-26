Release Notes
=============

___

v1.1.0 (2026-09-26)
-------------------

Security headers on pass-through responses
------------------------------------------

### Added

- **Security headers on every pass-through response.** The adapter applies the engine's `ResponseHeaders()` set in one loop before the handler writes, so clean responses carry the same default header set as blocked ones (mirroring the engine's `process_response`). Disabling `SecurityHeaders` restores the header-free pass, and config overrides plus custom headers flow through the adapter untouched.

___

v1.0.1 (2026-09-26)
-------------------

guard-core-go v4.1.0 floor bump
-------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.1.0`.** The engine now attaches its default security headers to blocked responses, and the adapter translates that header set verbatim alongside the verdict status and body. The floor also carries the engine's per-route IP allow/block lists, `exempt_ips`, geo country blocking, and CORS support.
- **The suite now requires the engine's security headers on blocked responses.** The `TestMiddlewareBlocksBannedIPExactly` lockstep window (headers optional while the adapter floor lagged the engine) is closed: a blocked response must carry exactly the engine's default security header set, verbatim, with nothing added and nothing stripped.

___

v1.0.0 (2026-09-24)
-------------------

First stable release (v1.0.0)
-----------------------------

### Added

- **The first stable release of echo-guard, the net/http middleware adapter for the guard-core-go engine.** It translates `echo.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact HTTP responses. Works with any `echo.Echo` or `echo.Group` chain via `e.Use`; a verdict is written to `c.Response()` and the chain stops by not calling `next(c)` (Echo has no explicit abort call).
- **17/17 security checks parity with guard-core 4.0.4**, covering suspicious activity detection, penetration attempts, IP bans and allow lists, cloud provider detection, rate limiting, HTTPS enforcement, required headers, referrer policy, user agent filtering, and route-level configuration, with binary-noise gates on the detection engine.
- **Fail-closed behavior on engine malfunctions**: any engine error answers 500 instead of letting the request through. Detection covers at most the first `MaxBodyBytes` of the body (default 262144, tunable via `guardecho.WithMaxBodyBytes`); payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.
- **Route-level configuration** via `engine.Routes.Register` plus `guardecho.WithRouteID(ctx, id)` on the request context (set the wrapped request with `c.SetRequest` in a middleware registered before the guard), and a swappable fail-closed logger via `guardecho.WithLogger(l)`.
- **Documentation site** (MkDocs: index and usage/configuration pages), simple and advanced example apps, and a dockerized live smoke workflow over the example apps.

### Changed

- **Migrated to the guard-core-go `/v4` module path.** The dependency is now `github.com/rennf93/guard-core-go/v4 v4.0.4` and every import uses `github.com/rennf93/guard-core-go/v4/guardcore`. The previous `github.com/rennf93/guard-core-go v0.1.0` pre-release is retired.
- **Release engineering harmonized with guard-core-go**: a dockerized `Makefile` (install, test, lint, clean, bump-version) and a stdlib-only `.github/scripts/bump_version.py` that scaffolds this changelog; the git tag is the version.
- **Upstream drift guard, demo container publishing, and community workflows** from the parity polish: a daily test run of the adapter suite against guard-core-go@master, a container-release workflow for the demo image, docs publishing to GitHub Pages, plus labeling, staleness, and greetings workflows.

___
