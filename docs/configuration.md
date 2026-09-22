# Configuration

The adapter has exactly two options (`WithMaxBodyBytes`, `WithLogger`); all
security tuning is engine configuration. See the
[guard-core-go configuration reference](https://rennf93.github.io/guard-core-go/configuration/)
for the full `SecurityConfig` surface.

## Minimal tuned setup

```go
cfg := guardcore.DefaultSecurityConfig()
cfg.EnableRateLimiting = true
cfg.RateLimit = 30
cfg.RateLimitWindow = 60
cfg.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
    "/rate/strict": {Requests: 1, Window: 10},
}
cfg.EnableIPBanning = true
cfg.AutoBanThreshold = 5
cfg.AutoBanDuration = 300
cfg.CustomErrorResponses = map[int]string{
    403: "Blocked by echo-guard",
}
```

## Address headers

The Python engine skips ssrf scanning for address headers (`host`,
`x-forwarded-for`, `x-real-ip`, ...) automatically. The Go engine does not
apply that built-in exclusion yet, and the Echo adapter passes an explicit
`Host` header, so mirror the exclusion when clients can send internal
hostnames:

```go
cfg.ExcludedDetectionHeaders = map[string]bool{
    "host": true, "origin": true, "via": true,
    "x-forwarded-for": true, "x-forwarded-host": true,
    "x-real-ip": true, "x-client-ip": true,
}
```

## Redis

Distributed bans and rate limits require Redis:

```go
cfg.EnableRedis = true
cfg.RedisURL = os.Getenv("REDIS_URL") // e.g. redis://redis:6379
cfg.RedisPrefix = "echo_guard:"
```

Without Redis the managers fall back to in-process state, which does not
share across replicas.

## Body inspection

`WithMaxBodyBytes` bounds what the detector sees. Bodies larger than the
limit are still forwarded to your handler; only the inspected prefix is
truncated. The default matches the engine's `MaxBodyInspectBytes` (262144).

## Trusted proxies

When behind a reverse proxy, trust only the proxy hop so the engine resolves
the real client IP from forwarded headers:

```go
cfg.TrustedProxies = []string{"172.16.0.0/12", "10.0.0.0/8"}
cfg.TrustedProxyDepth = 1
```
