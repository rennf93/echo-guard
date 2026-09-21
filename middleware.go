package echo

import (
	"errors"
	"fmt"
	"log"

	echolib "github.com/labstack/echo/v4"
	"github.com/rennf93/guard-core-go/guardcore"
)

const failClosedMessage = "Security check failed"

type middleware struct {
	engine   *guardcore.Engine
	maxBytes int64
	logger   *log.Logger
}

type Option func(*middleware)

func WithMaxBodyBytes(maxBodyBytes int64) Option {
	return func(m *middleware) {
		if maxBodyBytes > 0 {
			m.maxBytes = maxBodyBytes
		}
	}
}

func WithLogger(logger *log.Logger) Option {
	return func(m *middleware) {
		if logger != nil {
			m.logger = logger
		}
	}
}

func New(engine *guardcore.Engine, opts ...Option) (echolib.MiddlewareFunc, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}
	m := &middleware{engine: engine, maxBytes: DefaultMaxBodyBytes, logger: log.Default()}
	for _, opt := range opts {
		opt(m)
	}
	return m.wrap, nil
}

func (m *middleware) wrap(next echolib.HandlerFunc) echolib.HandlerFunc {
	return func(c echolib.Context) error {
		req := newRequestShim(c, m.maxBytes)
		verdict, err := m.check(req)
		if err != nil {
			m.logger.Printf("guardcore echo: engine malfunction, failing closed: %v", err)
			applyResponse(c, m.engine.CreateErrorResponse(500, failClosedMessage))
			return nil
		}
		if verdict != nil {
			applyResponse(c, verdict)
			return nil
		}
		return next(c)
	}
}

func (m *middleware) check(req guardcore.Request) (verdict *guardcore.Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine panic: %v", r)
		}
	}()
	return m.engine.Check(req), nil
}

func applyResponse(c echolib.Context, response *guardcore.Response) {
	for name, value := range response.Headers {
		c.Response().Header().Set(name, value)
	}
	c.Response().WriteHeader(response.StatusCode)
	if len(response.Body) > 0 {
		_, _ = c.Response().Write(response.Body)
	}
	// Aborting in Echo means not calling next: the wrap caller returns nil here.
}
