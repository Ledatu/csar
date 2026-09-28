// Package redisx attributes failures on the router's shared Redis client to
// the subsystem that issued the command.
package redisx

import (
	"context"
	"errors"

	"github.com/redis/go-redis/v9"
)

// Subsystems that share the router's Redis client.
const (
	SubsystemCache    = "cache"
	SubsystemThrottle = "throttle"
	SubsystemStartup  = "startup"
	SubsystemUnknown  = "unknown"
)

const pipelineCommand = "pipeline"

type subsystemKey struct{}

// WithSubsystem tags ctx so that Redis command errors issued with it are
// attributed to subsystem.
func WithSubsystem(ctx context.Context, subsystem string) context.Context {
	return context.WithValue(ctx, subsystemKey{}, subsystem)
}

// Subsystem returns the subsystem tagged on ctx, or SubsystemUnknown.
func Subsystem(ctx context.Context) string {
	if s, ok := ctx.Value(subsystemKey{}).(string); ok && s != "" {
		return s
	}
	return SubsystemUnknown
}

// ErrorRecorder receives one call per failed command or pipeline.
type ErrorRecorder func(subsystem, command string)

// NewErrorHook returns a go-redis hook that reports failed commands to record.
func NewErrorHook(record ErrorRecorder) redis.Hook {
	return errorHook{record: record}
}

type errorHook struct {
	record ErrorRecorder
}

func (h errorHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h errorHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if isNested(ctx) {
			return next(ctx, cmd)
		}
		err := next(markNested(ctx), cmd)
		if isFailure(err) {
			h.record(Subsystem(ctx), cmd.Name())
		}
		return err
	}
}

func (h errorHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if isNested(ctx) {
			return next(ctx, cmds)
		}
		err := next(markNested(ctx), cmds)
		if isFailure(err) || anyFailed(cmds) {
			h.record(Subsystem(ctx), pipelineCommand)
		}
		return err
	}
}

// go-redis runs its connection handshake (HELLO, CLIENT SETINFO, ...) through
// the hooks with the caller's context and ignores those errors; a handshake
// failure that matters surfaces on the outer command instead.
type nestedKey struct{}

func markNested(ctx context.Context) context.Context {
	return context.WithValue(ctx, nestedKey{}, true)
}

func isNested(ctx context.Context) bool {
	nested, _ := ctx.Value(nestedKey{}).(bool)
	return nested
}

// isFailure reports whether err is a Redis failure rather than a normal
// outcome: a missing key, a client that went away, or the NOSCRIPT miss that
// Script.Run recovers from with EVAL.
func isFailure(err error) bool {
	return err != nil &&
		!errors.Is(err, redis.Nil) &&
		!errors.Is(err, context.Canceled) &&
		!redis.HasErrorPrefix(err, "NOSCRIPT")
}

func anyFailed(cmds []redis.Cmder) bool {
	for _, cmd := range cmds {
		if isFailure(cmd.Err()) {
			return true
		}
	}
	return false
}
