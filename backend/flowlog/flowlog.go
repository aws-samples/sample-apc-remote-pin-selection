// Package flowlog prints numbered, per-request steps so you can follow the
// flow from the blog post in the backend logs.
//
// Two opt-in levels, both off by default:
//
//	LOG_LEVEL=debug                  Step lines: which component does what, in order.
//	                                 Never includes PANs, PIN blocks, or verifier values.
//	DEMO_LOG_SENSITIVE_VALUES=true   Also prints synthetic demo values (PAN, encrypted
//	                                 PIN blocks, PVV). Requires LOG_LEVEL=debug.
//
// Lines are correlated by operation ID, as the blog recommends, so certificate
// issuance, translation, and the processor handoff for one operation can be
// read together. No level ever prints the clear PIN, private or derived keys,
// or certificates, because the backend never has the first two and the third
// adds noise without insight.
package flowlog

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

type contextKey struct{}

type flow struct {
	name        string
	operationID string
	step        int
}

var (
	debugEnabled     atomic.Bool
	sensitiveEnabled atomic.Bool
)

// Configure sets the log level: "info" (default) or "debug".
func Configure(level string) error {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		debugEnabled.Store(false)
	case "debug":
		debugEnabled.Store(true)
	default:
		return fmt.Errorf("LOG_LEVEL must be info or debug")
	}
	return nil
}

// ConfigureSensitive enables printing synthetic demo values. It must be called
// after Configure and requires debug level. Never enable it with real
// cardholder data.
func ConfigureSensitive(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "false", "0", "no":
		sensitiveEnabled.Store(false)
	case "true", "1", "yes":
		if !debugEnabled.Load() {
			return fmt.Errorf("DEMO_LOG_SENSITIVE_VALUES=true requires LOG_LEVEL=debug")
		}
		sensitiveEnabled.Store(true)
	default:
		return fmt.Errorf("DEMO_LOG_SENSITIVE_VALUES must be true or false")
	}
	return nil
}

// Level returns the active log level.
func Level() string {
	if debugEnabled.Load() {
		return "debug"
	}
	return "info"
}

// SensitiveEnabled reports whether synthetic demo values are printed.
func SensitiveEnabled() bool { return debugEnabled.Load() && sensitiveEnabled.Load() }

// Start begins a named flow for one HTTP request. Steps are numbered from 1.
func Start(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, contextKey{}, &flow{name: name, operationID: "-"})
}

// SetOperation attaches the operation ID to the flow once it is known.
func SetOperation(ctx context.Context, operationID string) {
	if f, ok := ctx.Value(contextKey{}).(*flow); ok {
		f.operationID = operationID
	}
}

// Step prints the next numbered step at debug level. component names the
// actor from the sequence diagram: backend, private-ca, payment-cryptography,
// or processor. message must not contain sensitive values.
func Step(ctx context.Context, component, message string) {
	if !debugEnabled.Load() {
		return
	}
	f := current(ctx)
	f.step++
	log.Printf("DEBUG flow=%s op=%s step=%02d component=%s message=%q",
		f.name, f.operationID, f.step, component, message)
}

// Field is one synthetic demo value to print.
type Field struct {
	Name  string
	Value string
}

// Sensitive prints synthetic demo values attached to the most recent step.
// Callers must never pass clear PINs, private or derived keys, or AWS key
// identifiers.
func Sensitive(ctx context.Context, component string, fields ...Field) {
	if !SensitiveEnabled() {
		return
	}
	f := current(ctx)
	var values strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&values, " %s=%q", field.Name, field.Value)
	}
	log.Printf("SENSITIVE_DEMO flow=%s op=%s step=%02d component=%s%s",
		f.name, f.operationID, f.step, component, values.String())
}

func current(ctx context.Context) *flow {
	if f, ok := ctx.Value(contextKey{}).(*flow); ok {
		return f
	}
	return &flow{name: "unscoped", operationID: "-"}
}
