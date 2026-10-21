package flowlog

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	originalWriter, originalFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
		_ = Configure("info")
		_ = ConfigureSensitive("false")
	})
	return &output
}

func TestStepRequiresDebugAndNumbersStepsPerFlow(t *testing.T) {
	output := captureLog(t)

	_ = Configure("info")
	Step(Start(context.Background(), "pin-set"), "backend", "request received")
	if output.Len() != 0 {
		t.Fatalf("info level emitted debug output: %s", output.String())
	}

	_ = Configure("debug")
	ctx := Start(context.Background(), "pin-set")
	Step(ctx, "backend", "request received")
	SetOperation(ctx, "op-123")
	Step(ctx, "payment-cryptography", "translating")

	got := output.String()
	for _, expected := range []string{
		`DEBUG flow=pin-set op=- step=01 component=backend message="request received"`,
		`DEBUG flow=pin-set op=op-123 step=02 component=payment-cryptography message="translating"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("debug output %q does not contain %q", got, expected)
		}
	}
}

func TestConfigureRejectsUnknownLevel(t *testing.T) {
	if err := Configure("verbose"); err == nil {
		t.Fatal("expected invalid log level error")
	}
}

func TestSensitiveRequiresBothFlags(t *testing.T) {
	output := captureLog(t)

	_ = Configure("info")
	if err := ConfigureSensitive("true"); err == nil {
		t.Fatal("sensitive values must require debug logging")
	}

	_ = Configure("debug")
	_ = ConfigureSensitive("false")
	ctx := Start(context.Background(), "pin-set")
	Sensitive(ctx, "backend", Field{Name: "pan", Value: "4000000000000002"})
	if output.Len() != 0 {
		t.Fatalf("disabled sensitive logging emitted output: %s", output.String())
	}

	_ = ConfigureSensitive("true")
	Sensitive(ctx, "backend",
		Field{Name: "pan", Value: "4000000000000002"},
		Field{Name: "incoming_pin_block", Value: "0011223344556677"},
	)
	got := output.String()
	for _, expected := range []string{
		"SENSITIVE_DEMO flow=pin-set",
		`pan="4000000000000002"`,
		`incoming_pin_block="0011223344556677"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("sensitive output %q does not contain %q", got, expected)
		}
	}
}
