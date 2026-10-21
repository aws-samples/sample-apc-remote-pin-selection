// Package processor is a STAND-IN for the banking system or card processor.
//
// In a real deployment, everything in this package runs on the processor's
// side of the integration, not in the issuer backend. The issuer backend's job
// ends when it delivers the PEK-encrypted PIN block (plus the PAN and an
// operation reference) to the processor. The processor then owns:
//
//   - generating the PIN verifier (here, a Visa PVV) and storing it
//   - PIN verification at transaction time, retry counting, and lockout
//
// The demo runs these steps in-process, with AWS Payment Cryptography and a
// DynamoDB table, so you can see how a PVV is generated from the translated PIN
// block and what gets stored. It deliberately implements no retry counter or
// lockout, and the validate flow exists only to prove that the enrolled PIN
// works. Do not copy this package into an issuer backend.
package processor

import (
	"context"
	"errors"

	"remote-pin-selection/backend/apc"
	"remote-pin-selection/backend/flowlog"
	"remote-pin-selection/backend/pinstore"
)

// PinVerifier is the subset of the apc.Client used by the processor.
type PinVerifier interface {
	GeneratePinVerificationValue(ctx context.Context, pekArn, pekPinBlockHex, pan string) (string, error)
	VerifyPin(ctx context.Context, pekArn, pekPinBlockHex, pan, pvv string, pvkIndex int32, pvkArn string) (bool, error)
}

// Processor enrolls and verifies PINs from PEK-encrypted PIN blocks.
type Processor struct {
	APC   PinVerifier
	Store pinstore.Store
	// PvkArn and PvkIndex identify the Visa PIN verification key. They are
	// stored with each verifier record so later verification uses the same key.
	PvkArn   string
	PvkIndex int32
}

// Enroll generates a PVV for the PEK-encrypted PIN block and stores it under
// the PAN. It returns the record version, which increments on every reset.
//
// Nothing stored here is the PIN or a PIN block: the record holds the PVV, the
// key reference and index needed to verify against it, and timestamps.
func (p *Processor) Enroll(ctx context.Context, translated apc.TranslateResult, pan string) (int64, error) {
	flowlog.Step(ctx, "processor", "generating Visa PVV from the PEK-encrypted PIN block (GeneratePinData)")
	pvv, err := p.APC.GeneratePinVerificationValue(ctx, translated.KeyArn, translated.PinBlock, pan)
	if err != nil {
		return 0, err
	}
	flowlog.Sensitive(ctx, "processor", flowlog.Field{Name: "pvv", Value: pvv})

	flowlog.Step(ctx, "processor", "storing the PVV verifier record in DynamoDB")
	stored, err := p.Store.Put(ctx, pinstore.Verifier{
		PAN:                pan,
		VerificationValue:  pvv,
		PVKIndex:           p.PvkIndex,
		VerificationKeyRef: p.PvkArn,
	})
	if err != nil {
		return 0, err
	}
	return stored.Version, nil
}

// Verify checks a PEK-encrypted PIN attempt against the stored PVV. An unknown
// PAN and a wrong PIN both return (false, nil) so the response does not reveal
// whether a card is enrolled. Service failures return an error.
//
// In production, this check happens at the processor during transaction
// authorization, not through an issuer API.
func (p *Processor) Verify(ctx context.Context, translated apc.TranslateResult, pan string) (bool, error) {
	flowlog.Step(ctx, "processor", "loading the stored PVV verifier record from DynamoDB")
	stored, err := p.Store.Get(ctx, pan)
	if errors.Is(err, pinstore.ErrNotFound) {
		flowlog.Step(ctx, "processor", "no verifier stored for this PAN; returning invalid")
		return false, nil
	}
	if err != nil {
		return false, err
	}
	flowlog.Sensitive(ctx, "processor", flowlog.Field{Name: "stored_pvv", Value: stored.VerificationValue})

	flowlog.Step(ctx, "processor", "verifying the PIN attempt against the stored PVV (VerifyPinData)")
	_, err = p.APC.VerifyPin(ctx, translated.KeyArn, translated.PinBlock, stored.PAN,
		stored.VerificationValue, stored.PVKIndex, stored.VerificationKeyRef)
	if errors.Is(err, apc.ErrPINMismatch) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
