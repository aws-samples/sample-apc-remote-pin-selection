// Package pinstore stores PIN verifier records for the processor stand-in.
//
// PROCESSOR SIDE. In production, the banking system or card processor owns
// verifier storage. The issuer backend should not recreate it in a temporary
// application datastore just to complete the remote channel flow. This package
// exists so the demo can show what a verifier record contains.
//
// A record never contains the PIN or any PIN block. It holds:
//
//	pan                    String  partition key (synthetic PANs only; production
//	                               uses a token and resolves the PAN elsewhere)
//	verification_value     String  Visa PVV from GeneratePinData
//	pvk_index              Number  Visa PVKI used to compute the PVV
//	verification_key_ref   String  ARN of the PIN verification key (PVK)
//	version                Number  incremented on every PIN reset
//	created_at, updated_at String  RFC 3339 timestamps
package pinstore

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound means no verifier is stored for the PAN.
var ErrNotFound = errors.New("PIN verifier not found")

// Verifier is one stored PIN verifier record.
type Verifier struct {
	PAN                string
	VerificationValue  string
	PVKIndex           int32
	VerificationKeyRef string
	Version            int64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Store reads and writes verifier records.
type Store interface {
	Put(ctx context.Context, verifier Verifier) (Verifier, error)
	Get(ctx context.Context, pan string) (Verifier, error)
}
