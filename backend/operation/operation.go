// Package operation tracks single-use PIN operations in memory.
//
// Every PIN set or PIN validate attempt is three HTTP calls bound to one
// operation ID:
//
//	POST /api/operations  -> Begin:            issue an ID for (type, PAN)
//	POST /api/csr-sign    -> StartSigning and
//	                         CertificateIssued: sign exactly one CSR for the ID
//	POST /api/pin/...     -> Claim:            accept exactly one envelope
//
// This binding gives the demo two properties from the blog post:
//
//   - The backend signs a CSR only for an operation it has approved, so it is
//     not an open certificate issuer for the Payment Cryptography trust anchor.
//   - A captured encrypted PIN envelope cannot be replayed. The envelope must
//     carry the same operation ID, PAN, and client certificate that the
//     operation recorded, and an operation accepts only one envelope.
//
// Any failure after a step starts ends the operation. The client begins a new
// one instead of retrying, which keeps retry behavior simple and explicit.
//
// Production note: this store lives in process memory and has no notion of a
// user. A production backend binds each operation to an authenticated session,
// checks card eligibility with the banking system in Begin, and keeps the
// state in a shared store so that multiple backend instances agree.
package operation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Type is the PIN operation an ID was issued for. An ID issued for one type
// cannot be used to submit the other.
type Type string

const (
	PinSet      Type = "pin-set"
	PinValidate Type = "pin-validate"
)

// Valid reports whether t is a known operation type.
func (t Type) Valid() bool { return t == PinSet || t == PinValidate }

type state int

const (
	stateStarted    state = iota // ID issued; waiting for the client CSR
	stateSigning                 // CSR accepted; AWS Private CA is issuing
	stateCertIssued              // client certificate issued; waiting for the envelope
	stateClaimed                 // envelope accepted; the ID can never be used again
)

// Operation is a snapshot of one operation. The store keeps the authoritative
// copy.
type Operation struct {
	ID        string
	Type      Type
	PAN       string
	ExpiresAt time.Time

	state         state
	clientCertPEM string
}

var (
	// ErrNotFound covers unknown, expired, and failed operations. Callers
	// return one generic error so a client cannot probe which case applied.
	ErrNotFound = errors.New("operation not found or expired")
	// ErrWrongState means the step was already performed or is out of order,
	// for example a second CSR or a replayed envelope.
	ErrWrongState = errors.New("operation is not in the expected state")
	// ErrMismatch means the request does not match what the operation
	// recorded (type, PAN, or client certificate).
	ErrMismatch = errors.New("request does not match the operation")
)

// Store is a concurrency-safe, in-memory operation store.
type Store struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	ops map[string]*Operation
}

// NewStore returns a store whose operations expire ttl after Begin. The TTL
// covers the whole flow: CSR signing and envelope submission must both happen
// before it elapses.
func NewStore(ttl time.Duration) *Store {
	return &Store{ttl: ttl, now: time.Now, ops: make(map[string]*Operation)}
}

// Begin issues a new, random, single-use operation ID for (t, pan).
//
// The ID is 32 hexadecimal characters, which also fits the 36-character limit
// of the AWS Private CA IssueCertificate idempotency token.
func (s *Store) Begin(t Type, pan string) (Operation, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Operation{}, err
	}
	op := &Operation{
		ID:        hex.EncodeToString(raw[:]),
		Type:      t,
		PAN:       pan,
		ExpiresAt: s.now().Add(s.ttl),
		state:     stateStarted,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.ops[op.ID] = op
	return *op, nil
}

// StartSigning reserves the operation for CSR signing. Only one CSR can be
// signed per operation: a second call returns ErrWrongState.
//
// The state change happens before the (slow, remote) AWS Private CA call so
// that two concurrent requests for the same ID cannot both get a certificate.
func (s *Store) StartSigning(id string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, err := s.liveLocked(id)
	if err != nil {
		return Operation{}, err
	}
	if op.state != stateStarted {
		return Operation{}, ErrWrongState
	}
	op.state = stateSigning
	return *op, nil
}

// CertificateIssued records the certificate that AWS Private CA issued for the
// operation. Claim later requires the envelope to carry this exact
// certificate, so a certificate issued for one operation cannot be used with
// another.
func (s *Store) CertificateIssued(id, clientCertPEM string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, err := s.liveLocked(id)
	if err != nil {
		return err
	}
	if op.state != stateSigning {
		return ErrWrongState
	}
	op.clientCertPEM = clientCertPEM
	op.state = stateCertIssued
	return nil
}

// Claim accepts the encrypted PIN envelope for the operation. It succeeds once;
// every later call for the same ID returns ErrWrongState (while the ID is
// retained) or ErrNotFound (after it expires). Either way, a replayed envelope
// is rejected before any Payment Cryptography call.
func (s *Store) Claim(id string, t Type, pan, clientCertPEM string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, err := s.liveLocked(id)
	if err != nil {
		return Operation{}, err
	}
	if op.state != stateCertIssued {
		return Operation{}, ErrWrongState
	}
	if op.Type != t || op.PAN != pan || op.clientCertPEM != clientCertPEM {
		return Operation{}, ErrMismatch
	}
	op.state = stateClaimed
	return *op, nil
}

// Fail ends an operation after a failed step. The client must call Begin again.
func (s *Store) Fail(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ops, id)
}

// liveLocked returns the operation if it exists and has not expired.
func (s *Store) liveLocked(id string) (*Operation, error) {
	op, ok := s.ops[id]
	if !ok || !s.now().Before(op.ExpiresAt) {
		return nil, ErrNotFound
	}
	return op, nil
}

// pruneLocked drops expired operations so the map does not grow without bound.
// Claimed operations are kept until they expire, which is what lets Claim
// report a replay as ErrWrongState rather than ErrNotFound.
func (s *Store) pruneLocked() {
	now := s.now()
	for id, op := range s.ops {
		if !now.Before(op.ExpiresAt) {
			delete(s.ops, id)
		}
	}
}
