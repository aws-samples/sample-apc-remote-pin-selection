package operation

import (
	"errors"
	"testing"
	"time"
)

const (
	pan  = "4000123456789010"
	cert = "client-certificate"
)

func newTestStore(now *time.Time) *Store {
	s := NewStore(5 * time.Minute)
	s.now = func() time.Time { return *now }
	return s
}

func TestHappyPathThenReplayIsRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestStore(&now)

	op, err := s.Begin(PinSet, pan)
	if err != nil {
		t.Fatal(err)
	}
	if len(op.ID) != 32 {
		t.Fatalf("operation ID length = %d, want 32", len(op.ID))
	}
	if _, err := s.StartSigning(op.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CertificateIssued(op.ID, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(op.ID, PinSet, pan, cert); err != nil {
		t.Fatal(err)
	}

	// Replaying the same envelope must fail.
	if _, err := s.Claim(op.ID, PinSet, pan, cert); !errors.Is(err, ErrWrongState) {
		t.Fatalf("replayed Claim error = %v, want ErrWrongState", err)
	}
}

func TestOnlyOneCSRPerOperation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestStore(&now)
	op, _ := s.Begin(PinSet, pan)

	if _, err := s.StartSigning(op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartSigning(op.ID); !errors.Is(err, ErrWrongState) {
		t.Fatalf("second StartSigning error = %v, want ErrWrongState", err)
	}
}

func TestClaimRequiresMatchingTypePANAndCertificate(t *testing.T) {
	cases := map[string]struct {
		typ  Type
		pan  string
		cert string
	}{
		"wrong type": {PinValidate, pan, cert},
		"wrong PAN":  {PinSet, "5555555555554444", cert},
		"wrong cert": {PinSet, pan, "other-certificate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0)
			s := newTestStore(&now)
			op, _ := s.Begin(PinSet, pan)
			_, _ = s.StartSigning(op.ID)
			_ = s.CertificateIssued(op.ID, cert)

			if _, err := s.Claim(op.ID, tc.typ, tc.pan, tc.cert); !errors.Is(err, ErrMismatch) {
				t.Fatalf("Claim error = %v, want ErrMismatch", err)
			}
		})
	}
}

func TestClaimBeforeCertificateIsRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestStore(&now)
	op, _ := s.Begin(PinSet, pan)

	if _, err := s.Claim(op.ID, PinSet, pan, cert); !errors.Is(err, ErrWrongState) {
		t.Fatalf("Claim error = %v, want ErrWrongState", err)
	}
}

func TestExpiredAndFailedOperationsAreNotFound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestStore(&now)

	expired, _ := s.Begin(PinSet, pan)
	now = now.Add(5 * time.Minute)
	if _, err := s.StartSigning(expired.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired StartSigning error = %v, want ErrNotFound", err)
	}

	failed, _ := s.Begin(PinSet, pan)
	s.Fail(failed.ID)
	if _, err := s.StartSigning(failed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed StartSigning error = %v, want ErrNotFound", err)
	}
}
