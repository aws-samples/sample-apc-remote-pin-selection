package processor

import (
	"context"
	"errors"
	"testing"

	"remote-pin-selection/backend/apc"
	"remote-pin-selection/backend/pinstore"
)

type fakeAPC struct {
	pvv              string
	generateErr      error
	verifyErr        error
	verifyPVV        string
	verifyIndex      int32
	verifyKeyRef     string
	generatePEK      string
	generatePinBlock string
}

func (f *fakeAPC) GeneratePinVerificationValue(_ context.Context, pekArn, pekPinBlockHex, _ string) (string, error) {
	f.generatePEK, f.generatePinBlock = pekArn, pekPinBlockHex
	return f.pvv, f.generateErr
}

func (f *fakeAPC) VerifyPin(_ context.Context, _, _, _, pvv string, pvkIndex int32, pvkArn string) (bool, error) {
	f.verifyPVV, f.verifyIndex, f.verifyKeyRef = pvv, pvkIndex, pvkArn
	return f.verifyErr == nil, f.verifyErr
}

type fakeStore struct {
	put    pinstore.Verifier
	puts   int
	get    pinstore.Verifier
	getErr error
}

func (f *fakeStore) Put(_ context.Context, v pinstore.Verifier) (pinstore.Verifier, error) {
	f.puts++
	f.put = v
	v.Version = 3
	return v, nil
}

func (f *fakeStore) Get(context.Context, string) (pinstore.Verifier, error) { return f.get, f.getErr }

var translated = apc.TranslateResult{PinBlock: "PEKBLOCK", KeyArn: "pek-ref"}

func TestEnrollStoresPVVAndKeyReference(t *testing.T) {
	store := &fakeStore{}
	apcFake := &fakeAPC{pvv: "1234"}
	p := &Processor{APC: apcFake, Store: store, PvkArn: "pvk-ref", PvkIndex: 1}

	version, err := p.Enroll(context.Background(), translated, "4000123456789010")
	if err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("version = %d", version)
	}
	if apcFake.generatePEK != "pek-ref" || apcFake.generatePinBlock != "PEKBLOCK" {
		t.Fatalf("PVV not generated from the translated block: %+v", apcFake)
	}
	want := pinstore.Verifier{PAN: "4000123456789010", VerificationValue: "1234", PVKIndex: 1, VerificationKeyRef: "pvk-ref"}
	if store.put != want {
		t.Fatalf("stored %+v, want %+v", store.put, want)
	}
}

func TestEnrollDoesNotStoreAfterGenerationFailure(t *testing.T) {
	store := &fakeStore{}
	p := &Processor{APC: &fakeAPC{generateErr: errors.New("APC unavailable")}, Store: store}

	if _, err := p.Enroll(context.Background(), translated, "4000123456789010"); err == nil {
		t.Fatal("expected error")
	}
	if store.puts != 0 {
		t.Fatalf("Put called %d times", store.puts)
	}
}

func TestVerifyUsesStoredVerifierRecord(t *testing.T) {
	apcFake := &fakeAPC{}
	store := &fakeStore{get: pinstore.Verifier{PAN: "4000123456789010", VerificationValue: "9876", PVKIndex: 2, VerificationKeyRef: "stored-pvk"}}
	p := &Processor{APC: apcFake, Store: store, PvkArn: "current-pvk", PvkIndex: 1}

	valid, err := p.Verify(context.Background(), translated, "4000123456789010")
	if err != nil || !valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
	if apcFake.verifyPVV != "9876" || apcFake.verifyIndex != 2 || apcFake.verifyKeyRef != "stored-pvk" {
		t.Fatalf("verification did not use the stored record: %+v", apcFake)
	}
}

func TestVerifyTreatsUnknownPANAndMismatchAlike(t *testing.T) {
	unknown := &Processor{APC: &fakeAPC{}, Store: &fakeStore{getErr: pinstore.ErrNotFound}}
	mismatch := &Processor{APC: &fakeAPC{verifyErr: apc.ErrPINMismatch}, Store: &fakeStore{}}

	for name, p := range map[string]*Processor{"unknown PAN": unknown, "mismatch": mismatch} {
		valid, err := p.Verify(context.Background(), translated, "4000123456789010")
		if valid || err != nil {
			t.Fatalf("%s: valid=%v err=%v, want false, nil", name, valid, err)
		}
	}
}

func TestVerifyReturnsServiceErrors(t *testing.T) {
	for name, p := range map[string]*Processor{
		"store": {APC: &fakeAPC{}, Store: &fakeStore{getErr: errors.New("DynamoDB unavailable")}},
		"APC":   {APC: &fakeAPC{verifyErr: errors.New("APC unavailable")}, Store: &fakeStore{}},
	} {
		if _, err := p.Verify(context.Background(), translated, "4000123456789010"); err == nil {
			t.Fatalf("%s: expected a service error, not a PIN result", name)
		}
	}
}
