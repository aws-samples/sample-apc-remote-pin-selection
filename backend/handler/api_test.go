package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"remote-pin-selection/backend/apc"
	"remote-pin-selection/backend/ca"
	"remote-pin-selection/backend/operation"
)

const (
	testPAN        = "4000123456789010"
	testClientCert = "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n"
)

type fakeAPC struct {
	translateCalls int
	translateErr   error
	agreementErr   error
}

func (f *fakeAPC) AgreementCertificatePEM(context.Context) (string, error) {
	return "agreement-pem", f.agreementErr
}

func (f *fakeAPC) TranslatePinBlock(context.Context, string, string, string, string) (apc.TranslateResult, error) {
	f.translateCalls++
	if f.translateErr != nil {
		return apc.TranslateResult{}, f.translateErr
	}
	return apc.TranslateResult{PinBlock: "PEKBLOCK", KeyArn: "pek-ref", KeyCheckValue: "ABC123"}, nil
}

type fakeCA struct {
	calls int
	token string
	err   error
}

func (f *fakeCA) Issue(_ context.Context, _ []byte, token string) (string, error) {
	f.calls++
	f.token = token
	return testClientCert, f.err
}

type fakeProcessor struct {
	enrollCalls int
	verifyCalls int
	pan         string
	translated  apc.TranslateResult
	valid       bool
	err         error
}

func (f *fakeProcessor) Enroll(_ context.Context, translated apc.TranslateResult, pan string) (int64, error) {
	f.enrollCalls++
	f.pan, f.translated = pan, translated
	return 1, f.err
}

func (f *fakeProcessor) Verify(_ context.Context, translated apc.TranslateResult, pan string) (bool, error) {
	f.verifyCalls++
	f.pan, f.translated = pan, translated
	return f.valid, f.err
}

type testEnv struct {
	api       *API
	mux       *http.ServeMux
	apc       *fakeAPC
	ca        *fakeCA
	processor *fakeProcessor
}

func newTestEnv() *testEnv {
	env := &testEnv{apc: &fakeAPC{}, ca: &fakeCA{}, processor: &fakeProcessor{valid: true}}
	env.api = &API{
		APC:        env.apc,
		CA:         env.ca,
		Operations: operation.NewStore(5 * time.Minute),
		Processor:  env.processor,
	}
	env.mux = http.NewServeMux()
	env.api.Register(env.mux)
	return env
}

func (e *testEnv) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	e.mux.ServeHTTP(recorder, request)
	return recorder
}

// beginAndSign runs the first two steps and returns the operation ID.
func (e *testEnv) beginAndSign(t *testing.T, typ string) string {
	t.Helper()
	begin := e.post(t, "/api/operations", map[string]string{"type": typ, "pan": testPAN})
	if begin.Code != http.StatusOK {
		t.Fatalf("begin status = %d, body = %s", begin.Code, begin.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(begin.Body.Bytes(), &out)
	if out["agreement_certificate_pem"] != "agreement-pem" || out["expires_at"] == "" {
		t.Fatalf("unexpected begin response: %v", out)
	}
	id := out["operation_id"]

	sign := e.post(t, "/api/csr-sign", map[string]string{"operation_id": id, "csr_pem": "csr"})
	if sign.Code != http.StatusOK || !strings.Contains(sign.Body.String(), "CLIENT") {
		t.Fatalf("csr-sign status = %d, body = %s", sign.Code, sign.Body.String())
	}
	return id
}

func envelope(id string) map[string]string {
	return map[string]string{
		"operation_id":        id,
		"pan":                 testPAN,
		"encrypted_pin_block": "0011223344556677",
		"client_cert_pem":     testClientCert,
		"shared_information":  strings.Repeat("ab", 32),
	}
}

func TestPinSetFlowHandsTranslatedBlockToProcessor(t *testing.T) {
	env := newTestEnv()
	id := env.beginAndSign(t, "pin-set")

	if env.ca.token != id {
		t.Fatalf("idempotency token = %q, want the operation ID", env.ca.token)
	}

	response := env.post(t, "/api/pin/set", envelope(id))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":1`) {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if env.processor.enrollCalls != 1 || env.processor.pan != testPAN || env.processor.translated.PinBlock != "PEKBLOCK" {
		t.Fatalf("processor did not receive the translated block: %+v", env.processor)
	}
	for _, secret := range []string{testPAN, "PEKBLOCK", "pek-ref", "ABC123"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("response exposes %q: %s", secret, response.Body.String())
		}
	}
}

func TestReplayedEnvelopeIsRejectedBeforeTranslation(t *testing.T) {
	env := newTestEnv()
	id := env.beginAndSign(t, "pin-set")

	first := env.post(t, "/api/pin/set", envelope(id))
	replay := env.post(t, "/api/pin/set", envelope(id))

	if first.Code != http.StatusOK || replay.Code != http.StatusConflict {
		t.Fatalf("statuses: first=%d replay=%d", first.Code, replay.Code)
	}
	if env.apc.translateCalls != 1 || env.processor.enrollCalls != 1 {
		t.Fatalf("replay reached AWS: translate=%d enroll=%d", env.apc.translateCalls, env.processor.enrollCalls)
	}
}

func TestEnvelopeMustMatchOperation(t *testing.T) {
	cases := map[string]struct {
		path   string
		mutate func(map[string]string)
	}{
		"other certificate": {"/api/pin/set", func(e map[string]string) { e["client_cert_pem"] = "other" }},
		"other PAN":         {"/api/pin/set", func(e map[string]string) { e["pan"] = "5555555555554444" }},
		"other type":        {"/api/pin/validate", func(map[string]string) {}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv()
			id := env.beginAndSign(t, "pin-set")
			body := envelope(id)
			tc.mutate(body)

			response := env.post(t, tc.path, body)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if env.apc.translateCalls != 0 {
				t.Fatal("mismatched envelope reached TranslatePinData")
			}
		})
	}
}

func TestCSRIsSignedOnlyOncePerOperation(t *testing.T) {
	env := newTestEnv()
	id := env.beginAndSign(t, "pin-set")

	second := env.post(t, "/api/csr-sign", map[string]string{"operation_id": id, "csr_pem": "csr"})
	if second.Code != http.StatusConflict || env.ca.calls != 1 {
		t.Fatalf("second CSR: status=%d CA calls=%d", second.Code, env.ca.calls)
	}
}

func TestCSRForUnknownOperationIsNotSigned(t *testing.T) {
	env := newTestEnv()
	response := env.post(t, "/api/csr-sign", map[string]string{"operation_id": strings.Repeat("a", 32), "csr_pem": "csr"})
	if response.Code != http.StatusConflict || env.ca.calls != 0 {
		t.Fatalf("status=%d CA calls=%d", response.Code, env.ca.calls)
	}
}

func TestInvalidCSRIsBadRequestAndEndsOperation(t *testing.T) {
	env := newTestEnv()
	env.ca.err = ca.ErrInvalidCSR
	begin := env.post(t, "/api/operations", map[string]string{"type": "pin-set", "pan": testPAN})
	var out map[string]string
	_ = json.Unmarshal(begin.Body.Bytes(), &out)

	response := env.post(t, "/api/csr-sign", map[string]string{"operation_id": out["operation_id"], "csr_pem": "csr"})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
	env.ca.err = nil
	retry := env.post(t, "/api/csr-sign", map[string]string{"operation_id": out["operation_id"], "csr_pem": "csr"})
	if retry.Code != http.StatusConflict {
		t.Fatalf("retry on failed operation status = %d, want 409", retry.Code)
	}
}

func TestSharedInformationWithZeroByteIsRejected(t *testing.T) {
	env := newTestEnv()
	id := env.beginAndSign(t, "pin-set")
	body := envelope(id)
	body["shared_information"] = "00" + strings.Repeat("ab", 31)

	response := env.post(t, "/api/pin/set", body)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "zero bytes") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestServiceFailuresAreGenericAndConsumeOperation(t *testing.T) {
	env := newTestEnv()
	env.apc.translateErr = errors.New("AccessDeniedException: arn:aws:payment-cryptography:secret")
	id := env.beginAndSign(t, "pin-set")

	response := env.post(t, "/api/pin/set", envelope(id))
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "arn:") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if env.processor.enrollCalls != 0 {
		t.Fatal("processor called after translation failure")
	}
	env.apc.translateErr = nil
	if retry := env.post(t, "/api/pin/set", envelope(id)); retry.Code != http.StatusConflict {
		t.Fatalf("retry status = %d, want 409 (start a new operation)", retry.Code)
	}
}

func TestPinValidateReturnsProcessorResult(t *testing.T) {
	env := newTestEnv()
	env.processor.valid = false
	id := env.beginAndSign(t, "pin-validate")

	response := env.post(t, "/api/pin/validate", envelope(id))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"valid":false`) {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if env.processor.verifyCalls != 1 {
		t.Fatalf("verify calls = %d", env.processor.verifyCalls)
	}
}

func TestRequestsRejectUnknownFieldsAndBadInput(t *testing.T) {
	env := newTestEnv()

	for name, tc := range map[string]struct {
		path string
		body any
	}{
		"unknown field": {"/api/operations", map[string]string{"type": "pin-set", "pan": testPAN, "extra": "x"}},
		"bad type":      {"/api/operations", map[string]string{"type": "pin-reveal", "pan": testPAN}},
		"bad PAN":       {"/api/operations", map[string]string{"type": "pin-set", "pan": "1234"}},
		"no operation":  {"/api/pin/set", envelope("")},
		"short block": {"/api/pin/set", func() map[string]string {
			e := envelope(strings.Repeat("a", 32))
			e["encrypted_pin_block"] = "00"
			return e
		}()},
		"oversized body": {"/api/pin/set", map[string]string{"padding": strings.Repeat("x", maxRequestBytes)}},
	} {
		t.Run(name, func(t *testing.T) {
			if response := env.post(t, tc.path, tc.body); response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}
