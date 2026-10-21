// Package handler implements the issuer backend's HTTP API.
//
// The endpoints follow the per-operation sequence in the blog post:
//
//	POST /api/operations    Begin an operation. Returns a single-use operation
//	                        ID and the Payment Cryptography agreement certificate.
//	POST /api/csr-sign      AWS Private CA issues the app's client certificate.
//	POST /api/pin/set       Translate the PIN block, then hand it to the processor
//	                        to enroll.
//	POST /api/pin/validate  Translate the PIN block, then hand it to the processor
//	                        to verify.
//
// The backend never receives the clear PIN, the app's ephemeral private key,
// the ECDH shared secret, or the derived key. It sees the PAN, the encrypted
// PIN block, the client certificate, and the KDF SharedInformation.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"remote-pin-selection/backend/apc"
	"remote-pin-selection/backend/ca"
	"remote-pin-selection/backend/flowlog"
	"remote-pin-selection/backend/operation"
)

// PaymentCryptography is the issuer-side subset of apc.Client.
type PaymentCryptography interface {
	AgreementCertificatePEM(ctx context.Context) (string, error)
	TranslatePinBlock(ctx context.Context, encryptedPinBlockHex, clientCertPEM, pan, sharedInfoHex string) (apc.TranslateResult, error)
}

// CertificateIssuer issues the app's client certificate (ca.PrivateCA).
type CertificateIssuer interface {
	Issue(ctx context.Context, csrPEM []byte, idempotencyToken string) (string, error)
}

// Processor is the banking system or card processor that receives the
// translated PIN block (processor.Processor is the demo's stand-in).
type Processor interface {
	Enroll(ctx context.Context, translated apc.TranslateResult, pan string) (version int64, err error)
	Verify(ctx context.Context, translated apc.TranslateResult, pan string) (valid bool, err error)
}

// API wires the endpoints to their dependencies.
type API struct {
	APC        PaymentCryptography
	CA         CertificateIssuer
	Operations *operation.Store
	Processor  Processor
}

// Register adds the API routes to mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/operations", a.BeginOperation)
	mux.HandleFunc("POST /api/csr-sign", a.CSRSign)
	mux.HandleFunc("POST /api/pin/set", a.PinSet)
	mux.HandleFunc("POST /api/pin/validate", a.PinValidate)
}

// Input limits. Strict validation runs before any AWS call.
const maxRequestBytes = 64 << 10

var (
	panPattern         = regexp.MustCompile(`^[0-9]{13,19}$`)
	pinBlockPattern    = regexp.MustCompile(`^[0-9A-Fa-f]{16}$`)
	sharedInfoPattern  = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	operationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ---------------------------------------------------------------------------
// POST /api/operations
// ---------------------------------------------------------------------------

type beginRequest struct {
	Type string `json:"type"` // "pin-set" or "pin-validate"
	PAN  string `json:"pan"`
}

// BeginOperation authorizes a PIN operation and returns what the app needs to
// build its envelope: the operation ID and the agreement certificate.
func (a *API) BeginOperation(w http.ResponseWriter, r *http.Request) {
	ctx := flowlog.Start(r.Context(), "begin")
	flowlog.Step(ctx, "backend", "operation request received")

	var req beginRequest
	if err := decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	typ := operation.Type(req.Type)
	pan := strings.TrimSpace(req.PAN)
	if !typ.Valid() {
		writeError(w, http.StatusBadRequest, "type must be pin-set or pin-validate")
		return
	}
	if !panPattern.MatchString(pan) {
		writeError(w, http.StatusBadRequest, "pan must contain 13-19 digits")
		return
	}

	// PRODUCTION: this is where the issuer authenticates the cardholder,
	// confirms they can manage this card, and asks the banking system whether
	// the card is in a state that allows PIN selection. The demo has no users,
	// so any well-formed PAN is accepted.
	op, err := a.Operations.Begin(typ, pan)
	if err != nil {
		log.Printf("begin operation: %v", err)
		writeServiceError(w)
		return
	}
	flowlog.SetOperation(ctx, op.ID)
	flowlog.Step(ctx, "backend", "single-use operation issued")

	flowlog.Step(ctx, "payment-cryptography", "fetching agreement certificate (GetPublicKeyCertificate)")
	agreementCert, err := a.APC.AgreementCertificatePEM(ctx)
	if err != nil {
		a.Operations.Fail(op.ID)
		log.Printf("GetPublicKeyCertificate: %v", err)
		writeServiceError(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"operation_id":              op.ID,
		"expires_at":                op.ExpiresAt.UTC().Format(time.RFC3339),
		"agreement_certificate_pem": agreementCert,
	})
	flowlog.Step(ctx, "backend", "operation ID and agreement certificate returned")
}

// ---------------------------------------------------------------------------
// POST /api/csr-sign
// ---------------------------------------------------------------------------

type csrSignRequest struct {
	OperationID string `json:"operation_id"`
	CSRPem      string `json:"csr_pem"`
}

// CSRSign has AWS Private CA issue a short-lived certificate for the app's
// ephemeral public key. It signs only for a live operation, and only once.
func (a *API) CSRSign(w http.ResponseWriter, r *http.Request) {
	ctx := flowlog.Start(r.Context(), "csr-sign")
	flowlog.Step(ctx, "backend", "CSR received")

	var req csrSignRequest
	if err := decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !operationIDPattern.MatchString(req.OperationID) {
		writeError(w, http.StatusBadRequest, "operation_id is required")
		return
	}
	if req.CSRPem == "" || len(req.CSRPem) > 8<<10 {
		writeError(w, http.StatusBadRequest, "csr_pem is required and must not exceed 8 KiB")
		return
	}
	flowlog.SetOperation(ctx, req.OperationID)

	// Reserve the operation first, so the CSR is signed only for an
	// operation the backend approved, and at most once.
	op, err := a.Operations.StartSigning(req.OperationID)
	if err != nil {
		writeOperationError(w, err)
		return
	}

	flowlog.Step(ctx, "private-ca", "issuing client certificate (IssueCertificate, GetCertificate)")
	cert, err := a.CA.Issue(ctx, []byte(req.CSRPem), op.ID)
	if err != nil {
		a.Operations.Fail(op.ID)
		if errors.Is(err, ca.ErrInvalidCSR) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("issue client certificate: %v", err)
		writeServiceError(w)
		return
	}
	if err := a.Operations.CertificateIssued(op.ID, cert); err != nil {
		writeOperationError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"certificate_pem": cert})
	flowlog.Step(ctx, "backend", "client certificate returned")
}

// ---------------------------------------------------------------------------
// POST /api/pin/set and POST /api/pin/validate
// ---------------------------------------------------------------------------

// pinRequest is the encrypted PIN envelope from the blog post. It carries no
// clear PIN and no key material the backend could use to recover it.
type pinRequest struct {
	OperationID       string `json:"operation_id"`
	PAN               string `json:"pan"`
	EncryptedPinBlock string `json:"encrypted_pin_block"` // ISO-0, TDES-ECB under the ECDH-derived key, hex
	ClientCertPem     string `json:"client_cert_pem"`     // certificate from /api/csr-sign
	SharedInformation string `json:"shared_information"`  // KDF SharedInformation, hex, no zero bytes
}

// PinSet translates the PIN block and hands it to the processor to enroll.
func (a *API) PinSet(w http.ResponseWriter, r *http.Request) {
	a.submit(w, r, operation.PinSet, func(ctx context.Context, translated apc.TranslateResult, pan string) (map[string]any, error) {
		version, err := a.Processor.Enroll(ctx, translated, pan)
		if err != nil {
			return nil, err
		}
		return map[string]any{"success": true, "version": version}, nil
	})
}

// PinValidate translates a fresh PIN attempt and hands it to the processor to
// verify. The whole validate flow is a demo convenience: in production, PIN
// verification happens at the processor during transaction authorization.
func (a *API) PinValidate(w http.ResponseWriter, r *http.Request) {
	a.submit(w, r, operation.PinValidate, func(ctx context.Context, translated apc.TranslateResult, pan string) (map[string]any, error) {
		valid, err := a.Processor.Verify(ctx, translated, pan)
		if err != nil {
			return nil, err
		}
		return map[string]any{"success": true, "valid": valid}, nil
	})
}

type handoffFunc func(ctx context.Context, translated apc.TranslateResult, pan string) (map[string]any, error)

// submit is shared by PinSet and PinValidate: validate the envelope, claim the
// operation, translate the PIN block, then hand off to the processor.
func (a *API) submit(w http.ResponseWriter, r *http.Request, typ operation.Type, handoff handoffFunc) {
	ctx := flowlog.Start(r.Context(), string(typ))
	flowlog.Step(ctx, "backend", "encrypted PIN envelope received")

	var req pinRequest
	if err := decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.PAN = strings.TrimSpace(req.PAN)
	if err := validateEnvelope(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	flowlog.SetOperation(ctx, req.OperationID)
	flowlog.Sensitive(ctx, "backend",
		flowlog.Field{Name: "pan", Value: req.PAN},
		flowlog.Field{Name: "ecdh_encrypted_pin_block", Value: req.EncryptedPinBlock},
	)

	// Claim the operation before calling AWS. The envelope must match the
	// operation's type, PAN, and issued certificate, and it is accepted only
	// once, so a replayed envelope stops here. The operation stays consumed
	// even if a later step fails; the app starts a new operation to retry.
	if _, err := a.Operations.Claim(req.OperationID, typ, req.PAN, req.ClientCertPem); err != nil {
		writeOperationError(w, err)
		return
	}
	flowlog.Step(ctx, "backend", "operation claimed; envelope cannot be replayed")

	flowlog.Step(ctx, "payment-cryptography", "translating ECDH PIN block to the PEK (TranslatePinData)")
	translated, err := a.APC.TranslatePinBlock(ctx, req.EncryptedPinBlock, req.ClientCertPem, req.PAN, req.SharedInformation)
	if err != nil {
		log.Printf("TranslatePinData: %v", err)
		writeServiceError(w)
		return
	}
	flowlog.Sensitive(ctx, "payment-cryptography",
		flowlog.Field{Name: "pek_encrypted_pin_block", Value: translated.PinBlock},
		flowlog.Field{Name: "pek_key_check_value", Value: translated.KeyCheckValue},
	)

	// Handoff to the banking system or processor. In production this is a
	// call to the processor with the PAN or card reference, the operation ID,
	// and the PEK-encrypted PIN block, with defined idempotency, timeout, and
	// reconciliation behavior. Do not persist the translated block as a
	// recovery mechanism.
	flowlog.Step(ctx, "backend", "handing PEK-encrypted PIN block to the processor")
	response, err := handoff(ctx, translated, req.PAN)
	if err != nil {
		log.Printf("processor handoff: %v", err)
		writeServiceError(w)
		return
	}

	writeJSON(w, http.StatusOK, response)
	flowlog.Step(ctx, "backend", "operation complete")
}

func validateEnvelope(req pinRequest) error {
	switch {
	case !operationIDPattern.MatchString(req.OperationID):
		return fmt.Errorf("operation_id is required")
	case !panPattern.MatchString(req.PAN):
		return fmt.Errorf("pan must contain 13-19 digits")
	case !pinBlockPattern.MatchString(req.EncryptedPinBlock):
		return fmt.Errorf("encrypted_pin_block must be 16 hexadecimal characters")
	case req.ClientCertPem == "" || len(req.ClientCertPem) > 32<<10:
		return fmt.Errorf("client_cert_pem is required and must not exceed 32 KiB")
	case !sharedInfoPattern.MatchString(req.SharedInformation):
		return fmt.Errorf("shared_information must be 64 hexadecimal characters")
	case hasZeroByte(req.SharedInformation):
		// Payment Cryptography rejects SharedInformation containing 0x00 bytes.
		return fmt.Errorf("shared_information must not contain zero bytes")
	}
	return nil
}

// hasZeroByte reports whether a hex string contains a "00" byte. The caller
// has already checked that the length is even.
func hasZeroByte(hexString string) bool {
	for i := 0; i+1 < len(hexString); i += 2 {
		if hexString[i:i+2] == "00" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JSON helpers and stable public errors
// ---------------------------------------------------------------------------

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeOperationError returns one message for every operation failure
// (unknown, expired, reused, or mismatched) so a client cannot probe which
// case applied.
func writeOperationError(w http.ResponseWriter, err error) {
	if !errors.Is(err, operation.ErrNotFound) && !errors.Is(err, operation.ErrWrongState) && !errors.Is(err, operation.ErrMismatch) {
		log.Printf("operation: %v", err)
	}
	writeError(w, http.StatusConflict, "operation is not valid; start a new operation")
}

// writeServiceError hides which dependency failed. The detail is in the
// backend log.
func writeServiceError(w http.ResponseWriter) {
	writeError(w, http.StatusBadGateway, "PIN service is temporarily unavailable")
}
