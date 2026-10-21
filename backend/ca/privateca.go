// Package ca issues the short-lived client certificate that carries the app's
// ephemeral ECDH public key, using AWS Private CA.
//
// AWS Payment Cryptography trusts these certificates because the CA's own
// certificate was imported into Payment Cryptography as a root certificate
// public key (the ImportKey step in the README). TranslatePinData references that
// imported key through CertificateAuthorityPublicKeyIdentifier.
//
// The CA private key never leaves AWS Private CA, and the app's ephemeral
// private key never leaves the app. The backend only relays the CSR and the
// issued certificate.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

// endEntityTemplateArn is the AWS Private CA template for leaf certificates.
// It matches the AWS Payment Cryptography ECDH sample.
const endEntityTemplateArn = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"

// ErrInvalidCSR means the CSR was rejected locally, before any AWS call.
var ErrInvalidCSR = errors.New("invalid CSR")

// API is the subset of the AWS Private CA client this package uses.
type API interface {
	IssueCertificate(context.Context, *acmpca.IssueCertificateInput, ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error)
	GetCertificate(context.Context, *acmpca.GetCertificateInput, ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error)
}

// PrivateCA issues client certificates from one AWS Private CA.
type PrivateCA struct {
	Client API
	// CAArn is the CA created by terraform/main.tf, in SHORT_LIVED_CERTIFICATE
	// mode.
	CAArn string
	// SigningAlgorithm must match the CA's key algorithm. The setup script
	// creates an EC_prime256v1 CA, so this is SHA256WITHECDSA.
	SigningAlgorithm types.SigningAlgorithm
	// Validity is the client certificate lifetime. Keep it short: the key it
	// certifies is used for one operation. Expiry limits how long a
	// certificate can be presented, but it is not replay protection; the
	// operation package provides that.
	Validity time.Duration

	// PollInterval and PollTimeout bound the GetCertificate retries while
	// issuance is in progress. Zero values use the defaults below.
	PollInterval time.Duration
	PollTimeout  time.Duration

	now func() time.Time
}

// Issue signs csrPEM and returns the issued leaf certificate as PEM.
//
// idempotencyToken should be the operation ID. If the SDK retries
// IssueCertificate after a network error, AWS Private CA returns the same
// certificate instead of issuing a second one.
func (p *PrivateCA) Issue(ctx context.Context, csrPEM []byte, idempotencyToken string) (string, error) {
	// Check the CSR locally before making a billable AWS call. The key must be
	// P-256 because Payment Cryptography performs ECDH with an ECC_NIST_P256
	// key-agreement key, and both sides of ECDH must use the same curve.
	if err := checkCSR(csrPEM); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	now := time.Now
	if p.now != nil {
		now = p.now
	}

	// Step 1: request the certificate. IssueCertificate is asynchronous and
	// returns only the ARN of the certificate being issued.
	issued, err := p.Client.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(p.CAArn),
		Csr:                     csrPEM,
		SigningAlgorithm:        p.SigningAlgorithm,
		TemplateArn:             aws.String(endEntityTemplateArn),
		// ABSOLUTE is an expiry time in seconds since the Unix epoch, which
		// allows lifetimes shorter than one day.
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeAbsolute,
			Value: aws.Int64(now().Add(p.Validity).Unix()),
		},
		IdempotencyToken: aws.String(idempotencyToken),
	})
	if err != nil {
		return "", fmt.Errorf("IssueCertificate: %w", err)
	}

	// Step 2: fetch the certificate. GetCertificate returns
	// RequestInProgressException until issuance completes, so poll with a
	// bounded number of retries.
	interval, timeout := p.PollInterval, p.PollTimeout
	if interval == 0 {
		interval = 250 * time.Millisecond
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		out, err := p.Client.GetCertificate(ctx, &acmpca.GetCertificateInput{
			CertificateAuthorityArn: aws.String(p.CAArn),
			CertificateArn:          issued.CertificateArn,
		})
		if err == nil {
			// Only the leaf is returned. Payment Cryptography validates it
			// against the imported CA key, so the chain is not needed.
			return aws.ToString(out.Certificate), nil
		}
		var inProgress *types.RequestInProgressException
		if !errors.As(err, &inProgress) {
			return "", fmt.Errorf("GetCertificate: %w", err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("GetCertificate: certificate not issued within %s", timeout)
		case <-time.After(interval):
		}
	}
}

// checkCSR verifies that csrPEM is a well-formed, self-signed CSR for a P-256
// public key.
func checkCSR(csrPEM []byte) error {
	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return errors.New("CSR must be a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	// The self-signature proves the requester holds the private key.
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature: %w", err)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return errors.New("CSR public key must be ECDSA P-256")
	}
	return nil
}
