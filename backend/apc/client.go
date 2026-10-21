// Package apc calls AWS Payment Cryptography for the issuer backend.
//
// Issuer-side operations (translate.go):
//   - GetPublicKeyCertificate: fetch the ECDH agreement-key certificate that
//     the app uses as its ECDH counterparty
//   - TranslatePinData: re-encrypt the app's ECDH-protected PIN block under
//     the outgoing PIN encryption key (PEK)
//
// Processor-side operations (verify.go), used only by the processor stand-in:
//   - GeneratePinData: generate a Visa PIN verification value (PVV)
//   - VerifyPinData: check a PIN attempt against a stored PVV
//
// None of these operations returns the clear PIN. Translation, generation, and
// verification all happen inside the service's HSM boundary.
package apc

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	pc "github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pcd "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata"
	pcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
)

// ECDH interoperability profile. These values are fixed by the processor
// integration, not by the app framework, and they must match the app's
// frontend/lib/services/crypto_service.dart exactly:
//
//	Key agreement            ECC_NIST_P256
//	Key derivation           NIST_SP800 (ConcatKDF) with SHA_512
//	Temporary symmetric key  TDES_2KEY
//	PIN block (in and out)   ISO Format 0
const (
	derivedKeyAlgorithm   = pcdtypes.SymmetricKeyAlgorithmTdes2key
	keyDerivationFunction = pcdtypes.KeyDerivationFunctionNistSp800
	keyDerivationHash     = pcdtypes.KeyDerivationHashAlgorithmSha512
)

// Config holds the Payment Cryptography key identifiers created in the
// README setup steps (terraform/ and the ImportKey step).
type Config struct {
	// KeyAgreementKeyArn is the ECC_NIST_P256 key-agreement key: the service's
	// side of ECDH and the IncomingKeyIdentifier for TranslatePinData.
	KeyAgreementKeyArn string
	// PekArn is the TDES_2KEY PIN encryption key that the translated PIN block
	// is encrypted under (OutgoingKeyIdentifier). In production this key is
	// shared with the banking system or processor through a key exchange.
	PekArn string
	// CAPublicKeyArn is the AWS Private CA certificate imported as a root
	// certificate public key. Payment Cryptography uses it to validate the
	// app's client certificate.
	CAPublicKeyArn string
	// PvkArn is the Visa PIN verification key (processor side).
	PvkArn string
	// PvkIndex is the Visa PIN verification key index (PVKI), normally set by
	// the issuer. The setup script uses 1.
	PvkIndex int32
}

// ControlAPI is the subset of the Payment Cryptography control plane used here.
type ControlAPI interface {
	GetPublicKeyCertificate(context.Context, *pc.GetPublicKeyCertificateInput, ...func(*pc.Options)) (*pc.GetPublicKeyCertificateOutput, error)
}

// DataAPI is the subset of the Payment Cryptography data plane used here.
type DataAPI interface {
	TranslatePinData(context.Context, *pcd.TranslatePinDataInput, ...func(*pcd.Options)) (*pcd.TranslatePinDataOutput, error)
	GeneratePinData(context.Context, *pcd.GeneratePinDataInput, ...func(*pcd.Options)) (*pcd.GeneratePinDataOutput, error)
	VerifyPinData(context.Context, *pcd.VerifyPinDataInput, ...func(*pcd.Options)) (*pcd.VerifyPinDataOutput, error)
}

// Client bundles the control-plane and data-plane clients with their config.
type Client struct {
	Cfg  Config
	Ctrl ControlAPI
	Data DataAPI
}

// New builds a Client from a shared AWS config.
func New(awsCfg aws.Config, cfg Config) *Client {
	return &Client{
		Cfg:  cfg,
		Ctrl: pc.NewFromConfig(awsCfg),
		Data: pcd.NewFromConfig(awsCfg),
	}
}
