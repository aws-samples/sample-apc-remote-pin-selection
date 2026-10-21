package apc

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	pc "github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pcd "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata"
	pcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
)

// AgreementCertificatePEM returns the certificate for the Payment Cryptography
// ECDH key-agreement key. The app extracts the agreement public key from it.
func (c *Client) AgreementCertificatePEM(ctx context.Context) (string, error) {
	out, err := c.Ctrl.GetPublicKeyCertificate(ctx, &pc.GetPublicKeyCertificateInput{
		KeyIdentifier: aws.String(c.Cfg.KeyAgreementKeyArn),
	})
	if err != nil {
		return "", fmt.Errorf("GetPublicKeyCertificate: %w", err)
	}
	// The API returns the PEM certificate base64-encoded.
	pemBytes, err := base64.StdEncoding.DecodeString(aws.ToString(out.KeyCertificate))
	if err != nil {
		return "", fmt.Errorf("decode agreement certificate: %w", err)
	}
	return string(pemBytes), nil
}

// TranslateResult is the output of TranslatePinData. It never contains the
// clear PIN, only the PIN block re-encrypted under the outgoing PEK.
type TranslateResult struct {
	PinBlock      string // ISO-0 PIN block encrypted under the PEK, hex
	KeyArn        string // the PEK that encrypts PinBlock
	KeyCheckValue string // lets the processor confirm it holds the same PEK
}

// TranslatePinBlock moves the app's PIN block from the per-operation ECDH key
// domain into the PEK domain used by the banking system.
//
// Inputs from the app's envelope:
//   - encryptedPinBlockHex: ISO-0 PIN block, TDES-ECB under the ECDH-derived key
//   - clientCertPEM: the certificate AWS Private CA issued for the app's
//     ephemeral public key
//   - pan: the PAN, which ISO-0 mixes into the PIN block
//   - sharedInfoHex: the per-operation KDF SharedInformation, which must be
//     the same bytes the app used
//
// Payment Cryptography validates clientCertPEM against the imported CA key,
// performs ECDH with its private agreement key and the app's public key,
// derives the same TDES key as the app, decrypts the block, and re-encrypts it
// under the PEK, all inside its HSMs.
func (c *Client) TranslatePinBlock(ctx context.Context, encryptedPinBlockHex, clientCertPEM, pan, sharedInfoHex string) (TranslateResult, error) {
	ecdh := pcdtypes.EcdhDerivationAttributes{
		CertificateAuthorityPublicKeyIdentifier: aws.String(c.Cfg.CAPublicKeyArn),
		KeyAlgorithm:                            derivedKeyAlgorithm,
		KeyDerivationFunction:                   keyDerivationFunction,
		KeyDerivationHashAlgorithm:              keyDerivationHash,
		// The API expects the PEM certificate base64-encoded.
		PublicKeyCertificate: aws.String(base64.StdEncoding.EncodeToString([]byte(clientCertPEM))),
		SharedInformation:    aws.String(sharedInfoHex),
	}

	in := &pcd.TranslatePinDataInput{
		EncryptedPinBlock: aws.String(encryptedPinBlockHex),

		// Incoming side: the PIN block is encrypted under a key derived by
		// ECDH, so the incoming key is the agreement key plus the derivation
		// attributes above.
		IncomingKeyIdentifier: aws.String(c.Cfg.KeyAgreementKeyArn),
		IncomingWrappedKey: &pcdtypes.WrappedKey{
			WrappedKeyMaterial: &pcdtypes.WrappedKeyMaterialMemberDiffieHellmanSymmetricKey{
				Value: ecdh,
			},
		},
		IncomingTranslationAttributes: &pcdtypes.TranslationIsoFormatsMemberIsoFormat0{
			Value: pcdtypes.TranslationPinDataIsoFormat034{
				PrimaryAccountNumber: aws.String(pan),
			},
		},

		// Outgoing side: the processor's PEK and PIN block format. The PEK is
		// TDES_2KEY, so the outgoing format is ISO-0 (ISO-4 requires AES).
		// Change the format only together with the processor contract.
		OutgoingKeyIdentifier: aws.String(c.Cfg.PekArn),
		OutgoingTranslationAttributes: &pcdtypes.TranslationIsoFormatsMemberIsoFormat0{
			Value: pcdtypes.TranslationPinDataIsoFormat034{
				PrimaryAccountNumber: aws.String(pan),
			},
		},
	}

	out, err := c.Data.TranslatePinData(ctx, in)
	if err != nil {
		return TranslateResult{}, fmt.Errorf("TranslatePinData: %w", err)
	}
	return TranslateResult{
		PinBlock:      aws.ToString(out.PinBlock),
		KeyArn:        aws.ToString(out.KeyArn),
		KeyCheckValue: aws.ToString(out.KeyCheckValue),
	}, nil
}
