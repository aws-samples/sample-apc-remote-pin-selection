package apc

// PROCESSOR SIDE. These operations belong to the banking system or card
// processor, not the issuer backend. The demo's processor stand-in
// (package processor) calls them so you can see how a PIN verification value
// is generated from the translated PIN block and later used to verify a PIN.

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	pcd "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata"
	pcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
)

// ErrPINMismatch means VerifyPinData ran and the PIN did not match. It is
// distinct from service errors so an outage is never reported as a wrong PIN.
var ErrPINMismatch = errors.New("PIN verification mismatch")

// GeneratePinVerificationValue derives a Visa PVV from a PEK-encrypted PIN
// block. The PVV is a 4-digit value computed from the PIN, the PAN, and the PIN
// verification key (PVK). It is not the PIN and cannot be reversed into the
// PIN without the PVK, which is why a processor can store it and later verify
// PIN attempts against it.
func (c *Client) GeneratePinVerificationValue(ctx context.Context, pekArn, pekPinBlockHex, pan string) (string, error) {
	out, err := c.Data.GeneratePinData(ctx, &pcd.GeneratePinDataInput{
		// The PIN block is encrypted under the PEK from TranslatePinData.
		EncryptionKeyIdentifier: aws.String(pekArn),
		// The PVV is computed with the PVK.
		GenerationKeyIdentifier: aws.String(c.Cfg.PvkArn),
		PinBlockFormat:          pcdtypes.PinBlockFormatForPinDataIsoFormat0,
		PrimaryAccountNumber:    aws.String(pan),
		// VisaPinVerificationValue uses the PIN from EncryptedPinBlock (the
		// cardholder-selected PIN) instead of generating a random one.
		GenerationAttributes: &pcdtypes.PinGenerationAttributesMemberVisaPinVerificationValue{
			Value: pcdtypes.VisaPinVerificationValue{
				EncryptedPinBlock:       aws.String(pekPinBlockHex),
				PinVerificationKeyIndex: aws.Int32(c.Cfg.PvkIndex),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("GeneratePinData: %w", err)
	}
	pvv, ok := out.PinData.(*pcdtypes.PinDataMemberVerificationValue)
	if !ok {
		return "", fmt.Errorf("GeneratePinData: unexpected PinData type %T", out.PinData)
	}
	return pvv.Value, nil
}

// VerifyPin checks a PEK-encrypted PIN attempt against a stored PVV. It
// returns ErrPINMismatch when the PIN is wrong.
//
// pvkIndex and pvkArn come from the stored verifier record rather than the
// current config, so a record stays verifiable with the key it was created
// under.
func (c *Client) VerifyPin(ctx context.Context, pekArn, pekPinBlockHex, pan, pvv string, pvkIndex int32, pvkArn string) (bool, error) {
	_, err := c.Data.VerifyPinData(ctx, &pcd.VerifyPinDataInput{
		EncryptedPinBlock:         aws.String(pekPinBlockHex),
		EncryptionKeyIdentifier:   aws.String(pekArn),
		VerificationKeyIdentifier: aws.String(pvkArn),
		PinBlockFormat:            pcdtypes.PinBlockFormatForPinDataIsoFormat0,
		PrimaryAccountNumber:      aws.String(pan),
		VerificationAttributes: &pcdtypes.PinVerificationAttributesMemberVisaPin{
			Value: pcdtypes.VisaPinVerification{
				PinVerificationKeyIndex: aws.Int32(pvkIndex),
				VerificationValue:       aws.String(pvv),
			},
		},
	})
	if err != nil {
		// A wrong PIN is reported as VerificationFailedException.
		var failed *pcdtypes.VerificationFailedException
		if errors.As(err, &failed) {
			return false, ErrPINMismatch
		}
		return false, fmt.Errorf("VerifyPinData: %w", err)
	}
	return true, nil
}
