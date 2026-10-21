package apc

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	pcd "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata"
	pcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
)

type fakeDataAPI struct {
	translateInput *pcd.TranslatePinDataInput
	generateInput  *pcd.GeneratePinDataInput
	generateOut    *pcd.GeneratePinDataOutput
	generateErr    error
	verifyInput    *pcd.VerifyPinDataInput
	verifyErr      error
}

func (f *fakeDataAPI) TranslatePinData(_ context.Context, in *pcd.TranslatePinDataInput, _ ...func(*pcd.Options)) (*pcd.TranslatePinDataOutput, error) {
	f.translateInput = in
	return &pcd.TranslatePinDataOutput{
		PinBlock:      aws.String("PEKBLOCK"),
		KeyArn:        aws.String("pek-ref"),
		KeyCheckValue: aws.String("ABC123"),
	}, nil
}

func (f *fakeDataAPI) GeneratePinData(_ context.Context, in *pcd.GeneratePinDataInput, _ ...func(*pcd.Options)) (*pcd.GeneratePinDataOutput, error) {
	f.generateInput = in
	return f.generateOut, f.generateErr
}

func (f *fakeDataAPI) VerifyPinData(_ context.Context, in *pcd.VerifyPinDataInput, _ ...func(*pcd.Options)) (*pcd.VerifyPinDataOutput, error) {
	f.verifyInput = in
	return &pcd.VerifyPinDataOutput{}, f.verifyErr
}

func TestGeneratePinVerificationValueBuildsVisaPVVRequest(t *testing.T) {
	data := &fakeDataAPI{
		generateOut: &pcd.GeneratePinDataOutput{
			PinData: &pcdtypes.PinDataMemberVerificationValue{Value: "1234"},
		},
	}
	client := &Client{
		Cfg: Config{
			PvkArn:   "pvk-ref",
			PvkIndex: 2,
		},
		Data: data,
	}

	got, err := client.GeneratePinVerificationValue(context.Background(), "pek-ref", "A1B2", "4000123456789010")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1234" {
		t.Fatalf("PVV = %q, want 1234", got)
	}
	if aws.ToString(data.generateInput.EncryptionKeyIdentifier) != "pek-ref" ||
		aws.ToString(data.generateInput.GenerationKeyIdentifier) != "pvk-ref" ||
		aws.ToString(data.generateInput.PrimaryAccountNumber) != "4000123456789010" {
		t.Fatalf("unexpected GeneratePinData input: %+v", data.generateInput)
	}
	attributes, ok := data.generateInput.GenerationAttributes.(*pcdtypes.PinGenerationAttributesMemberVisaPinVerificationValue)
	if !ok {
		t.Fatalf("unexpected generation attributes: %T", data.generateInput.GenerationAttributes)
	}
	if aws.ToString(attributes.Value.EncryptedPinBlock) != "A1B2" ||
		aws.ToInt32(attributes.Value.PinVerificationKeyIndex) != 2 {
		t.Fatalf("unexpected Visa PVV attributes: %+v", attributes.Value)
	}
}

func TestVerifyPinUsesStoredVerificationMetadata(t *testing.T) {
	data := &fakeDataAPI{}
	client := &Client{Data: data}

	valid, err := client.VerifyPin(
		context.Background(),
		"pek-ref",
		"A1B2",
		"4000123456789010",
		"9876",
		3,
		"stored-pvk-ref",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid PIN")
	}
	if aws.ToString(data.verifyInput.VerificationKeyIdentifier) != "stored-pvk-ref" {
		t.Fatalf("verification key = %q", aws.ToString(data.verifyInput.VerificationKeyIdentifier))
	}
	attributes, ok := data.verifyInput.VerificationAttributes.(*pcdtypes.PinVerificationAttributesMemberVisaPin)
	if !ok {
		t.Fatalf("unexpected verification attributes: %T", data.verifyInput.VerificationAttributes)
	}
	if aws.ToString(attributes.Value.VerificationValue) != "9876" ||
		aws.ToInt32(attributes.Value.PinVerificationKeyIndex) != 3 {
		t.Fatalf("unexpected Visa verification attributes: %+v", attributes.Value)
	}
}

func TestVerifyPinMapsVerificationFailureToMismatch(t *testing.T) {
	data := &fakeDataAPI{
		verifyErr: &pcdtypes.VerificationFailedException{Message: aws.String("PIN mismatch")},
	}
	client := &Client{Data: data}

	valid, err := client.VerifyPin(context.Background(), "pek", "block", "pan", "pvv", 1, "pvk")
	if valid {
		t.Fatal("mismatch must not be valid")
	}
	if !errors.Is(err, ErrPINMismatch) {
		t.Fatalf("expected ErrPINMismatch, got %v", err)
	}
}
