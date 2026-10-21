package apc

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	pc "github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
)

type fakeControlAPI struct{ keyCertificate string }

func (f *fakeControlAPI) GetPublicKeyCertificate(context.Context, *pc.GetPublicKeyCertificateInput, ...func(*pc.Options)) (*pc.GetPublicKeyCertificateOutput, error) {
	return &pc.GetPublicKeyCertificateOutput{KeyCertificate: aws.String(f.keyCertificate)}, nil
}

func TestAgreementCertificatePEMDecodesBase64(t *testing.T) {
	pemText := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	client := &Client{Ctrl: &fakeControlAPI{keyCertificate: base64.StdEncoding.EncodeToString([]byte(pemText))}}

	got, err := client.AgreementCertificatePEM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != pemText {
		t.Fatalf("certificate = %q", got)
	}
}

func TestTranslatePinBlockBuildsECDHToPEKRequest(t *testing.T) {
	data := &fakeDataAPI{}
	client := &Client{
		Cfg: Config{
			KeyAgreementKeyArn: "agreement-ref",
			PekArn:             "pek-ref",
			CAPublicKeyArn:     "ca-ref",
		},
		Data: data,
	}

	got, err := client.TranslatePinBlock(context.Background(), "0011223344556677", "client-pem", "4000123456789010", "0A0B")
	if err != nil {
		t.Fatal(err)
	}
	if got.PinBlock != "PEKBLOCK" || got.KeyArn != "pek-ref" || got.KeyCheckValue != "ABC123" {
		t.Fatalf("unexpected result: %+v", got)
	}

	in := data.translateInput
	if aws.ToString(in.IncomingKeyIdentifier) != "agreement-ref" || aws.ToString(in.OutgoingKeyIdentifier) != "pek-ref" {
		t.Fatalf("unexpected key identifiers: in=%q out=%q",
			aws.ToString(in.IncomingKeyIdentifier), aws.ToString(in.OutgoingKeyIdentifier))
	}
	wrapped, ok := in.IncomingWrappedKey.WrappedKeyMaterial.(*pcdtypes.WrappedKeyMaterialMemberDiffieHellmanSymmetricKey)
	if !ok {
		t.Fatalf("unexpected wrapped key material: %T", in.IncomingWrappedKey.WrappedKeyMaterial)
	}
	ecdh := wrapped.Value
	if aws.ToString(ecdh.CertificateAuthorityPublicKeyIdentifier) != "ca-ref" ||
		aws.ToString(ecdh.PublicKeyCertificate) != base64.StdEncoding.EncodeToString([]byte("client-pem")) ||
		aws.ToString(ecdh.SharedInformation) != "0A0B" ||
		ecdh.KeyAlgorithm != pcdtypes.SymmetricKeyAlgorithmTdes2key ||
		ecdh.KeyDerivationFunction != pcdtypes.KeyDerivationFunctionNistSp800 ||
		ecdh.KeyDerivationHashAlgorithm != pcdtypes.KeyDerivationHashAlgorithmSha512 {
		t.Fatalf("unexpected ECDH attributes: %+v", ecdh)
	}
	for name, attrs := range map[string]pcdtypes.TranslationIsoFormats{
		"incoming": in.IncomingTranslationAttributes,
		"outgoing": in.OutgoingTranslationAttributes,
	} {
		iso0, ok := attrs.(*pcdtypes.TranslationIsoFormatsMemberIsoFormat0)
		if !ok || aws.ToString(iso0.Value.PrimaryAccountNumber) != "4000123456789010" {
			t.Fatalf("%s format must be ISO-0 with the PAN, got %#v", name, attrs)
		}
	}
}
