package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

type fakePCA struct {
	issueInput    *acmpca.IssueCertificateInput
	issueCalls    int
	pendingPolls  int
	getCalls      int
	getErr        error
	certificate   string
	certificateID string
}

func (f *fakePCA) IssueCertificate(_ context.Context, in *acmpca.IssueCertificateInput, _ ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error) {
	f.issueCalls++
	f.issueInput = in
	return &acmpca.IssueCertificateOutput{CertificateArn: aws.String(f.certificateID)}, nil
}

func (f *fakePCA) GetCertificate(_ context.Context, in *acmpca.GetCertificateInput, _ ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getCalls <= f.pendingPolls {
		return nil, &types.RequestInProgressException{}
	}
	return &acmpca.GetCertificateOutput{Certificate: aws.String(f.certificate)}, nil
}

func csrPEM(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "remote-pin-demo-app"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueRequestsShortLivedEndEntityCertificateAndPolls(t *testing.T) {
	fake := &fakePCA{pendingPolls: 2, certificate: "leaf-pem", certificateID: "cert-arn"}
	now := time.Unix(1_700_000_000, 0)
	p := &PrivateCA{
		Client:           fake,
		CAArn:            "ca-arn",
		SigningAlgorithm: types.SigningAlgorithmSha256withecdsa,
		Validity:         15 * time.Minute,
		PollInterval:     time.Millisecond,
		now:              func() time.Time { return now },
	}

	got, err := p.Issue(context.Background(), csrPEM(t, elliptic.P256()), "operation-id")
	if err != nil {
		t.Fatal(err)
	}
	if got != "leaf-pem" {
		t.Fatalf("certificate = %q", got)
	}
	if fake.getCalls != 3 {
		t.Fatalf("GetCertificate calls = %d, want 3 (two in progress, one success)", fake.getCalls)
	}

	in := fake.issueInput
	if aws.ToString(in.TemplateArn) != endEntityTemplateArn ||
		aws.ToString(in.CertificateAuthorityArn) != "ca-arn" ||
		aws.ToString(in.IdempotencyToken) != "operation-id" ||
		in.SigningAlgorithm != types.SigningAlgorithmSha256withecdsa {
		t.Fatalf("unexpected IssueCertificate input: %+v", in)
	}
	if in.Validity.Type != types.ValidityPeriodTypeAbsolute ||
		aws.ToInt64(in.Validity.Value) != now.Add(15*time.Minute).Unix() {
		t.Fatalf("unexpected validity: %+v", in.Validity)
	}
}

func TestIssueRejectsNonP256CSRWithoutCallingAWS(t *testing.T) {
	fake := &fakePCA{}
	p := &PrivateCA{Client: fake, Validity: time.Minute}

	if _, err := p.Issue(context.Background(), csrPEM(t, elliptic.P384()), "id"); err == nil {
		t.Fatal("expected P-384 CSR to be rejected")
	}
	if _, err := p.Issue(context.Background(), []byte("not a csr"), "id"); err == nil {
		t.Fatal("expected malformed CSR to be rejected")
	}
	if fake.issueCalls != 0 {
		t.Fatalf("IssueCertificate calls = %d, want 0", fake.issueCalls)
	}
}

func TestIssueStopsOnNonRetryableError(t *testing.T) {
	fake := &fakePCA{getErr: errors.New("access denied"), certificateID: "cert-arn"}
	p := &PrivateCA{Client: fake, Validity: time.Minute, PollInterval: time.Millisecond}

	if _, err := p.Issue(context.Background(), csrPEM(t, elliptic.P256()), "id"); err == nil {
		t.Fatal("expected error")
	}
	if fake.getCalls != 1 {
		t.Fatalf("GetCertificate calls = %d, want 1", fake.getCalls)
	}
}

func TestIssueGivesUpAfterPollTimeout(t *testing.T) {
	fake := &fakePCA{pendingPolls: 1 << 30, certificateID: "cert-arn"}
	p := &PrivateCA{
		Client:       fake,
		Validity:     time.Minute,
		PollInterval: time.Millisecond,
		PollTimeout:  20 * time.Millisecond,
	}

	if _, err := p.Issue(context.Background(), csrPEM(t, elliptic.P256()), "id"); err == nil {
		t.Fatal("expected timeout error")
	}
}
