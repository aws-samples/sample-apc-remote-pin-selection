package pinstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type fakeDynamoDB struct {
	getInput    *dynamodb.GetItemInput
	getOutput   *dynamodb.GetItemOutput
	updateInput *dynamodb.UpdateItemInput
	updateOut   *dynamodb.UpdateItemOutput
}

func (f *fakeDynamoDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.getInput = in
	return f.getOutput, nil
}

func (f *fakeDynamoDB) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.updateInput = in
	return f.updateOut, nil
}

func TestGetUsesConsistentReadAndDecodesVerifier(t *testing.T) {
	stored := item{
		PAN:                "4000123456789010",
		VerificationValue:  "1234",
		PVKIndex:           1,
		VerificationKeyRef: "key-ref",
		Version:            2,
		CreatedAt:          "2026-09-01T00:00:00Z",
		UpdatedAt:          "2026-09-02T00:00:00Z",
	}
	attributes, err := attributevalue.MarshalMap(stored)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeDynamoDB{getOutput: &dynamodb.GetItemOutput{Item: attributes}}
	store, err := NewDynamoDB(client, "pin-table")
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(context.Background(), stored.PAN)
	if err != nil {
		t.Fatal(err)
	}
	if !aws.ToBool(client.getInput.ConsistentRead) {
		t.Fatal("GetItem must use a consistent read")
	}
	if got.PAN != stored.PAN || got.Version != stored.Version || got.VerificationValue != stored.VerificationValue {
		t.Fatalf("unexpected verifier: %+v", got)
	}
}

func TestGetMapsMissingItemToErrNotFound(t *testing.T) {
	client := &fakeDynamoDB{getOutput: &dynamodb.GetItemOutput{}}
	store, err := NewDynamoDB(client, "pin-table")
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPutUsesAtomicVersionIncrementAndReturnsUpdatedItem(t *testing.T) {
	updated := item{
		PAN:                "4000123456789010",
		VerificationValue:  "9876",
		PVKIndex:           1,
		VerificationKeyRef: "key-ref",
		Version:            3,
		CreatedAt:          "2026-09-01T00:00:00Z",
		UpdatedAt:          "2026-09-02T00:00:00Z",
	}
	attributes, err := attributevalue.MarshalMap(updated)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeDynamoDB{updateOut: &dynamodb.UpdateItemOutput{Attributes: attributes}}
	store, err := NewDynamoDB(client, "pin-table")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time {
		return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	}

	got, err := store.Put(context.Background(), Verifier{
		PAN:                updated.PAN,
		VerificationValue:  updated.VerificationValue,
		PVKIndex:           updated.PVKIndex,
		VerificationKeyRef: updated.VerificationKeyRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 3 {
		t.Fatalf("version = %d, want 3", got.Version)
	}
	if client.updateInput.ReturnValues != types.ReturnValueAllNew {
		t.Fatalf("ReturnValues = %q, want ALL_NEW", client.updateInput.ReturnValues)
	}
	expression := aws.ToString(client.updateInput.UpdateExpression)
	for _, fragment := range []string{
		"if_not_exists(version, :zero) + :one",
		"if_not_exists(created_at, :created_at)",
	} {
		if !strings.Contains(expression, fragment) {
			t.Fatalf("update expression %q missing %q", expression, fragment)
		}
	}
}
