package pinstore

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoDBAPI is the subset of the DynamoDB client used by the store.
type DynamoDBAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// DynamoDBStore keeps verifier records in a table keyed by pan.
type DynamoDBStore struct {
	client DynamoDBAPI
	table  string
	now    func() time.Time
}

type item struct {
	PAN                string `dynamodbav:"pan"`
	VerificationValue  string `dynamodbav:"verification_value"`
	PVKIndex           int32  `dynamodbav:"pvk_index"`
	VerificationKeyRef string `dynamodbav:"verification_key_ref"`
	Version            int64  `dynamodbav:"version"`
	CreatedAt          string `dynamodbav:"created_at"`
	UpdatedAt          string `dynamodbav:"updated_at"`
}

// NewDynamoDB returns a store for the named table.
func NewDynamoDB(client DynamoDBAPI, table string) (*DynamoDBStore, error) {
	if client == nil {
		return nil, fmt.Errorf("DynamoDB client is required")
	}
	if table == "" {
		return nil, fmt.Errorf("PIN verifier table name is required")
	}
	return &DynamoDBStore{client: client, table: table, now: time.Now}, nil
}

// Get reads the verifier for pan with a strongly consistent read, so a
// validation right after enrollment sees the new PVV.
func (s *DynamoDBStore) Get(ctx context.Context, pan string) (Verifier, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"pan": &types.AttributeValueMemberS{Value: pan},
		},
	})
	if err != nil {
		return Verifier{}, fmt.Errorf("get PIN verifier: %w", err)
	}
	if len(out.Item) == 0 {
		return Verifier{}, ErrNotFound
	}

	var stored item
	if err := attributevalue.UnmarshalMap(out.Item, &stored); err != nil {
		return Verifier{}, fmt.Errorf("decode PIN verifier: %w", err)
	}
	return stored.verifier()
}

// Put creates or replaces the verifier for verifier.PAN in one atomic
// UpdateItem. created_at is kept from the first enrollment, and version is
// incremented, so a PIN reset is visible in the record.
func (s *DynamoDBStore) Put(ctx context.Context, verifier Verifier) (Verifier, error) {
	now := s.now().UTC().Format(time.RFC3339)
	values, err := attributevalue.MarshalMap(map[string]any{
		":verification_value":   verifier.VerificationValue,
		":pvk_index":            verifier.PVKIndex,
		":verification_key_ref": verifier.VerificationKeyRef,
		":created_at":           now,
		":updated_at":           now,
		":zero":                 int64(0),
		":one":                  int64(1),
	})
	if err != nil {
		return Verifier{}, fmt.Errorf("encode PIN verifier: %w", err)
	}

	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"pan": &types.AttributeValueMemberS{Value: verifier.PAN},
		},
		UpdateExpression: aws.String(
			"SET verification_value = :verification_value, " +
				"pvk_index = :pvk_index, verification_key_ref = :verification_key_ref, " +
				"created_at = if_not_exists(created_at, :created_at), " +
				"updated_at = :updated_at, version = if_not_exists(version, :zero) + :one",
		),
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
	})
	if err != nil {
		return Verifier{}, fmt.Errorf("put PIN verifier: %w", err)
	}

	var stored item
	if err := attributevalue.UnmarshalMap(out.Attributes, &stored); err != nil {
		return Verifier{}, fmt.Errorf("decode updated PIN verifier: %w", err)
	}
	return stored.verifier()
}

func (i item) verifier() (Verifier, error) {
	createdAt, err := time.Parse(time.RFC3339, i.CreatedAt)
	if err != nil {
		return Verifier{}, fmt.Errorf("decode created_at: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339, i.UpdatedAt)
	if err != nil {
		return Verifier{}, fmt.Errorf("decode updated_at: %w", err)
	}
	return Verifier{
		PAN:                i.PAN,
		VerificationValue:  i.VerificationValue,
		PVKIndex:           i.PVKIndex,
		VerificationKeyRef: i.VerificationKeyRef,
		Version:            i.Version,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
	}, nil
}
