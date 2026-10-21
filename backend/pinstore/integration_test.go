package pinstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Runs against DynamoDB Local: docker compose -f docker-compose.local.yaml up -d
// then DYNAMODB_ENDPOINT=http://localhost:8000 go test ./pinstore/
func TestDynamoDBLocalPutGetAndVersionIncrement(t *testing.T) {
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT is not set")
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
		options.BaseEndpoint = aws.String(endpoint)
	})
	table := fmt.Sprintf("pin-verifiers-test-%d", time.Now().UnixNano())
	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pan"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pan"), KeyType: types.KeyTypeHash},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
			TableName: aws.String(table),
		})
	})
	if err := dynamodb.NewTableExistsWaiter(client).Wait(
		ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(table)},
		30*time.Second,
	); err != nil {
		t.Fatal(err)
	}

	store, err := NewDynamoDB(client, table)
	if err != nil {
		t.Fatal(err)
	}
	input := Verifier{
		PAN:                "4000123456789010",
		VerificationValue:  "1234",
		PVKIndex:           1,
		VerificationKeyRef: "pvk-ref",
	}
	first, err := store.Put(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	input.VerificationValue = "9876"
	second, err := store.Put(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, input.PAN)
	if err != nil {
		t.Fatal(err)
	}

	if first.Version != 1 || second.Version != 2 || got.Version != 2 {
		t.Fatalf("versions: first=%d second=%d get=%d", first.Version, second.Version, got.Version)
	}
	if got.VerificationValue != "9876" || got.CreatedAt != first.CreatedAt {
		t.Fatalf("unexpected stored verifier: %+v", got)
	}
}
