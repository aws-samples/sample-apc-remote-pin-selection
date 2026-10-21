// Command backend is the issuer backend for the remote PIN selection demo.
//
// It wires together:
//
//	AWS Private CA              issues the app's short-lived client certificate
//	AWS Payment Cryptography    provides the agreement certificate and translates
//	                            the PIN block into the processor's PEK domain
//	processor (stand-in)        generates and stores the PVV, and verifies PINs;
//	                            in production this is the banking system or processor
//
// Configuration comes from environment variables in backend/.env (see the
// README setup steps). AWS credentials and region come from the standard AWS SDK
// chain (environment, shared config, or SSO).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"remote-pin-selection/backend/apc"
	"remote-pin-selection/backend/ca"
	"remote-pin-selection/backend/flowlog"
	"remote-pin-selection/backend/handler"
	"remote-pin-selection/backend/operation"
	"remote-pin-selection/backend/pinstore"
	"remote-pin-selection/backend/processor"
)

const (
	// operationTTL bounds the whole begin -> CSR -> submit sequence.
	operationTTL = 5 * time.Minute
	// clientCertValidity is the lifetime of each app certificate. It only
	// needs to outlive the operation that requested it.
	clientCertValidity = 15 * time.Minute
	// defaultAllowedOrigins is where the README serves the web app.
	defaultAllowedOrigins = "http://localhost:8081,http://127.0.0.1:8081"
)

func main() {
	if err := flowlog.Configure(os.Getenv("LOG_LEVEL")); err != nil {
		log.Fatal(err)
	}
	if err := flowlog.ConfigureSensitive(os.Getenv("DEMO_LOG_SENSITIVE_VALUES")); err != nil {
		log.Fatal(err)
	}
	if flowlog.SensitiveEnabled() {
		log.Println("WARNING: sensitive demo logging is on. Use synthetic PANs and test PINs only.")
	}

	env, err := loadEnv()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("load AWS config: %v", err)
	}
	if awsCfg.Region == "" {
		log.Fatal("no AWS Region configured; set AWS_REGION in backend/.env")
	}

	// Issuer side: Payment Cryptography and AWS Private CA.
	paymentCrypto := apc.New(awsCfg, apc.Config{
		KeyAgreementKeyArn: env.keyAgreementKeyArn,
		PekArn:             env.pekArn,
		CAPublicKeyArn:     env.caPublicKeyArn,
		PvkArn:             env.pvkArn,
		PvkIndex:           env.pvkIndex,
	})
	privateCA := &ca.PrivateCA{
		Client: acmpca.NewFromConfig(awsCfg),
		CAArn:  env.privateCAArn,
		// The setup script creates an EC_prime256v1 CA.
		SigningAlgorithm: pcatypes.SigningAlgorithmSha256withecdsa,
		Validity:         clientCertValidity,
	}

	// Processor side (stand-in): PVV generation and a DynamoDB verifier table.
	dynamo := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if env.dynamoEndpoint != "" {
			o.BaseEndpoint = aws.String(env.dynamoEndpoint) // DynamoDB Local
		}
	})
	store, err := pinstore.NewDynamoDB(dynamo, env.verifierTable)
	if err != nil {
		log.Fatal(err)
	}
	proc := &processor.Processor{
		APC:      paymentCrypto,
		Store:    store,
		PvkArn:   env.pvkArn,
		PvkIndex: env.pvkIndex,
	}

	api := &handler.API{
		APC:        paymentCrypto,
		CA:         privateCA,
		Operations: operation.NewStore(operationTTL),
		Processor:  proc,
	}
	mux := http.NewServeMux()
	api.Register(mux)

	log.Printf("Issuer backend listening on %s (region %s, log level %s)", env.addr, awsCfg.Region, flowlog.Level())
	// Timeouts stop slow clients from holding connections open.
	server := &http.Server{
		Addr:              env.addr,
		Handler:           withCORS(mux, env.allowedOrigins),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type settings struct {
	addr               string
	privateCAArn       string
	keyAgreementKeyArn string
	pekArn             string
	caPublicKeyArn     string
	pvkArn             string
	pvkIndex           int32
	verifierTable      string
	dynamoEndpoint     string
	allowedOrigins     []string
}

// loadEnv reads the settings from backend/.env and reports every
// missing required value at once.
func loadEnv() (settings, error) {
	var missing []string
	required := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}

	s := settings{
		addr:               getenv("BACKEND_ADDR", "127.0.0.1:8080"),
		privateCAArn:       required("PRIVATE_CA_ARN"),
		keyAgreementKeyArn: required("APC_KEY_AGREEMENT_KEY_ARN"),
		pekArn:             required("APC_PEK_ARN"),
		caPublicKeyArn:     required("APC_CA_PUBLIC_KEY_ARN"),
		pvkArn:             required("APC_PVK_ARN"),
		verifierTable:      required("PIN_VERIFIER_TABLE_NAME"),
		dynamoEndpoint:     os.Getenv("DYNAMODB_ENDPOINT"),
		allowedOrigins:     splitList(getenv("ALLOWED_ORIGINS", defaultAllowedOrigins)),
	}
	if len(missing) > 0 {
		return settings{}, fmt.Errorf("missing required settings: %s (see the README setup steps)", strings.Join(missing, ", "))
	}

	index, err := strconv.Atoi(getenv("APC_PVK_INDEX", "1"))
	if err != nil || index < 0 || index > 9 {
		return settings{}, fmt.Errorf("APC_PVK_INDEX must be a digit 0-9")
	}
	s.pvkIndex = int32(index)
	return s, nil
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// splitList parses a comma-separated setting, ignoring empty entries.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// withCORS lets the Flutter web app, served from another origin, call the API.
// Only the listed origins get CORS headers, and preflight requests from any
// other origin are refused. CORS restricts browsers only; it is not
// authentication.
func withCORS(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		ok := origin != "" && allowed[origin]
		if ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
