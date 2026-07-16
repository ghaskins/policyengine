//
//  Copyright © Manetu Inc. All rights reserved.
//

package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config carries the same connection knobs as mpe-iam-lite's
// notary/anchor/s3.clj create-anchor-store: an explicit endpoint override for
// S3-compatible stores (MinIO, Ceph RGW, ...), path-style addressing for
// those endpoints, static credentials, and an optional pinned CA cert.
type S3Config struct {
	Bucket          string
	Region          string // required when Endpoint is empty (the SDK derives the regional endpoint from it)
	Endpoint        string // e.g. "https://minio.internal:9000"; empty selects the standard AWS endpoint
	AccessKeyID     string
	SecretAccessKey string
	PathStyleAccess bool
	CACertPath      string // PEM CA bundle to pin TLS trust; empty uses the system trust store
}

// NewS3Client builds an S3Client backed by a real aws-sdk-go-v2 client.
func NewS3Client(ctx context.Context, cfg S3Config) (*S3Client, error) {
	if cfg.Endpoint == "" && cfg.Region == "" {
		return nil, fmt.Errorf("scan: s3 config requires an explicit Region when Endpoint is empty")
	}
	httpClient := &http.Client{}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("scan: s3 config: failed to read CACertPath: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("scan: s3 config: CACertPath does not contain a valid PEM certificate")
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1" // endpoint override present; region only labels SigV4 signing
	}

	client := s3.New(s3.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		HTTPClient:   httpClient,
		UsePathStyle: cfg.PathStyleAccess,
		BaseEndpoint: nonEmptyPtr(cfg.Endpoint),
	})
	return &S3Client{Client: client, Bucket: cfg.Bucket}, nil
}

func nonEmptyPtr(s string) *string {
	if s == "" {
		return nil
	}
	return aws.String(s)
}

// ImmudbConfig carries the same connection knobs as mpe-iam-lite's
// notary/anchor/immudb.clj create-anchor-store.
type ImmudbConfig struct {
	Host          string
	Port          int
	Database      string
	Username      string
	Password      string
	CACertPath    string // PEM CA bundle to pin TLS trust; empty + AllowInsecure selects plain HTTP
	AllowInsecure bool
}

// NewImmudbClient builds an ImmudbClient. If CACertPath is set, the base URL
// is https:// with trust pinned to that CA; otherwise AllowInsecure must be
// true to select plain http:// (immudb's login sends credentials in the
// request body, so plaintext transport exposes them to any network
// observer -- refuse-unless-flag, mirroring the Clojure anchor store).
func NewImmudbClient(cfg ImmudbConfig) (*ImmudbClient, error) {
	httpClient := &http.Client{}
	scheme := "http"
	switch {
	case cfg.CACertPath != "":
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("scan: immudb config: failed to read CACertPath: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("scan: immudb config: CACertPath does not contain a valid PEM certificate")
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
		scheme = "https"
	case cfg.AllowInsecure:
		// plain http, as requested
	default:
		return nil, fmt.Errorf("scan: refusing to create an immudb client over plain HTTP: set CACertPath, or AllowInsecure for development")
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, cfg.Port)
	return &ImmudbClient{
		BaseURL:    baseURL,
		Database:   cfg.Database,
		Username:   cfg.Username,
		Password:   cfg.Password,
		HTTPClient: httpClient,
	}, nil
}
