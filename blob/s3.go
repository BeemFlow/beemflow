package blob

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/beemflow/beemflow/utils"
)

// S3BlobStore implements BlobStore using AWS S3.
// This is NOT the default. Use only if configured explicitly.
type S3BlobStore struct {
	client *s3.Client
	bucket string
	region string
}

// NewS3BlobStore creates a new S3BlobStore using the provided context.
func NewS3BlobStore(ctx context.Context, bucket, region string) (*S3BlobStore, error) {
	if bucket == "" || region == "" {
		return nil, utils.Errorf("bucket and region must be non-empty")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)
	return &S3BlobStore{client: client, bucket: bucket, region: region}, nil
}

// Put uploads data to S3 and returns its URL.
func (s *S3BlobStore) Put(ctx context.Context, data []byte, mime, filename string) (string, error) {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(filename),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mime),
		ACL:         types.ObjectCannedACLPrivate,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("s3://%s/%s", s.bucket, filename), nil
}

// Get retrieves data from S3 by URL.
func (s *S3BlobStore) Get(ctx context.Context, url string) ([]byte, error) {
	// Expect url format: s3://bucket/key
	var bucket, key string
	_, err := fmt.Sscanf(url, "s3://%[^/]/%s", &bucket, &key)
	if err != nil {
		return nil, err
	}
	if bucket != s.bucket {
		return nil, fmt.Errorf("requested bucket %s does not match configured bucket %s", bucket, s.bucket)
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
