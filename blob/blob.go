package blob

import (
	"context"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/utils"
)

// BlobStore is the interface for pluggable blob storage backends.
type BlobStore interface {
	Put(ctx context.Context, data []byte, mime, filename string) (url string, err error)
	Get(ctx context.Context, url string) ([]byte, error)
}

// See filesystem.go and s3.go for driver implementations.

// BlobConfig is a minimal struct for blob store configuration.
type BlobConfig struct {
	Driver    string
	Directory string
	Bucket    string
	Region    string
}

// NewDefaultBlobStore returns a BlobStore based on config, or FilesystemBlobStore in ./beemflow-files if config is nil or empty.
func NewDefaultBlobStore(ctx context.Context, cfg *BlobConfig) (BlobStore, error) {
	if cfg == nil || cfg.Driver == "" || cfg.Driver == "filesystem" {
		dir := config.DefaultBlobDir
		if cfg != nil && cfg.Directory != "" {
			dir = cfg.Directory
		}
		return NewFilesystemBlobStore(dir)
	}
	if cfg.Driver == "s3" {
		if cfg.Bucket == "" || cfg.Region == "" {
			return nil, utils.Errorf("s3 driver requires bucket and region")
		}
		return NewS3BlobStore(ctx, cfg.Bucket, cfg.Region)
	}
	return nil, utils.Errorf("unsupported blob driver: %s", cfg.Driver)
}
