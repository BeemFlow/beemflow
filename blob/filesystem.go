package blob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/beemflow/beemflow/utils"
)

// FilesystemBlobStore implements BlobStore using the local filesystem.
// This is the default and recommended blob store for local/dev/prod.
type FilesystemBlobStore struct {
	dir string
}

// NewFilesystemBlobStore creates a new FilesystemBlobStore with the given directory.
// The directory will be created if it does not exist.
func NewFilesystemBlobStore(dir string) (*FilesystemBlobStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FilesystemBlobStore{dir: dir}, nil
}

// Put stores the blob as a file in the directory. Returns a file:// URL.
func (f *FilesystemBlobStore) Put(ctx context.Context, data []byte, mime, filename string) (string, error) {
	if filename == "" {
		filename = fmt.Sprintf("blob-%d", time.Now().UnixNano())
	}
	path := filepath.Join(f.dir, filename)
	// Write atomically
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}
	return "file://" + path, nil
}

// Get retrieves the blob from the file:// URL.
func (f *FilesystemBlobStore) Get(ctx context.Context, url string) ([]byte, error) {
	const prefix = "file://"
	if !strings.HasPrefix(url, prefix) {
		return nil, utils.Errorf("invalid file URL: %s", url)
	}
	path := url[len(prefix):]
	return os.ReadFile(path)
}
