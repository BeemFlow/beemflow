package blob

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/utils"
)

func TestMain(m *testing.M) {
	os.Exit(utils.WithCleanDirs(m, ".beemflow", config.DefaultConfigDir))
}

func newTestFilesystemBlobStore(t *testing.T) *FilesystemBlobStore {
	dir := filepath.Join(t.TempDir(), t.Name()+"-blobstore")
	store, err := NewFilesystemBlobStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemBlobStore failed: %v", err)
	}
	return store
}

func TestFilesystemBlobStore_RoundTrip(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	value := []byte("test-data")
	mime := "text/plain"
	filename := "test.txt"
	url, err := store.Put(context.Background(), value, mime, filename)
	if err != nil {
		t.Errorf("Put failed: %v", err)
	}
	got, err := store.Get(context.Background(), url)
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("expected %q, got %q", value, got)
	}
}

func TestFilesystemBlobStore_EmptyData(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	url, err := store.Put(context.Background(), []byte{}, "text/plain", "empty.txt")
	if err != nil {
		t.Errorf("Put failed for empty data: %v", err)
	}
	got, err := store.Get(context.Background(), url)
	if err != nil {
		t.Errorf("Get failed for empty data: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty data, got %v bytes", len(got))
	}
}

func TestFilesystemBlobStore_GetUnknownURL(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	_, err := store.Get(context.Background(), "file:///does/not/exist.txt")
	if err == nil {
		t.Errorf("expected error for unknown file, got nil")
	}
}

func TestFilesystemBlobStore_Concurrency(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	done := make(chan bool, 2)
	go func() {
		if _, err := store.Put(context.Background(), []byte("a"), "text/plain", "a.txt"); err != nil {
			t.Errorf("Put failed: %v", err)
		}
		if _, err := store.Get(context.Background(), "file://"+store.dir+"/a.txt"); err != nil {
			t.Errorf("Get failed: %v", err)
		}
		done <- true
	}()
	go func() {
		if _, err := store.Put(context.Background(), []byte("b"), "text/plain", "b.txt"); err != nil {
			t.Errorf("Put failed: %v", err)
		}
		if _, err := store.Get(context.Background(), "file://"+store.dir+"/b.txt"); err != nil {
			t.Errorf("Get failed: %v", err)
		}
		done <- true
	}()
	<-done
	<-done
}

func TestFilesystemBlobStore_DoubleStore(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	_, err1 := store.Put(context.Background(), []byte("first"), "text/plain", "dup.txt")
	_, err2 := store.Put(context.Background(), []byte("second"), "text/plain", "dup.txt")
	if err1 != nil || err2 != nil {
		t.Errorf("expected no error for double store, got %v, %v", err1, err2)
	}
}

func TestFilesystemBlobStore_ErrorCase(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	url, err := store.Put(context.Background(), nil, "", "errorcase.txt")
	if err != nil {
		t.Errorf("expected no error for nil input, got %v", err)
	}
	got, err := store.Get(context.Background(), url)
	if err != nil {
		t.Errorf("Get failed for errorcase.txt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty data, got %v bytes", len(got))
	}
}

func TestFilesystemBlobStore_InvalidURL(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	_, err := store.Get(context.Background(), "not-a-file-url")
	if err == nil {
		t.Errorf("expected error for invalid file URL, got nil")
	}
}

func TestFilesystemBlobStore_EmptyFilename(t *testing.T) {
	store := newTestFilesystemBlobStore(t)

	// Test with empty filename - should generate a unique filename
	url, err := store.Put(context.Background(), []byte("test data"), "text/plain", "")
	if err != nil {
		t.Errorf("Put with empty filename failed: %v", err)
	}

	if url == "" {
		t.Error("Expected non-empty URL for empty filename")
	}

	// Should be able to retrieve the data
	got, err := store.Get(context.Background(), url)
	if err != nil {
		t.Errorf("Get failed for auto-generated filename: %v", err)
	}

	expected := []byte("test data")
	if !bytes.Equal(got, expected) {
		t.Errorf("Expected %q, got %q", expected, got)
	}
}

// Tests for NewDefaultBlobStore function

func TestNewDefaultBlobStore(t *testing.T) {
	ctx := context.Background()

	// Test with nil config (should default to filesystem)
	store, err := NewDefaultBlobStore(ctx, nil)
	if err != nil {
		t.Errorf("NewDefaultBlobStore with nil config should not fail, got: %v", err)
	}
	if store == nil {
		t.Error("Expected non-nil store")
	}

	// Test with empty config (should default to filesystem)
	cfg := &BlobConfig{}
	store, err = NewDefaultBlobStore(ctx, cfg)
	if err != nil {
		t.Errorf("NewDefaultBlobStore with empty config should not fail, got: %v", err)
	}
	if store == nil {
		t.Error("Expected non-nil store")
	}

	// Test with filesystem driver using temp directory
	cfg = &BlobConfig{
		Driver:    "filesystem",
		Directory: filepath.Join(t.TempDir(), "test-blobs"),
	}
	store, err = NewDefaultBlobStore(ctx, cfg)
	if err != nil {
		t.Errorf("NewDefaultBlobStore with filesystem config should not fail, got: %v", err)
	}
	if store == nil {
		t.Error("Expected non-nil store")
	}

	// Test with s3 driver but missing bucket
	cfg = &BlobConfig{
		Driver: "s3",
		Region: "us-west-2",
	}
	store, err = NewDefaultBlobStore(ctx, cfg)
	if err == nil {
		t.Error("NewDefaultBlobStore with S3 config missing bucket should fail")
	}
	if store != nil {
		t.Error("Expected nil store for invalid S3 config")
	}

	// Test with unsupported driver
	cfg = &BlobConfig{
		Driver: "unsupported",
	}
	store, err = NewDefaultBlobStore(ctx, cfg)
	if err == nil {
		t.Error("NewDefaultBlobStore with unsupported driver should fail")
	}
	if store != nil {
		t.Error("Expected nil store for unsupported driver")
	}
}

func TestNewFilesystemBlobStore_ErrorCases(t *testing.T) {
	// Test with invalid directory paths
	testCases := []struct {
		name string
		dir  string
	}{
		{"empty directory", ""},
		{"root directory", "/"},
		{"directory with null byte", "/tmp/test\x00"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewFilesystemBlobStore(tc.dir)
			if tc.dir == "" {
				// Empty directory should fail
				if err == nil {
					t.Error("Expected error for empty directory")
				}
				if store != nil {
					t.Error("Expected nil store for empty directory")
				}
			} else {
				// Other cases may or may not fail depending on OS permissions
				// but shouldn't panic
				t.Logf("NewFilesystemBlobStore with %s: err=%v, store=%v", tc.name, err, store != nil)
			}
		})
	}
}

func TestFilesystemBlobStore_AdvancedErrorCases(t *testing.T) {
	store := newTestFilesystemBlobStore(t)

	ctx := context.Background()

	// Test Get with various invalid URLs
	invalidURLs := []string{
		"",                        // Empty URL
		"http://example.com/file", // Wrong scheme
		"file://",                 // Missing path
		"file:///\x00invalid",     // Invalid characters
		"not-a-url",               // No scheme
	}

	for _, url := range invalidURLs {
		t.Run("invalid_url_"+url, func(t *testing.T) {
			_, err := store.Get(ctx, url)
			if err == nil {
				t.Errorf("Expected error for invalid URL %s", url)
			}
		})
	}

	// Test Put with edge case filenames
	edgeCaseFilenames := []string{
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"file.with.dots.txt",
		"UPPERCASE.TXT",
		"123numeric.txt",
		"very-long-filename-that-might-cause-issues-in-some-filesystems-but-should-still-work.txt",
	}

	for _, filename := range edgeCaseFilenames {
		t.Run("edge_filename_"+filename, func(t *testing.T) {
			data := []byte("test data for " + filename)
			url, err := store.Put(ctx, data, "text/plain", filename)
			if err != nil {
				t.Errorf("Put failed for filename %s: %v", filename, err)
				return
			}

			retrieved, err := store.Get(ctx, url)
			if err != nil {
				t.Errorf("Get failed for filename %s: %v", filename, err)
				return
			}

			if !bytes.Equal(data, retrieved) {
				t.Errorf("Data mismatch for filename %s", filename)
			}
		})
	}
}

func TestFilesystemBlobStore_LargeData(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	ctx := context.Background()

	// Test with large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	url, err := store.Put(ctx, largeData, "application/octet-stream", "large_file.bin")
	if err != nil {
		t.Fatalf("Put failed for large data: %v", err)
	}

	retrieved, err := store.Get(ctx, url)
	if err != nil {
		t.Fatalf("Get failed for large data: %v", err)
	}

	if len(retrieved) != len(largeData) {
		t.Errorf("Size mismatch: expected %d bytes, got %d bytes", len(largeData), len(retrieved))
	}

	if !bytes.Equal(largeData, retrieved) {
		t.Error("Large data content mismatch")
	}
}

func TestFilesystemBlobStore_MimeTypes(t *testing.T) {
	store := newTestFilesystemBlobStore(t)
	ctx := context.Background()

	// Test various MIME types
	mimeTypes := []string{
		"text/plain",
		"application/json",
		"image/jpeg",
		"video/mp4",
		"application/pdf",
		"text/html; charset=utf-8",
		"", // Empty MIME type
	}

	for _, mime := range mimeTypes {
		t.Run("mime_"+mime, func(t *testing.T) {
			data := []byte("test data for " + mime)
			filename := "test_" + filepath.Base(mime) + ".file"

			url, err := store.Put(ctx, data, mime, filename)
			if err != nil {
				t.Errorf("Put failed for MIME type %s: %v", mime, err)
				return
			}

			retrieved, err := store.Get(ctx, url)
			if err != nil {
				t.Errorf("Get failed for MIME type %s: %v", mime, err)
				return
			}

			if !bytes.Equal(data, retrieved) {
				t.Errorf("Data mismatch for MIME type %s", mime)
			}
		})
	}
}

func TestFilesystemBlobStore_DirectoryStructure(t *testing.T) {
	// Test that the blob store properly creates directory structure
	tempDir := t.TempDir()
	blobDir := filepath.Join(tempDir, "nested", "blob", "directory")

	store, err := NewFilesystemBlobStore(blobDir)
	if err != nil {
		t.Fatalf("NewFilesystemBlobStore failed: %v", err)
	}

	ctx := context.Background()
	data := []byte("test data")

	url, err := store.Put(ctx, data, "text/plain", "test.txt")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify the directory was created
	if _, err := os.Stat(blobDir); os.IsNotExist(err) {
		t.Error("Blob directory was not created")
	}

	// Verify we can retrieve the data
	retrieved, err := store.Get(ctx, url)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(data, retrieved) {
		t.Error("Data mismatch")
	}
}

func TestBlobConfig_AllFieldsCovered(t *testing.T) {
	// Test that all BlobConfig fields are properly used
	ctx := context.Background()

	// Test with all fields set for filesystem
	cfg := &BlobConfig{
		Driver:    "filesystem",
		Directory: t.TempDir(),
		Bucket:    "ignored-for-filesystem",
		Region:    "ignored-for-filesystem",
	}

	store, err := NewDefaultBlobStore(ctx, cfg)
	if err != nil {
		t.Errorf("NewDefaultBlobStore with complete filesystem config failed: %v", err)
	}
	if store == nil {
		t.Error("Expected non-nil store")
	}

	// Test filesystem store functionality
	data := []byte("test data")
	url, err := store.Put(ctx, data, "text/plain", "test.txt")
	if err != nil {
		t.Errorf("Put failed: %v", err)
	}

	retrieved, err := store.Get(ctx, url)
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}

	if !bytes.Equal(data, retrieved) {
		t.Error("Data mismatch")
	}
}
