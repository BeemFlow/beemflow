package api

import (
	"testing"

	"github.com/beemflow/beemflow/config"
)

func TestInitializeDependencies(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "valid config with sqlite storage",
			cfg: &config.Config{
				Storage: config.StorageConfig{
					Driver: "sqlite",
					DSN:    ":memory:",
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with sqlite storage",
			cfg: &config.Config{
				Storage: config.StorageConfig{
					Driver: "sqlite",
					DSN:    ":memory:",
				},
			},
			wantErr: false,
		},
		{
			name: "config with event bus",
			cfg: &config.Config{
				Storage: config.StorageConfig{
					Driver: "sqlite",
					DSN:    ":memory:",
				},
				Event: &config.EventConfig{
					Driver: "memory",
				},
			},
			wantErr: false,
		},
		{
			name: "config with blob store",
			cfg: &config.Config{
				Storage: config.StorageConfig{
					Driver: "sqlite",
					DSN:    ":memory:",
				},
				Blob: &config.BlobConfig{
					Driver: "filesystem",
					Bucket: "/tmp/test-blobs",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid storage driver",
			cfg: &config.Config{
				Storage: config.StorageConfig{
					Driver: "invalid",
					DSN:    "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup, err := InitializeDependencies(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeDependencies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && cleanup == nil {
				t.Error("InitializeDependencies() returned nil cleanup function")
				return
			}

			if cleanup != nil {
				// Test that cleanup function doesn't panic
				cleanup()
			}
		})
	}
}

func TestInitializeDependencies_NilConfig(t *testing.T) {
	// Test that function doesn't panic with minimal config
	cfg := &config.Config{}
	cleanup, err := InitializeDependencies(cfg)

	if err != nil {
		t.Errorf("InitializeDependencies() with empty config failed: %v", err)
	}

	if cleanup != nil {
		cleanup()
	}
}

func TestInitializeDependencies_EventBusError(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Driver: "sqlite",
			DSN:    ":memory:",
		},
		Event: &config.EventConfig{
			Driver: "invalid-driver",
		},
	}

	cleanup, err := InitializeDependencies(cfg)

	// Should not error even if event bus fails (fallback to in-memory)
	if err != nil {
		t.Errorf("InitializeDependencies() should not error on event bus failure: %v", err)
	}

	if cleanup != nil {
		cleanup()
	}
}

func TestInitializeDependencies_BlobStoreError(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Driver: "sqlite",
			DSN:    ":memory:",
		},
		Blob: &config.BlobConfig{
			Driver: "invalid-driver",
			Bucket: "test",
		},
	}

	cleanup, err := InitializeDependencies(cfg)

	// Should not error even if blob store fails (fallback to nil)
	if err != nil {
		t.Errorf("InitializeDependencies() should not error on blob store failure: %v", err)
	}

	if cleanup != nil {
		cleanup()
	}
}
