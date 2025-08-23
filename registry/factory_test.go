package registry

import (
	"context"
	"testing"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
)

func TestRegistryFactory_CreateStandardManager(t *testing.T) {
	factory := NewFactory()
	ctx := context.Background()

	// Test with nil config
	mgr := factory.CreateStandardManager(ctx, nil)
	if mgr == nil {
		t.Fatal("Expected manager, got nil")
	}

	// Verify it includes default registry
	stats := mgr.GetRegistryStats(ctx)
	if _, hasDefault := stats["*registry.DefaultRegistry"]; !hasDefault {
		t.Error("Expected default registry in manager")
	}

	// Test with config containing remote registry
	cfg := &config.Config{
		Registries: []config.RegistryConfig{
			{
				Type: "remote",
				URL:  "http://example.com/registry.json",
			},
		},
	}

	mgr2 := factory.CreateStandardManager(ctx, cfg)
	stats2 := mgr2.GetRegistryStats(ctx)

	// Should have at least builtin registry
	if len(stats2) == 0 {
		t.Error("Expected at least one registry in manager")
	}
}

func TestRegistryFactory_CreateAPIManager(t *testing.T) {
	factory := NewFactory()

	mgr := factory.CreateAPIManager()
	if mgr == nil {
		t.Fatal("Expected API manager, got nil")
	}

	// Should be lightweight with just builtin + local
	stats := mgr.GetRegistryStats(context.Background())
	if len(stats) == 0 {
		t.Error("Expected registries in API manager")
	}
}

func TestRegistryFactory_GetLocalRegistryPath(t *testing.T) {
	factory := NewFactory()

	// Test with nil config
	path := factory.getLocalRegistryPath(nil)
	if path == "" {
		t.Error("Expected default path for nil config")
	}

	// Test with config override
	cfg := &config.Config{
		Registries: []config.RegistryConfig{
			{
				Type: constants.LocalRegistryType,
				Path: "/custom/path/registry.json",
			},
		},
	}

	customPath := factory.getLocalRegistryPath(cfg)
	if customPath != "/custom/path/registry.json" {
		t.Errorf("Expected custom path, got %s", customPath)
	}
}

func TestRegistryFactory_HasHubRegistry(t *testing.T) {
	factory := NewFactory()

	// Test with nil config
	if factory.hasHubRegistry(nil) {
		t.Error("Expected false for nil config")
	}

	// Test with hub registry configured
	cfg := &config.Config{
		Registries: []config.RegistryConfig{
			{
				Type: "remote",
				URL:  "https://hub.beemflow.com/index.json",
			},
		},
	}

	if !factory.hasHubRegistry(cfg) {
		t.Error("Expected true when hub registry is configured")
	}

	// Test with different remote registry
	cfg2 := &config.Config{
		Registries: []config.RegistryConfig{
			{
				Type: "remote",
				URL:  "https://other.example.com/registry.json",
			},
		},
	}

	if factory.hasHubRegistry(cfg2) {
		t.Error("Expected false for different remote registry")
	}
}

// ============================================================================
// END OF FILE - Global functions removed as unnecessary delegation
// ============================================================================
