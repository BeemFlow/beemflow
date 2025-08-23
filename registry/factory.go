package registry

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/utils"
)

// RegistryFactory creates standardized registry managers with consistent configuration
type RegistryFactory struct{}

// NewFactory creates a new registry factory
func NewFactory() *RegistryFactory {
	return &RegistryFactory{}
}

// CreateStandardManager creates a registry manager with all standard registries:
// Resolution order: local → hub/remote → default (highest to lowest priority)
func (f *RegistryFactory) CreateStandardManager(ctx context.Context, cfg *config.Config) *RegistryManager {
	var registries []MCPRegistry

	// 1. Local registry (HIGHEST precedence - user's private tools override everything)
	localPath := f.getLocalRegistryPath(cfg)
	if localReg := NewLocalRegistry(localPath); localReg != nil {
		registries = append(registries, localReg)
		utils.Debug("Added local registry: %s (highest precedence)", localPath)
	}

	// 2. Remote registries from config (in order specified by user)
	remoteRegistries := f.loadRemoteRegistries(cfg)
	registries = append(registries, remoteRegistries...)

	// 3. Default hub registry (community curated - if not already configured)
	if !f.hasHubRegistry(cfg) {
		hubReg := NewRemoteRegistry("https://hub.beemflow.com/index.json", "hub")
		registries = append(registries, hubReg)
		utils.Debug("Added default hub registry (community curated)")
	}

	// 4. Default registry (LOWEST precedence - founder curated fallbacks)
	registries = append(registries, NewDefaultRegistry())
	utils.Debug("Added default registry with founder-curated tools (lowest precedence)")

	utils.Debug("Created registry manager with %d registries", len(registries))
	return NewRegistryManager(registries...)
}

// CreateAPIManager creates a lightweight manager for API endpoints (local overrides default)
func (f *RegistryFactory) CreateAPIManager() *RegistryManager {
	return NewRegistryManager(
		NewLocalRegistry(""), // Higher precedence
		NewDefaultRegistry(), // Lower precedence (fallback)
	)
}

// loadRemoteRegistries loads all remote registries from config
func (f *RegistryFactory) loadRemoteRegistries(cfg *config.Config) []MCPRegistry {
	var registries []MCPRegistry

	if cfg == nil {
		return registries
	}

	for _, regCfg := range cfg.Registries {
		if regCfg.Type == "remote" && regCfg.URL != "" {
			remoteReg := NewRemoteRegistry(regCfg.URL, "remote")
			registries = append(registries, remoteReg)
			utils.Debug("Added remote registry: %s", regCfg.URL)
		}
	}

	return registries
}

// getLocalRegistryPath determines the local registry path from config
func (f *RegistryFactory) getLocalRegistryPath(cfg *config.Config) string {
	if cfg == nil {
		return config.DefaultLocalRegistryPath
	}

	for _, regCfg := range cfg.Registries {
		if regCfg.Type == constants.LocalRegistryType && regCfg.Path != "" {
			// Sanitize the path to prevent path traversal attacks
			cleanPath := filepath.Clean(regCfg.Path)

			// Only reject paths with .. components (path traversal attacks)
			// Absolute paths are allowed for legitimate system-wide installations
			if strings.Contains(cleanPath, "..") {
				utils.Warn("Path traversal attempt detected in registry path '%s', using default", regCfg.Path)
				return config.DefaultLocalRegistryPath
			}

			return cleanPath
		}
	}

	return config.DefaultLocalRegistryPath
}

// hasHubRegistry checks if hub registry is already configured
func (f *RegistryFactory) hasHubRegistry(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}

	for _, regCfg := range cfg.Registries {
		if regCfg.URL == "https://hub.beemflow.com/index.json" {
			return true
		}
	}

	return false
}

// ============================================================================
// END OF FILE
// ============================================================================
