package registry

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/beemflow/beemflow/utils"
)

//go:embed default.json
var defaultRegistryData []byte

// DefaultRegistry provides default SaaS tools embedded in the binary
type DefaultRegistry struct {
	Registry string
}

// NewDefaultRegistry creates a new default registry
func NewDefaultRegistry() *DefaultRegistry {
	return &DefaultRegistry{
		Registry: "default",
	}
}

// ListServers returns all default registry entries
func (d *DefaultRegistry) ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	var entries []RegistryEntry
	if err := json.Unmarshal(defaultRegistryData, &entries); err != nil {
		return nil, err
	}

	// Label all entries with default registry
	for i := range entries {
		entries[i].Registry = d.Registry
	}

	return entries, nil
}

// GetServer finds a specific server/tool by name from the default registry
func (d *DefaultRegistry) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	entries, err := d.ListServers(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Name == name {
			return &entry, nil
		}
	}

	return nil, nil // Not found
}

// ListOAuthProviders returns OAuth providers from the default registry
func (d *DefaultRegistry) ListOAuthProviders(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	entries, err := d.ListServers(ctx, opts)
	if err != nil {
		return nil, err
	}

	var oauthProviders []RegistryEntry
	for _, entry := range entries {
		if entry.Type == "oauth_provider" {
			expanded := expandOAuthProviderEnvVars(entry)
			oauthProviders = append(oauthProviders, expanded)
		}
	}

	return oauthProviders, nil
}

// GetOAuthProvider finds a specific OAuth provider by name
func (d *DefaultRegistry) GetOAuthProvider(ctx context.Context, name string) (*RegistryEntry, error) {
	providers, err := d.ListOAuthProviders(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, provider := range providers {
		if provider.Name == name {
			// Expand environment variables in the provider configuration
			expandedProvider := expandOAuthProviderEnvVars(provider)
			return &expandedProvider, nil
		}
	}

	return nil, nil // Not found
}

// expandOAuthProviderEnvVars expands environment variables in OAuth provider fields using $env: format
func expandOAuthProviderEnvVars(entry RegistryEntry) RegistryEntry {
	expanded := entry

	// Expand environment variables in OAuth provider fields
	if expanded.ClientID != "" {
		expanded.ClientID = utils.ExpandEnvValue(expanded.ClientID)
	}

	if expanded.ClientSecret != "" {
		expanded.ClientSecret = utils.ExpandEnvValue(expanded.ClientSecret)
	}

	if expanded.AuthorizationURL != "" {
		expanded.AuthorizationURL = utils.ExpandEnvValue(expanded.AuthorizationURL)
	}

	if expanded.TokenURL != "" {
		expanded.TokenURL = utils.ExpandEnvValue(expanded.TokenURL)
	}

	return expanded
}
