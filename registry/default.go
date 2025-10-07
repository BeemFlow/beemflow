package registry

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"regexp"
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
			expandedProvider := provider
			expandedProvider.ClientID = os.ExpandEnv(provider.ClientID)
			expandedProvider.ClientSecret = os.ExpandEnv(provider.ClientSecret)
			return &expandedProvider, nil
		}
	}

	return nil, nil // Not found
}

// expandOAuthProviderEnvVars expands environment variables in OAuth provider fields
func expandOAuthProviderEnvVars(entry RegistryEntry) RegistryEntry {
	envVarPattern := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

	expanded := entry

	// Expand environment variables in OAuth provider fields
	if expanded.ClientID != "" {
		expanded.ClientID = envVarPattern.ReplaceAllStringFunc(expanded.ClientID, func(match string) string {
			envVar := match[2 : len(match)-1] // Remove ${ and }
			if val := os.Getenv(envVar); val != "" {
				return val
			}
			return match // Keep original if env var not found
		})
	}

	if expanded.ClientSecret != "" {
		expanded.ClientSecret = envVarPattern.ReplaceAllStringFunc(expanded.ClientSecret, func(match string) string {
			envVar := match[2 : len(match)-1] // Remove ${ and }
			if val := os.Getenv(envVar); val != "" {
				return val
			}
			return match // Keep original if env var not found
		})
	}

	if expanded.AuthorizationURL != "" {
		expanded.AuthorizationURL = envVarPattern.ReplaceAllStringFunc(expanded.AuthorizationURL, func(match string) string {
			envVar := match[2 : len(match)-1] // Remove ${ and }
			if val := os.Getenv(envVar); val != "" {
				return val
			}
			return match // Keep original if env var not found
		})
	}

	if expanded.TokenURL != "" {
		expanded.TokenURL = envVarPattern.ReplaceAllStringFunc(expanded.TokenURL, func(match string) string {
			envVar := match[2 : len(match)-1] // Remove ${ and }
			if val := os.Getenv(envVar); val != "" {
				return val
			}
			return match // Keep original if env var not found
		})
	}

	return expanded
}
