package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/utils"
)

// RegistryEntry is a unified representation of a server/tool in any registry.
type RegistryEntry struct {
	Registry    string            `json:"registry"` // e.g. "smithery", "local"
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Kind        string            `json:"kind,omitempty"`
	Parameters  map[string]any    `json:"parameters,omitempty"`
	Endpoint    string            `json:"endpoint,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	// MCP server fields
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Port      int               `json:"port,omitempty"`
	Transport string            `json:"transport,omitempty"`
	// OAuth provider fields
	DisplayName       string            `json:"display_name,omitempty"`
	Icon              string            `json:"icon,omitempty"`
	AuthorizationURL  string            `json:"authorization_url,omitempty"`
	TokenURL          string            `json:"token_url,omitempty"`
	Scopes            []OAuthScope      `json:"scopes,omitempty"`
	ScopeDescriptions map[string]string `json:"scope_descriptions,omitempty"`
	RequiredScopes    []OAuthScope      `json:"required_scopes,omitempty"`
	ClientID          string            `json:"client_id,omitempty"`
	ClientSecret      string            `json:"client_secret,omitempty"`
}

// ListOptions allows filtering and pagination for registry queries.
type ListOptions struct {
	Query    string
	Page     int
	PageSize int
}

// MCPRegistry is the interface for any MCP registry backend (Smithery, local, etc).
type MCPRegistry interface {
	ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error)
	GetServer(ctx context.Context, name string) (*RegistryEntry, error)
}

// OAuthRegistry is the interface for OAuth provider management
type OAuthRegistry interface {
	ListOAuthProviders(ctx context.Context, opts ListOptions) ([]RegistryEntry, error)
	GetOAuthProvider(ctx context.Context, name string) (*RegistryEntry, error)
}

// RegistryStats represents statistics for a single registry
type RegistryStats struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Error  string `json:"error,omitempty"`
}

// ============================================================================
// LOCAL REGISTRY IMPLEMENTATION
// ============================================================================

type LocalRegistry struct {
	Path string
}

func NewLocalRegistry(path string) *LocalRegistry {
	if path == "" {
		path = config.DefaultLocalRegistryFullPath()
	}
	return &LocalRegistry{Path: path}
}

func (l *LocalRegistry) ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	data, err := os.ReadFile(l.Path)
	if err != nil {
		return nil, err
	}
	var entries []RegistryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Registry = "local"
	}
	return entries, nil
}

func (l *LocalRegistry) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	servers, err := l.ListServers(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		if s.Name == name {
			return &s, nil
		}
	}
	return nil, nil
}

// ============================================================================
// REGISTRY MANAGER (AGGREGATES MULTIPLE REGISTRIES)
// ============================================================================

// RegistryManager aggregates multiple registries and provides unified access
type RegistryManager struct {
	registries []MCPRegistry
}

// NewRegistryManager creates a new registry manager with the given registries
func NewRegistryManager(registries ...MCPRegistry) *RegistryManager {
	return &RegistryManager{registries: registries}
}

// ListAllServers returns all servers from all registries with proper prioritization
// Entries from earlier registries override entries with the same name from later registries
func (m *RegistryManager) ListAllServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	seen := make(map[string]bool)
	allEntries := []RegistryEntry{} // Initialize as empty slice instead of nil
	var errors []string

	// Process registries in priority order (first = highest priority)
	for _, reg := range m.registries {
		entries, err := reg.ListServers(ctx, opts)
		if err != nil {
			// Log the error but continue with other registries
			regType := fmt.Sprintf("%T", reg)
			utils.Debug("Registry %s failed to load: %v", regType, err)
			errors = append(errors, fmt.Sprintf("%s: %v", regType, err))
			continue
		}

		// Add entries, skipping duplicates (first registry wins)
		for _, entry := range entries {
			if !seen[entry.Name] {
				seen[entry.Name] = true
				allEntries = append(allEntries, entry)
			}
		}
	}

	// If we got some entries, succeed even if some registries failed
	if len(allEntries) > 0 {
		if len(errors) > 0 {
			utils.Debug("Some registries failed but continuing with %d tools from working registries", len(allEntries))
		}
		return allEntries, nil
	}

	// If all registries failed, return a comprehensive error
	if len(errors) > 0 {
		return nil, fmt.Errorf("all registries failed: %s", strings.Join(errors, "; "))
	}

	// No registries configured
	return []RegistryEntry{}, nil
}

// GetServer finds a server/tool by name, trying all registries until found
func (m *RegistryManager) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	var errors []string

	for _, reg := range m.registries {
		entry, err := reg.GetServer(ctx, name)
		if err != nil {
			regType := fmt.Sprintf("%T", reg)
			errors = append(errors, fmt.Sprintf("%s: %v", regType, err))
			continue
		}
		if entry != nil {
			return entry, nil
		}
	}

	// If no entry found and there were errors, include them in the response
	if len(errors) > 0 {
		return nil, fmt.Errorf("server '%s' not found, registry errors: %s", name, strings.Join(errors, "; "))
	}

	return nil, nil // Not found, but no errors
}

// GetRegistryStats returns statistics about each registry
func (m *RegistryManager) GetRegistryStats(ctx context.Context) map[string]RegistryStats {
	stats := make(map[string]RegistryStats)

	for _, reg := range m.registries {
		regType := fmt.Sprintf("%T", reg)
		entries, err := reg.ListServers(ctx, ListOptions{})
		if err != nil {
			stats[regType] = RegistryStats{
				Name:   regType,
				Status: "error",
				Count:  0,
				Error:  err.Error(),
			}
		} else {
			stats[regType] = RegistryStats{
				Name:   regType,
				Status: "ok",
				Count:  len(entries),
			}
		}
	}

	return stats
}

// ============================================================================
// TOOL MANIFEST
// ============================================================================

// ToolManifest represents a tool manifest loaded from JSON.
type ToolManifest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Kind        string            `json:"kind"`
	Parameters  map[string]any    `json:"parameters"`
	Endpoint    string            `json:"endpoint,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}
