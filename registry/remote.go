package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/beemflow/beemflow/utils"
)

// RemoteRegistry fetches tools/servers from a remote HTTP endpoint
type RemoteRegistry struct {
	BaseURL  string
	Registry string // Registry name for labeling entries
}

// NewRemoteRegistry creates a new remote registry client
func NewRemoteRegistry(baseURL, registryName string) *RemoteRegistry {
	if registryName == "" {
		registryName = "remote"
	}
	return &RemoteRegistry{
		BaseURL:  baseURL,
		Registry: registryName,
	}
}

// ListServers fetches and returns all entries from the remote registry
func (r *RemoteRegistry) ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	// Use a default timeout only if no deadline is set in context
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	// Use http.DefaultClient which respects context deadlines
	client := &http.Client{
		// Don't set a client timeout - let the context handle it
		// This allows the context deadline to take precedence
	}

	req, err := http.NewRequestWithContext(ctx, "GET", r.BaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "BeemFlow/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote registry: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			utils.Warn("Failed to close remote registry response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote registry returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var entries []RegistryEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode remote registry response: %w", err)
	}

	// Label all entries with the registry name
	for i := range entries {
		entries[i].Registry = r.Registry
	}

	return entries, nil
}

// GetServer finds a specific server/tool by name from the remote registry
func (r *RemoteRegistry) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	entries, err := r.ListServers(ctx, ListOptions{})
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
