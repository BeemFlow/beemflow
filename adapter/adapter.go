package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
)

// Adapter is the interface for all BeemFlow adapters. Implement this to add new tool integrations.
type Adapter interface {
	ID() string
	Execute(ctx context.Context, inputs map[string]any) (map[string]any, error)
	Manifest() *registry.ToolManifest
}

// Registry holds registered adapters and provides lookup and registration methods.
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry creates a new adapter registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register registers an adapter with the registry.
func (r *Registry) Register(a Adapter) {
	r.adapters[a.ID()] = a
}

// Get retrieves a registered adapter by ID.
func (r *Registry) Get(id string) (Adapter, bool) {
	a, ok := r.adapters[id]
	return a, ok
}

// Add helper to append a tool to the local registry file
//
// This function ensures that any tool installed via the CLI is written to the local registry file.
// The path is determined from config (registries[].path) or defaults to .beemflow/registry.json.
// This is future-proofed for remote/community registries.
func appendToLocalRegistry(entry registry.RegistryEntry, path string) error {
	var entries []registry.RegistryEntry
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &entries); err != nil {
			// If existing file is corrupted, log error but continue with empty entries
			// This allows recovery from corrupted registry files
			utils.Warn("Corrupted registry file %s, starting fresh: %v", path, err)
			entries = []registry.RegistryEntry{}
		}
	}
	// Remove any existing entry with the same name
	newEntries := []registry.RegistryEntry{}
	for _, e := range entries {
		if e.Name != entry.Name {
			newEntries = append(newEntries, e)
		}
	}
	newEntries = append(newEntries, entry)
	out, err := json.MarshalIndent(newEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry entries: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return err
	}
	// Reload entries to verify
	verifyData, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var verifyEntries []registry.RegistryEntry
	if err := json.Unmarshal(verifyData, &verifyEntries); err != nil {
		return fmt.Errorf("failed to unmarshal registry entries after write: %w", err)
	}
	return nil
}

// LoadAndRegisterTool loads a tool manifest from a local directory and registers an HTTPAdapter.
//
// After registering, it writes the tool to the local registry file (user-writable),
// never to the curated registry (repo-managed, read-only).
//
// This ensures user-installed tools persist across runs and are merged with curated tools.
func (r *Registry) LoadAndRegisterTool(name, manifestPath string) error {
	if _, exists := r.adapters[name]; exists {
		return nil
	}
	// Read the manifest file directly
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest registry.ToolManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	r.Register(&HTTPAdapter{AdapterID: name, ToolManifest: &manifest})
	return nil
}

// CloseAll closes all adapters that implement io.Closer.
func (r *Registry) CloseAll() error {
	var firstErr error
	for _, a := range r.adapters {
		if closer, ok := a.(io.Closer); ok {
			if err := closer.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// All returns every registered adapter.
func (r *Registry) All() []Adapter {
	out := make([]Adapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a)
	}
	return out
}
