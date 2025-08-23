package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/beemflow/beemflow/config"
)

func writeTestRegistry(path string, entries []RegistryEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func TestNewLocalRegistry_DefaultPath(t *testing.T) {
	reg := NewLocalRegistry("")
	expected := config.DefaultLocalRegistryFullPath()
	if reg.Path != expected {
		t.Errorf("expected default path %s, got %s", expected, reg.Path)
	}
}

func TestLocalRegistry_ListAndGetServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), t.Name()+"-test_registry.json")
	entries := []RegistryEntry{
		{Registry: "local", Name: "foo", Type: "mcp_server", Description: "desc", Kind: "local", Endpoint: "http://foo"},
		{Registry: "local", Name: "bar", Type: "mcp_server", Description: "desc2", Kind: "local", Endpoint: "http://bar"},
	}
	if err := writeTestRegistry(path, entries); err != nil {
		t.Fatalf("failed to write test registry: %v", err)
	}
	reg := NewLocalRegistry(path)
	servers, err := reg.ListServers(context.Background(), ListOptions{Query: "", Page: 0, PageSize: 0})
	if err != nil {
		t.Fatalf("ListServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
	entry, err := reg.GetServer(context.Background(), "foo")
	if err != nil || entry == nil || entry.Name != "foo" {
		t.Errorf("GetServer failed: %v, entry: %+v", err, entry)
	}
	entry, err = reg.GetServer(context.Background(), "notfound")
	if err != nil || entry != nil {
		t.Errorf("expected nil for notfound, got: %+v, err: %v", entry, err)
	}
}

type mockRegistry struct {
	entries []RegistryEntry
}

func (m *mockRegistry) ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	return m.entries, nil
}
func (m *mockRegistry) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	for _, e := range m.entries {
		if e.Name == name {
			return &e, nil
		}
	}
	return nil, nil
}

func TestRegistryManager_ListAllServersAndGetServer(t *testing.T) {
	reg1 := &mockRegistry{entries: []RegistryEntry{{Registry: "r1", Name: "foo"}, {Registry: "r1", Name: "bar"}}}
	reg2 := &mockRegistry{entries: []RegistryEntry{{Registry: "r2", Name: "foo"}}}
	mgr := NewRegistryManager(reg1, reg2)
	servers, err := mgr.ListAllServers(context.Background(), ListOptions{})
	if err != nil {
		t.Fatalf("ListAllServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("expected 2 servers (deduplicated), got %d", len(servers))
	}

	var fooEntry *RegistryEntry
	for _, s := range servers {
		if s.Name == "foo" {
			fooEntry = &s
			break
		}
	}
	if fooEntry == nil || fooEntry.Registry != "r1" {
		t.Errorf("expected foo entry from r1, got %+v", fooEntry)
	}

	entry, err := mgr.GetServer(context.Background(), "foo")
	if err != nil {
		t.Errorf("GetServer failed: %v", err)
	}
	if entry == nil || entry.Name != "foo" {
		t.Errorf("expected foo, got %+v", entry)
	}
	entry, err = mgr.GetServer(context.Background(), "notfound")
	if err != nil || entry != nil {
		t.Errorf("expected nil for notfound, got: %+v, err: %v", entry, err)
	}
}

func TestLocalRegistry_ListServers_FileNotFound(t *testing.T) {
	reg := NewLocalRegistry(t.Name() + "-does_not_exist.json")
	_, err := reg.ListServers(context.Background(), ListOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLocalRegistry_ListServers_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), t.Name()+"-bad_registry.json")
	osErr := os.WriteFile(path, []byte("not json"), 0644)
	if osErr != nil {
		t.Fatalf("os.WriteFile failed: %v", osErr)
	}
	reg := NewLocalRegistry(path)
	_, err := reg.ListServers(context.Background(), ListOptions{})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRegistryEntry_Namespacing(t *testing.T) {
	entry := RegistryEntry{Registry: "smithery", Name: "airtable"}
	if entry.Registry+":"+entry.Name != "smithery:airtable" {
		t.Errorf("expected smithery:airtable, got %s:%s", entry.Registry, entry.Name)
	}
}

// TestLocalRegistry_ListMCPServers ensures ListMCPServers filters only mcp_server entries.
func TestLocalRegistry_ListMCPServers(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, t.Name()+"-index.json")
	entries := []RegistryEntry{
		{Registry: "local", Type: "mcp_server", Name: "foo", Description: "desc", Kind: "k", Endpoint: "e"},
		{Registry: "local", Type: "other", Name: "bar", Description: "desc", Kind: "k", Endpoint: "e"},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatal(err)
	}
	lr := NewLocalRegistry(filePath)
	out, err := lr.ListMCPServers(context.Background(), ListOptions{})
	if err != nil {
		t.Fatalf("ListMCPServers error: %v", err)
	}
	if len(out) != 1 || out[0].Name != "foo" {
		t.Errorf("expected 1 mcp_server foo, got %+v", out)
	}
}
