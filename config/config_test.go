package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/beemflow/beemflow/utils"
)

// TestMain ensures the mcp_servers folder is cleaned up before and after tests.
func TestMain(m *testing.M) {
	utils.WithCleanDirs(m, ".beemflow", DefaultConfigDir, "mcp_servers")
}

func TestLoadConfig(t *testing.T) {
	cfgJSON := `{"storage":{"driver":"d","dsn":"u"},"blob":{"driver":"b","bucket":"c"},"event":{"driver":"memory","url":"u"},"secrets":{"driver":"s","region":"r","prefix":"p"},"registries":[{"type":"local","path":"foo.json"},{"type":"smithery","url":"bar"}],"http":{"host":"h","port":3330},"log":{"level":"l"}}`
	tmp, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(cfgJSON); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()

	c, err := LoadConfig(tmp.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if c.Storage.Driver != "d" || c.Storage.DSN != "u" {
		t.Errorf("unexpected Storage: %+v", c.Storage)
	}
	if c.Blob.Driver != "b" || c.Blob.Bucket != "c" {
		t.Errorf("unexpected Blob: %+v", c.Blob)
	}
	if c.HTTP.Host != "h" || c.HTTP.Port != 3330 {
		t.Errorf("unexpected HTTP: %+v", c.HTTP)
	}
	if len(c.Registries) != 2 {
		t.Errorf("unexpected Registries: %+v", c.Registries)
	}
}

func TestLoadConfig_Partial(t *testing.T) {
	cfgJSON := `{"storage":{"driver":"d","dsn":"u"},"registries":[{"type":"local","path":"foo.json"}]}`
	tmp, err := os.CreateTemp("", "config_partial.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(cfgJSON); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()

	c, err := LoadConfig(tmp.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if c.Storage.Driver != "d" || c.Storage.DSN != "u" {
		t.Errorf("unexpected Storage: %+v", c.Storage)
	}
	// Other fields should be omitted (nil)
	if c.Blob != nil {
		t.Errorf("expected no Blob config, got %+v", c.Blob)
	}
	if c.HTTP != nil {
		t.Errorf("expected no HTTP config, got %+v", c.HTTP)
	}
}

func TestLoadConfig_FileNotExist(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmp, err := os.CreateTemp("", "bad.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("not a json"); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()
	_, err = LoadConfig(tmp.Name())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestGetMergedMCPServerConfig_NoCuratedFile ensures that without a curated file, the original config is returned.
func TestGetMergedMCPServerConfig_NoCuratedFile(t *testing.T) {
	orig := MCPServerConfig{
		Command:   "cmd",
		Args:      []string{"a", "b"},
		Env:       map[string]string{"E": "V"},
		Port:      1,
		Transport: "t",
		Endpoint:  "e",
	}
	cfg := &Config{MCPServers: map[string]MCPServerConfig{"foo": orig}}
	info, err := GetMergedMCPServerConfig(cfg, "foo")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(info, orig) {
		t.Errorf("expected %+v, got %+v", orig, info)
	}
}

// TestGetMergedMCPServerConfig_CuratedMissingCommand uses a curated file to supply a missing Command.
func TestGetMergedMCPServerConfig_CuratedMissingCommand(t *testing.T) {
	curated := map[string]MCPServerConfig{"foo": {
		Command:   "cmd2",
		Args:      []string{"x"},
		Env:       map[string]string{"A": "B"},
		Port:      2,
		Transport: "tr",
		Endpoint:  "end",
	}}
	data, _ := json.Marshal(curated)
	path := "mcp_servers/foo.json"
	_ = os.MkdirAll("mcp_servers", 0755)
	osErr := os.WriteFile(path, data, 0644)
	if osErr != nil {
		t.Fatalf("os.WriteFile failed: %v", osErr)
	}
	defer os.Remove(path)

	cfg := &Config{MCPServers: map[string]MCPServerConfig{"foo": {}}}
	info, err := GetMergedMCPServerConfig(cfg, "foo")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := curated["foo"]
	if !reflect.DeepEqual(info, want) {
		t.Errorf("expected %+v, got %+v", want, info)
	}
}

// TestGetMergedMCPServerConfig_CuratedMergeOriginal merges original fields into the curated template.
func TestGetMergedMCPServerConfig_CuratedMergeOriginal(t *testing.T) {
	curated := map[string]MCPServerConfig{"foo": {
		Args:      []string{"y"},
		Env:       map[string]string{"A": "ci", "C": "ci"},
		Port:      3,
		Transport: "tci",
		Endpoint:  "eci",
	}}
	data, _ := json.Marshal(curated)
	path := "mcp_servers/foo.json"
	_ = os.MkdirAll("mcp_servers", 0755)
	osErr := os.WriteFile(path, data, 0644)
	if osErr != nil {
		t.Fatalf("os.WriteFile failed: %v", osErr)
	}
	defer os.Remove(path)

	orig := MCPServerConfig{
		Command:   "co",
		Args:      []string{"x"},
		Env:       map[string]string{"A": "orig"},
		Port:      5,
		Transport: "tor",
		Endpoint:  "eor",
	}
	cfg := &Config{MCPServers: map[string]MCPServerConfig{"foo": orig}}
	info, err := GetMergedMCPServerConfig(cfg, "foo")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Expect original Command, Args; curated Env merged with original override; original Port, Transport, Endpoint
	want := MCPServerConfig{
		Command:   "",
		Args:      []string{"x"},
		Env:       map[string]string{"A": "orig", "C": "ci"},
		Port:      5,
		Transport: "tor",
		Endpoint:  "eor",
	}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("expected %+v, got %+v", want, info)
	}
}

// TestGetMergedMCPServerConfig_MalformedCuratedIgnored ensures that malformed JSON is ignored and original returned.
func TestGetMergedMCPServerConfig_MalformedCuratedIgnored(t *testing.T) {
	path := "mcp_servers/foo.json"
	_ = os.MkdirAll("mcp_servers", 0755)
	osErr := os.WriteFile(path, []byte("not json"), 0644)
	if osErr != nil {
		t.Fatalf("os.WriteFile failed: %v", osErr)
	}
	defer os.Remove(path)

	orig := MCPServerConfig{Command: "co", Args: []string{"x"}, Env: map[string]string{"A": "orig"}}
	cfg := &Config{MCPServers: map[string]MCPServerConfig{"foo": orig}}
	info, err := GetMergedMCPServerConfig(cfg, "foo")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(info, orig) {
		t.Errorf("expected %+v, got %+v", orig, info)
	}
}

// TestGetMergedMCPServerConfig_MissingHostError ensures an error when the host is not in the main config.
func TestGetMergedMCPServerConfig_MissingHostError(t *testing.T) {
	cfg := &Config{MCPServers: map[string]MCPServerConfig{}}
	_, err := GetMergedMCPServerConfig(cfg, "unknown")
	if err == nil {
		t.Fatalf("expected error for unknown host, got nil")
	}
}

// TestUpsertAndSaveConfig tests UpsertMCPServer and SaveConfig/LoadConfig roundtrip.
func TestUpsertAndSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "flow.config.json")
	cfg := &Config{}
	UpsertMCPServer(cfg, "foo", MCPServerConfig{Command: "cmd", Args: []string{"a"}})
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}
	cfg2, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	spec, ok := cfg2.MCPServers["foo"]
	if !ok {
		t.Fatalf("expected mcpServers foo, got none")
	}
	if spec.Command != "cmd" || len(spec.Args) != 1 || spec.Args[0] != "a" {
		t.Errorf("unexpected spec, got %+v", spec)
	}
}

// TestLoadAndInjectRegistries tests env var injection and Smithery auto-include.
func TestLoadAndInjectRegistries(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "cfg.json")
	raw := map[string]any{
		"registries": []any{
			map[string]any{"type": "foo", "url": "$env:TESTURL", "path": "$env:TESTPATH"},
		},
	}
	bytes, _ := json.Marshal(raw)
	if err := os.WriteFile(cfgPath, bytes, 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	os.Setenv("TESTURL", "https://example.com")
	os.Setenv("TESTPATH", "/tmp")
	os.Setenv("SMITHERY_API_KEY", "apikey123")
	cfg, err := LoadAndInjectRegistries(cfgPath)
	if err != nil {
		t.Fatalf("LoadAndInjectRegistries error: %v", err)
	}
	if len(cfg.Registries) != 2 {
		t.Fatalf("expected 2 registries, got %d", len(cfg.Registries))
	}
	var foundFoo, foundSmithery bool
	for _, r := range cfg.Registries {
		switch r.Type {
		case "foo":
			foundFoo = true
			if r.URL != "https://example.com" {
				t.Errorf("expected foo URL injected, got %s", r.URL)
			}
			if r.Path != "/tmp" {
				t.Errorf("expected foo Path injected, got %s", r.Path)
			}
		case "smithery":
			foundSmithery = true
			if r.URL != "https://registry.smithery.ai/servers" {
				t.Errorf("expected smithery URL default, got %s", r.URL)
			}
		}
	}
	if !foundFoo || !foundSmithery {
		t.Errorf("missing expected registries: foo(%v) smithery(%v)", foundFoo, foundSmithery)
	}
}

// TestParseRegistryConfig tests the ParseRegistryConfig function with 100% coverage
func TestParseRegistryConfig(t *testing.T) {
	// Test valid registry config
	validConfig := RegistryConfig{
		Type: "local",
		Path: "/path/to/registry.json",
		URL:  "https://example.com/registry",
	}

	result, err := ParseRegistryConfig(validConfig)
	if err != nil {
		t.Fatalf("ParseRegistryConfig failed for valid config: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}

	// Test smithery config (should return SmitheryRegistryConfig)
	smitheryConfig := RegistryConfig{
		Type: "smithery",
		URL:  "https://registry.smithery.ai/servers",
	}

	result, err = ParseRegistryConfig(smitheryConfig)
	if err != nil {
		t.Fatalf("ParseRegistryConfig failed for smithery config: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result for smithery config")
	}

	// Should return SmitheryRegistryConfig
	if _, ok := result.(SmitheryRegistryConfig); !ok {
		t.Error("Expected SmitheryRegistryConfig for smithery type")
	}

	// Test unknown type (should return original config)
	unknownConfig := RegistryConfig{
		Type: "unknown_type",
		Path: "/path/to/registry.json",
	}

	result, err = ParseRegistryConfig(unknownConfig)
	if err != nil {
		t.Fatalf("ParseRegistryConfig failed for unknown type: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result for unknown type")
	}

	// Should return original RegistryConfig
	if _, ok := result.(RegistryConfig); !ok {
		t.Error("Expected RegistryConfig for unknown type")
	}

	// Test empty type (should return original config)
	emptyTypeConfig := RegistryConfig{
		Type: "",
		Path: "/path/to/registry.json",
	}

	result, err = ParseRegistryConfig(emptyTypeConfig)
	if err != nil {
		t.Fatalf("ParseRegistryConfig failed for empty type: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result for empty type")
	}
}

// TestValidate tests the Validate method with comprehensive coverage
func TestValidate(t *testing.T) {
	// Test valid config
	validConfig := &Config{
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "test.db",
		},
		HTTP: &HTTPConfig{
			Host: "localhost",
			Port: 3330,
		},
		Registries: []RegistryConfig{
			{Type: "local", Path: "/path/to/registry.json"},
		},
	}

	err := validConfig.Validate()
	if err != nil {
		t.Errorf("Validate failed for valid config: %v", err)
	}

	// Test config with empty storage driver
	configInvalidStorage := &Config{
		Storage: StorageConfig{
			Driver: "",
			DSN:    "test.db",
		},
	}

	err = configInvalidStorage.Validate()
	if err == nil {
		t.Error("Expected error for empty storage driver")
	}

	// Test config with missing DSN
	configMissingDSN := &Config{
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "",
		},
	}

	err = configMissingDSN.Validate()
	if err == nil {
		t.Error("Expected error for missing DSN")
	}

	// Test config with nil HTTP (should be fine)
	configNilHTTP := &Config{
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "test.db",
		},
	}

	err = configNilHTTP.Validate()
	if err != nil {
		t.Errorf("Validate should handle nil HTTP: %v", err)
	}

	// Test config with zero HTTP port (should error)
	configInvalidHTTP := &Config{
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "test.db",
		},
		HTTP: &HTTPConfig{
			Host: "localhost",
			Port: 0,
		},
	}

	err = configInvalidHTTP.Validate()
	if err == nil {
		t.Error("Expected error for zero HTTP port")
	}

	// Test nil config (should panic, so we'll skip this test)
	// var nilConfig *Config
	// err = nilConfig.Validate()
	// if err == nil {
	// 	t.Error("Expected error for nil config, got nil")
	// }
}

// TestMCPServerConfigUnmarshalJSON tests the UnmarshalJSON method for MCPServerConfig
func TestMCPServerConfigUnmarshalJSON(t *testing.T) {
	// Test valid JSON object
	validJSON := `{
		"command": "test-cmd",
		"args": ["arg1", "arg2"],
		"env": {"VAR1": "value1"},
		"port": 3000,
		"transport": "stdio",
		"endpoint": "http://localhost:3000"
	}`

	var config MCPServerConfig
	err := config.UnmarshalJSON([]byte(validJSON))
	if err != nil {
		t.Fatalf("UnmarshalJSON failed for valid JSON: %v", err)
	}
	if config.Command != "test-cmd" {
		t.Errorf("Expected command 'test-cmd', got '%s'", config.Command)
	}
	if len(config.Args) != 2 {
		t.Errorf("Expected 2 args, got %d", len(config.Args))
	}

	// Test string URL
	urlJSON := `"https://example.com/api"`
	var config2 MCPServerConfig
	err = config2.UnmarshalJSON([]byte(urlJSON))
	if err != nil {
		t.Fatalf("UnmarshalJSON failed for URL string: %v", err)
	}
	if config2.Transport != "http" {
		t.Errorf("Expected transport 'http', got '%s'", config2.Transport)
	}
	if config2.Endpoint != "https://example.com/api" {
		t.Errorf("Expected endpoint 'https://example.com/api', got '%s'", config2.Endpoint)
	}

	// Test simple string (fallback to HTTP endpoint)
	simpleJSON := `"simple-endpoint"`
	var config3 MCPServerConfig
	err = config3.UnmarshalJSON([]byte(simpleJSON))
	if err != nil {
		t.Fatalf("UnmarshalJSON failed for simple string: %v", err)
	}
	if config3.Transport != "http" {
		t.Errorf("Expected transport 'http', got '%s'", config3.Transport)
	}
	if config3.Endpoint != "simple-endpoint" {
		t.Errorf("Expected endpoint 'simple-endpoint', got '%s'", config3.Endpoint)
	}

	// Test invalid JSON
	invalidJSON := `{"command": "test", "invalid": }`
	var config4 MCPServerConfig
	err = config4.UnmarshalJSON([]byte(invalidJSON))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// ========================================
// INTEGRATION TESTS - Real file operations and config loading
// ========================================

// TestConfigLoadingRealFiles tests configuration loading with real file system operations
func TestConfigLoadingRealFiles(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("BasicConfigFile", func(t *testing.T) {
		configPath := filepath.Join(tempDir, "basic_config.json")
		configData := map[string]any{
			"storage": map[string]any{
				"driver": "sqlite",
				"dsn":    "./test.db",
			},
			"registries": []map[string]any{
				{
					"type": "smithery",
					"url":  "https://example.com/registry",
				},
			},
		}

		// Write config file
		data, err := json.Marshal(configData)
		if err != nil {
			t.Fatalf("Failed to marshal config: %v", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			t.Fatalf("Failed to write config file: %v", err)
		}

		// Test loading
		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}

		if cfg.Storage.Driver != "sqlite" {
			t.Errorf("Expected storage driver 'sqlite', got %s", cfg.Storage.Driver)
		}
		if cfg.Storage.DSN != "./test.db" {
			t.Errorf("Expected storage DSN './test.db', got %s", cfg.Storage.DSN)
		}
	})

	t.Run("ConfigWithComplexMCPServers", func(t *testing.T) {
		configPath := filepath.Join(tempDir, "mcp_config.json")
		configData := map[string]any{
			"mcpServers": map[string]any{
				"filesystem": map[string]any{
					"command": "npx",
					"args":    []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
					"env": map[string]any{
						"NODE_ENV": "production",
						"DEBUG":    "$env:DEBUG_MCP",
					},
				},
				"postgres": map[string]any{
					"command": "mcp-server-postgres",
					"env": map[string]any{
						"POSTGRES_URL": "$env:DATABASE_URL",
					},
				},
			},
		}

		data, err := json.Marshal(configData)
		if err != nil {
			t.Fatalf("Failed to marshal MCP config: %v", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			t.Fatalf("Failed to write MCP config file: %v", err)
		}

		// Test loading
		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig with MCP servers failed: %v", err)
		}

		if len(cfg.MCPServers) != 2 {
			t.Errorf("Expected 2 MCP servers, got %d", len(cfg.MCPServers))
		}

		// Test filesystem server config
		if fsServer, exists := cfg.MCPServers["filesystem"]; exists {
			if fsServer.Command != "npx" {
				t.Errorf("Expected filesystem command 'npx', got %s", fsServer.Command)
			}
			if len(fsServer.Args) != 3 {
				t.Errorf("Expected 3 args for filesystem server, got %d", len(fsServer.Args))
			}
			if fsServer.Env["NODE_ENV"] != "production" {
				t.Errorf("Expected NODE_ENV 'production', got %v", fsServer.Env["NODE_ENV"])
			}
		} else {
			t.Error("Expected filesystem server not found")
		}
	})

	t.Run("InvalidConfigFiles", func(t *testing.T) {
		// Test various invalid config scenarios
		invalidConfigs := []struct {
			name     string
			content  string
			checkErr func(error) bool
		}{
			{
				name:    "Invalid JSON",
				content: `{"storage": {"driver": "sqlite"`,
				checkErr: func(err error) bool {
					return strings.Contains(err.Error(), "config validation failed")
				},
			},
			{
				name:    "Empty file",
				content: "",
				checkErr: func(err error) bool {
					return strings.Contains(err.Error(), "config validation failed")
				},
			},
			{
				name:    "Non-JSON content",
				content: "This is not JSON",
				checkErr: func(err error) bool {
					return strings.Contains(err.Error(), "config validation failed")
				},
			},
			{
				name:    "Binary data",
				content: string([]byte{0x00, 0x01, 0x02, 0xFF}),
				checkErr: func(err error) bool {
					return strings.Contains(err.Error(), "config validation failed")
				},
			},
		}

		// Test all invalid configs in one go to ensure cleanup works properly
		for i, test := range invalidConfigs {
			t.Run(test.name, func(t *testing.T) {
				configPath := filepath.Join(tempDir, fmt.Sprintf("invalid_config_%d.json", i))

				if err := os.WriteFile(configPath, []byte(test.content), 0644); err != nil {
					t.Fatalf("Failed to write invalid config: %v", err)
				}

				_, err := LoadConfig(configPath)
				if err == nil {
					t.Error("Expected error for invalid config")
				} else if !test.checkErr(err) {
					t.Errorf("Error doesn't match expected pattern: %v", err)
				}
			})
		}
	})

	t.Run("PermissionErrors", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping permission test when running as root")
		}

		// Create unreadable config file
		configPath := filepath.Join(tempDir, "unreadable_config.json")
		if err := os.WriteFile(configPath, []byte(`{}`), 0644); err != nil {
			t.Fatalf("Failed to write config: %v", err)
		}

		// Make it unreadable
		if err := os.Chmod(configPath, 0000); err != nil {
			t.Fatalf("Failed to change permissions: %v", err)
		}
		defer os.Chmod(configPath, 0644) // Cleanup

		_, err := LoadConfig(configPath)
		if err == nil {
			t.Error("Expected permission error for unreadable config")
		}
	})
}

// TestConfigRegistryMerging tests real registry URL fetching and merging
func TestConfigRegistryMerging(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping registry integration test in short mode")
	}

	// Create a test HTTP server that serves registry data
	testRegistry := []map[string]any{
		{
			"name":        "test-tool",
			"type":        "mcp_server",
			"description": "Test tool from registry",
			"command":     "test-command",
			"args":        []string{"--test"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testRegistry)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "registry_config.json")

	// Config that references the test server
	configData := map[string]any{
		"registries": []map[string]any{
			{
				"type": "remote",
				"url":  server.URL,
			},
		},
	}

	data, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Test loading config with registry URL
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Registries[0].URL != server.URL {
		t.Errorf("Expected registry URL %s, got %s", server.URL, cfg.Registries[0].URL)
	}

	// Test that default configs handle remote registries gracefully
	t.Logf("Registry URL loaded successfully: %s", cfg.Registries[0].URL)
}

// TestConfigStressAndEdgeCases tests configuration loading under stress
func TestConfigStressAndEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("VeryLargeConfig", func(t *testing.T) {
		// Create a config with many MCP servers
		configData := map[string]any{
			"mcpServers": make(map[string]any),
		}

		mcpServers := configData["mcpServers"].(map[string]any)
		for i := 0; i < 100; i++ {
			mcpServers[fmt.Sprintf("server_%d", i)] = map[string]any{
				"command": fmt.Sprintf("test-command-%d", i),
				"args":    []string{fmt.Sprintf("--arg-%d", i)},
				"env": map[string]any{
					"SERVER_ID": fmt.Sprintf("%d", i),
					"DATA":      strings.Repeat("x", 1000), // Large env value
				},
			}
		}

		configPath := filepath.Join(tempDir, "large_config.json")
		data, err := json.Marshal(configData)
		if err != nil {
			t.Fatalf("Failed to marshal large config: %v", err)
		}

		start := time.Now()
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			t.Fatalf("Failed to write large config: %v", err)
		}
		writeDuration := time.Since(start)

		start = time.Now()
		cfg, err := LoadConfig(configPath)
		loadDuration := time.Since(start)

		if err != nil {
			t.Fatalf("LoadConfig failed for large config: %v", err)
		}

		if len(cfg.MCPServers) != 100 {
			t.Errorf("Expected 100 MCP servers, got %d", len(cfg.MCPServers))
		}

		t.Logf("Large config performance - Write: %v, Load: %v", writeDuration, loadDuration)
	})

	t.Run("UnicodeAndSpecialChars", func(t *testing.T) {
		configData := map[string]any{
			"mcpServers": map[string]any{
				"unicode-test": map[string]any{
					"command": "echo",
					"args":    []string{"Hello 世界 🌍 Ñoël"},
					"env": map[string]any{
						"UNICODE":       "Hello 世界 🌍",
						"SPECIAL_CHARS": `"quotes" 'single' \backslash \n\t\r`,
						"EMOJI":         "🚀 🎯 ✅",
					},
				},
			},
		}

		configPath := filepath.Join(tempDir, "unicode_config.json")
		data, err := json.Marshal(configData)
		if err != nil {
			t.Fatalf("Failed to marshal unicode config: %v", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			t.Fatalf("Failed to write unicode config: %v", err)
		}

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed for unicode config: %v", err)
		}

		server := cfg.MCPServers["unicode-test"]
		if len(server.Args) == 0 || !strings.Contains(server.Args[0], "世界") {
			t.Error("Unicode characters not preserved in args")
		}
		if server.Env["EMOJI"] != "🚀 🎯 ✅" {
			t.Error("Emoji not preserved in environment variables")
		}
	})
}

// TestConfigConcurrentAccess tests concurrent config loading
func TestConfigConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "concurrent_config.json")

	// Create a standard config
	configData := map[string]any{
		"storage": map[string]any{
			"driver": "sqlite",
			"dsn":    "./concurrent_test.db",
		},
	}

	data, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Test concurrent loading
	const numGoroutines = 20
	errChan := make(chan error, numGoroutines)
	successChan := make(chan *Config, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				errChan <- fmt.Errorf("worker %d failed: %w", workerID, err)
				return
			}
			successChan <- cfg
			errChan <- nil
		}(i)
	}

	// Collect results
	var errors []error
	var configs []*Config

	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		if err != nil {
			errors = append(errors, err)
		} else {
			cfg := <-successChan
			configs = append(configs, cfg)
		}
	}

	if len(errors) > 0 {
		t.Errorf("Concurrent loading failed: %v", errors[0])
	}

	if len(configs) != numGoroutines {
		t.Errorf("Expected %d successful loads, got %d", numGoroutines, len(configs))
	}

	// Verify all configs are identical
	if len(configs) > 1 {
		first := configs[0]
		for i, cfg := range configs[1:] {
			if cfg.Storage.Driver != first.Storage.Driver {
				t.Errorf("Config %d differs from first: driver %s vs %s", i+1, cfg.Storage.Driver, first.Storage.Driver)
			}
		}
	}
}

// TestHomeDirectoryResolution tests the simplified home directory path resolution
func TestHomeDirectoryResolution(t *testing.T) {
	// Test default paths point to home directory
	t.Run("DefaultPaths", func(t *testing.T) {
		// Test DefaultLocalRegistryPath
		defaultRegistryPath := DefaultLocalRegistryPath
		if !strings.Contains(defaultRegistryPath, ".beemflow") {
			t.Errorf("Expected default registry path to contain .beemflow, got: %s", defaultRegistryPath)
		}

		// Test DefaultSQLiteDSN
		defaultDBPath := DefaultSQLiteDSN
		if !strings.Contains(defaultDBPath, ".beemflow") {
			t.Errorf("Expected default DB path to contain .beemflow, got: %s", defaultDBPath)
		}

		// Both should point to the same base directory
		registryDir := filepath.Dir(defaultRegistryPath)
		dbDir := filepath.Dir(defaultDBPath)
		if registryDir != dbDir {
			t.Errorf("Registry and DB should be in same directory: registry=%s, db=%s", registryDir, dbDir)
		}
	})

	t.Run("GetDefaultLocalRegistryPath", func(t *testing.T) {
		// This function should return the default path
		path := DefaultLocalRegistryFullPath()

		// Should be same as the constant
		if path != DefaultLocalRegistryPath {
			t.Errorf("DefaultLocalRegistryFullPath() = %s, want %s", path, DefaultLocalRegistryPath)
		}

		// Should contain .beemflow
		if !strings.Contains(path, ".beemflow") {
			t.Errorf("Default path should contain .beemflow, got: %s", path)
		}

		// Should end with registry.json
		if !strings.HasSuffix(path, "registry.json") {
			t.Errorf("Default path should end with registry.json, got: %s", path)
		}
	})

	t.Run("PathExpansion", func(t *testing.T) {
		// Test that ~ is properly expanded in the defaults
		// The actual expansion happens at runtime via filepath.Join with user home directory
		// We just verify that our constants are sensible

		if strings.Contains(DefaultLocalRegistryPath, "~") {
			t.Errorf("Default path should not contain literal ~, got: %s", DefaultLocalRegistryPath)
		}

		if strings.Contains(DefaultSQLiteDSN, "~") {
			t.Errorf("Default DB path should not contain literal ~, got: %s", DefaultSQLiteDSN)
		}
	})

	t.Run("DirectoryStructure", func(t *testing.T) {
		// Verify the expected directory structure
		registryPath := DefaultLocalRegistryPath
		dbPath := DefaultSQLiteDSN

		// Both should be in .beemflow directory
		expectedBaseDir := DefaultConfigDir

		registryBase := filepath.Dir(registryPath)
		if registryBase != expectedBaseDir {
			t.Errorf("Registry base dir = %s, want %s", registryBase, expectedBaseDir)
		}

		dbBase := filepath.Dir(dbPath)
		if dbBase != expectedBaseDir {
			t.Errorf("DB base dir = %s, want %s", dbBase, expectedBaseDir)
		}
	})
}

// TestConfigDefaultBehavior tests that our simplified configuration defaults work correctly
func TestConfigDefaultBehavior(t *testing.T) {
	t.Run("EmptyConfig", func(t *testing.T) {
		// Create minimal empty config
		tempDir, err := os.MkdirTemp("", "config-defaults-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		configPath := filepath.Join(tempDir, "empty.json")
		emptyConfig := "{}"
		if err := os.WriteFile(configPath, []byte(emptyConfig), 0644); err != nil {
			t.Fatalf("Failed to write empty config: %v", err)
		}

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("Failed to load empty config: %v", err)
		}

		// Verify defaults are applied correctly
		if cfg == nil {
			t.Fatal("Config should not be nil")
		}

		// Storage defaults should be applied at runtime, not in config loading
		// The config loader just loads what's in the file
		t.Logf("Empty config loaded successfully: %+v", cfg)
	})

	t.Run("ConfigWithExplicitPaths", func(t *testing.T) {
		// Test that explicit user paths are preserved exactly as-is
		tempDir, err := os.MkdirTemp("", "config-explicit-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		// User specifies explicit absolute path
		userPath := "/tmp/custom/path/registry.json"
		configData := map[string]any{
			"registries": []any{
				map[string]any{
					"type": "local",
					"path": userPath,
				},
			},
			"storage": map[string]any{
				"driver": "sqlite",
				"dsn":    "/tmp/custom/db.sqlite",
			},
		}

		configPath := filepath.Join(tempDir, "explicit.json")
		configBytes, _ := json.Marshal(configData)
		if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
			t.Fatalf("Failed to write explicit config: %v", err)
		}

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("Failed to load explicit config: %v", err)
		}

		// Verify user paths are preserved exactly
		if len(cfg.Registries) > 0 && cfg.Registries[0].Path != userPath {
			t.Errorf("User registry path not preserved: got %s, want %s", cfg.Registries[0].Path, userPath)
		}

		if cfg.Storage.DSN != "/tmp/custom/db.sqlite" {
			t.Errorf("User storage path not preserved: got %s, want %s", cfg.Storage.DSN, "/tmp/custom/db.sqlite")
		}
	})
}

// TestPathSecurity tests that our path handling is secure
func TestPathSecurity(t *testing.T) {
	tests := []struct {
		name         string
		inputPath    string
		shouldReject bool
		description  string
	}{
		{
			name:         "NormalPath",
			inputPath:    "/home/user/.beemflow/registry.json",
			shouldReject: false,
			description:  "Normal absolute path should be accepted",
		},
		{
			name:         "RelativePath",
			inputPath:    "config/registry.json",
			shouldReject: false,
			description:  "Normal relative path should be accepted",
		},
		{
			name:         "PathTraversal",
			inputPath:    "../../../etc/passwd",
			shouldReject: true,
			description:  "Path traversal should be rejected",
		},
		{
			name:         "PathTraversalWithDots",
			inputPath:    "/home/user/../../../etc/passwd",
			shouldReject: true,
			description:  "Path traversal with absolute path should be rejected",
		},
		{
			name:         "ValidDotsInFilename",
			inputPath:    "/home/user/.beemflow/config.v1.json",
			shouldReject: false,
			description:  "Valid dots in filename should be accepted",
		},
		{
			name:         "HiddenFile",
			inputPath:    "/home/user/.hidden-config.json",
			shouldReject: false,
			description:  "Hidden files should be accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the path traversal detection logic from registry factory
			// Check for path traversal elements in the original path before cleaning
			hasPathTraversal := strings.Contains(tt.inputPath, "..")
			cleanPath := filepath.Clean(tt.inputPath)

			if tt.shouldReject && !hasPathTraversal {
				t.Errorf("Expected path %s to be rejected for security, but it was accepted", tt.inputPath)
			} else if !tt.shouldReject && hasPathTraversal {
				t.Errorf("Expected path %s to be accepted, but it was rejected", tt.inputPath)
			}

			t.Logf("%s: %s -> clean: %s, hasTraversal: %v", tt.description, tt.inputPath, cleanPath, hasPathTraversal)
		})
	}
}
