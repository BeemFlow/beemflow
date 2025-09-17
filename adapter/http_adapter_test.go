package adapter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/registry"
)

// TestHTTPAdapter_PathParameterSubstitution tests path parameter replacement in manifest URLs
func TestHTTPAdapter_PathParameterSubstitution(t *testing.T) {
	// Create a test server that verifies the path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that path parameters were properly substituted
		if !strings.Contains(r.URL.Path, "test-sheet-id") || !strings.Contains(r.URL.Path, "Sheet1!A:D") {
			t.Errorf("Path parameters not substituted. Got path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}

		// Check that path parameters are NOT in the body
		body, _ := io.ReadAll(r.Body)
		var bodyData map[string]any
		json.Unmarshal(body, &bodyData)

		if _, exists := bodyData["spreadsheetId"]; exists {
			t.Errorf("spreadsheetId should not be in request body")
			w.WriteHeader(400)
			return
		}

		if _, exists := bodyData["range"]; exists {
			t.Errorf("range should not be in request body")
			w.WriteHeader(400)
			return
		}

		// Check that only non-path parameters are in body
		if bodyData["values"] == nil {
			t.Errorf("values should be in request body")
			w.WriteHeader(400)
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	// Create manifest with path parameters
	manifest := &registry.ToolManifest{
		Name:        "test.sheets.append",
		Description: "Test Google Sheets append",
		Endpoint:    server.URL + "/spreadsheets/{spreadsheetId}/values/{range}:append",
		Method:      "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "http",
		ToolManifest: manifest,
	}

	// Execute with path parameters and body data
	result, err := adapter.Execute(context.Background(), map[string]any{
		"spreadsheetId": "test-sheet-id",
		"range":         "Sheet1!A:D",
		"values": [][]any{
			{"2025-08-21", "Test Title", "Test Content", "pending"},
		},
	})

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result["success"] != true {
		t.Errorf("Expected success=true, got %v", result)
	}
}

// TestHTTPAdapter_SecurityValidation tests security measures for path parameters
func TestHTTPAdapter_SecurityValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "test.security",
		Endpoint: server.URL + "/api/{resource}/{id}",
		Method:   "GET",
	}

	adapter := &HTTPAdapter{
		AdapterID:    "http",
		ToolManifest: manifest,
	}

	// Test path traversal attempts
	testCases := []struct {
		name      string
		params    map[string]any
		shouldErr bool
		errMsg    string
	}{
		{
			name: "valid parameters",
			params: map[string]any{
				"resource": "users",
				"id":       "123",
			},
			shouldErr: false,
		},
		{
			name: "path traversal with ..",
			params: map[string]any{
				"resource": "../etc/passwd",
				"id":       "123",
			},
			shouldErr: true,
			errMsg:    "path traversal",
		},
		{
			name: "null byte injection",
			params: map[string]any{
				"resource": "users\x00.txt",
				"id":       "123",
			},
			shouldErr: true,
			errMsg:    "null byte",
		},
		{
			name: "encoded path traversal",
			params: map[string]any{
				"resource": "%2e%2e/etc/passwd",
				"id":       "123",
			},
			shouldErr: true,
			errMsg:    "encoded path traversal",
		},
		{
			name: "very long parameter",
			params: map[string]any{
				"resource": strings.Repeat("a", 2000),
				"id":       "123",
			},
			shouldErr: true,
			errMsg:    "too long",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := adapter.Execute(context.Background(), tc.params)

			if tc.shouldErr {
				if err == nil {
					t.Errorf("Expected error for %s, got none", tc.name)
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tc.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.name, err)
				}
			}
		})
	}
}

// TestHTTPAdapter_EnvironmentVariableExpansion tests $env: variable expansion in manifests
func TestHTTPAdapter_EnvironmentVariableExpansion(t *testing.T) {
	// Set test environment variable
	os.Setenv("TEST_API_TOKEN", "secret-token-123")
	defer os.Unsetenv("TEST_API_TOKEN")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that Authorization header was expanded from environment
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer secret-token-123"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"authenticated": true}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "test.auth",
		Endpoint: server.URL + "/api/test",
		Method:   "GET",
		Headers: map[string]string{
			"Authorization": "Bearer $env:TEST_API_TOKEN",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "http",
		ToolManifest: manifest,
	}

	result, err := adapter.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result["authenticated"] != true {
		t.Errorf("Expected authenticated=true, got %v", result)
	}
}

// TestHTTPAdapter_Generic covers both manifest-based and generic HTTP requests.
func TestHTTPAdapter_Generic(t *testing.T) {
	// Test generic HTTP GET
	getServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer getServer.Close()

	adapter := &HTTPAdapter{AdapterID: "http"}
	result, err := adapter.Execute(context.Background(), map[string]any{
		"url":    getServer.URL,
		"method": "GET",
	})
	if err != nil {
		t.Errorf("GET request failed: %v", err)
	}
	if result["body"] != "hello" {
		t.Errorf("expected body=hello, got %v", result["body"])
	}

	// Test generic HTTP POST
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["test"] != "data" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer postServer.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url":    postServer.URL,
		"method": "POST",
		"body":   map[string]any{"test": "data"},
	})
	if err != nil {
		t.Errorf("POST request failed: %v", err)
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}

	// Test missing URL error
	_, err = adapter.Execute(context.Background(), map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "missing or invalid url") {
		t.Errorf("expected missing or invalid url error, got %v", err)
	}

	// Test HTTP error status
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("server error"))
	}))
	defer errorServer.Close()

	_, err = adapter.Execute(context.Background(), map[string]any{
		"url": errorServer.URL,
	})
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected status 500 error, got %v", err)
	}
}

// TestHTTPAdapter_ManifestBased tests manifest-based HTTP requests.
func TestHTTPAdapter_ManifestBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("json.Decode failed: %v", err)
		}
		if body["foo"] != "bar" {
			t.Errorf("expected foo=bar in request body, got %v", body["foo"])
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "test-defaults",
		Endpoint: server.URL,
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"foo": map[string]any{"type": "string", "default": "bar"},
			},
		},
	}

	adapter := &HTTPAdapter{AdapterID: "test-defaults", ToolManifest: manifest}
	result, err := adapter.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result["ok"] != true {
		t.Errorf("expected ok=true in response, got %v", result)
	}
}

// TestHTTPAdapter_EnvVarExpansionInDefaults tests environment variable expansion in parameter defaults
func TestHTTPAdapter_EnvVarExpansionInDefaults(t *testing.T) {
	// Set test environment variables
	os.Setenv("TEST_API_KEY", "secret-key-123")
	defer func() {
		os.Unsetenv("TEST_API_KEY")
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the Authorization header was expanded correctly
		auth := r.Header.Get("Authorization")
		if auth != "Bearer secret-key-123" {
			t.Errorf("expected Authorization header 'Bearer secret-key-123', got '%s'", auth)
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "test-env-expansion",
		Endpoint: server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer $env:TEST_API_KEY",
		},
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"api_key": map[string]any{
					"type":    "string",
					"default": "$env:TEST_API_KEY",
				},
			},
		},
	}

	adapter := &HTTPAdapter{AdapterID: "test-env-expansion", ToolManifest: manifest}
	result, err := adapter.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result["success"] != true {
		t.Errorf("expected success=true in response, got %v", result)
	}
}

// TestHTTPAdapter_ID tests the adapter ID
func TestHTTPAdapter_ID(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test-id"}
	if adapter.ID() != "test-id" {
		t.Errorf("expected ID 'test-id', got %q", adapter.ID())
	}
}

// TestHTTPAdapter_Manifest tests the Manifest method
func TestHTTPAdapter_Manifest(t *testing.T) {
	manifest := &registry.ToolManifest{Name: "test"}
	adapter := &HTTPAdapter{ToolManifest: manifest}
	if adapter.Manifest() != manifest {
		t.Errorf("expected manifest to be returned, got %v", adapter.Manifest())
	}
}

// TestHTTPAdapter_InvalidURL tests error with invalid URL
func TestHTTPAdapter_InvalidURL(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test with non-string URL
	_, err := adapter.Execute(context.Background(), map[string]any{
		"url": 123,
	})
	if err == nil || !strings.Contains(err.Error(), "missing or invalid url") {
		t.Errorf("expected invalid url error, got %v", err)
	}
}

// TestHTTPAdapter_ManifestRequest tests manifest-based requests with various scenarios
func TestHTTPAdapter_ManifestRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method (manifest requests are always POST)
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}

		// Check headers
		if r.Header.Get(constants.HeaderContentType) != constants.ContentTypeJSON {
			t.Errorf("expected Content-Type %s, got %s", constants.ContentTypeJSON, r.Header.Get(constants.HeaderContentType))
		}
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("expected X-Custom header test-value, got %s", r.Header.Get("X-Custom"))
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"result": "success"}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "test-manifest",
		Endpoint: server.URL,
		Headers: map[string]string{
			constants.HeaderContentType: constants.ContentTypeJSON,
			"X-Custom":                  "test-value",
		},
	}

	adapter := &HTTPAdapter{AdapterID: "test-manifest", ToolManifest: manifest}
	result, err := adapter.Execute(context.Background(), map[string]any{
		"test": "data",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["result"] != "success" {
		t.Errorf("expected result=success, got %v", result["result"])
	}
}

// TestHTTPAdapter_HeaderExtraction tests header extraction edge cases
func TestHTTPAdapter_HeaderExtraction(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test with valid headers map
	inputs := map[string]any{
		"headers": map[string]any{
			"Authorization":             "Bearer token",
			constants.HeaderContentType: constants.ContentTypeJSON,
		},
	}
	headers := adapter.extractHeaders(inputs)
	if headers["Authorization"] != "Bearer token" {
		t.Errorf("expected Authorization header, got %v", headers["Authorization"])
	}

	// Test with invalid headers (not a map)
	inputs = map[string]any{
		"headers": "invalid",
	}
	headers = adapter.extractHeaders(inputs)
	if len(headers) != 0 {
		t.Errorf("expected empty headers for invalid input, got %v", headers)
	}

	// Test with headers containing non-string values
	inputs = map[string]any{
		"headers": map[string]any{
			"Valid":   "string-value",
			"Invalid": 123,
		},
	}
	headers = adapter.extractHeaders(inputs)
	if headers["Valid"] != "string-value" {
		t.Errorf("expected Valid header, got %v", headers["Valid"])
	}
	if _, exists := headers["Invalid"]; exists {
		t.Errorf("expected Invalid header to be filtered out, but it exists")
	}
}

// TestHTTPAdapter_MethodExtraction tests method extraction
func TestHTTPAdapter_MethodExtraction(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test default method
	method := adapter.extractMethod(map[string]any{})
	if method != "GET" {
		t.Errorf("expected default method GET, got %s", method)
	}

	// Test explicit method
	method = adapter.extractMethod(map[string]any{"method": "POST"})
	if method != "POST" {
		t.Errorf("expected method POST, got %s", method)
	}

	// Test non-string method (should default to GET)
	method = adapter.extractMethod(map[string]any{"method": 123})
	if method != "GET" {
		t.Errorf("expected default method GET for invalid input, got %s", method)
	}
}

// TestHTTPAdapter_EnvironmentExpansion tests environment variable expansion edge cases
func TestHTTPAdapter_EnvironmentExpansion(t *testing.T) {
	// Set test environment variable
	os.Setenv("TEST_VAR", "test-value")
	defer os.Unsetenv("TEST_VAR")

	// Test valid expansion
	result := expandEnvValue("$env:TEST_VAR")
	if result != "test-value" {
		t.Errorf("expected test-value, got %s", result)
	}

	// Test non-env value
	result = expandEnvValue("regular-value")
	if result != "regular-value" {
		t.Errorf("expected regular-value, got %s", result)
	}

	// Test missing environment variable
	result = expandEnvValue("$env:MISSING_VAR")
	if result != "$env:MISSING_VAR" {
		t.Errorf("expected original value for missing env var, got %s", result)
	}
}

// TestHTTPAdapter_DefaultEnrichment tests input enrichment with defaults
func TestHTTPAdapter_DefaultEnrichment(t *testing.T) {
	manifest := &registry.ToolManifest{
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"param1": map[string]any{
					"type":    "string",
					"default": "default-value",
				},
				"param2": map[string]any{
					"type":    "string",
					"default": "$env:TEST_DEFAULT",
				},
				"param3": map[string]any{
					"type": "string",
					// No default
				},
			},
		},
	}

	os.Setenv("TEST_DEFAULT", "env-default")
	defer os.Unsetenv("TEST_DEFAULT")

	adapter := &HTTPAdapter{AdapterID: "test", ToolManifest: manifest}

	inputs := map[string]any{
		"param3": "user-value",
	}

	enriched := adapter.enrichInputsWithDefaults(inputs)

	if enriched["param1"] != "default-value" {
		t.Errorf("expected param1=default-value, got %v", enriched["param1"])
	}
	if enriched["param2"] != "env-default" {
		t.Errorf("expected param2=env-default, got %v", enriched["param2"])
	}
	if enriched["param3"] != "user-value" {
		t.Errorf("expected param3=user-value, got %v", enriched["param3"])
	}
}

// TestHTTPAdapter_ManifestHeaders tests manifest header preparation
func TestHTTPAdapter_ManifestHeaders(t *testing.T) {
	os.Setenv("TEST_TOKEN", "secret-token")
	defer os.Unsetenv("TEST_TOKEN")

	manifest := &registry.ToolManifest{
		Headers: map[string]string{
			"Authorization":             "Bearer $env:TEST_TOKEN",
			constants.HeaderContentType: constants.ContentTypeJSON,
			"X-Static":                  "static-value",
		},
	}

	adapter := &HTTPAdapter{AdapterID: "test", ToolManifest: manifest}
	headers := adapter.prepareManifestHeaders(context.Background(), map[string]any{})

	if headers["Authorization"] != "Bearer secret-token" {
		t.Errorf("expected Authorization=Bearer secret-token, got %s", headers["Authorization"])
	}
	if headers[constants.HeaderContentType] != constants.ContentTypeJSON {
		t.Errorf("expected Content-Type=%s, got %s", constants.ContentTypeJSON, headers[constants.HeaderContentType])
	}
	if headers["X-Static"] != "static-value" {
		t.Errorf("expected X-Static=static-value, got %s", headers["X-Static"])
	}
}

// TestHTTPAdapter_ResponseProcessing tests HTTP response processing edge cases
func TestHTTPAdapter_ResponseProcessing(t *testing.T) {
	// Test JSON response
	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		w.Write([]byte(`{"key": "value"}`))
	}))
	defer jsonServer.Close()

	adapter := &HTTPAdapter{AdapterID: "test"}
	result, err := adapter.Execute(context.Background(), map[string]any{
		"url": jsonServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result["key"])
	}

	// Test non-JSON response
	textServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeText)
		w.Write([]byte("plain text"))
	}))
	defer textServer.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url": textServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["body"] != "plain text" {
		t.Errorf("expected body=plain text, got %v", result["body"])
	}

	// Test invalid JSON response
	invalidJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		w.Write([]byte(`invalid json{`))
	}))
	defer invalidJSONServer.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url": invalidJSONServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["body"] != "invalid json{" {
		t.Errorf("expected body=invalid json{, got %v", result["body"])
	}
}

// TestHTTPAdapter_SafeAssertions tests safe type assertion functions
func TestHTTPAdapter_SafeAssertions(t *testing.T) {
	// Test safeStringAssert
	if result, ok := safeStringAssert("test"); !ok || result != "test" {
		t.Errorf("expected (test, true), got (%s, %v)", result, ok)
	}
	if result, ok := safeStringAssert(123); ok || result != "" {
		t.Errorf("expected (\"\", false) for non-string, got (%s, %v)", result, ok)
	}
	if result, ok := safeStringAssert(nil); ok || result != "" {
		t.Errorf("expected (\"\", false) for nil, got (%s, %v)", result, ok)
	}

	// Test safeMapAssert
	testMap := map[string]any{"key": "value"}
	if result, ok := safeMapAssert(testMap); !ok || result["key"] != "value" {
		t.Errorf("expected map with key=value, got %v, %v", result, ok)
	}
	if result, ok := safeMapAssert("not a map"); ok || len(result) != 0 {
		t.Errorf("expected (empty map, false) for non-map, got (%v, %v)", result, ok)
	}
	if result, ok := safeMapAssert(nil); ok || len(result) != 0 {
		t.Errorf("expected (empty map, false) for nil, got (%v, %v)", result, ok)
	}
}

// TestHTTPAdapter_NetworkError tests network error handling
func TestHTTPAdapter_NetworkError(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test with invalid URL that will cause network error
	_, err := adapter.Execute(context.Background(), map[string]any{
		"url": "http://invalid-host-that-does-not-exist.local",
	})
	if err == nil {
		t.Error("expected network error, got nil")
	}
}

// TestHTTPAdapter_ComplexManifestScenario tests a complex manifest-based scenario
func TestHTTPAdapter_ComplexManifestScenario(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method (manifest requests are always POST)
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}

		// Verify headers
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header, got %s", r.Header.Get("Authorization"))
		}

		// Verify body
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "test-name" {
			t.Errorf("expected name=test-name, got %v", body["name"])
		}
		if body["default_param"] != "default-value" {
			t.Errorf("expected default_param=default-value, got %v", body["default_param"])
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"updated": true, "id": 123}`))
	}))
	defer server.Close()

	manifest := &registry.ToolManifest{
		Name:     "complex-test",
		Endpoint: server.URL,
		Headers: map[string]string{
			"Authorization":             "Bearer test-token",
			constants.HeaderContentType: constants.ContentTypeJSON,
		},
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type": "string",
				},
				"default_param": map[string]any{
					"type":    "string",
					"default": "default-value",
				},
			},
		},
	}

	adapter := &HTTPAdapter{AdapterID: "complex-test", ToolManifest: manifest}
	result, err := adapter.Execute(context.Background(), map[string]any{
		"name": "test-name",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["updated"] != true {
		t.Errorf("expected updated=true, got %v", result["updated"])
	}
	if result["id"] != float64(123) { // JSON numbers are float64
		t.Errorf("expected id=123, got %v", result["id"])
	}
}

// TestHTTPAdapter_PrepareManifestHeaders_ErrorPaths tests error handling in prepareManifestHeaders
func TestHTTPAdapter_PrepareManifestHeaders_ErrorPaths(t *testing.T) {
	manifest := &registry.ToolManifest{
		Headers: map[string]string{
			"Authorization":             "Bearer token",
			constants.HeaderContentType: constants.ContentTypeJSON,
		},
	}

	adapter := &HTTPAdapter{AdapterID: "test", ToolManifest: manifest}

	// Test with valid inputs
	inputs := map[string]any{
		"headers": map[string]any{
			"X-Custom": "custom-value",
		},
	}

	headers := adapter.prepareManifestHeaders(context.Background(), inputs)

	if headers["Authorization"] != "Bearer token" {
		t.Errorf("expected Authorization header from manifest, got %v", headers["Authorization"])
	}
	if headers["X-Custom"] != "custom-value" {
		t.Errorf("expected X-Custom header from inputs, got %v", headers["X-Custom"])
	}

	// Test with nil manifest headers
	adapter.ToolManifest.Headers = nil
	headers = adapter.prepareManifestHeaders(context.Background(), inputs)
	if headers["X-Custom"] != "custom-value" {
		t.Errorf("expected X-Custom header from inputs, got %v", headers["X-Custom"])
	}
}

// TestHTTPAdapter_EnrichInputsWithDefaults_EdgeCases tests edge cases in enrichInputsWithDefaults
func TestHTTPAdapter_EnrichInputsWithDefaults_EdgeCases(t *testing.T) {
	// Test with nil parameters
	manifest := &registry.ToolManifest{
		Parameters: nil,
	}

	adapter := &HTTPAdapter{AdapterID: "test", ToolManifest: manifest}
	inputs := map[string]any{"test": "value"}

	enriched := adapter.enrichInputsWithDefaults(inputs)
	if enriched["test"] != "value" {
		t.Errorf("expected original input to be preserved, got %v", enriched["test"])
	}

	// Test with invalid properties structure
	manifest.Parameters = map[string]any{
		"type":       "object",
		"properties": "invalid", // Should be a map
	}

	enriched = adapter.enrichInputsWithDefaults(inputs)
	if enriched["test"] != "value" {
		t.Errorf("expected original input to be preserved with invalid properties, got %v", enriched["test"])
	}

	// Test with invalid property definition
	manifest.Parameters = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"valid_prop": map[string]any{
				"type":    "string",
				"default": "valid_default",
			},
			"invalid_prop": "not_a_map", // Should be a map
		},
	}

	enriched = adapter.enrichInputsWithDefaults(inputs)
	if enriched["valid_prop"] != "valid_default" {
		t.Errorf("expected valid_prop to have default value, got %v", enriched["valid_prop"])
	}
	if _, exists := enriched["invalid_prop"]; exists {
		t.Error("expected invalid_prop to be skipped")
	}

	// Test with non-string default that doesn't need env expansion
	manifest.Parameters = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"number_prop": map[string]any{
				"type":    "number",
				"default": 42,
			},
			"bool_prop": map[string]any{
				"type":    "boolean",
				"default": true,
			},
		},
	}

	enriched = adapter.enrichInputsWithDefaults(map[string]any{})
	if enriched["number_prop"] != 42 {
		t.Errorf("expected number_prop=42, got %v", enriched["number_prop"])
	}
	if enriched["bool_prop"] != true {
		t.Errorf("expected bool_prop=true, got %v", enriched["bool_prop"])
	}
}

// TestHTTPAdapter_ProcessHTTPResponse_EdgeCases tests edge cases in processHTTPResponse
func TestHTTPAdapter_ProcessHTTPResponse_EdgeCases(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test with JSON array response
	arrayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		w.Write([]byte(`[1, 2, 3]`))
	}))
	defer arrayServer.Close()

	result, err := adapter.Execute(context.Background(), map[string]any{
		"url": arrayServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Array should be wrapped in body
	body, ok := result["body"].([]any)
	if !ok {
		t.Errorf("expected body to contain array, got %T", result["body"])
	} else if len(body) != 3 {
		t.Errorf("expected array length 3, got %d", len(body))
	}

	// Test with JSON primitive response
	primitiveServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		w.Write([]byte(`"hello world"`))
	}))
	defer primitiveServer.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url": primitiveServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// String primitive should be wrapped in body
	if result["body"] != "hello world" {
		t.Errorf("expected body='hello world', got %v", result["body"])
	}

	// Test with empty response
	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// No body
	}))
	defer emptyServer.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url": emptyServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["body"] != "" {
		t.Errorf("expected empty body, got %v", result["body"])
	}
}

// TestHTTPAdapter_ExecuteManifestRequest_EdgeCases tests edge cases in executeManifestRequest
func TestHTTPAdapter_ExecuteManifestRequest_EdgeCases(t *testing.T) {
	// Test with manifest that has no endpoint (should not happen in practice)
	manifest := &registry.ToolManifest{
		Name: "test",
		// No endpoint
	}

	adapter := &HTTPAdapter{AdapterID: "test", ToolManifest: manifest}

	// Should fall back to generic request handling
	_, err := adapter.Execute(context.Background(), map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "missing or invalid url") {
		t.Errorf("expected missing url error, got %v", err)
	}
}

// TestHTTPAdapter_ExecuteGenericRequest_EdgeCases tests edge cases in executeGenericRequest
func TestHTTPAdapter_ExecuteGenericRequest_EdgeCases(t *testing.T) {
	adapter := &HTTPAdapter{AdapterID: "test"}

	// Test with POST request and nil body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}

		// Check that body is empty for nil body case
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("expected empty body, got %s", string(body))
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	result, err := adapter.Execute(context.Background(), map[string]any{
		"url":    server.URL,
		"method": "POST",
		"body":   nil, // Explicitly nil body
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}

	// Test with POST request and valid body (separate server to avoid interference)
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}

		// Check that body contains the expected data
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		if body["valid"] != "body" {
			t.Errorf("expected valid=body, got %v", body["valid"])
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server2.Close()

	result, err = adapter.Execute(context.Background(), map[string]any{
		"url":    server2.URL,
		"method": "POST",
		"body":   map[string]any{"valid": "body"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}
}
