package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

func TestMain(m *testing.M) {
	utils.WithCleanDirs(m, ".beemflow", config.DefaultConfigDir)
}

// Helper function to create a test config
func createTestConfig(t *testing.T) *config.Config {
	_ = t // Parameter not needed for this simple config creation
	return &config.Config{
		Storage: config.StorageConfig{
			Driver: "sqlite",
			DSN:    ":memory:",
		},
		OAuth: &config.OAuthConfig{
			Enabled: false, // Disable OAuth for unit tests
		},
	}
}

// Helper function to create and write a config file
func createTempConfigFile(t *testing.T, cfg *config.Config) {
	configDir := filepath.Dir(constants.ConfigFileName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	configFile, err := os.Create(constants.ConfigFileName)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	defer configFile.Close()

	if err := json.NewEncoder(configFile).Encode(cfg); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
}

// Helper function to test middleware with different scenarios
// Commented out - unused function
/*
func testMiddlewareScenarios(t *testing.T, middleware func(http.Handler) http.Handler, scenarios []testScenario) {
	for _, scenario := range scenarios {
		req := httptest.NewRequest(scenario.method, scenario.path, nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(scenario.handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != scenario.expectedStatus {
			t.Errorf("Scenario %s %s: expected status %d, got %d",
				scenario.method, scenario.path, scenario.expectedStatus, rec.Code)
		}
	}
}
*/

func TestRequestIDMiddleware(t *testing.T) {
	// Test handler that checks for request ID
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID, ok := utils.RequestIDFromContext(r.Context())
		if !ok {
			t.Error("Request ID not found in context")
		}
		if reqID == "" {
			t.Error("Request ID is empty")
		}

		// Check that response header is set
		responseReqID := w.Header().Get("X-Request-Id")
		if responseReqID == "" {
			t.Error("X-Request-Id header not set in response")
		}
		if responseReqID != reqID {
			t.Errorf("Response header X-Request-Id (%s) doesn't match context (%s)", responseReqID, reqID)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test without X-Request-Id header (should generate one)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler := requestIDMiddleware(testHandler)
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Test with existing X-Request-Id header (should use it)
	existingReqID := "test-request-id-123"
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-Id", existingReqID)
	rec = httptest.NewRecorder()

	testHandler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID, ok := utils.RequestIDFromContext(r.Context())
		if !ok {
			t.Error("Request ID not found in context")
		}
		if reqID != existingReqID {
			t.Errorf("Expected request ID %s, got %s", existingReqID, reqID)
		}
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler2 := requestIDMiddleware(testHandler2)
	wrappedHandler2.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	responseReqID := rec.Header().Get("X-Request-Id")
	if responseReqID != existingReqID {
		t.Errorf("Expected response X-Request-Id %s, got %s", existingReqID, responseReqID)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	// Test scenario type for this test
	type testScenario struct {
		method         string
		path           string
		handler        http.Handler
		expectedStatus int
	}

	// Create test scenarios
	scenarios := []testScenario{
		{"GET", "/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}), http.StatusOK},
		{"POST", "/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}), http.StatusCreated},
		{"PUT", "/error", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}), http.StatusInternalServerError},
		{"DELETE", "/notfound", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}), http.StatusNotFound},
	}

	// Test each scenario
	for _, scenario := range scenarios {
		req := httptest.NewRequest(scenario.method, scenario.path, nil)
		rec := httptest.NewRecorder()

		wrappedHandler := metricsMiddleware("test-handler", scenario.handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != scenario.expectedStatus {
			t.Errorf("Method %s Path %s: expected status %d, got %d",
				scenario.method, scenario.path, scenario.expectedStatus, rec.Code)
		}
	}
}

func TestResponseWriter(t *testing.T) {
	// Test the responseWriter wrapper
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, status: 200}

	// Test default status
	if rw.status != 200 {
		t.Errorf("Expected default status 200, got %d", rw.status)
	}

	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)
	if rw.status != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, rw.status)
	}

	// Test Write and Header
	data := []byte("test data")
	rw.Header().Set("Content-Type", "text/plain")
	n, err := rw.Write(data)

	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Expected Content-Type 'text/plain', got %s", ct)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("Expected recorder status %d, got %d", http.StatusCreated, rec.Code)
	}
	if body := rec.Body.String(); body != "test data" {
		t.Errorf("Expected body 'test data', got %s", body)
	}
}

func TestInitTracerFromConfig(t *testing.T) {
	// Test different tracing configurations
	configs := []*config.Config{
		{}, // Empty config
		{Tracing: &config.TracingConfig{ServiceName: "test-service", Exporter: "stdout"}},
		{Tracing: &config.TracingConfig{ServiceName: "test-otlp", Exporter: "otlp", Endpoint: "http://localhost:4318"}},
		{Tracing: &config.TracingConfig{ServiceName: "test-otlp-default", Exporter: "otlp"}},
		{Tracing: &config.TracingConfig{ServiceName: "test-unknown", Exporter: "unknown"}},
		{Tracing: nil},
	}

	for i, cfg := range configs {
		t.Run(fmt.Sprintf("config_%d", i), func(t *testing.T) {
			// These should not panic
			initTracerFromConfig(cfg)
		})
	}
}

func TestUpdateRunEvent(t *testing.T) {
	tempConfig := createTestConfig(t)
	createTempConfigFile(t, tempConfig)
	defer os.Remove(constants.ConfigFileName)

	runID := uuid.New()
	newEvent := map[string]any{"hello": "world"}

	// We expect this to fail with a "run not found" error
	err := UpdateRunEvent(runID, newEvent)
	if err == nil {
		t.Fatalf("expected 'run not found' error, got nil")
	}
	if !strings.Contains(err.Error(), "run not found") {
		t.Errorf("expected 'run not found' error, got: %v", err)
	}
}

func TestHTTPServer_ListRuns(t *testing.T) {
	tempConfig := createTestConfig(t)
	createTempConfigFile(t, tempConfig)
	defer os.Remove(constants.ConfigFileName)

	// Create handler without starting a real server
	handler, cleanup, err := NewHandler(tempConfig)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}
	defer cleanup()

	// Create test server
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test the endpoint
	resp, err := http.Get(server.URL + "/runs")
	if err != nil {
		t.Fatalf("Failed to GET /runs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Expected application/json, got %s", ct)
	}
}
