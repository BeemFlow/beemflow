package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beemflow/beemflow/config"
)

func TestInit(t *testing.T) {
	// Test Init with empty config
	cfg := &config.Config{}
	err := Init(cfg)
	if err != nil {
		t.Errorf("Init with empty config should not fail, got: %v", err)
	}

	// Test Init with tracing config (stdout)
	cfg = &config.Config{
		Tracing: &config.TracingConfig{
			ServiceName: "test-service",
			Exporter:    "stdout",
		},
	}
	err = Init(cfg)
	if err != nil {
		t.Errorf("Init with stdout config should not fail, got: %v", err)
	}

	// Test Init with OTLP config
	cfg = &config.Config{
		Tracing: &config.TracingConfig{
			ServiceName: "test-service-otlp",
			Exporter:    "otlp",
			Endpoint:    "http://localhost:4318",
		},
	}
	err = Init(cfg)
	if err != nil {
		t.Errorf("Init with OTLP config should not fail, got: %v", err)
	}

	// Test Init with OTLP config without endpoint (should use default)
	cfg = &config.Config{
		Tracing: &config.TracingConfig{
			ServiceName: "test-service-otlp-default",
			Exporter:    "otlp",
		},
	}
	err = Init(cfg)
	if err != nil {
		t.Errorf("Init with OTLP config (default endpoint) should not fail, got: %v", err)
	}
}

func TestWrapHandler(t *testing.T) {
	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Wrap the handler
	wrappedHandler := WrapHandler("test-handler", testHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Call the wrapped handler
	wrappedHandler.ServeHTTP(rec, req)

	// Check response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body != "test response" {
		t.Errorf("Expected 'test response', got %s", body)
	}
}

func TestWrapHandlerWithDifferentMethods(t *testing.T) {
	// Test handler with different HTTP methods
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("method: " + r.Method))
	})

	wrappedHandler := WrapHandler("method-test", testHandler)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/test", nil)
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Errorf("Expected status code 202 for %s, got %d", method, rec.Code)
		}

		expectedBody := "method: " + method
		if body := rec.Body.String(); body != expectedBody {
			t.Errorf("Expected '%s', got %s", expectedBody, body)
		}
	}
}

func TestMetricsHandler(t *testing.T) {
	// Test MetricsHandler
	metricsHandler := MetricsHandler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()

	metricsHandler.ServeHTTP(rec, req)

	// Should return 200
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rec.Code)
	}

	// Should return some metrics content
	body := rec.Body.String()
	if body == "" {
		t.Error("Expected non-empty metrics response")
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	// Test the ResponseWriter wrapper functionality
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test that we can write headers
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("test content"))
	})

	wrappedHandler := WrapHandler("create-test", testHandler)

	req := httptest.NewRequest("POST", "/create", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// Check status code
	if rec.Code != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", rec.Code)
	}

	// Check header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected Content-Type 'text/plain', got %s", contentType)
	}

	// Check body
	body := rec.Body.String()
	if body != "test content" {
		t.Errorf("Expected 'test content', got %s", body)
	}
}

func TestResponseWriterWrapperMultipleWrites(t *testing.T) {
	// Test multiple writes to the response writer
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("part1"))
		w.Write([]byte("part2"))
		w.Write([]byte("part3"))
	})

	wrappedHandler := WrapHandler("multiwrite-test", testHandler)

	req := httptest.NewRequest("GET", "/multiwrite", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// Check status code
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rec.Code)
	}

	// Check body contains all parts
	body := rec.Body.String()
	if body != "part1part2part3" {
		t.Errorf("Expected 'part1part2part3', got %s", body)
	}
}

func TestWrapHandlerWithNilHandler(t *testing.T) {
	// Test wrapping nil handler - it will panic since the implementation doesn't handle nil
	defer func() {
		if r := recover(); r == nil {
			t.Error("WrapHandler with nil handler should panic (current implementation doesn't handle nil)")
		}
	}()

	wrappedHandler := WrapHandler("nil-test", nil)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)
}

func TestHandlerWithPanicRecovery(t *testing.T) {
	// Test handler that panics - the current implementation doesn't recover panics
	defer func() {
		if r := recover(); r == nil {
			t.Error("Wrapped handler should propagate panics (current implementation doesn't recover)")
		}
	}()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	wrappedHandler := WrapHandler("panic-test", panicHandler)

	req := httptest.NewRequest("GET", "/panic", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)
}

func TestMetricsHandlerWithDifferentPaths(t *testing.T) {
	// Test MetricsHandler with different request scenarios
	metricsHandler := MetricsHandler()

	// Test basic GET request
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()

	metricsHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body == "" {
		t.Error("Expected non-empty metrics response")
	}

	// Test that metrics contain expected patterns
	if !containsMetrics(body) {
		t.Error("Expected metrics content to contain metric patterns")
	}
}

func TestResponseWriterWrapperHeaders(t *testing.T) {
	// Test that headers are properly passed through
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("X-Another-Header", "another-value")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("headers test"))
	})

	wrappedHandler := WrapHandler("headers-test", testHandler)

	req := httptest.NewRequest("GET", "/headers", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// Check status code
	if rec.Code != http.StatusPartialContent {
		t.Errorf("Expected status code 206, got %d", rec.Code)
	}

	// Check headers
	if customHeader := rec.Header().Get("X-Custom-Header"); customHeader != "custom-value" {
		t.Errorf("Expected X-Custom-Header 'custom-value', got %s", customHeader)
	}

	if anotherHeader := rec.Header().Get("X-Another-Header"); anotherHeader != "another-value" {
		t.Errorf("Expected X-Another-Header 'another-value', got %s", anotherHeader)
	}
}

func TestInitWithDifferentConfigs(t *testing.T) {
	// Test that multiple calls to Init with different configs don't cause issues
	configs := []*config.Config{
		{}, // Empty config
		{
			Tracing: &config.TracingConfig{
				ServiceName: "test1",
				Exporter:    "stdout",
			},
		},
		{
			Tracing: &config.TracingConfig{
				ServiceName: "test2",
				Exporter:    "otlp",
				Endpoint:    "http://example.com:4318",
			},
		},
		{
			Tracing: &config.TracingConfig{
				ServiceName: "test3",
				Exporter:    "unknown", // Should fallback to stdout
			},
		},
	}

	for i, cfg := range configs {
		err := Init(cfg)
		if err != nil {
			t.Errorf("Config %d should not fail, got: %v", i, err)
		}
	}
}

func TestWrapperIntegration(t *testing.T) {
	// Test integration of wrapper with a more complex handler
	complexHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some work
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "success"}`))
		case "/error":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		case "/redirect":
			w.Header().Set("Location", "/somewhere")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}
	})

	wrappedHandler := WrapHandler("complex-test", complexHandler)

	testCases := []struct {
		path           string
		expectedStatus int
		expectedBody   string
		expectedHeader string
	}{
		{"/json", http.StatusOK, `{"message": "success"}`, "application/json"},
		{"/error", http.StatusBadRequest, "bad request", ""},
		{"/redirect", http.StatusFound, "", ""},
		{"/unknown", http.StatusNotFound, "not found", ""},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.path, nil)
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != tc.expectedStatus {
			t.Errorf("Path %s: expected status code %d, got %d", tc.path, tc.expectedStatus, rec.Code)
		}

		if tc.expectedBody != "" {
			body := rec.Body.String()
			if body != tc.expectedBody {
				t.Errorf("Path %s: expected body '%s', got '%s'", tc.path, tc.expectedBody, body)
			}
		}

		if tc.expectedHeader != "" {
			contentType := rec.Header().Get("Content-Type")
			if contentType != tc.expectedHeader {
				t.Errorf("Path %s: expected Content-Type '%s', got '%s'", tc.path, tc.expectedHeader, contentType)
			}
		}
	}
}

// Helper function to check if the response contains expected metrics patterns
func containsMetrics(body string) bool {
	// Check for common Prometheus metric patterns
	patterns := []string{
		"beemflow_http_requests_total",
		"beemflow_http_request_duration_seconds",
		"# HELP",
		"# TYPE",
	}

	for _, pattern := range patterns {
		if !strings.Contains(body, pattern) {
			return false
		}
	}
	return true
}
