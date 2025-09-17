package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
)

// storageContextKey is already defined in http_adapter.go

func TestHTTPAdapter_ExpandValue_EnvironmentVariables(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		expected   string
		setupEnv   func()
		cleanupEnv func()
	}{
		{
			name:     "simple env expansion",
			value:    "$env:TEST_TOKEN",
			expected: "test_token_value",
			setupEnv: func() {
				os.Setenv("TEST_TOKEN", "test_token_value")
			},
			cleanupEnv: func() {
				os.Unsetenv("TEST_TOKEN")
			},
		},
		{
			name:       "env var not found keeps original",
			value:      "$env:NONEXISTENT_TOKEN",
			expected:   "$env:NONEXISTENT_TOKEN",
			setupEnv:   func() {},
			cleanupEnv: func() {},
		},
		{
			name:       "no expansion needed",
			value:      "Bearer static_token",
			expected:   "Bearer static_token",
			setupEnv:   func() {},
			cleanupEnv: func() {},
		},
		{
			name:     "multiple env vars",
			value:    "Bearer $env:TOKEN_PREFIX-$env:TOKEN_SUFFIX",
			expected: "Bearer prefix-suffix",
			setupEnv: func() {
				os.Setenv("TOKEN_PREFIX", "prefix")
				os.Setenv("TOKEN_SUFFIX", "suffix")
			},
			cleanupEnv: func() {
				os.Unsetenv("TOKEN_PREFIX")
				os.Unsetenv("TOKEN_SUFFIX")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer tt.cleanupEnv()

			storage := storage.NewMemoryStorage()
			ctx := context.WithValue(context.Background(), storageContextKey, storage)

			adapter := &HTTPAdapter{AdapterID: "test"}
			result := adapter.expandValue(ctx, tt.value)

			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestHTTPAdapter_ExpandValue_OAuth(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		expected     string
		setupStorage func() storage.Storage
	}{
		{
			name:     "oauth token found",
			value:    "$oauth:google:sheets_default",
			expected: "Bearer oauth_token_123",
			setupStorage: func() storage.Storage {
				s := storage.NewMemoryStorage()
				cred := &model.OAuthCredential{
					ID:          "test-id",
					Provider:    "google",
					Integration: "sheets_default",
					AccessToken: "oauth_token_123",
					ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				s.SaveOAuthCredential(context.Background(), cred)
				return s
			},
		},
		{
			name:     "oauth token not found keeps original",
			value:    "$oauth:nonexistent:integration",
			expected: "$oauth:nonexistent:integration",
			setupStorage: func() storage.Storage {
				return storage.NewMemoryStorage()
			},
		},
		{
			name:     "oauth with different provider",
			value:    "$oauth:github:repos_main",
			expected: "Bearer github_token_456",
			setupStorage: func() storage.Storage {
				s := storage.NewMemoryStorage()
				cred := &model.OAuthCredential{
					ID:          "github-id",
					Provider:    "github",
					Integration: "repos_main",
					AccessToken: "github_token_456",
					ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				s.SaveOAuthCredential(context.Background(), cred)
				return s
			},
		},
		{
			name:     "invalid oauth format keeps original",
			value:    "$oauth:incomplete",
			expected: "$oauth:incomplete",
			setupStorage: func() storage.Storage {
				return storage.NewMemoryStorage()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := tt.setupStorage()
			ctx := context.WithValue(context.Background(), storageContextKey, storage)

			adapter := &HTTPAdapter{AdapterID: "test"}
			result := adapter.expandValue(ctx, tt.value)

			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestHTTPAdapter_GetOAuthToken(t *testing.T) {
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	// Save test credential
	cred := &model.OAuthCredential{
		ID:          "test-id",
		Provider:    "google",
		Integration: "sheets_test",
		AccessToken: "valid_token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	adapter := &HTTPAdapter{AdapterID: "test"}
	token, err := adapter.getOAuthToken(ctx, "google", "sheets_test")
	if err != nil {
		t.Fatalf("getOAuthToken failed: %v", err)
	}

	if token != "valid_token" {
		t.Errorf("Expected token 'valid_token', got %q", token)
	}
}

func TestHTTPAdapter_GetOAuthToken_NotFound(t *testing.T) {
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	adapter := &HTTPAdapter{AdapterID: "test"}
	_, err := adapter.getOAuthToken(ctx, "nonexistent", "integration")
	if err == nil {
		t.Error("Expected error for non-existent OAuth credential")
	}

	if !strings.Contains(err.Error(), "failed to get OAuth credential") {
		t.Errorf("Expected credential error, got %v", err)
	}
}

func TestHTTPAdapter_GetOAuthToken_NoStorage(t *testing.T) {
	// Context without storage
	ctx := context.Background()

	adapter := &HTTPAdapter{AdapterID: "test"}
	_, err := adapter.getOAuthToken(ctx, "google", "sheets_test")
	if err == nil {
		t.Error("Expected error when storage not available in context")
	}

	if !strings.Contains(err.Error(), "storage not available") {
		t.Errorf("Expected storage error, got %v", err)
	}
}

func TestHTTPAdapter_GetOAuthToken_ExpiredToken(t *testing.T) {
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	// Save expired credential
	cred := &model.OAuthCredential{
		ID:           "expired-id",
		Provider:     "google",
		Integration:  "sheets_expired",
		AccessToken:  "expired_token",
		RefreshToken: stringPtr("valid_refresh_token"),
		ExpiresAt:    timePtr(time.Now().Add(-time.Hour)), // Expired
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save expired credential: %v", err)
	}

	adapter := &HTTPAdapter{AdapterID: "test"}

	// This should fail since we don't have token refresh implemented yet
	_, err = adapter.getOAuthToken(ctx, "google", "sheets_expired")
	if err == nil {
		t.Error("Expected error for expired token without refresh implementation")
	}
}

func TestHTTPAdapter_OAuthIntegration_EndToEnd(t *testing.T) {
	// Create test server that checks for OAuth token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer oauth_integration_token"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"success": true, "message": "OAuth token worked"}`))
	}))
	defer server.Close()

	// Setup storage with OAuth credential
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	cred := &model.OAuthCredential{
		ID:          "integration-test-id",
		Provider:    "google",
		Integration: "sheets_integration",
		AccessToken: "oauth_integration_token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	// Create manifest with OAuth header
	manifest := &registry.ToolManifest{
		Name:     "test.oauth.integration",
		Endpoint: server.URL + "/api/test",
		Method:   "GET",
		Headers: map[string]string{
			"Authorization": "$oauth:google:sheets_integration",
			"Content-Type":  "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "oauth_test",
		ToolManifest: manifest,
	}

	// Execute request - should resolve OAuth token and make successful call
	result, err := adapter.Execute(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result["success"] != true {
		t.Errorf("Expected success=true, got %v", result)
	}

	if result["message"] != "OAuth token worked" {
		t.Errorf("Expected success message, got %v", result)
	}
}

func TestHTTPAdapter_OAuthWithEnvironmentFallback(t *testing.T) {
	// Set up environment variable fallback
	os.Setenv("FALLBACK_TOKEN", "env_fallback_token")
	defer os.Unsetenv("FALLBACK_TOKEN")

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer env_fallback_token"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"fallback": true}`))
	}))
	defer server.Close()

	// Setup storage without OAuth credential (empty)
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	// Create manifest with OAuth + env fallback
	manifest := &registry.ToolManifest{
		Name:     "test.oauth.fallback",
		Endpoint: server.URL + "/api/test",
		Method:   "GET",
		Headers: map[string]string{
			// This should fallback to environment variable when OAuth not found
			"Authorization": "Bearer $env:FALLBACK_TOKEN",
			"Content-Type":  "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "fallback_test",
		ToolManifest: manifest,
	}

	// Execute request - should fallback to env var
	result, err := adapter.Execute(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if result["fallback"] != true {
		t.Errorf("Expected fallback=true, got %v", result)
	}
}

// Helper functions
func timePtr(t time.Time) *time.Time {
	return &t
}

func stringPtr(s string) *string {
	return &s
}
