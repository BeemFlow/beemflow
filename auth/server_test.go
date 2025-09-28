package auth

import (
	"testing"
	"time"

	"github.com/beemflow/beemflow/storage"
)

func TestOAuthServer_NewOAuthServer(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &OAuthConfig{
		Issuer:        "https://example.com",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		TokenExpiry:   time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	server := NewOAuthServer(cfg, store)
	if server == nil {
		t.Fatal("NewOAuthServer returned nil")
	}
	if server.config.Issuer != cfg.Issuer {
		t.Errorf("Expected issuer %s, got %s", cfg.Issuer, server.config.Issuer)
	}
}

func TestOAuthServer_HandleMetadataDiscovery(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &OAuthConfig{
		Issuer:        "https://example.com",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		TokenExpiry:   time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	_ = NewOAuthServer(cfg, store)

	// This would normally require an HTTP request/response
	// For unit testing, we can test the metadata structure
	// by calling the method directly if we refactor it

	t.Skip("HTTP handler testing requires httptest.Server setup")
}

func TestIsValidRedirectURI(t *testing.T) {
	// Test with production config (localhost redirects disabled)
	prodCfg := &OAuthConfig{AllowLocalhostRedirects: false}
	prodServer := &OAuthServer{config: prodCfg}

	// Test with development config (localhost redirects enabled)
	devCfg := &OAuthConfig{AllowLocalhostRedirects: true}
	devServer := &OAuthServer{config: devCfg}

	tests := []struct {
		name     string
		uri      string
		expected bool
		server   *OAuthServer
	}{
		{"valid HTTPS", "https://example.com/callback", true, prodServer},
		{"invalid HTTP", "http://example.com/callback", false, prodServer},
		{"localhost HTTPS (prod)", "https://localhost:8080/callback", false, prodServer},
		{"localhost HTTPS (dev)", "https://localhost:8080/callback", true, devServer},
		{"invalid localhost HTTP", "http://localhost:8080/callback", false, prodServer},
		{"invalid 127.0.0.1 HTTP", "http://127.0.0.1:8080/callback", false, prodServer},
		{"invalid IP address", "https://192.168.1.1/callback", false, prodServer},
		{"invalid fragment", "https://example.com/callback#fragment", false, prodServer},
		{"empty string", "", false, prodServer},
		{"invalid URL", "not-a-url", false, prodServer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.server.isValidRedirectURI(tt.uri)
			if result != tt.expected {
				t.Errorf("isValidRedirectURI(%q) = %v, want %v", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestGenerateClientSecret(t *testing.T) {
	secret1 := generateClientSecret()
	secret2 := generateClientSecret()

	if secret1 == "" {
		t.Error("generateClientSecret returned empty string")
	}
	if secret1 == secret2 {
		t.Error("generateClientSecret should generate unique secrets")
	}
	if len(secret1) == 0 {
		t.Error("generateClientSecret returned empty secret")
	}

	// Should be base64 URL encoded
	// 32 bytes -> base64 should be ~43 characters
	if len(secret1) < 40 {
		t.Errorf("generateClientSecret too short: %d chars", len(secret1))
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(time.Minute, 2)

	// First request should be allowed
	if !rl.allow("ip1") {
		t.Error("First request should be allowed")
	}

	// Second request should be allowed
	if !rl.allow("ip1") {
		t.Error("Second request should be allowed")
	}

	// Third request should be denied
	if rl.allow("ip1") {
		t.Error("Third request should be denied")
	}

	// Different IP should be allowed
	if !rl.allow("ip2") {
		t.Error("Different IP should be allowed")
	}
}
