package model

import (
	"strings"
	"testing"
	"time"
)

func TestOAuthCredential_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cred      *OAuthCredential
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid credential",
			cred: &OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: false,
		},
		{
			name: "missing provider",
			cred: &OAuthCredential{
				ID:          "test-id",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "provider is required",
		},
		{
			name: "missing integration",
			cred: &OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "integration is required",
		},
		{
			name: "missing access token",
			cred: &OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "sheets_default",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "access_token is required",
		},
		{
			name: "empty provider",
			cred: &OAuthCredential{
				ID:          "test-id",
				Provider:    "",
				Integration: "sheets_default",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "provider is required",
		},
		{
			name: "empty integration",
			cred: &OAuthCredential{
				ID:          "test-id",
				Provider:    "google",
				Integration: "",
				AccessToken: "token123",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			wantError: true,
			errorMsg:  "integration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cred.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestOAuthCredential_IsExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "no expiry",
			expiresAt: nil,
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: &[]time.Time{now.Add(-time.Hour)}[0],
			expected:  true,
		},
		{
			name:      "not expired",
			expiresAt: &[]time.Time{now.Add(time.Hour)}[0],
			expected:  false,
		},
		{
			name:      "expires exactly now",
			expiresAt: &now,
			expected:  true, // Should be considered expired if exactly at expiry time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &OAuthCredential{ExpiresAt: tt.expiresAt}
			if got := cred.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthCredential_UniqueKey(t *testing.T) {
	tests := []struct {
		name     string
		cred     *OAuthCredential
		expected string
	}{
		{
			name: "basic key",
			cred: &OAuthCredential{
				Provider:    "google",
				Integration: "sheets_default",
			},
			expected: "google:sheets_default",
		},
		{
			name: "different provider",
			cred: &OAuthCredential{
				Provider:    "github",
				Integration: "repos_main",
			},
			expected: "github:repos_main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cred.UniqueKey(); got != tt.expected {
				t.Errorf("UniqueKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthProvider_Validate(t *testing.T) {
	tests := []struct {
		name      string
		provider  *OAuthProvider
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid provider",
			provider: &OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
				Scopes:       []string{"https://www.googleapis.com/auth/spreadsheets"},
			},
			wantError: false,
		},
		{
			name: "missing client id",
			provider: &OAuthProvider{
				ID:           "google",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "client_id is required",
		},
		{
			name: "missing client secret",
			provider: &OAuthProvider{
				ID:       "google",
				ClientID: "client123",
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "client_secret is required",
		},
		{
			name: "missing auth url",
			provider: &OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				TokenURL:     "https://oauth2.googleapis.com/token",
			},
			wantError: true,
			errorMsg:  "auth_url is required",
		},
		{
			name: "missing token url",
			provider: &OAuthProvider{
				ID:           "google",
				ClientID:     "client123",
				ClientSecret: "secret456",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			},
			wantError: true,
			errorMsg:  "token_url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.provider.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}
