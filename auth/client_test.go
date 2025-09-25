package auth

import (
	"context"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/storage"
)

func TestOAuthClient_GetToken(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewOAuthClient(store)

	ctx := context.Background()

	// Test with no credential
	token, err := client.GetToken(ctx, "google", "sheets")
	if err == nil {
		t.Error("Expected error for missing credential, got nil")
	}
	if token != "" {
		t.Errorf("Expected empty token, got %s", token)
	}

	// Add a credential
	cred := &model.OAuthCredential{
		ID:          "test-cred",
		Provider:    "google",
		Integration: "sheets",
		AccessToken: "test-token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		Scope:       "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = store.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	// Test successful retrieval
	token, err = client.GetToken(ctx, "google", "sheets")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected token 'test-token', got %s", token)
	}
}

func TestOAuthClient_GetToken_Expired(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewOAuthClient(store)

	ctx := context.Background()

	// Add an expired credential
	pastTime := time.Now().Add(-time.Hour)
	cred := &model.OAuthCredential{
		ID:           "test-cred",
		Provider:     "google",
		Integration:  "sheets",
		AccessToken:  "expired-token",
		ExpiresAt:    &pastTime,
		RefreshToken: stringPtr("refresh-token-123"),
		Scope:        "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := store.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	// Since we don't have a real OAuth provider set up for refreshing,
	// the token refresh will fail, but we should still get the expired token
	token, err := client.GetToken(ctx, "google", "sheets")
	// We expect an error due to failed refresh, but the token should be returned
	if token != "expired-token" {
		t.Errorf("Expected token 'expired-token', got %s", token)
	}
	// Error is expected since refresh will fail without provider
}

func TestOAuthClient_GetToken_NoExpiry(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewOAuthClient(store)

	ctx := context.Background()

	// Add a credential with no expiry
	cred := &model.OAuthCredential{
		ID:          "test-cred",
		Provider:    "github",
		Integration: "repo",
		AccessToken: "no-expiry-token",
		ExpiresAt:   nil, // No expiry
		Scope:       "repo",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := store.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	// Test successful retrieval
	token, err := client.GetToken(ctx, "github", "repo")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if token != "no-expiry-token" {
		t.Errorf("Expected token 'no-expiry-token', got %s", token)
	}
}

func TestNewOAuthClient(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewOAuthClient(store)

	if client == nil {
		t.Fatal("NewOAuthClient returned nil")
	}
	if client.store != store {
		t.Error("NewOAuthClient did not set store correctly")
	}
}

func TestOAuthClient_RefreshToken(t *testing.T) {
	// This test would require setting up a mock HTTP server
	// For now, just test the error case when no provider exists
	store := storage.NewMemoryStorage()
	client := NewOAuthClient(store)

	ctx := context.Background()

	cred := &model.OAuthCredential{
		ID:           "test-cred",
		Provider:     "google",
		Integration:  "sheets",
		AccessToken:  "expired-token",
		RefreshToken: stringPtr("refresh-token-123"),
		ExpiresAt:    timePtr(time.Now().Add(-time.Hour)),
		Scope:        "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := client.RefreshToken(ctx, cred)
	if err == nil {
		t.Error("Expected error when no OAuth provider configured")
	}
}

// Helper function
func timePtr(t time.Time) *time.Time {
	return &t
}

func stringPtr(s string) *string {
	return &s
}
