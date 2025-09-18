package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
)

func TestMemoryStorage_OAuthCredential_RoundTrip(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialRoundTrip(t, storage)
}

func TestSqliteStorage_OAuthCredential_RoundTrip(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialRoundTrip(t, storage)
}

func testOAuthCredentialRoundTrip(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	cred := &model.OAuthCredential{
		ID:           "test-id",
		Provider:     "google",
		Integration:  "sheets_default",
		AccessToken:  "access_token_123",
		RefreshToken: stringPtr("refresh_token_456"),
		ExpiresAt:    &expiresAt,
		Scope:        "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Test save
	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Test get
	retrieved, err := storage.GetOAuthCredential(ctx, "google", "sheets_default")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed: %v", err)
	}

	// Verify data integrity
	if retrieved.ID != cred.ID {
		t.Errorf("Expected ID %s, got %s", cred.ID, retrieved.ID)
	}
	if retrieved.Provider != cred.Provider {
		t.Errorf("Expected Provider %s, got %s", cred.Provider, retrieved.Provider)
	}
	if retrieved.Integration != cred.Integration {
		t.Errorf("Expected Integration %s, got %s", cred.Integration, retrieved.Integration)
	}
	if retrieved.AccessToken != cred.AccessToken {
		t.Errorf("Expected AccessToken %s, got %s", cred.AccessToken, retrieved.AccessToken)
	}
	if retrieved.RefreshToken == nil || *retrieved.RefreshToken != *cred.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %v, got %v",
			cred.RefreshToken, retrieved.RefreshToken)
	}
	if retrieved.Scope != cred.Scope {
		t.Errorf("Expected Scope %s, got %s", cred.Scope, retrieved.Scope)
	}
}

func TestMemoryStorage_OAuthCredential_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialNotFound(t, storage)
}

func TestSqliteStorage_OAuthCredential_NotFound(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialNotFound(t, storage)
}

func testOAuthCredentialNotFound(t *testing.T, storage Storage) {
	ctx := context.Background()

	_, err := storage.GetOAuthCredential(ctx, "nonexistent", "integration")
	if err == nil {
		t.Error("Expected error for non-existent credential")
	}

	// Should be a "not found" type error
	if !errors.Is(err, sql.ErrNoRows) && err.Error() != "credential not found" {
		t.Errorf("Expected not found error, got %v", err)
	}
}

func TestMemoryStorage_OAuthCredential_List(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialList(t, storage)
}

func TestSqliteStorage_OAuthCredential_List(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialList(t, storage)
}

func testOAuthCredentialList(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()

	// Initially should be empty
	creds, err := storage.ListOAuthCredentials(ctx)
	if err != nil {
		t.Fatalf("ListOAuthCredentials failed: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("Expected 0 credentials, got %d", len(creds))
	}

	// Add test credentials
	cred1 := &model.OAuthCredential{
		ID:          "test-id-1",
		Provider:    "google",
		Integration: "sheets_default",
		AccessToken: "token1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	cred2 := &model.OAuthCredential{
		ID:          "test-id-2",
		Provider:    "github",
		Integration: "repos_main",
		AccessToken: "token2",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err = storage.SaveOAuthCredential(ctx, cred1)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed for cred1: %v", err)
	}

	err = storage.SaveOAuthCredential(ctx, cred2)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed for cred2: %v", err)
	}

	// List should now return both credentials
	creds, err = storage.ListOAuthCredentials(ctx)
	if err != nil {
		t.Fatalf("ListOAuthCredentials failed: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(creds))
	}

	// Verify both credentials are present
	var foundCred1, foundCred2 bool
	for _, cred := range creds {
		if cred.ID == "test-id-1" {
			foundCred1 = true
		}
		if cred.ID == "test-id-2" {
			foundCred2 = true
		}
	}
	if !foundCred1 || !foundCred2 {
		t.Error("Not all credentials found in list")
	}
}

func TestMemoryStorage_OAuthCredential_Delete(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialDelete(t, storage)
}

func TestSqliteStorage_OAuthCredential_Delete(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialDelete(t, storage)
}

func testOAuthCredentialDelete(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()

	// Add test credential
	cred := &model.OAuthCredential{
		ID:          "test-delete-id",
		Provider:    "google",
		Integration: "sheets_test",
		AccessToken: "token_to_delete",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Verify it exists
	_, err = storage.GetOAuthCredential(ctx, "google", "sheets_test")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed: %v", err)
	}

	// Delete it
	err = storage.DeleteOAuthCredential(ctx, "test-delete-id")
	if err != nil {
		t.Fatalf("DeleteOAuthCredential failed: %v", err)
	}

	// Verify it's gone
	_, err = storage.GetOAuthCredential(ctx, "google", "sheets_test")
	if err == nil {
		t.Error("Expected error after deletion, but credential still exists")
	}
}

func TestMemoryStorage_OAuthCredential_RefreshToken(t *testing.T) {
	storage := NewMemoryStorage()
	testOAuthCredentialRefreshToken(t, storage)
}

func TestSqliteStorage_OAuthCredential_RefreshToken(t *testing.T) {
	storage, err := NewSqliteStorage(":memory:")
	if err != nil {
		t.Fatalf("NewSqliteStorage() failed: %v", err)
	}
	defer storage.Close()

	testOAuthCredentialRefreshToken(t, storage)
}

func testOAuthCredentialRefreshToken(t *testing.T, storage Storage) {
	ctx := context.Background()
	now := time.Now()
	originalExpiry := now.Add(time.Hour)

	// Add test credential
	cred := &model.OAuthCredential{
		ID:          "test-refresh-id",
		Provider:    "google",
		Integration: "sheets_refresh",
		AccessToken: "old_token",
		ExpiresAt:   &originalExpiry,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := storage.SaveOAuthCredential(ctx, cred)
	if err != nil {
		t.Fatalf("SaveOAuthCredential failed: %v", err)
	}

	// Refresh the token
	newExpiry := now.Add(2 * time.Hour)
	err = storage.RefreshOAuthCredential(ctx, "test-refresh-id", "new_token", &newExpiry)
	if err != nil {
		t.Fatalf("RefreshOAuthCredential failed: %v", err)
	}

	// Verify the token was updated
	refreshed, err := storage.GetOAuthCredential(ctx, "google", "sheets_refresh")
	if err != nil {
		t.Fatalf("GetOAuthCredential failed after refresh: %v", err)
	}

	if refreshed.AccessToken != "new_token" {
		t.Errorf("Expected new token 'new_token', got %s", refreshed.AccessToken)
	}
	if refreshed.ExpiresAt == nil {
		t.Error("Expected ExpiresAt to be set")
	} else {
		// Compare timestamps at second precision (SQLite stores as Unix seconds)
		expectedSeconds := newExpiry.Unix()
		actualSeconds := refreshed.ExpiresAt.Unix()
		if expectedSeconds != actualSeconds {
			t.Errorf("Expected expiry %v (unix: %d), got %v (unix: %d)",
				newExpiry, expectedSeconds, *refreshed.ExpiresAt, actualSeconds)
		}
	}
}

func TestOAuthCredential_ValidationBeforeSave(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Try to save invalid credential
	invalidCred := &model.OAuthCredential{
		ID:          "test-invalid",
		Provider:    "", // Missing provider
		Integration: "sheets_test",
		AccessToken: "token",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, invalidCred)
	if err == nil {
		t.Error("Expected validation error when saving invalid credential")
	}
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}
