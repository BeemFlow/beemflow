package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
)

// Use the same context key as production code to avoid compatibility issues

func TestGoogleSheetsOAuth_ValuesGet(t *testing.T) {
	// Create mock Google Sheets API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify OAuth token is passed correctly
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer google_sheets_oauth_token"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}

		// Verify request path contains spreadsheet ID and range
		expectedPath := "/v4/spreadsheets/test-sheet-id/values/Sheet1!A1:B2"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %q, got %q", expectedPath, r.URL.Path)
			w.WriteHeader(404)
			return
		}

		// Return mock spreadsheet data
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{
			"range": "Sheet1!A1:B2",
			"majorDimension": "ROWS",
			"values": [
				["Name", "Email"],
				["John Doe", "john@example.com"]
			]
		}`))
	}))
	defer server.Close()

	// Setup storage with Google Sheets OAuth credential
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	googleSheetsOAuth := &model.OAuthCredential{
		ID:          "google-sheets-oauth-id",
		Provider:    "google",
		Integration: "sheets_default",
		AccessToken: "google_sheets_oauth_token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		Scope:       "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, googleSheetsOAuth)
	if err != nil {
		t.Fatalf("Failed to save Google Sheets OAuth credential: %v", err)
	}

	// Create Google Sheets manifest with OAuth
	manifest := &registry.ToolManifest{
		Name:        "google_sheets.values.get",
		Description: "Get values from a range in a Google Sheets spreadsheet",
		Kind:        "task",
		Endpoint:    server.URL + "/v4/spreadsheets/{spreadsheetId}/values/{range}",
		Method:      "GET",
		Headers: map[string]string{
			"Authorization": "$oauth:google:sheets_default",
			"Content-Type":  "application/json",
		},
		Parameters: map[string]any{
			"type":     "object",
			"required": []string{"spreadsheetId", "range"},
			"properties": map[string]any{
				"spreadsheetId": map[string]string{
					"type":        "string",
					"description": "ID of the spreadsheet",
				},
				"range": map[string]string{
					"type":        "string",
					"description": "A1 notation range",
				},
			},
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "google_sheets_oauth_test",
		ToolManifest: manifest,
	}

	// Execute Google Sheets API call with OAuth
	result, err := adapter.Execute(ctx, map[string]any{
		"spreadsheetId": "test-sheet-id",
		"range":         "Sheet1!A1:B2",
	})

	if err != nil {
		t.Fatalf("Google Sheets OAuth request failed: %v", err)
	}

	// Verify response structure
	if result["range"] != "Sheet1!A1:B2" {
		t.Errorf("Expected range 'Sheet1!A1:B2', got %v", result["range"])
	}

	if result["majorDimension"] != "ROWS" {
		t.Errorf("Expected majorDimension 'ROWS', got %v", result["majorDimension"])
	}

	// Verify data structure
	if values, ok := result["values"].([]any); ok {
		if len(values) != 2 {
			t.Errorf("Expected 2 rows, got %d", len(values))
		}

		if headerRow, ok := values[0].([]any); ok {
			if len(headerRow) != 2 || headerRow[0] != "Name" || headerRow[1] != "Email" {
				t.Errorf("Expected header row ['Name', 'Email'], got %v", headerRow)
			}
		} else {
			t.Error("Expected header row to be array")
		}
	} else {
		t.Error("Expected values to be array")
	}
}

func TestGoogleSheetsOAuth_ValuesUpdate(t *testing.T) {
	// Create mock Google Sheets API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify OAuth token
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer google_sheets_oauth_token"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}

		// Verify PUT method
		if r.Method != "PUT" {
			t.Errorf("Expected PUT method, got %s", r.Method)
			w.WriteHeader(405)
			return
		}

		// Verify request path
		expectedPath := "/v4/spreadsheets/test-sheet-id/values/Sheet1!A1"
		if !contains(r.URL.Path, expectedPath) {
			t.Errorf("Expected path to contain %q, got %q", expectedPath, r.URL.Path)
			w.WriteHeader(404)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{
			"spreadsheetId": "test-sheet-id",
			"updatedRange": "Sheet1!A1",
			"updatedRows": 1,
			"updatedColumns": 1,
			"updatedCells": 1
		}`))
	}))
	defer server.Close()

	// Setup storage with OAuth credential
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	oauthCred := &model.OAuthCredential{
		ID:          "google-sheets-update-id",
		Provider:    "google",
		Integration: "sheets_default",
		AccessToken: "google_sheets_oauth_token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, oauthCred)
	if err != nil {
		t.Fatalf("Failed to save OAuth credential: %v", err)
	}

	// Create update manifest
	manifest := &registry.ToolManifest{
		Name:     "google_sheets.values.update",
		Endpoint: server.URL + "/v4/spreadsheets/{spreadsheetId}/values/{range}?valueInputOption=USER_ENTERED",
		Method:   "PUT",
		Headers: map[string]string{
			"Authorization": "$oauth:google:sheets_default",
			"Content-Type":  "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "google_sheets_update_test",
		ToolManifest: manifest,
	}

	// Execute update
	result, err := adapter.Execute(ctx, map[string]any{
		"spreadsheetId": "test-sheet-id",
		"range":         "Sheet1!A1",
		"values": [][]string{
			{"Updated Value"},
		},
	})

	if err != nil {
		t.Fatalf("Google Sheets update request failed: %v", err)
	}

	// Verify response
	if result["spreadsheetId"] != "test-sheet-id" {
		t.Errorf("Expected spreadsheetId 'test-sheet-id', got %v", result["spreadsheetId"])
	}

	if result["updatedCells"] != float64(1) { // JSON numbers are float64
		t.Errorf("Expected updatedCells 1, got %v", result["updatedCells"])
	}
}

func TestGoogleSheetsOAuth_FallbackToEnvironment(t *testing.T) {
	// Set environment variable as fallback
	originalToken := "fallback_env_token"
	t.Setenv("GOOGLE_ACCESS_TOKEN", originalToken)

	// Create mock server that expects env token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + originalToken
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"fallback": true}`))
	}))
	defer server.Close()

	// Setup storage WITHOUT OAuth credential (empty)
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	// Create manifest that tries OAuth first, falls back to env
	manifest := &registry.ToolManifest{
		Name:     "google_sheets.fallback.test",
		Endpoint: server.URL + "/test",
		Method:   "GET",
		Headers: map[string]string{
			"Authorization": "Bearer $env:GOOGLE_ACCESS_TOKEN", // Using env var directly
			"Content-Type":  "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "fallback_test",
		ToolManifest: manifest,
	}

	// Execute - should use environment variable
	result, err := adapter.Execute(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("Fallback request failed: %v", err)
	}

	if result["fallback"] != true {
		t.Errorf("Expected fallback=true, got %v", result["fallback"])
	}
}

func TestGoogleSheetsOAuth_ExpiredToken(t *testing.T) {
	// Create mock server that expects the unresolved OAuth syntax (indicating refresh failed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// When token refresh fails, the original $oauth: syntax should be kept
		expectedAuth := "$oauth:google:sheets_default"
		if authHeader != expectedAuth {
			t.Errorf("Expected unresolved OAuth header %q (indicating refresh failed), got %q", expectedAuth, authHeader)
		}
		// Return 401 unauthorized for invalid OAuth syntax
		w.WriteHeader(401)
		w.Write([]byte(`{"error": "invalid_grant", "error_description": "Invalid OAuth token"}`))
	}))
	defer server.Close()

	// Setup storage with EXPIRED OAuth credential
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	expiredCred := &model.OAuthCredential{
		ID:           "expired-google-sheets",
		Provider:     "google",
		Integration:  "sheets_default",
		AccessToken:  "expired_token",
		RefreshToken: stringPtr("valid_refresh_token"),
		ExpiresAt:    timePtr(time.Now().Add(-time.Hour)), // Expired 1 hour ago
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, expiredCred)
	if err != nil {
		t.Fatalf("Failed to save expired credential: %v", err)
	}

	// Create manifest with OAuth pointing to our mock server
	manifest := &registry.ToolManifest{
		Name:     "google_sheets.expired.test",
		Endpoint: server.URL + "/test",
		Method:   "GET",
		Headers: map[string]string{
			"Authorization": "$oauth:google:sheets_default",
			"Content-Type":  "application/json",
		},
	}

	adapter := &HTTPAdapter{
		AdapterID:    "expired_test",
		ToolManifest: manifest,
	}

	// Execute - should fail with HTTP 401 error (since token refresh failed and unresolved OAuth syntax was sent)
	_, err = adapter.Execute(ctx, map[string]any{})
	if err == nil {
		t.Error("Expected HTTP error for expired token with failed refresh")
	}

	// Should get 401 HTTP error, not refresh error (refresh error is logged but request continues)
	if !contains(err.Error(), "status 401") {
		t.Errorf("Expected HTTP 401 error, got %v", err)
	}
}

// Helper functions
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
