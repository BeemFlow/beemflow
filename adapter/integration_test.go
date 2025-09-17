package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
)

func TestGoogleSheetsOAuth_EndToEnd_Integration(t *testing.T) {
	// Create mock Google Sheets API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify OAuth token from storage
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer integration_test_oauth_token"
		if authHeader != expectedAuth {
			t.Errorf("Expected OAuth token %q, got %q", expectedAuth, authHeader)
			w.WriteHeader(401)
			return
		}

		// Return mock data based on endpoint
		switch r.URL.Path {
		case "/v4/spreadsheets/test-sheet-id/values/Sheet1!A1:B2":
			// GET values
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"range":          "Sheet1!A1:B2",
				"majorDimension": "ROWS",
				"values": [][]string{
					{"Name", "Email"},
					{"Jane Doe", "jane@example.com"},
				},
			})
		case "/v4/spreadsheets/test-sheet-id/values/Sheet1!A3:append":
			// POST append
			if r.Method == "POST" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(map[string]any{
					"spreadsheetId": "test-sheet-id",
					"tableRange":    "Sheet1!A1:B3",
					"updates": map[string]any{
						"spreadsheetId":  "test-sheet-id",
						"updatedRange":   "Sheet1!A3:B3",
						"updatedRows":    1,
						"updatedColumns": 2,
						"updatedCells":   2,
					},
				})
			} else {
				w.WriteHeader(405)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Setup storage with Google Sheets OAuth credential
	storage := storage.NewMemoryStorage()
	ctx := context.WithValue(context.Background(), storageContextKey, storage)

	// Save OAuth credential
	oauthCred := &model.OAuthCredential{
		ID:          "integration-test-google-sheets",
		Provider:    "google",
		Integration: "sheets_default",
		AccessToken: "integration_test_oauth_token",
		ExpiresAt:   timePtr(time.Now().Add(time.Hour)),
		Scope:       "https://www.googleapis.com/auth/spreadsheets",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := storage.SaveOAuthCredential(ctx, oauthCred)
	if err != nil {
		t.Fatalf("Failed to save OAuth credential: %v", err)
	}

	// Create default registry for loading manifests
	defaultReg := registry.NewDefaultRegistry()

	// Test 1: Get values
	getEntry, err := defaultReg.GetServer(ctx, "google_sheets.values.get")
	if err != nil {
		t.Fatalf("Failed to load google_sheets.values.get: %v", err)
	}
	if getEntry == nil {
		t.Fatalf("google_sheets.values.get not found")
	}

	// Convert RegistryEntry to ToolManifest
	getManifest := &registry.ToolManifest{
		Name:        getEntry.Name,
		Description: getEntry.Description,
		Kind:        getEntry.Kind,
		Parameters:  getEntry.Parameters,
		Endpoint:    getEntry.Endpoint,
		Method:      getEntry.Method,
		Headers:     getEntry.Headers,
	}

	// Override endpoint for testing
	getManifest.Endpoint = server.URL + "/v4/spreadsheets/{spreadsheetId}/values/{range}"

	getAdapter := &HTTPAdapter{
		AdapterID:    "integration_get_test",
		ToolManifest: getManifest,
	}

	getResult, err := getAdapter.Execute(ctx, map[string]any{
		"spreadsheetId": "test-sheet-id",
		"range":         "Sheet1!A1:B2",
	})
	if err != nil {
		t.Fatalf("Google Sheets get values failed: %v", err)
	}

	// Verify get response
	if getResult["range"] != "Sheet1!A1:B2" {
		t.Errorf("Expected range 'Sheet1!A1:B2', got %v", getResult["range"])
	}

	if values, ok := getResult["values"].([]any); ok {
		if len(values) != 2 {
			t.Errorf("Expected 2 rows, got %d", len(values))
		}
	} else {
		t.Error("Expected values array in response")
	}

	// Test 2: Append values
	appendEntry, err := defaultReg.GetServer(ctx, "google_sheets.values.append")
	if err != nil {
		t.Fatalf("Failed to load google_sheets.values.append: %v", err)
	}
	if appendEntry == nil {
		t.Fatalf("google_sheets.values.append not found")
	}

	// Convert RegistryEntry to ToolManifest
	appendManifest := &registry.ToolManifest{
		Name:        appendEntry.Name,
		Description: appendEntry.Description,
		Kind:        appendEntry.Kind,
		Parameters:  appendEntry.Parameters,
		Endpoint:    appendEntry.Endpoint,
		Method:      appendEntry.Method,
		Headers:     appendEntry.Headers,
	}

	// Override endpoint for testing
	appendManifest.Endpoint = server.URL + "/v4/spreadsheets/{spreadsheetId}/values/{range}:append"

	appendAdapter := &HTTPAdapter{
		AdapterID:    "integration_append_test",
		ToolManifest: appendManifest,
	}

	appendResult, err := appendAdapter.Execute(ctx, map[string]any{
		"spreadsheetId": "test-sheet-id",
		"range":         "Sheet1!A3",
		"values": [][]string{
			{"Bob Smith", "bob@example.com"},
		},
		"valueInputOption": "USER_ENTERED",
	})
	if err != nil {
		t.Fatalf("Google Sheets append values failed: %v", err)
	}

	// Verify append response
	if appendResult["spreadsheetId"] != "test-sheet-id" {
		t.Errorf("Expected spreadsheetId 'test-sheet-id', got %v", appendResult["spreadsheetId"])
	}

	if updates, ok := appendResult["updates"].(map[string]any); ok {
		if updates["updatedCells"] != float64(2) {
			t.Errorf("Expected 2 updated cells, got %v", updates["updatedCells"])
		}
	} else {
		t.Error("Expected updates object in append response")
	}

	// Test 3: Verify stored credential is still valid
	retrievedCred, err := storage.GetOAuthCredential(ctx, "google", "sheets_default")
	if err != nil {
		t.Fatalf("Failed to retrieve OAuth credential: %v", err)
	}

	if retrievedCred.AccessToken != "integration_test_oauth_token" {
		t.Errorf("Expected token 'integration_test_oauth_token', got %q", retrievedCred.AccessToken)
	}

	if retrievedCred.IsExpired() {
		t.Error("OAuth credential should not be expired")
	}

	t.Logf("✅ Google Sheets OAuth integration test completed successfully!")
	t.Logf("   - OAuth credential storage: ✅")
	t.Logf("   - Token resolution in HTTP adapter: ✅")
	t.Logf("   - GET values API call: ✅")
	t.Logf("   - POST append API call: ✅")
}
