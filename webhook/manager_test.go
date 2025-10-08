package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
)

func TestMain(m *testing.M) {
	code := utils.WithCleanDirs(m, ".beemflow", config.DefaultConfigDir)
	os.Exit(code)
}

// Test helper to create a mock event bus
type mockEventBus struct {
	publishedEvents []mockEvent
}

type mockEvent struct {
	topic   string
	payload any
}

func (m *mockEventBus) Publish(topic string, payload any) error {
	m.publishedEvents = append(m.publishedEvents, mockEvent{
		topic:   topic,
		payload: payload,
	})
	return nil
}

func (m *mockEventBus) Subscribe(ctx context.Context, topic string, handler func(payload any)) {
	// Mock implementation - not needed for these tests
}

// Test helper to create a mock registry with generic webhook config
func createMockRegistry(includeSlackWebhook bool) *registry.RegistryManager {
	entries := []registry.RegistryEntry{}
	
	if includeSlackWebhook {
		entries = append(entries, registry.RegistryEntry{
			Type: "oauth_provider",
			Name: "slack",
			Webhook: &registry.WebhookConfig{
				Enabled:   true,
				Path:      "/slack",
				SecretEnv: "SLACK_WEBHOOK_SECRET",
				Signature: &registry.WebhookSignatureConfig{
					Header:          "X-Slack-Signature",
					TimestampHeader: "X-Slack-Request-Timestamp",
					Algorithm:       "hmac-sha256",
					Format:          "v0={signature}",
					MaxAge:          300,
				},
				Events: []registry.WebhookEvent{
					{
						Type:  "message",
						Topic: "slack.message",
						Match: map[string]any{
							"type":       "event_callback",
							"event.type": "message",
						},
						Extract: map[string]string{
							"channel": "event.channel",
							"user":    "event.user",
							"text":    "event.text",
							"ts":      "event.ts",
							"team_id": "team_id",
						},
					},
					{
						Type:  "app_mention",
						Topic: "slack.mention",
						Match: map[string]any{
							"type":       "event_callback",
							"event.type": "app_mention",
						},
						Extract: map[string]string{
							"channel": "event.channel",
							"user":    "event.user",
							"text":    "event.text",
							"ts":      "event.ts",
							"team_id": "team_id",
						},
					},
					{
						Type: "url_verification",
						Topic: "slack.url_verification",
						Match: map[string]any{
							"type": "url_verification",
						},
						Extract: map[string]string{
							"challenge": "challenge",
						},
					},
				},
			},
		})
	}

	mockRegistry := &mockLocalRegistry{entries: entries}
	return registry.NewRegistryManager(mockRegistry)
}

type mockLocalRegistry struct {
	entries []registry.RegistryEntry
}

func (m *mockLocalRegistry) ListServers(ctx context.Context, opts registry.ListOptions) ([]registry.RegistryEntry, error) {
	return m.entries, nil
}

func (m *mockLocalRegistry) GetServer(ctx context.Context, name string) (*registry.RegistryEntry, error) {
	for _, entry := range m.entries {
		if entry.Name == name {
			return &entry, nil
		}
	}
	return nil, nil
}

func TestManager_NewManager(t *testing.T) {
	mux := http.NewServeMux()
	eventBus := &mockEventBus{}
	regManager := createMockRegistry(false)

	manager := NewManager(mux, eventBus, regManager)
	
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	
	if manager.mux != mux {
		t.Error("Manager mux not set correctly")
	}
	
	if manager.eventBus != eventBus {
		t.Error("Manager eventBus not set correctly")
	}
	
	if manager.registry != regManager {
		t.Error("Manager registry not set correctly")
	}
}

func TestManager_Close(t *testing.T) {
	mux := http.NewServeMux()
	eventBus := &mockEventBus{}
	regManager := createMockRegistry(false)
	
	manager := NewManager(mux, eventBus, regManager)
	
	// Should be able to close without error
	err := manager.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
	
	// Second close should also work
	err = manager.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
	
	// Operations after close should fail
	err = manager.LoadProvidersWithWebhooks(context.Background())
	if err == nil {
		t.Error("LoadProvidersWithWebhooks should fail after close")
	}
}

func TestManager_LoadProvidersWithWebhooks(t *testing.T) {
	mux := http.NewServeMux()
	eventBus := &mockEventBus{}
	regManager := createMockRegistry(true) // Include Slack provider
	
	manager := NewManager(mux, eventBus, regManager)
	defer manager.Close()
	
	err := manager.LoadProvidersWithWebhooks(context.Background())
	if err != nil {
		t.Errorf("LoadProvidersWithWebhooks failed: %v", err)
	}
	
	// Should have registered the Slack webhook handler
	if len(manager.routes) == 0 {
		t.Error("No routes were registered")
	}
	
	expectedRoute := "/webhooks/slack"
	found := false
	for _, route := range manager.routes {
		if route == expectedRoute {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected route %s not found in registered routes", expectedRoute)
	}
}

func TestGenericHandler_VerifySignature(t *testing.T) {
	secret := "test_secret"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	body := `{"test": "data"}`

	// Create valid signature
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	validSignature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name            string
		signatureConfig *registry.WebhookSignatureConfig
		headers         map[string]string
		body            string
		secret          string
		expectValid     bool
	}{
		{
			name: "Valid Slack signature",
			signatureConfig: &registry.WebhookSignatureConfig{
				Header:          "X-Slack-Signature",
				TimestampHeader: "X-Slack-Request-Timestamp",
				Algorithm:       "hmac-sha256",
				Format:          "v0={signature}",
				MaxAge:          300,
			},
			headers: map[string]string{
				"X-Slack-Signature":          validSignature,
				"X-Slack-Request-Timestamp": timestamp,
			},
			body:        body,
			secret:      secret,
			expectValid: true,
		},
		{
			name: "Invalid signature",
			signatureConfig: &registry.WebhookSignatureConfig{
				Header:          "X-Slack-Signature",
				TimestampHeader: "X-Slack-Request-Timestamp",
				Algorithm:       "hmac-sha256",
				Format:          "v0={signature}",
				MaxAge:          300,
			},
			headers: map[string]string{
				"X-Slack-Signature":          "v0=invalid",
				"X-Slack-Request-Timestamp": timestamp,
			},
			body:        body,
			secret:      secret,
			expectValid: false,
		},
		{
			name: "Missing signature",
			signatureConfig: &registry.WebhookSignatureConfig{
				Header:          "X-Slack-Signature",
				TimestampHeader: "X-Slack-Request-Timestamp",
				Algorithm:       "hmac-sha256",
				Format:          "v0={signature}",
				MaxAge:          300,
			},
			headers: map[string]string{
				"X-Slack-Request-Timestamp": timestamp,
			},
			body:        body,
			secret:      secret,
			expectValid: false,
		},
		{
			name: "Old timestamp",
			signatureConfig: &registry.WebhookSignatureConfig{
				Header:          "X-Slack-Signature",
				TimestampHeader: "X-Slack-Request-Timestamp",
				Algorithm:       "hmac-sha256",
				Format:          "v0={signature}",
				MaxAge:          300,
			},
			headers: map[string]string{
				"X-Slack-Signature":          validSignature,
				"X-Slack-Request-Timestamp": fmt.Sprintf("%d", time.Now().Unix()-400),
			},
			body:        body,
			secret:      secret,
			expectValid: false,
		},
		{
			name:            "No signature config",
			signatureConfig: nil,
			headers:         map[string]string{},
			body:            body,
			secret:          secret,
			expectValid:     true, // Should pass when no signature verification configured
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &GenericWebhookHandler{
				signatureConfig: tt.signatureConfig,
			}

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(tt.body)))
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := handler.VerifySignature(req, tt.secret)
			if result != tt.expectValid {
				t.Errorf("VerifySignature() = %v, expected %v", result, tt.expectValid)
			}
		})
	}
}

func TestGenericHandler_ParseEvents(t *testing.T) {
	handler := &GenericWebhookHandler{}
	
	eventConfigs := []registry.WebhookEvent{
		{
			Type:  "message",
			Topic: "slack.message",
			Match: map[string]any{
				"type":       "event_callback",
				"event.type": "message",
			},
			Extract: map[string]string{
				"channel": "event.channel",
				"user":    "event.user",
				"text":    "event.text",
				"ts":      "event.ts",
				"team_id": "team_id",
			},
		},
		{
			Type:  "url_verification",
			Topic: "slack.url_verification",
			Match: map[string]any{
				"type": "url_verification",
			},
			Extract: map[string]string{
				"challenge": "challenge",
			},
		},
	}

	tests := []struct {
		name          string
		payload       map[string]any
		expectEvents  int
		expectTopic   string
		expectError   bool
	}{
		{
			name: "Valid message event",
			payload: map[string]any{
				"type": "event_callback",
				"event": map[string]any{
					"type":    "message",
					"channel": "C1234567890",
					"user":    "U1234567890",
					"text":    "Hello world",
					"ts":      "1234567890.123456",
				},
				"team_id":    "T1234567890",
				"event_id":   "Ev1234567890",
				"event_time": 1234567890,
			},
			expectEvents: 1,
			expectTopic:  "slack.message",
			expectError:  false,
		},
		{
			name: "URL verification challenge",
			payload: map[string]any{
				"type":      "url_verification",
				"challenge": "test_challenge",
			},
			expectEvents: 1,
			expectTopic:  "slack.url_verification",
			expectError:  false,
		},
		{
			name: "Unknown event type",
			payload: map[string]any{
				"type": "event_callback",
				"event": map[string]any{
					"type": "unknown_event",
				},
			},
			expectEvents: 0,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payloadBytes))

			events, err := handler.ParseEvents(req, eventConfigs)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if len(events) != tt.expectEvents {
				t.Errorf("Expected %d events, got %d", tt.expectEvents, len(events))
			}
			
			if tt.expectEvents > 0 && events[0].Topic != tt.expectTopic {
				t.Errorf("Expected topic %s, got %s", tt.expectTopic, events[0].Topic)
			}
		})
	}
}

func TestWebhookIntegration_GenericSlackWebhook(t *testing.T) {
	// Set up environment
	os.Setenv("SLACK_WEBHOOK_SECRET", "test_secret")
	defer os.Unsetenv("SLACK_WEBHOOK_SECRET")

	mux := http.NewServeMux()
	eventBus := &mockEventBus{}
	regManager := createMockRegistry(true)
	
	manager := NewManager(mux, eventBus, regManager)
	defer manager.Close()
	
	err := manager.LoadProvidersWithWebhooks(context.Background())
	if err != nil {
		t.Fatalf("LoadProvidersWithWebhooks failed: %v", err)
	}

	// Create test Slack event using generic structure
	slackEvent := map[string]any{
		"type": "event_callback",
		"event": map[string]any{
			"type":    "message",
			"channel": "C1234567890",
			"user":    "U1234567890",
			"text":    "Hello from test",
			"ts":      "1234567890.123456",
		},
		"team_id":    "T1234567890",
		"event_id":   "Ev1234567890",
		"event_time": 1234567890,
	}

	payloadBytes, _ := json.Marshal(slackEvent)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	
	// Create signature
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, string(payloadBytes))
	mac := hmac.New(sha256.New, []byte("test_secret"))
	mac.Write([]byte(baseString))
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/webhooks/slack", bytes.NewReader(payloadBytes))
	req.Header.Set("X-Slack-Signature", signature)
	req.Header.Set("X-Slack-Request-Timestamp", timestamp)
	req.Header.Set("Content-Type", "application/json")
	
	// Record response
	rec := httptest.NewRecorder()
	
	// Execute webhook
	mux.ServeHTTP(rec, req)
	
	// Check response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	
	// Check that event was published
	if len(eventBus.publishedEvents) == 0 {
		t.Fatal("No events were published")
	}
	
	publishedEvent := eventBus.publishedEvents[0]
	if publishedEvent.topic != "slack.message" {
		t.Errorf("Expected topic 'slack.message', got '%s'", publishedEvent.topic)
	}
	
	// Check event data
	eventData, ok := publishedEvent.payload.(map[string]any)
	if !ok {
		t.Fatal("Published event data is not a map")
	}
	
	if eventData["text"] != "Hello from test" {
		t.Errorf("Expected text 'Hello from test', got '%v'", eventData["text"])
	}
}

func TestWebhookManager_ErrorHandling(t *testing.T) {
	mux := http.NewServeMux()
	eventBus := &mockEventBus{}
	
	// Create registry with invalid webhook config
	invalidEntry := registry.RegistryEntry{
		Type: "oauth_provider",
		Name: "invalid",
		Webhook: &registry.WebhookConfig{
			Enabled: true,
			Path:    "", // Invalid empty path
		},
	}
	
	mockReg := &mockLocalRegistry{entries: []registry.RegistryEntry{invalidEntry}}
	regManager := registry.NewRegistryManager(mockReg)
	
	manager := NewManager(mux, eventBus, regManager)
	defer manager.Close()
	
	// This should complete without fatal error, but log warnings
	err := manager.LoadProvidersWithWebhooks(context.Background())
	if err == nil {
		t.Error("Expected error for invalid webhook config, but got none")
	}
}

// Test that validates webhook path validation
func TestValidateWebhookPath(t *testing.T) {
	tests := []struct {
		path        string
		expectError bool
	}{
		{"/slack", false},
		{"/github", false},
		{"", true},          // Empty path
		{"slack", true},     // Missing leading slash
		{"/slack/../", true}, // Path traversal
		{"/valid/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := validateWebhookPath(tt.path)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Test JSON path extraction
func TestGenericHandler_ExtractValue(t *testing.T) {
	handler := &GenericWebhookHandler{}
	
	data := map[string]any{
		"type": "event_callback",
		"event": map[string]any{
			"type":    "message",
			"channel": "C123",
			"user":    "U456",
			"text":    "Hello world",
		},
		"team_id": "T789",
	}

	tests := []struct {
		path     string
		expected any
	}{
		{"type", "event_callback"},
		{"event.type", "message"},
		{"event.channel", "C123"},
		{"event.user", "U456"},
		{"team_id", "T789"},
		{"nonexistent", nil},
		{"event.nonexistent", nil},
		{"event.channel.nonexistent", nil},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := handler.extractValue(data, tt.path)
			if result != tt.expected {
				t.Errorf("extractValue(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}