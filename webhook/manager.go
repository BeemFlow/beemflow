package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beemflow/beemflow/event"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
)

// Manager handles webhook registration and routing with proper resource management
type Manager struct {
	mux      *http.ServeMux
	eventBus event.EventBus
	registry *registry.RegistryManager
	routes   []string // Track registered routes for cleanup
	mu       sync.RWMutex
	closed   bool
	errWrap  *utils.ErrorWrapper
}

// GenericWebhookHandler handles webhooks using configuration-driven parsing
type GenericWebhookHandler struct {
	signatureConfig *registry.WebhookSignatureConfig
}

// ParsedEvent represents an event extracted from a webhook
type ParsedEvent struct {
	Topic string
	Data  map[string]any
}

// NewManager creates a new webhook manager following existing patterns
func NewManager(mux *http.ServeMux, eventBus event.EventBus, registryManager *registry.RegistryManager) *Manager {
	return &Manager{
		mux:      mux,
		eventBus: eventBus,
		registry: registryManager,
		routes:   make([]string, 0),
		errWrap:  utils.NewErrorWrapper("webhook.manager"),
	}
}

// Close implements proper resource cleanup following existing patterns
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil // Already closed
	}

	m.closed = true

	// Clear routes (HTTP mux doesn't support route removal, but we track them)
	if len(m.routes) > 0 {
		utils.Debug("Webhook manager closed, %d routes were registered", len(m.routes))
	}

	return nil
}

// LoadProvidersWithWebhooks scans the registry for providers with webhook configs and registers them
func (m *Manager) LoadProvidersWithWebhooks(ctx context.Context) error {
	// Check if closed without holding lock for long
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()

	if closed {
		return m.errWrap.Failf("manager is closed")
	}

	entries, err := m.registry.ListAllServers(ctx, registry.ListOptions{})
	if err != nil {
		return m.errWrap.Wrapf(err, "failed to load registry entries")
	}

	webhooksRegistered := 0
	var errors []string

	for _, entry := range entries {
		if entry.Type == "oauth_provider" && entry.Webhook != nil && entry.Webhook.Enabled {
			if err := m.registerWebhookEndpoint(entry); err != nil {
				errMsg := fmt.Sprintf("failed to register webhook for %s: %v", entry.Name, err)
				errors = append(errors, errMsg)
				utils.ErrorCtx(ctx, errMsg)
				continue
			}
			webhooksRegistered++
			utils.Info("Registered webhook: %s -> /webhooks%s", entry.Name, entry.Webhook.Path)
		}
	}

	if len(errors) > 0 && webhooksRegistered == 0 {
		return m.errWrap.Failf("failed to register any webhooks: %s", strings.Join(errors, "; "))
	}

	if len(errors) > 0 {
		utils.Warn("Some webhooks failed to register: %s", strings.Join(errors, "; "))
	}

	utils.Info("Webhook manager loaded %d webhook endpoints", webhooksRegistered)
	return nil
}

// registerWebhookEndpoint creates an HTTP handler for a webhook-enabled provider
func (m *Manager) registerWebhookEndpoint(entry registry.RegistryEntry) error {
	if entry.Webhook == nil {
		return m.errWrap.Failf("webhook config is nil")
	}

	// Validate webhook path
	if err := validateWebhookPath(entry.Webhook.Path); err != nil {
		return m.errWrap.Wrapf(err, "invalid webhook path for %s", entry.Name)
	}

	// Create the endpoint path: /webhooks + provider's path
	endpoint := "/webhooks" + entry.Webhook.Path

	// Create generic handler for this webhook
	handler := m.getWebhookHandler(entry)

	// Create HTTP handler function
	webhookHandler := m.createWebhookHandler(entry, handler)

	// Register with HTTP mux
	m.mux.HandleFunc(endpoint, webhookHandler)

	// Track registered routes (with proper locking)
	m.mu.Lock()
	m.routes = append(m.routes, endpoint)
	m.mu.Unlock()

	utils.Debug("Registered webhook endpoint: %s for service: %s", endpoint, entry.Name)
	return nil
}

// createWebhookHandler creates the actual HTTP handler function following existing patterns
func (m *Manager) createWebhookHandler(entry registry.RegistryEntry, handler *GenericWebhookHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		utils.Debug("Webhook received: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Only accept POST requests
		if r.Method != http.MethodPost {
			utils.WriteHTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify webhook signature if configured
		if entry.Webhook.Secret != "" {
			secret := utils.ExpandEnvValue(entry.Webhook.Secret)
			if secret != "" && secret != entry.Webhook.Secret {
				if !handler.VerifySignature(r, secret) {
					utils.ErrorCtx(ctx, "Invalid webhook signature for %s from %s", entry.Name, r.RemoteAddr)
					utils.WriteHTTPError(w, "Invalid signature", http.StatusUnauthorized)
					return
				}
			} else {
				utils.Warn("Webhook secret environment variable not set for %s", entry.Name)
			}
		}

		// Parse events from the webhook payload using generic parsing
		events, err := handler.ParseEvents(r, entry.Webhook.Events)
		if err != nil {
			utils.ErrorCtx(ctx, "Failed to parse webhook events for %s: %v", entry.Name, err)
			utils.WriteHTTPError(w, "Invalid event payload", http.StatusBadRequest)
			return
		}

		// Publish events to the event bus
		for _, event := range events {
			if err := m.eventBus.Publish(event.Topic, event.Data); err != nil {
				utils.ErrorCtx(ctx, "Failed to publish event %s: %v", event.Topic, err)
				utils.WriteHTTPError(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			utils.Debug("Published webhook event: %s with data: %+v", event.Topic, event.Data)
		}

		// Return success response
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			utils.ErrorCtx(ctx, "Failed to write response for %s webhook: %v", entry.Name, err)
		}
	}
}

// getWebhookHandler creates a generic handler for the webhook entry
func (m *Manager) getWebhookHandler(entry registry.RegistryEntry) *GenericWebhookHandler {
	var signatureConfig *registry.WebhookSignatureConfig
	if entry.Webhook != nil && entry.Webhook.Signature != nil {
		signatureConfig = entry.Webhook.Signature
	}

	return &GenericWebhookHandler{
		signatureConfig: signatureConfig,
	}
}

// ============================================================================
// GENERIC WEBHOOK HANDLER IMPLEMENTATION
// ============================================================================

// VerifySignature verifies webhook signature using configuration-driven approach
func (h *GenericWebhookHandler) VerifySignature(r *http.Request, secret string) bool {
	if h.signatureConfig == nil {
		// No signature verification configured
		return true
	}

	sig := r.Header.Get(h.signatureConfig.Header)
	timestamp := r.Header.Get(h.signatureConfig.TimestampHeader)

	if sig == "" || (h.signatureConfig.TimestampHeader != "" && timestamp == "") {
		return false
	}

	// Check timestamp age if configured
	if h.signatureConfig.TimestampHeader != "" {
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return false
		}

		maxAge := h.signatureConfig.MaxAge
		if maxAge == 0 {
			maxAge = 300 // Default 5 minutes
		}

		if time.Now().Unix()-ts > int64(maxAge) {
			return false
		}
	}

	// Read and restore request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Build signature string based on format
	var baseString string
	if h.signatureConfig.TimestampHeader != "" {
		baseString = fmt.Sprintf("v0:%s:%s", timestamp, string(bodyBytes))
	} else {
		baseString = string(bodyBytes)
	}

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Apply format template
	if h.signatureConfig.Format != "" {
		expectedSig = strings.ReplaceAll(h.signatureConfig.Format, "{signature}", expectedSig)
	}

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// ParseEvents extracts events using generic JSON path extraction
func (h *GenericWebhookHandler) ParseEvents(r *http.Request, eventConfigs []registry.WebhookEvent) ([]ParsedEvent, error) {
	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse JSON payload
	var payload map[string]any
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JSON payload: %w", err)
	}

	var events []ParsedEvent

	// Check each event configuration
	for _, eventConfig := range eventConfigs {
		// Check if this payload matches the event configuration
		if h.matchesEvent(payload, eventConfig.Match) {
			// Extract data using JSON paths
			eventData := make(map[string]any)
			for key, jsonPath := range eventConfig.Extract {
				if value := h.extractValue(payload, jsonPath); value != nil {
					eventData[key] = value
				}
			}

			events = append(events, ParsedEvent{
				Topic: eventConfig.Topic,
				Data:  eventData,
			})
		}
	}

	return events, nil
}

// matchesEvent checks if payload matches the event match conditions
func (h *GenericWebhookHandler) matchesEvent(payload map[string]any, match map[string]any) bool {
	for path, expectedValue := range match {
		actualValue := h.extractValue(payload, path)
		if actualValue != expectedValue {
			return false
		}
	}
	return true
}

// extractValue extracts a value from JSON using dot notation path
func (h *GenericWebhookHandler) extractValue(data map[string]any, path string) any {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts {
		if current == nil {
			return nil
		}

		// Handle the last part of the path
		if i == len(parts)-1 {
			return current[part]
		}

		// Navigate deeper into the structure
		if nextLevel, ok := current[part].(map[string]any); ok {
			current = nextLevel
		} else {
			return nil
		}
	}

	return current
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// validateWebhookPath ensures webhook path is valid
func validateWebhookPath(path string) error {
	if path == "" {
		return fmt.Errorf("webhook path cannot be empty")
	}

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("webhook path must start with /")
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("webhook path cannot contain '..'")
	}

	return nil
}
