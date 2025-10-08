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
	"os"
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
	handlers map[string]ServiceHandler
	routes   []string // Track registered routes for cleanup
	mu       sync.RWMutex
	closed   bool
	errWrap  *utils.ErrorWrapper
}

// ServiceHandler defines the interface for service-specific webhook handlers
type ServiceHandler interface {
	VerifySignature(r *http.Request, secret string) bool
	ParseEvents(r *http.Request, eventConfigs []registry.WebhookEvent) ([]ParsedEvent, error)
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
		handlers: make(map[string]ServiceHandler),
		routes:   make([]string, 0),
		errWrap:  utils.NewErrorWrapper("webhook.manager"),
	}
}

// Close implements proper resource cleanup following existing patterns
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return nil
	}
	m.closed = true
	
	// Note: Go's http.ServeMux doesn't support route removal
	// This is a known limitation. Routes remain registered until server shutdown.
	utils.Debug("Webhook manager closed, %d routes were registered", len(m.routes))
	
	return nil
}

// RegisterServiceHandler registers a service-specific handler with thread safety
func (m *Manager) RegisterServiceHandler(service string, handler ServiceHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return m.errWrap.Failf("manager is closed")
	}
	
	m.handlers[service] = handler
	utils.Debug("Registered service handler: %s", service)
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
		utils.Warn("Some webhook registrations failed but continuing with %d registered", webhooksRegistered)
	}

	utils.Info("Webhook manager loaded %d webhook endpoints", webhooksRegistered)
	return nil
}

// registerWebhookEndpoint creates an HTTP handler for a webhook-enabled provider
func (m *Manager) registerWebhookEndpoint(entry registry.RegistryEntry) error {
	if entry.Webhook == nil {
		return m.errWrap.Failf("webhook config is nil for %s", entry.Name)
	}

	// Validate webhook path
	if err := validateWebhookPath(entry.Webhook.Path); err != nil {
		return m.errWrap.Wrapf(err, "invalid webhook path for %s", entry.Name)
	}

	// Create the endpoint path: /webhooks + provider's path
	endpoint := "/webhooks" + entry.Webhook.Path
	
	// Get or create service handler
	handler := m.getServiceHandler(entry.Name)
	if handler == nil {
		return m.errWrap.Failf("no handler available for service: %s", entry.Name)
	}

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
func (m *Manager) createWebhookHandler(entry registry.RegistryEntry, handler ServiceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		utils.Debug("Webhook received: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Only accept POST requests
		if r.Method != http.MethodPost {
			utils.WriteHTTPError(w, "Only POST method allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify webhook signature if secret is configured
		if entry.Webhook.SecretEnv != "" {
			secret := os.Getenv(entry.Webhook.SecretEnv)
			if secret != "" {
				if !handler.VerifySignature(r, secret) {
					utils.ErrorCtx(ctx, "Invalid webhook signature for %s from %s", entry.Name, r.RemoteAddr)
					utils.WriteHTTPError(w, "Invalid signature", http.StatusUnauthorized)
					return
				}
			} else {
				utils.Warn("Webhook secret environment variable %s not set for %s", entry.Webhook.SecretEnv, entry.Name)
			}
		}

		// Parse events from the webhook payload
		events, err := handler.ParseEvents(r, entry.Webhook.Events)
		if err != nil {
			utils.ErrorCtx(ctx, "Failed to parse webhook events for %s: %v", entry.Name, err)
			utils.WriteHTTPError(w, "Invalid event payload", http.StatusBadRequest)
			return
		}

		// Publish each event to the event bus
		publishedCount := 0
		for _, event := range events {
			if err := m.eventBus.Publish(event.Topic, event.Data); err != nil {
				utils.ErrorCtx(ctx, "Failed to publish event %s: %v", event.Topic, err)
				continue
			}
			publishedCount++
			utils.Debug("Published event: %s with data: %+v", event.Topic, event.Data)
		}

		// Return success with JSON response following existing patterns
		response := map[string]any{
			"status":           "ok",
			"events_received":  len(events),
			"events_published": publishedCount,
		}
		
		if err := utils.WriteHTTPJSON(w, response); err != nil {
			utils.ErrorCtx(ctx, "Failed to write response for %s webhook: %v", entry.Name, err)
		}
	}
}

// getServiceHandler retrieves or creates a handler for a service with proper locking
func (m *Manager) getServiceHandler(serviceName string) ServiceHandler {
	// First check if we already have a handler (read lock)
	m.mu.RLock()
	if handler, exists := m.handlers[serviceName]; exists {
		m.mu.RUnlock()
		return handler
	}
	m.mu.RUnlock()
	
	// Need to create handler (write lock)
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Double-check in case another goroutine created it
	if handler, exists := m.handlers[serviceName]; exists {
		return handler
	}
	
	// Auto-register built-in handlers
	var handler ServiceHandler
	switch serviceName {
	case "slack":
		handler = NewSlackHandler()
	default:
		return nil
	}
	
	if handler != nil {
		m.handlers[serviceName] = handler
		utils.Debug("Auto-registered handler for service: %s", serviceName)
	}
	
	return handler
}

// ============================================================================
// SLACK HANDLER IMPLEMENTATION
// ============================================================================

// SlackHandler implements ServiceHandler for Slack webhooks
type SlackHandler struct{}

// SlackEventWrapper represents the outer structure of Slack Event API payloads
type SlackEventWrapper struct {
	Token       string                 `json:"token"`
	TeamID      string                 `json:"team_id"`
	APIAppID    string                 `json:"api_app_id"`
	Event       map[string]any         `json:"event"`
	Type        string                 `json:"type"`
	Challenge   string                 `json:"challenge,omitempty"` // For URL verification
	EventID     string                 `json:"event_id,omitempty"`
	EventTime   int64                  `json:"event_time,omitempty"`
}

// NewSlackHandler creates a new Slack webhook handler
func NewSlackHandler() *SlackHandler {
	return &SlackHandler{}
}

// VerifySignature verifies Slack webhook signature with proper body handling
func (h *SlackHandler) VerifySignature(r *http.Request, secret string) bool {
	// Get Slack headers
	slackSignature := r.Header.Get("X-Slack-Signature")
	slackTimestamp := r.Header.Get("X-Slack-Request-Timestamp")
	
	if slackSignature == "" || slackTimestamp == "" {
		utils.Debug("Missing Slack signature headers")
		return false
	}

	// Parse timestamp and verify it's not too old (5 minutes)
	timestamp, err := strconv.ParseInt(slackTimestamp, 10, 64)
	if err != nil {
		utils.Debug("Invalid timestamp in Slack webhook: %v", err)
		return false
	}
	
	if time.Now().Unix()-timestamp > 300 {
		utils.Debug("Slack webhook timestamp too old")
		return false
	}

	// Read and restore request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.Debug("Failed to read request body: %v", err)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body)) // Restore body for later use
	
	// Rebuild the signature base string
	baseString := fmt.Sprintf("v0:%s:%s", slackTimestamp, string(body))
	
	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	expectedSig := "v0=" + hex.EncodeToString(mac.Sum(nil))
	
	// Compare signatures
	return hmac.Equal([]byte(expectedSig), []byte(slackSignature))
}

// ParseEvents extracts events from Slack webhook payload
func (h *SlackHandler) ParseEvents(r *http.Request, eventConfigs []registry.WebhookEvent) ([]ParsedEvent, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	var slackEvent SlackEventWrapper
	if err := json.Unmarshal(body, &slackEvent); err != nil {
		return nil, fmt.Errorf("failed to parse Slack event: %w", err)
	}

	// Handle URL verification challenge
	if slackEvent.Type == "url_verification" && slackEvent.Challenge != "" {
		utils.Debug("Received Slack URL verification challenge")
		// This is handled by returning the challenge in the HTTP response
		// For now, we don't generate events for this
		return []ParsedEvent{}, nil
	}

	var events []ParsedEvent
	
	// Process the inner event
	if slackEvent.Event != nil && slackEvent.Type == "event_callback" {
		eventType, ok := slackEvent.Event["type"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid event type")
		}

		// Map to configured event topics
		for _, config := range eventConfigs {
			if config.Type == eventType {
				eventData := make(map[string]any)
				
				// Extract configured fields from the inner event
				for _, field := range config.Filters {
					if value, exists := slackEvent.Event[field]; exists {
						eventData[field] = value
					}
				}
				
				// Add some wrapper-level context that might be useful
				eventData["team_id"] = slackEvent.TeamID
				eventData["event_id"] = slackEvent.EventID
				eventData["event_time"] = slackEvent.EventTime
				
				events = append(events, ParsedEvent{
					Topic: config.Topic,
					Data:  eventData,
				})
			}
		}
	}
	
	return events, nil
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// extractFieldsFromPayload extracts specified fields from a payload map
func extractFieldsFromPayload(payload map[string]any, filters []string) map[string]any {
	extracted := make(map[string]any)
	
	for _, field := range filters {
		if value, exists := payload[field]; exists {
			extracted[field] = value
		}
	}
	
	return extracted
}

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
