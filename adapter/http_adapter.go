package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/beemflow/beemflow/auth"
	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
)

// getHTTPClient returns an HTTP client that respects context deadlines
func getHTTPClient() *http.Client {
	return &http.Client{
		// Don't set a timeout here - let the context handle timeouts
		// This allows proper context cancellation and deadline handling
	}
}

// storageContextKey is used to inject storage into context
// Use same constant as engine to ensure compatibility
const storageContextKey = "beemflow.storage"

// validatePathParameter validates a path parameter to prevent security issues
func validatePathParameter(_, value string) error {
	// Check for path traversal attempts
	if strings.Contains(value, "..") {
		return fmt.Errorf("path traversal attempt detected")
	}

	// Check for null bytes
	if strings.Contains(value, "\x00") {
		return fmt.Errorf("null byte injection detected")
	}

	// Check for URL encoding attacks
	if strings.Contains(value, "%2e%2e") || strings.Contains(value, "%252e") {
		return fmt.Errorf("encoded path traversal detected")
	}

	// Limit length to prevent buffer overflow attacks
	const maxParamLength = 1024
	if len(value) > maxParamLength {
		return fmt.Errorf("parameter too long (max %d chars)", maxParamLength)
	}

	return nil
}

// isComplexType checks if a value is a complex type (map, slice, etc)
func isComplexType(v any) bool {
	switch v.(type) {
	case map[string]any, []any, []map[string]any:
		return true
	default:
		return false
	}
}

// HTTPAdapter is a unified HTTP adapter that handles both manifest-based and generic HTTP requests.
type HTTPAdapter struct {
	AdapterID    string
	ToolManifest *registry.ToolManifest
}

// HTTPRequest represents a prepared HTTP request
type HTTPRequest struct {
	Method  string
	URL     string
	Body    []byte
	Headers map[string]string
}

// HTTPResponse represents a processed HTTP response
type HTTPResponse struct {
	StatusCode int
	Body       any
	Headers    map[string]string
}

// ID returns the unique identifier of the adapter.
func (a *HTTPAdapter) ID() string {
	return a.AdapterID
}

// Execute performs HTTP requests based on manifest or generic parameters.
func (a *HTTPAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	// Handle manifest-based requests
	if a.ToolManifest != nil && a.ToolManifest.Endpoint != "" {
		return a.executeManifestRequest(ctx, inputs)
	}

	// Handle generic HTTP requests
	return a.executeGenericRequest(ctx, inputs)
}

// executeManifestRequest handles requests with a predefined manifest
func (a *HTTPAdapter) executeManifestRequest(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	// Create a copy of inputs to avoid mutation
	enrichedInputs := a.enrichInputsWithDefaults(inputs)

	// Prepare headers
	headers, err := a.prepareManifestHeaders(ctx, enrichedInputs)
	if err != nil {
		return nil, err
	}

	// Replace path parameters in URL with validation
	url := a.ToolManifest.Endpoint
	for k, v := range enrichedInputs {
		placeholder := "{" + k + "}"
		// Only process if this parameter is actually in the URL
		if !strings.Contains(url, placeholder) {
			continue
		}
		// Handle string values with security validation
		if str, ok := v.(string); ok {
			// Validate to prevent path traversal attacks
			if err := validatePathParameter(k, str); err != nil {
				return nil, utils.Errorf("invalid path parameter %s: %w", k, err)
			}
			url = strings.ReplaceAll(url, placeholder, str)
		}
		// Handle other types by converting to string
		if v != nil && !isComplexType(v) {
			sanitized := fmt.Sprintf("%v", v)
			if err := validatePathParameter(k, sanitized); err != nil {
				return nil, utils.Errorf("invalid path parameter %s: %w", k, err)
			}
			url = strings.ReplaceAll(url, placeholder, sanitized)
		}
	}

	// Determine HTTP method (default to POST for manifest tools)
	method := constants.HTTPMethodPOST
	if a.ToolManifest.Method != "" {
		method = a.ToolManifest.Method
	}

	// Create request
	req := HTTPRequest{
		Method:  method,
		URL:     url,
		Headers: headers,
	}

	// Marshal body (but not for GET requests)
	if method != constants.HTTPMethodGET {
		// Filter out parameters that are used in the URL path
		bodyInputs := make(map[string]any)
		for k, v := range enrichedInputs {
			// Skip parameters that appear as placeholders in the original endpoint
			if !strings.Contains(a.ToolManifest.Endpoint, "{"+k+"}") {
				bodyInputs[k] = v
			}
		}

		body, err := json.Marshal(bodyInputs)
		if err != nil {
			return nil, utils.Errorf("failed to marshal request body: %w", err)
		}
		req.Body = body
	}

	// Execute request
	return a.executeHTTPRequest(ctx, req)
}

// executeGenericRequest handles generic HTTP requests
func (a *HTTPAdapter) executeGenericRequest(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	url, ok := utils.SafeStringAssert(inputs["url"])
	if !ok || url == "" {
		return nil, utils.Errorf("missing or invalid url")
	}

	method := a.extractMethod(inputs)
	headers := a.extractHeaders(inputs)

	req := HTTPRequest{
		Method:  method,
		URL:     url,
		Headers: headers,
	}

	// Add body for non-GET requests
	if method != constants.HTTPMethodGET {
		if body := inputs["body"]; body != nil {
			bodyBytes, err := json.Marshal(body)
			if err != nil {
				return nil, utils.Errorf("failed to marshal request body: %w", err)
			}
			req.Body = bodyBytes
		}
	}

	return a.executeHTTPRequest(ctx, req)
}

// executeHTTPRequest executes an HTTP request and returns the response
func (a *HTTPAdapter) executeHTTPRequest(ctx context.Context, req HTTPRequest) (map[string]any, error) {
	// Create HTTP request
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, utils.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set default headers if not provided
	if req.Method != constants.HTTPMethodGET && httpReq.Header.Get(constants.HeaderContentType) == "" {
		httpReq.Header.Set(constants.HeaderContentType, constants.ContentTypeJSON)
	}
	if httpReq.Header.Get(constants.HeaderAccept) == "" {
		httpReq.Header.Set(constants.HeaderAccept, constants.DefaultJSONAccept)
	}

	// Set content-type if sending body
	if len(req.Body) > 0 {
		httpReq.Header.Set(constants.HeaderContentType, constants.ContentTypeJSON)
	}
	httpReq.Header.Set(constants.HeaderAccept, constants.DefaultJSONAccept)

	// Execute request with context-aware client
	client := getHTTPClient()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, utils.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Process response
	return a.processHTTPResponse(resp, req.Method, req.URL)
}

// processHTTPResponse processes an HTTP response and returns structured data
func (a *HTTPAdapter) processHTTPResponse(resp *http.Response, method, url string) (map[string]any, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, utils.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, utils.Errorf("HTTP %s %s: status %d: %s", method, url, resp.StatusCode, string(data))
	}

	// Try to parse as JSON first
	var parsed any
	if err := json.Unmarshal(data, &parsed); err == nil {
		// If it's a JSON object, return it directly
		if obj, ok := parsed.(map[string]any); ok {
			return obj, nil
		}
		// For non-object JSON (arrays, primitives), wrap in body
		return map[string]any{"body": parsed}, nil
	}

	// Fallback to raw string wrapped in body
	return map[string]any{"body": string(data)}, nil
}

// enrichInputsWithDefaults creates a copy of inputs with defaults applied (no mutation)
func (a *HTTPAdapter) enrichInputsWithDefaults(inputs map[string]any) map[string]any {
	// Create a copy to avoid mutating the original
	enriched := make(map[string]any, len(inputs))
	maps.Copy(enriched, inputs)

	if a.ToolManifest.Parameters == nil {
		return enriched
	}

	props, ok := safeMapAssert(a.ToolManifest.Parameters["properties"])
	if !ok {
		return enriched
	}

	for k, v := range props {
		prop, ok := safeMapAssert(v)
		if !ok {
			continue
		}

		// Only apply default if key is not present
		if _, present := enriched[k]; !present {
			if def, hasDefault := prop["default"]; hasDefault {
				// Expand environment variables in default values if they're strings
				if defStr, ok := safeStringAssert(def); ok {
					enriched[k] = utils.ExpandEnvValue(defStr)
				} else {
					enriched[k] = def
				}
			}
		}
	}

	return enriched
}

// prepareManifestHeaders prepares headers for manifest-based requests
func (a *HTTPAdapter) prepareManifestHeaders(ctx context.Context, inputs map[string]any) (map[string]string, error) {
	headers := make(map[string]string)

	// Add manifest headers with OAuth and environment variable expansion
	if a.ToolManifest.Headers != nil {
		for k, v := range a.ToolManifest.Headers {
			expanded, err := a.expandValue(ctx, v)
			if err != nil {
				return nil, err
			}
			headers[k] = expanded
		}
	}

	// Override with input headers
	if h, ok := utils.SafeMapAssert(inputs["headers"]); ok {
		for k, v := range h {
			if s, ok := utils.SafeStringAssert(v); ok {
				headers[k] = s
			}
		}
	}

	return headers, nil
}

// extractMethod extracts HTTP method from inputs with safe default
func (a *HTTPAdapter) extractMethod(inputs map[string]any) string {
	if m, ok := utils.SafeStringAssert(inputs["method"]); ok && m != "" {
		return strings.ToUpper(m)
	}
	return constants.HTTPMethodGET
}

// extractHeaders extracts headers from inputs safely
func (a *HTTPAdapter) extractHeaders(inputs map[string]any) map[string]string {
	headers := make(map[string]string)
	if h, ok := utils.SafeMapAssert(inputs["headers"]); ok {
		for k, v := range h {
			if s, ok := utils.SafeStringAssert(v); ok {
				headers[k] = s
			}
		}
	}
	return headers
}

// expandValue expands both OAuth tokens and environment variables in a value string
func (a *HTTPAdapter) expandValue(ctx context.Context, value string) (string, error) {
	// Get storage from context for OAuth client
	store, ok := ctx.Value(storageContextKey).(storage.Storage)
	if !ok {
		utils.Debug("Storage not available in context for OAuth expansion, falling back to environment variables only")
		// Fall back to environment variable expansion only
		return utils.ExpandEnvValue(value), nil
	}

	oauthClient := auth.NewOAuthClient(store)

	// First handle OAuth patterns
	var oauthError error
	expanded := utils.OAuthPattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := strings.Split(match[7:], ":") // Remove "$oauth:" prefix
		if len(parts) != 2 {
			oauthError = fmt.Errorf("invalid OAuth pattern: %s (expected format: $oauth:provider:integration)", match)
			return match
		}
		provider, integration := parts[0], parts[1]

		token, err := oauthClient.GetToken(ctx, provider, integration)
		if err != nil {
			oauthError = fmt.Errorf("failed to retrieve OAuth token for %s:%s: %w", provider, integration, err)
			return match
		}
		return "Bearer " + token
	})

	// Return error immediately if OAuth expansion failed
	if oauthError != nil {
		return "", oauthError
	}

	// Then handle environment variables using shared utility
	return utils.ExpandEnvValue(expanded), nil
}

func (a *HTTPAdapter) Manifest() *registry.ToolManifest {
	return a.ToolManifest
}

// Safe type assertion helpers to prevent panics
func safeStringAssert(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func safeMapAssert(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}
