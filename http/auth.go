package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/beemflow/beemflow/auth"
	"github.com/beemflow/beemflow/config"
	api "github.com/beemflow/beemflow/core"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

// setupOAuthServer creates and returns an OAuth server instance
func setupOAuthServer(cfg *config.Config, store storage.Storage) *auth.OAuthServer {
	// Create OAuth server configuration
	oauthCfg := &auth.OAuthConfig{
		Issuer:                  getOAuthIssuerURL(cfg),
		ClientID:                "beemflow",         // Default client ID
		ClientSecret:            "beemflow-secret",  // Default client secret (should be configurable)
		TokenExpiry:             3600 * time.Second, // 1 hour
		RefreshExpiry:           7200 * time.Second, // 2 hours
		AllowLocalhostRedirects: strings.Contains(getOAuthIssuerURL(cfg), "localhost") || strings.Contains(getOAuthIssuerURL(cfg), "127.0.0.1"),
	}

	// Create OAuth server
	oauthServer := auth.NewOAuthServer(oauthCfg, store)

	return oauthServer
}

// SetupOAuthHandlers adds OAuth 2.1 endpoints to the HTTP server
func SetupOAuthHandlers(mux *http.ServeMux, cfg *config.Config, store storage.Storage) error {
	oauthServer := setupOAuthServer(cfg, store)

	// Register OAuth endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthServer.HandleMetadataDiscovery)
	mux.HandleFunc("/oauth/authorize", oauthServer.HandleAuthorize)
	mux.HandleFunc("/oauth/token", oauthServer.HandleToken)
	mux.HandleFunc("/oauth/register", oauthServer.HandleDynamicClientRegistration)

	return nil
}

// setupMCPRoutes sets up MCP routes with optional OAuth authentication
func setupMCPRoutes(mux *http.ServeMux, store storage.Storage, oauthServer *auth.OAuthServer, requireAuth bool) {
	// Create auth middleware only if OAuth server exists and auth is required
	var authMiddleware *AuthMiddleware
	if requireAuth && oauthServer != nil {
		authMiddleware = NewAuthMiddleware(store, oauthServer, "mcp")
	}

	// Initialize MCP server with all registered tools
	tools := api.GenerateMCPTools()

	// Create a simple MCP tool executor for HTTP-based requests
	// This bridges the gap between HTTP JSON-RPC and MCP tool execution
	mcpToolExecutor := make(map[string]interface{})
	for _, tool := range tools {
		mcpToolExecutor[tool.Name] = tool.Handler
	}

	utils.Info("Initialized MCP tool executor with %d tools", len(tools))

	// Create MCP HTTP handler that implements JSON-RPC over HTTP
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMsg := ""
		if requireAuth {
			authMsg = "Authenticated "
		}
		utils.Info("%sMCP request: %s %s from %s", authMsg, r.Method, r.URL.Path, r.RemoteAddr)

		// Validate request
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}

		// Parse JSON-RPC request
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.Warn("Failed to parse MCP JSON-RPC request: %v", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})

		utils.Debug("MCP request: method=%s, id=%v", method, id)

		w.Header().Set("Content-Type", "application/json")

		// Handle MCP protocol methods
		switch method {
		case "initialize":
			// Standard MCP initialization response
			response := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"capabilities": map[string]interface{}{
						"tools": map[string]interface{}{
							"listChanged": true,
						},
					},
					"serverInfo": map[string]interface{}{
						"name":    "beemflow",
						"version": "1.0.0",
					},
				},
			}
			json.NewEncoder(w).Encode(response)

		case "tools/list":
			// Return list of available tools
			toolList := make([]map[string]interface{}, 0, len(tools))
			for _, tool := range tools {
				toolList = append(toolList, map[string]interface{}{
					"name":        tool.Name,
					"description": tool.Description,
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
					},
				})
			}

			response := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"tools": toolList,
				},
			}
			json.NewEncoder(w).Encode(response)

		case "tools/call":
			// Execute a tool call
			toolName, _ := params["name"].(string)
			toolArgs, _ := params["arguments"].(map[string]interface{})

			if toolName == "" {
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "Invalid params: tool name required",
					},
				}
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(response)
				return
			}

			// Execute tool using the registered handler
			handler, exists := mcpToolExecutor[toolName]
			if !exists {
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error": map[string]interface{}{
						"code":    -32601,
						"message": "Tool not found",
					},
				}
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(response)
				return
			}

			// Call the tool handler (this will be type-safe based on the generated handlers)
			// For now, we'll handle the most common case - operations that take structured args
			result, err := callToolHandler(handler, toolArgs)
			if err != nil {
				utils.Warn("MCP tool execution failed: %v", err)
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error": map[string]interface{}{
						"code":    -32603,
						"message": fmt.Sprintf("Tool execution failed: %v", err),
					},
				}
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(response)
				return
			}

			response := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  result,
			}
			json.NewEncoder(w).Encode(response)

		default:
			// Method not supported
			response := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			}
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response)
		}
	})

	// Apply authentication middleware if required
	var mcpHandler http.Handler
	if authMiddleware != nil {
		mcpHandler = authMiddleware.Middleware(baseHandler)
	} else {
		mcpHandler = baseHandler
	}

	// Register MCP routes
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)
}

// callToolHandler dynamically calls an MCP tool handler with the provided arguments
func callToolHandler(handler interface{}, args map[string]interface{}) (interface{}, error) {
	handlerValue := reflect.ValueOf(handler)
	handlerType := handlerValue.Type()

	// Validate handler signature
	if err := validateHandlerSignature(handlerType); err != nil {
		return nil, fmt.Errorf("invalid handler: %w", err)
	}

	// Create and populate input struct
	inputValue, err := createAndPopulateInputStruct(handlerType.In(0), args)
	if err != nil {
		return nil, fmt.Errorf("failed to create input: %w", err)
	}

	// Call the handler
	results := handlerValue.Call([]reflect.Value{inputValue})
	if len(results) != 2 {
		return nil, fmt.Errorf("handler must return exactly 2 values")
	}

	// Extract result and error
	result := results[0].Interface()
	if errInterface := results[1].Interface(); errInterface != nil {
		if err, ok := errInterface.(error); ok {
			return nil, err
		}
		return nil, fmt.Errorf("handler returned non-error: %v", errInterface)
	}

	return result, nil
}

// validateHandlerSignature ensures the handler has the correct function signature
func validateHandlerSignature(handlerType reflect.Type) error {
	if handlerType.Kind() != reflect.Func {
		return fmt.Errorf("handler must be a function")
	}
	if handlerType.NumIn() != 1 {
		return fmt.Errorf("handler must accept exactly one argument, got %d", handlerType.NumIn())
	}
	if handlerType.NumOut() != 2 {
		return fmt.Errorf("handler must return exactly two values, got %d", handlerType.NumOut())
	}
	// Second return value should be error
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if !handlerType.Out(1).Implements(errorType) {
		return fmt.Errorf("handler second return value must implement error interface")
	}
	return nil
}

// createAndPopulateInputStruct creates a struct instance and populates it from args
func createAndPopulateInputStruct(inputType reflect.Type, args map[string]interface{}) (reflect.Value, error) {
	if inputType.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("input type must be a struct, got %s", inputType.Kind())
	}

	inputValue := reflect.New(inputType).Elem()

	for key, value := range args {
		if err := setStructField(inputValue, key, value); err != nil {
			return reflect.Value{}, fmt.Errorf("failed to set field %s: %w", key, err)
		}
	}

	return inputValue, nil
}

// setStructField sets a struct field with type conversion
func setStructField(structValue reflect.Value, key string, value interface{}) error {
	field := structValue.FieldByNameFunc(func(fieldName string) bool {
		return strings.EqualFold(fieldName, key)
	})

	if !field.IsValid() {
		// Field doesn't exist - skip silently for flexibility
		return nil
	}

	if !field.CanSet() {
		return fmt.Errorf("field %s cannot be set", key)
	}

	// Try direct assignment first
	convertedValue := reflect.ValueOf(value)
	if convertedValue.Type().AssignableTo(field.Type()) {
		field.Set(convertedValue)
		return nil
	}

	// Try type conversion for common cases
	return convertAndSetField(field, value)
}

// convertAndSetField performs type conversions for common JSON types
func convertAndSetField(field reflect.Value, value interface{}) error {
	switch field.Kind() {
	case reflect.String:
		if str, ok := value.(string); ok {
			field.SetString(str)
			return nil
		}
	case reflect.Bool:
		if b, ok := value.(bool); ok {
			field.SetBool(b)
			return nil
		}
	case reflect.Int, reflect.Int64:
		if f, ok := value.(float64); ok { // JSON numbers are float64
			field.SetInt(int64(f))
			return nil
		}
	case reflect.Float64:
		if f, ok := value.(float64); ok {
			field.SetFloat(f)
			return nil
		}
	case reflect.Slice:
		// Handle array conversion if needed
		if arr, ok := value.([]interface{}); ok {
			return setSliceField(field, arr)
		}
	}

	// If we can't convert, leave field as zero value
	// This is more permissive than failing
	return nil
}

// setSliceField converts []interface{} to typed slice
func setSliceField(field reflect.Value, arr []interface{}) error {
	elemType := field.Type().Elem()
	sliceValue := reflect.MakeSlice(field.Type(), len(arr), len(arr))

	for i, item := range arr {
		elemValue := reflect.ValueOf(item)
		if elemValue.Type().AssignableTo(elemType) {
			sliceValue.Index(i).Set(elemValue)
		} else {
			// Try basic conversions for slice elements
			elemField := reflect.New(elemType).Elem()
			if err := convertAndSetField(elemField, item); err == nil {
				sliceValue.Index(i).Set(elemField)
			}
		}
	}

	field.Set(sliceValue)
	return nil
}

// getOAuthIssuerURL determines the OAuth issuer URL from config
func getOAuthIssuerURL(cfg *config.Config) string {
	baseURL := "http://localhost:3333" // default HTTP server port

	if cfg.HTTP != nil {
		host := "localhost"
		if cfg.HTTP.Host != "" {
			host = cfg.HTTP.Host
		}

		port := 3333
		if cfg.HTTP.Port != 0 {
			port = cfg.HTTP.Port
		}

		if host == "0.0.0.0" {
			host = "localhost"
		}

		baseURL = fmt.Sprintf("http://%s:%d", host, port)
	}

	return baseURL
}

// AuthMiddleware provides OAuth 2.1 authentication for HTTP endpoints
type AuthMiddleware struct {
	store         storage.Storage
	oauthServer   *auth.OAuthServer
	requiredScope string
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(store storage.Storage, oauthServer *auth.OAuthServer, requiredScope string) *AuthMiddleware {
	if requiredScope == "" {
		requiredScope = "mcp"
	}
	return &AuthMiddleware{
		store:         store,
		oauthServer:   oauthServer,
		requiredScope: requiredScope,
	}
}

// Middleware returns an HTTP handler that wraps the provided handler with authentication
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.unauthorized(w, r, "Missing authorization header")
			return
		}

		// Parse Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.unauthorized(w, r, "Invalid authorization header format")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token and get user info
		tokenInfo, err := a.store.GetOAuthTokenByAccess(r.Context(), token)
		if err != nil || tokenInfo == nil {
			utils.Debug("Token validation failed: %v", err)
			a.unauthorized(w, r, "Invalid or expired token")
			return
		}

		// Check if token is expired
		if tokenInfo.AccessExpiresIn > 0 {
			accessExpiry := tokenInfo.AccessCreateAt.Add(tokenInfo.AccessExpiresIn)
			if time.Now().After(accessExpiry) {
				utils.Debug("Token has expired")
				a.unauthorized(w, r, "Token has expired")
				return
			}
		}

		// Store user ID in context for downstream handlers
		ctx := context.WithValue(r.Context(), "user_id", tokenInfo.UserID)
		r = r.WithContext(ctx)

		// Token is valid, proceed
		next.ServeHTTP(w, r)
	})
}

// unauthorized sends an HTTP 401 Unauthorized response with OAuth challenge
func (a *AuthMiddleware) unauthorized(w http.ResponseWriter, _ *http.Request, message string) {
	// According to MCP spec, when authorization is required but not provided,
	// servers should respond with HTTP 401 Unauthorized

	w.Header().Set("WWW-Authenticate", `Bearer realm="MCP Server", error="invalid_token", error_description="`+message+`"`)
	w.WriteHeader(http.StatusUnauthorized)

	// Use proper JSON marshaling to prevent injection
	response := map[string]string{
		"error":   "unauthorized",
		"message": message,
	}
	if jsonData, err := json.Marshal(response); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	} else {
		// Fallback if JSON marshaling fails
		w.Write([]byte(`{"error": "unauthorized", "message": "Authentication failed"}`))
	}
}

// OptionalMiddleware returns middleware that makes authentication optional
// If no token is provided, the request proceeds without user context
// If a token is provided, it must be valid
func (a *AuthMiddleware) OptionalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader != "" {
			// Token provided, validate it and extract user ID
			if !strings.HasPrefix(authHeader, "Bearer ") {
				a.unauthorized(w, r, "Invalid authorization header format")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate token and get user info
			tokenInfo, err := a.store.GetOAuthTokenByAccess(r.Context(), token)
			if err != nil || tokenInfo == nil {
				utils.Debug("Token validation failed: %v", err)
				a.unauthorized(w, r, "Invalid or expired token")
				return
			}

			// Check if token is expired
			if tokenInfo.AccessExpiresIn > 0 {
				accessExpiry := tokenInfo.AccessCreateAt.Add(tokenInfo.AccessExpiresIn)
				if time.Now().After(accessExpiry) {
					utils.Debug("Token has expired")
					a.unauthorized(w, r, "Token has expired")
					return
				}
			}

			// Store user ID in context for downstream handlers
			ctx := context.WithValue(r.Context(), "user_id", tokenInfo.UserID)
			r = r.WithContext(ctx)
		}

		// No token or valid token, proceed
		next.ServeHTTP(w, r)
	})
}

// enforceHTTPS ensures OAuth endpoints are accessed over HTTPS (except localhost and ngrok for development)
func enforceHTTPS(w http.ResponseWriter, r *http.Request) bool {
	// Allow HTTP for localhost development
	if r.Host == "localhost:8080" || r.Host == "127.0.0.1:8080" ||
		r.Host == "localhost:3333" || r.Host == "127.0.0.1:3333" ||
		r.Host == "localhost:3001" || r.Host == "127.0.0.1:3001" {
		return true
	}

	// Allow HTTP for ngrok tunnels (development)
	if strings.Contains(r.Host, ".ngrok-free.dev") || strings.Contains(r.Host, ".ngrok.io") {
		return true
	}

	if r.TLS == nil {
		http.Error(w, "HTTPS required for OAuth endpoints", http.StatusForbidden)
		return false
	}
	return true
}

// ============================================================================
// WEB-BASED OAUTH AUTHORIZATION FLOWS
// ============================================================================

// WebOAuthHandler provides web-based OAuth flows for external service authorization
type WebOAuthHandler struct {
	store            storage.Storage
	registry         registry.OAuthRegistry
	baseURL          string
	authStates       map[string]*OAuthAuthState // In production, use Redis
	sessionStore     *SessionStore
	templateRenderer *TemplateRenderer
}

// OAuthAuthState tracks the state of an OAuth authorization flow
type OAuthAuthState struct {
	Provider      string
	Integration   string
	UserID        string // From MCP client authentication
	CreatedAt     time.Time
	ExpiresAt     time.Time
	CodeVerifier  string // PKCE code verifier
	CodeChallenge string // PKCE code challenge
}

// generatePKCEChallenge generates a PKCE code verifier and challenge
func generatePKCEChallenge() (verifier, challenge string, err error) {
	// Generate a random code verifier (43-128 characters)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(verifierBytes)

	// Generate code challenge using SHA256
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])

	return verifier, challenge, nil
}

// NewWebOAuthHandler creates a new web OAuth handler
func NewWebOAuthHandler(store storage.Storage, registry registry.OAuthRegistry, baseURL string, sessionStore *SessionStore, templateRenderer *TemplateRenderer) *WebOAuthHandler {
	return &WebOAuthHandler{
		store:            store,
		registry:         registry,
		baseURL:          baseURL,
		authStates:       make(map[string]*OAuthAuthState),
		sessionStore:     sessionStore,
		templateRenderer: templateRenderer,
	}
}

// ProviderTemplateData represents data for the providers template
type ProviderTemplateData struct {
	Name               string
	DisplayName        string
	Icon               string
	Connected          bool
	Integration        string
	DefaultIntegration string
	Scopes             []string
	ExpiresAt          string
}

// HandleOAuthProviders serves a list of available OAuth providers
func (h *WebOAuthHandler) HandleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	if !enforceHTTPS(w, r) {
		return
	}

	providers, err := h.registry.ListOAuthProviders(r.Context(), registry.ListOptions{})
	if err != nil {
		utils.Error("Failed to load OAuth providers: %v", err)
		http.Error(w, "Failed to load OAuth providers", http.StatusInternalServerError)
		return
	}

	// Get current credentials to show connection status
	credentials, err := h.store.ListOAuthCredentials(r.Context())
	if err != nil {
		utils.Warn("Failed to load OAuth credentials: %v", err)
	}

	// Create map of connected providers
	connectedProviders := make(map[string]*model.OAuthCredential)
	for _, cred := range credentials {
		key := cred.Provider + ":" + cred.Integration
		connectedProviders[key] = cred
	}

	// Prepare template data
	templateData := make([]ProviderTemplateData, 0, len(providers))
	for _, provider := range providers {
		// Check if connected (use default integration)
		defaultIntegration := "default"
		key := provider.Name + ":" + defaultIntegration
		cred, connected := connectedProviders[key]

		data := ProviderTemplateData{
			Name:               provider.Name,
			DisplayName:        provider.DisplayName,
			Icon:               h.getProviderIcon(provider.Name),
			Connected:          connected,
			Integration:        defaultIntegration,
			DefaultIntegration: defaultIntegration,
			Scopes:             registry.ScopesToStrings(provider.Scopes),
		}

		if connected && cred.ExpiresAt != nil {
			data.ExpiresAt = cred.ExpiresAt.Format("2006-01-02 15:04")
		}

		templateData = append(templateData, data)
	}

	templateDataWrapper := struct {
		Providers []ProviderTemplateData
	}{
		Providers: templateData,
	}

	if err := h.templateRenderer.RenderTemplate(w, "providers", templateDataWrapper); err != nil {
		utils.Error("Failed to render providers template: %v", err)
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// getProviderIcon returns an icon for a provider from registry metadata
func (h *WebOAuthHandler) getProviderIcon(providerName string) string {
	ctx := context.Background()
	provider, err := h.registry.GetOAuthProvider(ctx, providerName)
	if err == nil && provider != nil && provider.Icon != "" {
		return provider.Icon
	}
	return "🔗" // Default icon
}

// getProviderDescription returns a description for a provider from registry metadata
func (h *WebOAuthHandler) getProviderDescription(providerName string) string {
	ctx := context.Background()
	provider, err := h.registry.GetOAuthProvider(ctx, providerName)
	if err == nil && provider != nil && provider.Description != "" {
		return provider.Description
	}
	return "Connect to " + providerName + " services"
}

// getIntegrationDescription returns a description for an integration
func (h *WebOAuthHandler) getIntegrationDescription(integration string) string {
	// Generic - integrations define their own descriptions in registry
	if integration == "default" {
		return "Default integration"
	}
	return integration + " integration"
}

// getScopeDescriptions returns descriptions for OAuth scopes from registry metadata
func (h *WebOAuthHandler) getScopeDescriptions(providerName string, scopes []registry.OAuthScope) []ScopeDescription {
	ctx := context.Background()
	provider, err := h.registry.GetOAuthProvider(ctx, providerName)

	var descriptions []ScopeDescription
	for _, scope := range scopes {
		desc := "Access to " + scope.Raw() // Default description using raw scope

		// Use registry metadata if available
		if err == nil && provider != nil && provider.ScopeDescriptions != nil {
			if customDesc, exists := provider.ScopeDescriptions[scope.Raw()]; exists {
				desc = customDesc
			}
		}

		// Check if this scope is required (from registry metadata)
		required := false
		if err == nil && provider != nil && provider.RequiredScopes != nil {
			for _, reqScope := range provider.RequiredScopes {
				if reqScope.Raw() == scope.Raw() {
					required = true
					break
				}
			}
		}

		descriptions = append(descriptions, ScopeDescription{
			Scope:       scope,
			Description: desc,
			Required:    required,
		})
	}
	return descriptions
}

// ProviderAuthTemplateData represents data for the provider auth template
type ProviderAuthTemplateData struct {
	ProviderName           string
	ProviderDisplayName    string
	ProviderIcon           string
	ProviderDescription    string
	Integration            string
	IntegrationDescription string
	AuthURL                string
	Scopes                 []ScopeDescription
}

// ScopeDescription describes a scope with human-readable text
type ScopeDescription struct {
	Scope       registry.OAuthScope
	Description string
	Required    bool
}

// HandleOAuthAuthorize initiates OAuth authorization for a provider
func (h *WebOAuthHandler) HandleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !enforceHTTPS(w, r) {
		return
	}

	// Extract provider from URL path: /oauth/authorize/{provider}
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "Invalid OAuth authorize URL", http.StatusBadRequest)
		return
	}
	providerName := pathParts[3]

	// Get integration from query parameter
	integration := r.URL.Query().Get("integration")
	if integration == "" {
		integration = "default"
	}

	// Get provider from registry
	provider, err := h.registry.GetOAuthProvider(r.Context(), providerName)
	if err != nil || provider == nil {
		utils.Error("OAuth provider not found: %s", providerName)
		http.Error(w, "OAuth provider not found", http.StatusNotFound)
		return
	}

	// Generate state parameter for CSRF protection
	stateBytes := make([]byte, 32)
	rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Generate PKCE challenge for X OAuth 2.0 (required by X)
	codeVerifier, codeChallenge, err := generatePKCEChallenge()
	if err != nil {
		utils.Error("Failed to generate PKCE challenge: %v", err)
		http.Error(w, "Failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	// Get user ID from session or create anonymous session
	session, _ := GetSessionFromRequest(r)
	var userID string
	if session != nil {
		userID = session.UserID
	} else {
		// Create anonymous session for this OAuth flow
		session, err := h.sessionStore.CreateSession("anonymous", 30*time.Minute)
		if err != nil {
			utils.Error("Failed to create session: %v", err)
			http.Error(w, "Session creation failed", http.StatusInternalServerError)
			return
		}
		userID = session.UserID
	}

	// Store auth state with PKCE parameters
	h.authStates[state] = &OAuthAuthState{
		Provider:      providerName,
		Integration:   integration,
		UserID:        userID,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute), // 10 minute expiry
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}

	// Build authorization URL
	authURL, err := url.Parse(provider.AuthorizationURL)
	if err != nil {
		utils.Error("Invalid provider authorization URL: %v", err)
		http.Error(w, "Invalid provider authorization URL", http.StatusInternalServerError)
		return
	}

	// Dynamically determine the redirect URI based on the request
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/oauth/callback", scheme, r.Host)

	query := authURL.Query()
	query.Set("client_id", provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", strings.Join(registry.ScopesToStrings(provider.Scopes), " "))
	query.Set("response_type", "code")
	query.Set("state", state)

	// Add PKCE parameters (required by X OAuth 2.0)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")

	authURL.RawQuery = query.Encode()

	// Prepare template data
	templateData := ProviderAuthTemplateData{
		ProviderName:           provider.Name,
		ProviderDisplayName:    provider.DisplayName,
		ProviderIcon:           h.getProviderIcon(provider.Name),
		ProviderDescription:    h.getProviderDescription(provider.Name),
		Integration:            integration,
		IntegrationDescription: h.getIntegrationDescription(integration),
		AuthURL:                authURL.String(),
		Scopes:                 h.getScopeDescriptions(provider.Name, provider.Scopes),
	}

	if err := h.templateRenderer.RenderTemplate(w, "provider_auth", templateData); err != nil {
		utils.Error("Failed to render provider auth template: %v", err)
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleOAuthCallback handles the OAuth callback from the provider
func (h *WebOAuthHandler) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !enforceHTTPS(w, r) {
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		utils.Error("OAuth authorization failed: %s", errorParam)
		http.Error(w, fmt.Sprintf("OAuth authorization failed: %s", errorParam), http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		utils.Error("Missing authorization code or state parameter")
		http.Error(w, "Missing authorization code or state", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	authState, exists := h.authStates[state]
	if !exists || time.Now().After(authState.ExpiresAt) {
		utils.Error("Invalid or expired state parameter: %s", state)
		http.Error(w, "Invalid or expired state parameter", http.StatusBadRequest)
		return
	}
	delete(h.authStates, state) // One-time use

	// Get provider from registry
	provider, err := h.registry.GetOAuthProvider(r.Context(), authState.Provider)
	if err != nil || provider == nil {
		utils.Error("OAuth provider not found: %s", authState.Provider)
		http.Error(w, "OAuth provider not found", http.StatusInternalServerError)
		return
	}

	// Exchange code for tokens
	tokenURL := provider.TokenURL

	// Dynamically determine the redirect URI based on the request (must match authorization)
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/oauth/callback", scheme, r.Host)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {authState.CodeVerifier}, // PKCE code verifier
	}

	// Create HTTP request with Basic Auth for confidential clients (X OAuth 2.0 requirement)
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		utils.Error("Failed to create token request: %v", err)
		http.Error(w, "Failed to create token request", http.StatusInternalServerError)
		return
	}

	// Set Basic Auth header with client credentials
	req.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		utils.Error("Failed to exchange code for tokens")
		http.Error(w, "Failed to exchange code for tokens", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.Error("Token exchange failed with status %d: %s", resp.StatusCode, string(body))
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Error("Failed to read token response body: %v", err)
		http.Error(w, "Failed to read token response", http.StatusInternalServerError)
		return
	}

	// Check content type to determine parsing method
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// Parse as JSON (Google, most providers)
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			utils.Error("Failed to parse JSON token response: %v", err)
			http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
			return
		}
	} else {
		// Parse as form-encoded (GitHub, some others)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			utils.Error("Failed to parse form-encoded token response: %v", err)
			http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
			return
		}

		tokenResp.AccessToken = values.Get("access_token")
		tokenResp.TokenType = values.Get("token_type")
		tokenResp.RefreshToken = values.Get("refresh_token")

		if expiresInStr := values.Get("expires_in"); expiresInStr != "" {
			if expiresIn, err := strconv.Atoi(expiresInStr); err == nil {
				tokenResp.ExpiresIn = expiresIn
			}
		}
	}

	// Store the credentials
	var refreshToken *string
	if tokenResp.RefreshToken != "" {
		refreshToken = &tokenResp.RefreshToken
	}

	var expiresAt *time.Time
	if tokenResp.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	cred := &model.OAuthCredential{
		ID:           uuid.New().String(),
		Provider:     authState.Provider,
		Integration:  authState.Integration,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Scope:        strings.Join(registry.ScopesToStrings(provider.Scopes), " "),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := h.store.SaveOAuthCredential(r.Context(), cred); err != nil {
		utils.Error("Failed to save OAuth credentials: %v", err)
		http.Error(w, "Failed to save OAuth credentials", http.StatusInternalServerError)
		return
	}

	utils.Info("Successfully authorized OAuth for %s:%s", authState.Provider, authState.Integration)

	// Redirect to success page
	templateData := struct {
		ProviderName string
		Integration  string
		Scopes       string
		Message      string
	}{
		ProviderName: authState.Provider,
		Integration:  authState.Integration,
		Scopes:       strings.Join(registry.ScopesToStrings(provider.Scopes), " "),
		Message:      fmt.Sprintf("%s has been successfully connected!", provider.DisplayName),
	}

	if err := h.templateRenderer.RenderTemplate(w, "success", templateData); err != nil {
		utils.Error("Failed to render success template: %v", err)
		http.Error(w, "Authorization successful but failed to show success page", http.StatusInternalServerError)
	}
}

// RegisterWebOAuthRoutes registers the web OAuth routes
func RegisterWebOAuthRoutes(mux *http.ServeMux, store storage.Storage, registry registry.OAuthRegistry, baseURL string, sessionStore *SessionStore, templateRenderer *TemplateRenderer) {
	handler := NewWebOAuthHandler(store, registry, baseURL, sessionStore, templateRenderer)

	mux.HandleFunc("/oauth/providers", handler.HandleOAuthProviders)
	mux.HandleFunc("/oauth/authorize/", handler.HandleOAuthAuthorize)
	mux.HandleFunc("/oauth/callback", handler.HandleOAuthCallback)
}
