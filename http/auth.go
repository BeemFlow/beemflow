package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
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
func setupOAuthServer(cfg *config.Config, store storage.Storage) (*auth.OAuthConfig, *auth.OAuthServer) {
	// Create OAuth server configuration
	oauthCfg := &auth.OAuthConfig{
		Issuer:                  getOAuthIssuerURL(cfg),
		ClientID:                "beemflow",        // Default client ID
		ClientSecret:            "beemflow-secret", // Default client secret (should be configurable)
		TokenExpiry:             3600,              // 1 hour
		RefreshExpiry:           7200,              // 2 hours
		AllowLocalhostRedirects: strings.Contains(getOAuthIssuerURL(cfg), "localhost") || strings.Contains(getOAuthIssuerURL(cfg), "127.0.0.1"),
	}

	// Create OAuth server
	oauthServer := auth.NewOAuthServer(oauthCfg, store)

	return oauthCfg, oauthServer
}

// SetupOAuthHandlers adds OAuth 2.1 endpoints to the HTTP server
func SetupOAuthHandlers(mux *http.ServeMux, cfg *config.Config, store storage.Storage) error {
	_, oauthServer := setupOAuthServer(cfg, store)

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
		ctx := r.Context()

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
			result, err := callToolHandler(ctx, handler, toolArgs)
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
func callToolHandler(ctx context.Context, handler interface{}, args map[string]interface{}) (interface{}, error) {
	// Use reflection to call the handler with proper argument types
	handlerValue := reflect.ValueOf(handler)
	handlerType := handlerValue.Type()

	// Get the input type (first parameter of the handler function)
	if handlerType.NumIn() != 1 {
		return nil, fmt.Errorf("handler must accept exactly one argument")
	}

	inputType := handlerType.In(0)
	inputValue := reflect.New(inputType).Elem()

	// Populate the input struct from the args map
	for key, value := range args {
		field := inputValue.FieldByNameFunc(func(fieldName string) bool {
			// Case-insensitive field matching
			return strings.EqualFold(fieldName, key)
		})
		if field.IsValid() && field.CanSet() {
			// Convert the value to the appropriate type
			convertedValue := reflect.ValueOf(value)
			if convertedValue.Type().AssignableTo(field.Type()) {
				field.Set(convertedValue)
			} else {
				// Try type conversion for basic types
				switch field.Kind() {
				case reflect.String:
					if str, ok := value.(string); ok {
						field.SetString(str)
					}
				case reflect.Bool:
					if b, ok := value.(bool); ok {
						field.SetBool(b)
					}
				case reflect.Int, reflect.Int64:
					if i, ok := value.(float64); ok { // JSON numbers are float64
						field.SetInt(int64(i))
					}
				case reflect.Float64:
					if f, ok := value.(float64); ok {
						field.SetFloat(f)
					}
				}
			}
		}
	}

	// Call the handler
	results := handlerValue.Call([]reflect.Value{inputValue})
	if len(results) != 2 {
		return nil, fmt.Errorf("handler must return (result, error)")
	}

	result := results[0].Interface()
	errInterface := results[1].Interface()

	if errInterface != nil {
		if err, ok := errInterface.(error); ok {
			return nil, err
		}
	}

	return result, nil
}

// getOAuthIssuerURL determines the OAuth issuer URL from config
func getOAuthIssuerURL(cfg *config.Config) string {
	baseURL := "http://localhost:3333" // default

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
func (a *AuthMiddleware) unauthorized(w http.ResponseWriter, r *http.Request, message string) {
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

// enforceHTTPS ensures OAuth endpoints are accessed over HTTPS
func enforceHTTPS(w http.ResponseWriter, r *http.Request) bool {
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
	store      storage.Storage
	registry   registry.OAuthRegistry
	baseURL    string
	authStates map[string]*OAuthAuthState // In production, use Redis
}

// OAuthAuthState tracks the state of an OAuth authorization flow
type OAuthAuthState struct {
	Provider    string
	Integration string
	UserID      string // From MCP client authentication
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// NewWebOAuthHandler creates a new web OAuth handler
func NewWebOAuthHandler(store storage.Storage, registry registry.OAuthRegistry, baseURL string) *WebOAuthHandler {
	return &WebOAuthHandler{
		store:      store,
		registry:   registry,
		baseURL:    baseURL,
		authStates: make(map[string]*OAuthAuthState),
	}
}

// HandleOAuthProviders serves a list of available OAuth providers
func (h *WebOAuthHandler) HandleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	if !enforceHTTPS(w, r) {
		return
	}

	providers, err := h.registry.ListOAuthProviders(r.Context(), registry.ListOptions{})
	if err != nil {
		http.Error(w, "Failed to load OAuth providers", http.StatusInternalServerError)
		return
	}

	// Return providers as JSON
	response := make([]map[string]interface{}, 0, len(providers))
	for _, provider := range providers {
		response = append(response, map[string]interface{}{
			"name":         provider.Name,
			"display_name": provider.DisplayName,
			"scopes":       provider.Scopes,
			"auth_url":     fmt.Sprintf("/oauth/authorize/%s", provider.Name),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
		http.Error(w, "OAuth provider not found", http.StatusNotFound)
		return
	}

	// Generate state parameter for CSRF protection
	stateBytes := make([]byte, 32)
	rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Get user ID from the MCP client authentication (stored in context by middleware)
	userID := "anonymous"
	if uid, ok := r.Context().Value("user_id").(string); ok && uid != "" {
		userID = uid
	}

	// Store auth state
	h.authStates[state] = &OAuthAuthState{
		Provider:    providerName,
		Integration: integration,
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute), // 10 minute expiry
	}

	// Build authorization URL
	authURL, err := url.Parse(provider.AuthorizationURL)
	if err != nil {
		http.Error(w, "Invalid provider authorization URL", http.StatusInternalServerError)
		return
	}

	query := authURL.Query()
	query.Set("client_id", provider.ClientID)
	query.Set("redirect_uri", h.baseURL+"/oauth/callback")
	query.Set("scope", strings.Join(provider.Scopes, " "))
	query.Set("response_type", "code")
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	// Redirect to provider's authorization endpoint
	http.Redirect(w, r, authURL.String(), http.StatusFound)
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
		http.Error(w, fmt.Sprintf("OAuth authorization failed: %s", errorParam), http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing authorization code or state", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	authState, exists := h.authStates[state]
	if !exists || time.Now().After(authState.ExpiresAt) {
		http.Error(w, "Invalid or expired state parameter", http.StatusBadRequest)
		return
	}
	delete(h.authStates, state) // One-time use

	// Get provider from registry
	provider, err := h.registry.GetOAuthProvider(r.Context(), authState.Provider)
	if err != nil || provider == nil {
		http.Error(w, "OAuth provider not found", http.StatusInternalServerError)
		return
	}

	// Exchange code for tokens
	tokenURL := provider.TokenURL
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.baseURL + "/oauth/callback"},
		"client_id":     {provider.ClientID},
		"client_secret": {provider.ClientSecret},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		http.Error(w, "Failed to exchange code for tokens", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
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
		Scope:        strings.Join(provider.Scopes, " "),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := h.store.SaveOAuthCredential(r.Context(), cred); err != nil {
		http.Error(w, "Failed to save OAuth credentials", http.StatusInternalServerError)
		return
	}

	// Return success page or redirect
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"provider":    authState.Provider,
		"integration": authState.Integration,
		"message":     "OAuth authorization completed successfully",
	})
}

// RegisterWebOAuthRoutes registers the web OAuth routes
func RegisterWebOAuthRoutes(mux *http.ServeMux, store storage.Storage, registry registry.OAuthRegistry, baseURL string) {
	handler := NewWebOAuthHandler(store, registry, baseURL)

	mux.HandleFunc("/oauth/providers", handler.HandleOAuthProviders)
	mux.HandleFunc("/oauth/authorize/", handler.HandleOAuthAuthorize)
	mux.HandleFunc("/oauth/callback", handler.HandleOAuthCallback)
}
