package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beemflow/beemflow/auth"
	"github.com/beemflow/beemflow/config"
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
		Issuer:        getOAuthIssuerURL(cfg),
		ClientID:      "beemflow",        // Default client ID
		ClientSecret:  "beemflow-secret", // Default client secret (should be configurable)
		TokenExpiry:   3600,              // 1 hour
		RefreshExpiry: 7200,              // 2 hours
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

// setupMCPRouteProtection protects MCP routes with OAuth authentication
func setupMCPRouteProtection(mux *http.ServeMux, store storage.Storage, oauthServer *auth.OAuthServer) {
	// Create auth middleware for MCP routes
	authMiddleware := NewAuthMiddleware(store, oauthServer, "mcp")

	// For now, we'll add a catch-all handler for MCP routes that requires auth
	// In a real implementation, this would delegate to the actual MCP server
	mux.Handle("/mcp/", authMiddleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler will only be reached if authentication passes
		utils.Info("Authenticated MCP request: %s %s", r.Method, r.URL.Path)
		http.Error(w, "MCP endpoint not implemented at this level", http.StatusNotImplemented)
	})))
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

		// Validate token
		if !a.validateToken(r.Context(), token) {
			a.unauthorized(w, r, "Invalid or expired token")
			return
		}

		// Token is valid, proceed
		next.ServeHTTP(w, r)
	})
}

// validateToken validates an OAuth access token
func (a *AuthMiddleware) validateToken(ctx context.Context, token string) bool {
	// Get token info from storage
	tokenInfo, err := a.store.GetOAuthTokenByAccess(ctx, token)
	if err != nil {
		utils.Debug("Token validation failed: %v", err)
		return false
	}

	// Check if token is expired
	if tokenInfo.AccessExpiresIn > 0 {
		// Check if token has expired
		accessExpiry := tokenInfo.AccessCreateAt.Add(tokenInfo.AccessExpiresIn)
		if time.Now().After(accessExpiry) {
			utils.Debug("Token has expired")
			return false
		}
	}

	// Check scope
	if a.requiredScope != "" && !strings.Contains(tokenInfo.Scope, a.requiredScope) {
		utils.Debug("Token scope %s does not include required scope %s", tokenInfo.Scope, a.requiredScope)
		return false
	}

	return true
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
			// Token provided, validate it
			if !strings.HasPrefix(authHeader, "Bearer ") {
				a.unauthorized(w, r, "Invalid authorization header format")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if !a.validateToken(r.Context(), token) {
				a.unauthorized(w, r, "Invalid or expired token")
				return
			}
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
	userID := "anonymous" // TODO: Get from authenticated MCP client context

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
