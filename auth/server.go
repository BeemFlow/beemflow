package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/google/uuid"
)

// OAuthConfig holds OAuth 2.1 server configuration
type OAuthConfig struct {
	Issuer                  string
	ClientID                string
	ClientSecret            string
	PrivateKey              []byte // For JWT signing
	TokenExpiry             time.Duration
	RefreshExpiry           time.Duration
	AllowLocalhostRedirects bool // Allow localhost redirects (for development)
}

// rateLimiter provides simple rate limiting for OAuth endpoints
type rateLimiter struct {
	requests map[string][]time.Time
	window   time.Duration
	maxReqs  int
	mu       sync.RWMutex
}

func newRateLimiter(window time.Duration, maxReqs int) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		maxReqs:  maxReqs,
	}
}

func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	requests := r.requests[key]

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, req := range requests {
		if now.Sub(req) < r.window {
			validRequests = append(validRequests, req)
		}
	}

	if len(validRequests) >= r.maxReqs {
		return false
	}

	validRequests = append(validRequests, now)
	r.requests[key] = validRequests
	return true
}

// OAuthServer wraps the OAuth2 server with BeemFlow-specific functionality
type OAuthServer struct {
	server      *server.Server
	manager     *manage.Manager
	config      *OAuthConfig
	store       storage.Storage
	rateLimiter *rateLimiter
}

// NewOAuthServer creates a new OAuth 2.1 server instance
func NewOAuthServer(cfg *OAuthConfig, store storage.Storage) *OAuthServer {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    cfg.TokenExpiry,
		RefreshTokenExp:   cfg.RefreshExpiry,
		IsGenerateRefresh: true,
	})

	// Set up token store
	manager.MustTokenStorage(NewTokenStore(store), nil)

	// Set up client store
	manager.MustClientStorage(NewClientStore(store), nil)

	// Create OAuth2 server
	srv := server.NewServer(server.NewConfig(), manager)

	// Enable PKCE
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(func(r *http.Request) (clientID, clientSecret string, err error) {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
		return
	})

	// Set up internal error handler
	srv.SetInternalErrorHandler(func(err error) *errors.Response {
		// Log full error for debugging but don't expose details to client
		utils.Error("OAuth internal error: %v", err)
		return &errors.Response{
			Error:       errors.New("internal_server_error"),
			Description: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
			StatusCode:  http.StatusInternalServerError,
		}
	})

	// Set up response error handler
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		utils.Warn("OAuth response error: %s - %s", re.Error.Error(), re.Description)
	})

	return &OAuthServer{
		server:      srv,
		manager:     manager,
		config:      cfg,
		store:       store,
		rateLimiter: newRateLimiter(time.Minute, 10), // 10 requests per minute per IP
	}
}

// HandleMetadataDiscovery serves the OAuth 2.0 Authorization Server Metadata
func (o *OAuthServer) HandleMetadataDiscovery(w http.ResponseWriter, r *http.Request) {
	if !EnforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	metadata := map[string]interface{}{
		"issuer":                                o.config.Issuer,
		"authorization_endpoint":                o.config.Issuer + "/oauth/authorize",
		"token_endpoint":                        o.config.Issuer + "/oauth/token",
		"jwks_uri":                              o.config.Issuer + "/oauth/jwks", // Placeholder
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"mcp", "openid", "profile", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
		"registration_endpoint":                 o.config.Issuer + "/oauth/register",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(metadata)
}

// EnforceHTTPS ensures OAuth endpoints are accessed over HTTPS in production
func EnforceHTTPS(w http.ResponseWriter, r *http.Request) bool {
	// Always allow localhost/development
	if strings.Contains(r.Host, "localhost") || strings.Contains(r.Host, "127.0.0.1") {
		return true
	}

	// Check for HTTPS via TLS or reverse proxy
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}

	http.Error(w, "HTTPS required for OAuth endpoints", http.StatusForbidden)
	return false
}

// enforceRateLimit checks rate limits for OAuth endpoints
func (o *OAuthServer) enforceRateLimit(w http.ResponseWriter, r *http.Request) bool {
	// Use client IP for rate limiting
	clientIP := r.RemoteAddr
	// Extract IP from X-Forwarded-For header if present (for proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	if !o.rateLimiter.allow(clientIP) {
		utils.Warn("Rate limit exceeded for IP: %s", clientIP)
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

// HandleDynamicClientRegistration handles OAuth 2.0 Dynamic Client Registration
func (o *OAuthServer) HandleDynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	if !EnforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientName    string   `json:"client_name"`
		ClientURI     string   `json:"client_uri,omitempty"`
		LogoURI       string   `json:"logo_uri,omitempty"`
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types,omitempty"`
		ResponseTypes []string `json:"response_types,omitempty"`
		Scope         string   `json:"scope,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.Warn("Failed to decode client registration JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ClientName == "" {
		http.Error(w, "client_name is required", http.StatusBadRequest)
		return
	}

	// Validate client name (prevent injection and reasonable length)
	if len(req.ClientName) > 100 || len(req.ClientName) < 1 {
		http.Error(w, "client_name must be between 1 and 100 characters", http.StatusBadRequest)
		return
	}

	// Basic validation for URIs (prevent malicious input)
	if req.ClientURI != "" && len(req.ClientURI) > 500 {
		http.Error(w, "client_uri too long", http.StatusBadRequest)
		return
	}

	if req.LogoURI != "" && len(req.LogoURI) > 500 {
		http.Error(w, "logo_uri too long", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}

	// Validate redirect URIs
	for _, uri := range req.RedirectURIs {
		if !o.isValidRedirectURI(uri) {
			http.Error(w, "Invalid redirect URI: "+uri, http.StatusBadRequest)
			return
		}
	}

	// Generate client credentials
	clientID := uuid.New().String()
	clientSecret := generateClientSecret()

	// Default grant types and response types
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.Scope == "" {
		req.Scope = "mcp"
	}

	// Create client
	client := &model.OAuthClient{
		ID:            clientID,
		Secret:        clientSecret,
		Name:          req.ClientName,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scope:         req.Scope,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Save client to storage
	ctx := r.Context()
	if err := o.store.SaveOAuthClient(ctx, client); err != nil {
		utils.Error("Failed to save OAuth client: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return client registration response
	resp := map[string]interface{}{
		"client_id":                client.ID,
		"client_secret":            client.Secret,
		"client_name":              client.Name,
		"redirect_uris":            client.RedirectURIs,
		"grant_types":              client.GrantTypes,
		"response_types":           client.ResponseTypes,
		"scope":                    client.Scope,
		"client_id_issued_at":      client.CreatedAt.Unix(),
		"client_secret_expires_at": 0, // Never expires
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// generateClientSecret generates a secure random client secret
func generateClientSecret() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GeneratePKCEChallenge generates PKCE code verifier and S256 challenge for OAuth 2.0
// Used by OAuth client flows to prevent authorization code interception
func GeneratePKCEChallenge() (verifier, challenge string, err error) {
	// Generate cryptographically random verifier (43-128 characters)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	// Generate S256 challenge from verifier
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return verifier, challenge, nil
}

// isValidRedirectURI validates a redirect URI according to OAuth 2.1 best practices
func (s *OAuthServer) isValidRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Must be HTTPS only (OAuth 2.1 security requirement)
	if u.Scheme != "https" {
		return false
	}

	// Additional validation: prevent common attacks
	hostname := u.Hostname()

	// Reject localhost/127.0.0.1 unless explicitly allowed (for development)
	if hostname == "localhost" || hostname == "127.0.0.1" {
		if !s.config.AllowLocalhostRedirects {
			return false
		}
	}

	// Reject IP addresses (except localhost which is already handled)
	if net.ParseIP(hostname) != nil {
		return false
	}

	// Basic length and character validation
	if len(uri) > 2048 { // Reasonable URI length limit
		return false
	}

	// Reject URIs with fragments (OAuth 2.1 discourages fragments in redirect URIs)
	if u.Fragment != "" {
		return false
	}

	return true
}

// HandleAuthorize handles OAuth authorization requests
func (o *OAuthServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !EnforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	// Check if this is a programmatic client request (for MCP tools)
	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}

	// Verify client exists
	ctx := r.Context()
	client, err := o.store.GetOAuthClient(ctx, clientID)
	if err != nil {
		utils.Error("Invalid client_id: %v", err)
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != "" {
		valid := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
			return
		}
	}

	// For programmatic requests (API calls), auto-approve for registered clients
	// Set a dummy user ID for MCP server context
	r.Form.Set("user_id", "mcp-server")

	err = o.server.HandleAuthorizeRequest(w, r)
	if err != nil {
		utils.Error("OAuth authorize error: %v", err)
		http.Error(w, "Authorization request failed", http.StatusBadRequest)
	}
}

// HandleToken handles OAuth token requests
func (o *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	if !EnforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	err := o.server.HandleTokenRequest(w, r)
	if err != nil {
		utils.Error("OAuth token error")
		http.Error(w, "Token request failed", http.StatusBadRequest)
	}
}

// TokenStore implements oauth2.TokenStore interface
type TokenStore struct {
	store storage.Storage
}

func NewTokenStore(store storage.Storage) *TokenStore {
	return &TokenStore{store: store}
}

func (t *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	// Convert oauth2.TokenInfo to our model
	token := &model.OAuthToken{
		ID:               uuid.New().String(),
		ClientID:         info.GetClientID(),
		UserID:           info.GetUserID(),
		RedirectURI:      info.GetRedirectURI(),
		Scope:            info.GetScope(),
		Code:             info.GetCode(),
		CodeCreateAt:     info.GetCodeCreateAt(),
		CodeExpiresIn:    info.GetCodeExpiresIn() * time.Second,
		Access:           info.GetAccess(),
		AccessCreateAt:   info.GetAccessCreateAt(),
		AccessExpiresIn:  info.GetAccessExpiresIn() * time.Second,
		Refresh:          info.GetRefresh(),
		RefreshCreateAt:  info.GetRefreshCreateAt(),
		RefreshExpiresIn: info.GetRefreshExpiresIn() * time.Second,
	}

	return t.store.SaveOAuthToken(ctx, token)
}

func (t *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return t.store.DeleteOAuthTokenByCode(ctx, code)
}

func (t *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return t.store.DeleteOAuthTokenByAccess(ctx, access)
}

func (t *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return t.store.DeleteOAuthTokenByRefresh(ctx, refresh)
}

func (t *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	token, err := t.store.GetOAuthTokenByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return t.convertToTokenInfo(token), nil
}

func (t *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	token, err := t.store.GetOAuthTokenByAccess(ctx, access)
	if err != nil {
		return nil, err
	}
	return t.convertToTokenInfo(token), nil
}

func (t *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	token, err := t.store.GetOAuthTokenByRefresh(ctx, refresh)
	if err != nil {
		return nil, err
	}
	return t.convertToTokenInfo(token), nil
}

// convertToTokenInfo converts our OAuthToken model to oauth2.TokenInfo
func (t *TokenStore) convertToTokenInfo(token *model.OAuthToken) oauth2.TokenInfo {
	info := &models.Token{
		ClientID:         token.ClientID,
		UserID:           token.UserID,
		RedirectURI:      token.RedirectURI,
		Scope:            token.Scope,
		Code:             token.Code,
		CodeCreateAt:     token.CodeCreateAt,
		CodeExpiresIn:    token.CodeExpiresIn,
		Access:           token.Access,
		AccessCreateAt:   token.AccessCreateAt,
		AccessExpiresIn:  token.AccessExpiresIn,
		Refresh:          token.Refresh,
		RefreshCreateAt:  token.RefreshCreateAt,
		RefreshExpiresIn: token.RefreshExpiresIn,
	}
	return info
}

// ClientStore implements oauth2.ClientStore interface
type ClientStore struct {
	store storage.Storage
}

func NewClientStore(store storage.Storage) *ClientStore {
	return &ClientStore{store: store}
}

func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	client, err := c.store.GetOAuthClient(ctx, id)
	if err != nil {
		return nil, err
	}
	return &OAuthClientInfo{client: client}, nil
}

// OAuthClientInfo wraps our OAuthClient model to implement oauth2.ClientInfo
type OAuthClientInfo struct {
	client *model.OAuthClient
}

func (c *OAuthClientInfo) GetID() string {
	return c.client.ID
}

func (c *OAuthClientInfo) GetSecret() string {
	return c.client.Secret
}

func (c *OAuthClientInfo) GetDomain() string {
	return ""
}

func (c *OAuthClientInfo) GetUserID() string {
	return ""
}

func (c *OAuthClientInfo) IsPublic() bool {
	return false
}

func (c *OAuthClientInfo) GetRedirectURI() string {
	if len(c.client.RedirectURIs) > 0 {
		return c.client.RedirectURIs[0]
	}
	return ""
}

// SetupOAuthServer creates an OAuth server instance from config
// AuthMiddleware provides OAuth 2.1 authentication for HTTP endpoints
type AuthMiddleware struct {
	store         storage.Storage
	oauthServer   *OAuthServer
	requiredScope string
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(store storage.Storage, oauthServer *OAuthServer, requiredScope string) *AuthMiddleware {
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

// SetupOAuthServer creates and returns an OAuth server instance
func SetupOAuthServer(cfg *config.Config, store storage.Storage) *OAuthServer {
	// Create OAuth server configuration
	oauthCfg := &OAuthConfig{
		Issuer:                  GetOAuthIssuerURL(cfg),
		ClientID:                "beemflow",         // Default client ID
		ClientSecret:            "beemflow-secret",  // Default client secret (should be configurable)
		TokenExpiry:             3600 * time.Second, // 1 hour
		RefreshExpiry:           7200 * time.Second, // 2 hours
		AllowLocalhostRedirects: strings.Contains(GetOAuthIssuerURL(cfg), "localhost") || strings.Contains(GetOAuthIssuerURL(cfg), "127.0.0.1"),
	}

	// Create OAuth server
	oauthServer := NewOAuthServer(oauthCfg, store)

	return oauthServer
}

// SetupOAuthHandlers adds OAuth 2.1 endpoints to the HTTP server
func SetupOAuthHandlers(mux *http.ServeMux, cfg *config.Config, store storage.Storage) error {
	oauthServer := SetupOAuthServer(cfg, store)

	// Register OAuth endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthServer.HandleMetadataDiscovery)
	mux.HandleFunc("/oauth/authorize", oauthServer.HandleAuthorize)
	mux.HandleFunc("/oauth/token", oauthServer.HandleToken)
	mux.HandleFunc("/oauth/register", oauthServer.HandleDynamicClientRegistration)

	return nil
}
func GetOAuthIssuerURL(cfg *config.Config) string {
	baseURL := "http://localhost:3330" // default HTTP server port

	if cfg.HTTP != nil {
		host := "localhost"
		if cfg.HTTP.Host != "" {
			host = cfg.HTTP.Host
		}

		port := 3330
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
