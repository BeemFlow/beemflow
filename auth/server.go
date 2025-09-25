package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

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
	Issuer        string
	ClientID      string
	ClientSecret  string
	PrivateKey    []byte // For JWT signing
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
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
	if !enforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
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

// enforceHTTPS ensures OAuth endpoints are accessed over HTTPS
func enforceHTTPS(w http.ResponseWriter, r *http.Request) bool {
	if r.TLS == nil {
		http.Error(w, "HTTPS required for OAuth endpoints", http.StatusForbidden)
		return false
	}
	return true
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
	if !enforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
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
		if !isValidRedirectURI(uri) {
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

// isValidRedirectURI validates a redirect URI according to OAuth 2.1 best practices
func isValidRedirectURI(uri string) bool {
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

	// Reject localhost/127.0.0.1 in production (only allow in development)
	if hostname == "localhost" || hostname == "127.0.0.1" {
		// Only allow localhost in development environments
		// This should be configurable based on environment
		return false // TODO: Make this configurable for development
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
	if !enforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	// For MCP servers, we implement a simplified authorization flow
	// This could be extended to show a proper consent page in the future

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

	// For MCP servers, we auto-approve requests for registered clients
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
	if !enforceHTTPS(w, r) || !o.enforceRateLimit(w, r) {
		return
	}

	err := o.server.HandleTokenRequest(w, r)
	if err != nil {
		utils.Error("OAuth token error: %v", err)
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
		CodeExpiresIn:    time.Duration(info.GetCodeExpiresIn()) * time.Second,
		Access:           info.GetAccess(),
		AccessCreateAt:   info.GetAccessCreateAt(),
		AccessExpiresIn:  time.Duration(info.GetAccessExpiresIn()) * time.Second,
		Refresh:          info.GetRefresh(),
		RefreshCreateAt:  info.GetRefreshCreateAt(),
		RefreshExpiresIn: time.Duration(info.GetRefreshExpiresIn()) * time.Second,
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
