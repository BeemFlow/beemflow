package api

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

	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
)

// OAuth operation argument types
type OAuthAuthorizationArgs struct {
	Provider    string `json:"provider"`
	Integration string `json:"integration"`
	State       string `json:"state,omitempty"` // Optional state parameter for security
}

type OAuthCallbackArgs struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state,omitempty"`
}

type OAuthListArgs struct {
	Provider string `json:"provider,omitempty"` // Optional filter by provider
}

type OAuthRevokeArgs struct {
	Provider    string `json:"provider"`
	Integration string `json:"integration"`
}

// OAuth response types
type OAuthAuthorizationResponse struct {
	AuthURL string `json:"authUrl"`
	State   string `json:"state"`
}

type OAuthCallbackResponse struct {
	Success     bool   `json:"success"`
	Integration string `json:"integration,omitempty"`
	Message     string `json:"message,omitempty"`
}

type OAuthCredentialInfo struct {
	ID          string     `json:"id"`
	Provider    string     `json:"provider"`
	Integration string     `json:"integration"`
	Scope       string     `json:"scope,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	IsExpired   bool       `json:"isExpired"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type OAuthListResponse struct {
	Credentials []OAuthCredentialInfo `json:"credentials"`
}

// OAuth state management (simple in-memory store for demo)
var oauthStates = make(map[string]OAuthAuthorizationArgs)

// OAuth operations registration
func init() {
	RegisterOperation(&OperationDefinition{
		ID:          "oauth_start",
		Name:        "Start OAuth Flow",
		Description: "Initiate OAuth 2.0 authorization flow for a provider",
		Group:       "oauth",
		HTTPMethod:  "POST",
		HTTPPath:    "/oauth/start",
		CLIUse:      "oauth start <provider> <integration>",
		CLIShort:    "Start OAuth authorization flow",
		MCPName:     "oauth.start",
		ArgsType:    reflect.TypeOf(OAuthAuthorizationArgs{}),
		Handler:     handleOAuthStart,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "oauth_callback",
		Name:        "OAuth Callback",
		Description: "Handle OAuth 2.0 authorization callback",
		Group:       "oauth",
		HTTPMethod:  "GET",
		HTTPPath:    "/oauth/callback",
		CLIUse:      "oauth callback <provider> <code>",
		CLIShort:    "Handle OAuth callback with authorization code",
		MCPName:     "oauth.callback",
		ArgsType:    reflect.TypeOf(OAuthCallbackArgs{}),
		Handler:     handleOAuthCallback,
		HTTPHandler: handleOAuthCallbackHTTP, // Custom handler for query parameters
	})

	RegisterOperation(&OperationDefinition{
		ID:          "oauth_list",
		Name:        "List OAuth Credentials",
		Description: "List stored OAuth credentials",
		Group:       "oauth",
		HTTPMethod:  "GET",
		HTTPPath:    "/oauth/credentials",
		CLIUse:      "oauth list [provider]",
		CLIShort:    "List stored OAuth credentials",
		MCPName:     "oauth.list",
		ArgsType:    reflect.TypeOf(OAuthListArgs{}),
		Handler:     handleOAuthList,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "oauth_revoke",
		Name:        "Revoke OAuth Credential",
		Description: "Revoke and delete stored OAuth credential",
		Group:       "oauth",
		HTTPMethod:  "DELETE",
		HTTPPath:    "/oauth/credentials",
		CLIUse:      "oauth revoke <provider> <integration>",
		CLIShort:    "Revoke OAuth credential",
		MCPName:     "oauth.revoke",
		ArgsType:    reflect.TypeOf(OAuthRevokeArgs{}),
		Handler:     handleOAuthRevoke,
	})
}

// OAuth operation handlers
func handleOAuthStart(ctx context.Context, args any) (any, error) {
	req := args.(OAuthAuthorizationArgs)

	// Get configuration
	cfg := GetConfigFromContext(ctx)
	if cfg == nil || cfg.OAuth == nil || cfg.OAuth.Providers == nil {
		return nil, utils.Errorf("OAuth not configured")
	}

	provider, exists := cfg.OAuth.Providers[req.Provider]
	if !exists {
		return nil, utils.Errorf("OAuth provider %q not configured", req.Provider)
	}

	// Generate state parameter for security
	state := req.State
	if state == "" {
		stateBytes := make([]byte, 32)
		if _, err := rand.Read(stateBytes); err != nil {
			return nil, utils.Errorf("failed to generate state: %w", err)
		}
		state = base64.URLEncoding.EncodeToString(stateBytes)
	}

	// Store state for validation
	oauthStates[state] = req

	// Build authorization URL
	redirectURI := buildRedirectURI(cfg, req.Provider, provider.RedirectPath)
	authURL := buildAuthURL(provider, redirectURI, state)

	return OAuthAuthorizationResponse{
		AuthURL: authURL,
		State:   state,
	}, nil
}

func handleOAuthCallback(ctx context.Context, args any) (any, error) {
	req := args.(OAuthCallbackArgs)

	// Validate state
	originalReq, exists := oauthStates[req.State]
	if !exists {
		return nil, utils.Errorf("invalid or expired OAuth state")
	}
	defer delete(oauthStates, req.State) // Clean up state

	if originalReq.Provider != req.Provider {
		return nil, utils.Errorf("provider mismatch in OAuth callback")
	}

	// Get configuration
	cfg := GetConfigFromContext(ctx)
	if cfg == nil || cfg.OAuth == nil || cfg.OAuth.Providers == nil {
		return nil, utils.Errorf("OAuth not configured")
	}

	provider, exists := cfg.OAuth.Providers[req.Provider]
	if !exists {
		return nil, utils.Errorf("OAuth provider %q not configured", req.Provider)
	}

	// Exchange code for tokens
	tokens, err := exchangeCodeForTokens(provider, req.Code, buildRedirectURI(cfg, req.Provider, provider.RedirectPath))
	if err != nil {
		return nil, utils.Errorf("failed to exchange authorization code: %w", err)
	}

	// Store OAuth credential
	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	credential := &model.OAuthCredential{
		ID:           generateCredentialID(req.Provider, originalReq.Integration),
		Provider:     req.Provider,
		Integration:  originalReq.Integration,
		AccessToken:  tokens.AccessToken,
		RefreshToken: &tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
		Scope:        strings.Join(provider.Scopes, " "),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := storage.SaveOAuthCredential(ctx, credential); err != nil {
		return nil, utils.Errorf("failed to save OAuth credential: %w", err)
	}

	utils.Info("OAuth credential saved for %s:%s", req.Provider, originalReq.Integration)

	return OAuthCallbackResponse{
		Success:     true,
		Integration: originalReq.Integration,
		Message:     fmt.Sprintf("OAuth credential saved for %s:%s", req.Provider, originalReq.Integration),
	}, nil
}

func handleOAuthList(ctx context.Context, args any) (any, error) {
	req := args.(OAuthListArgs)

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	credentials, err := storage.ListOAuthCredentials(ctx)
	if err != nil {
		return nil, utils.Errorf("failed to list OAuth credentials: %w", err)
	}

	// Filter by provider if specified
	var filtered []OAuthCredentialInfo
	for _, cred := range credentials {
		if req.Provider != "" && cred.Provider != req.Provider {
			continue
		}

		filtered = append(filtered, OAuthCredentialInfo{
			ID:          cred.ID,
			Provider:    cred.Provider,
			Integration: cred.Integration,
			Scope:       cred.Scope,
			ExpiresAt:   cred.ExpiresAt,
			IsExpired:   cred.IsExpired(),
			CreatedAt:   cred.CreatedAt,
			UpdatedAt:   cred.UpdatedAt,
		})
	}

	return OAuthListResponse{
		Credentials: filtered,
	}, nil
}

func handleOAuthRevoke(ctx context.Context, args any) (any, error) {
	req := args.(OAuthRevokeArgs)

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	credentialID := generateCredentialID(req.Provider, req.Integration)
	if err := storage.DeleteOAuthCredential(ctx, credentialID); err != nil {
		return nil, utils.Errorf("failed to revoke OAuth credential: %w", err)
	}

	utils.Info("OAuth credential revoked for %s:%s", req.Provider, req.Integration)

	return map[string]any{
		"success": true,
		"message": fmt.Sprintf("OAuth credential revoked for %s:%s", req.Provider, req.Integration),
	}, nil
}

// Custom HTTP handler for OAuth callback to handle query parameters
func handleOAuthCallbackHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	provider := r.URL.Query().Get("provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Handle OAuth errors
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		utils.Error("OAuth callback error: %s - %s", errorParam, errorDesc)
		http.Error(w, fmt.Sprintf("OAuth error: %s", errorParam), http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing required OAuth parameters", http.StatusBadRequest)
		return
	}

	// Create callback args
	args := OAuthCallbackArgs{
		Provider: provider,
		Code:     code,
		State:    state,
	}

	// Execute callback handler
	result, err := handleOAuthCallback(r.Context(), args)
	if err != nil {
		utils.Error("OAuth callback failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		utils.Error("Failed to encode OAuth callback response: %v", err)
	}
}

// Helper functions

func buildRedirectURI(cfg *config.Config, provider, customPath string) string {
	baseURL := cfg.OAuth.BaseURL
	if baseURL == "" {
		// Default to localhost with HTTP config port
		port := 8080
		if cfg.HTTP != nil && cfg.HTTP.Port != 0 {
			port = cfg.HTTP.Port
		}
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	redirectPath := customPath
	if redirectPath == "" {
		redirectPath = fmt.Sprintf("/oauth/callback?provider=%s", provider)
	}

	return baseURL + redirectPath
}

func buildAuthURL(provider config.OAuthProviderConfig, redirectURI, state string) string {
	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("state", state)

	if len(provider.Scopes) > 0 {
		params.Set("scope", strings.Join(provider.Scopes, " "))
	}

	return provider.AuthURL + "?" + params.Encode()
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

type oauthTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    *time.Time
}

func exchangeCodeForTokens(provider config.OAuthProviderConfig, code, redirectURI string) (*oauthTokens, error) {
	// Prepare token exchange request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	// Make token exchange request
	resp, err := http.PostForm(provider.TokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			utils.Warn("Failed to close token response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	// Parse token response
	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Calculate expiration time
	var expiresAt *time.Time
	if tokenResp.ExpiresIn > 0 {
		expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		expiresAt = &expiry
	}

	return &oauthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func generateCredentialID(provider, integration string) string {
	return fmt.Sprintf("%s-%s", provider, integration)
}
