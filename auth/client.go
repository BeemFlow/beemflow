package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
)

// OAuthClient provides client-side OAuth token management utilities
type OAuthClient struct {
	store storage.Storage
}

// NewOAuthClient creates a new OAuth client utility
func NewOAuthClient(store storage.Storage) *OAuthClient {
	return &OAuthClient{store: store}
}

// GetToken retrieves a valid OAuth access token for the given provider and integration
func (c *OAuthClient) GetToken(ctx context.Context, provider, integration string) (string, error) {
	cred, err := c.store.GetOAuthCredential(ctx, provider, integration)
	if err != nil {
		return "", utils.Errorf("failed to get OAuth credential for %s:%s: %w", provider, integration, err)
	}

	// Check if token needs refresh
	if cred.ExpiresAt != nil && time.Now().After(*cred.ExpiresAt) && cred.RefreshToken != nil && *cred.RefreshToken != "" {
		if err := c.RefreshToken(ctx, cred); err != nil {
			// If refresh fails, log warning but continue with expired token
			// This is better than failing the entire operation
			utils.Warn("Failed to refresh OAuth token for %s:%s: %v", provider, integration, err)
		} else {
			// Re-get the credential after successful refresh
			if updatedCred, err := c.store.GetOAuthCredential(ctx, provider, integration); err == nil {
				cred = updatedCred
			}
		}
	}

	return cred.AccessToken, nil
}

// RefreshToken refreshes an expired OAuth token
func (c *OAuthClient) RefreshToken(ctx context.Context, cred *model.OAuthCredential) error {
	if cred.RefreshToken == nil {
		return utils.Errorf("no refresh token available for credential %s:%s", cred.Provider, cred.Integration)
	}

	// Get the OAuth provider configuration
	provider, err := c.store.GetOAuthProvider(ctx, cred.Provider)
	if err != nil {
		return utils.Errorf("failed to get OAuth provider %s: %w", cred.Provider, err)
	}

	// Prepare refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", *cred.RefreshToken)
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)

	// Make HTTP request to token endpoint
	req, err := http.NewRequestWithContext(ctx, "POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return utils.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return utils.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return utils.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		AccessToken  string  `json:"access_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    int     `json:"expires_in"`
		RefreshToken *string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return utils.Errorf("failed to parse token response: %w", err)
	}

	// Update credential with new token
	cred.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != nil {
		cred.RefreshToken = tokenResp.RefreshToken
	}
	if tokenResp.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		cred.ExpiresAt = &expiresAt
	}
	cred.UpdatedAt = time.Now()

	// Save updated credential
	if err := c.store.SaveOAuthCredential(ctx, cred); err != nil {
		return utils.Errorf("failed to save refreshed credential: %w", err)
	}

	return nil
}
