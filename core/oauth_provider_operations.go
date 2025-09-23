package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
)

// OAuth provider operation argument types
type CreateOAuthProviderArgs struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	AuthURL      string   `json:"authUrl"`
	TokenURL     string   `json:"tokenUrl"`
	Scopes       []string `json:"scopes,omitempty"`
}

type GetOAuthProviderArgs struct {
	ID string `json:"id"`
}

type UpdateOAuthProviderArgs struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"clientId,omitempty"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	AuthURL      string   `json:"authUrl,omitempty"`
	TokenURL     string   `json:"tokenUrl,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type DeleteOAuthProviderArgs struct {
	ID string `json:"id"`
}

// OAuth provider response types
type OAuthProviderInfo struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"clientId"`
	AuthURL   string   `json:"authUrl"`
	TokenURL  string   `json:"tokenUrl"`
	Scopes    []string `json:"scopes,omitempty"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
	// Note: ClientSecret is intentionally omitted for security
}

type ListOAuthProvidersResponse struct {
	Providers []OAuthProviderInfo `json:"providers"`
}

// OAuth provider operations registration
func init() {
	RegisterOperation(&OperationDefinition{
		ID:          "create_oauth_provider",
		Name:        "Create OAuth Provider",
		Description: "Create a new OAuth 2.0 provider configuration",
		Group:       "oauth",
		HTTPMethod:  "POST",
		HTTPPath:    "/oauth/providers",
		CLIUse:      "oauth providers create <id>",
		CLIShort:    "Create OAuth provider",
		MCPName:     "oauth.providers.create",
		ArgsType:    reflect.TypeOf(CreateOAuthProviderArgs{}),
		Handler:     handleCreateOAuthProvider,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "get_oauth_provider",
		Name:        "Get OAuth Provider",
		Description: "Get an OAuth 2.0 provider configuration",
		Group:       "oauth",
		HTTPMethod:  "GET",
		HTTPPath:    "/oauth/providers/{id}",
		CLIUse:      "oauth providers get <id>",
		CLIShort:    "Get OAuth provider",
		MCPName:     "oauth.providers.get",
		ArgsType:    reflect.TypeOf(GetOAuthProviderArgs{}),
		Handler:     handleGetOAuthProvider,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "list_oauth",
		Name:        "List OAuth Providers",
		Description: "List all OAuth 2.0 provider configurations",
		Group:       "oauth",
		HTTPMethod:  "GET",
		HTTPPath:    "/oauth/providers",
		CLIUse:      "oauth providers list",
		CLIShort:    "List OAuth providers",
		MCPName:     "oauth.providers.list",
		ArgsType:    reflect.TypeOf(EmptyArgs{}),
		Handler:     handleListOAuthProviders,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "update_oauth_provider",
		Name:        "Update OAuth Provider",
		Description: "Update an OAuth 2.0 provider configuration",
		Group:       "oauth",
		HTTPMethod:  "PUT",
		HTTPPath:    "/oauth/providers/{id}",
		CLIUse:      "oauth providers update <id>",
		CLIShort:    "Update OAuth provider",
		MCPName:     "oauth.providers.update",
		ArgsType:    reflect.TypeOf(UpdateOAuthProviderArgs{}),
		Handler:     handleUpdateOAuthProvider,
	})

	RegisterOperation(&OperationDefinition{
		ID:          "delete_oauth_provider",
		Name:        "Delete OAuth Provider",
		Description: "Delete an OAuth 2.0 provider configuration",
		Group:       "oauth",
		HTTPMethod:  "DELETE",
		HTTPPath:    "/oauth/providers/{id}",
		CLIUse:      "oauth providers delete <id>",
		CLIShort:    "Delete OAuth provider",
		MCPName:     "oauth.providers.delete",
		ArgsType:    reflect.TypeOf(DeleteOAuthProviderArgs{}),
		Handler:     handleDeleteOAuthProvider,
	})
}

// OAuth provider operation handlers

func handleCreateOAuthProvider(ctx context.Context, args any) (any, error) {
	var req CreateOAuthProviderArgs
	switch v := args.(type) {
	case CreateOAuthProviderArgs:
		req = v
	case *CreateOAuthProviderArgs:
		req = *v
	default:
		return nil, utils.Errorf("invalid argument type for create OAuth provider: %T", args)
	}

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	// Check if provider already exists
	if existing, err := storage.GetOAuthProvider(ctx, req.ID); err == nil && existing != nil {
		return nil, utils.Errorf("OAuth provider %q already exists", req.ID)
	}

	provider := &model.OAuthProvider{
		ID:           req.ID,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		AuthURL:      req.AuthURL,
		TokenURL:     req.TokenURL,
		Scopes:       req.Scopes,
	}

	if err := storage.SaveOAuthProvider(ctx, provider); err != nil {
		return nil, utils.Errorf("failed to save OAuth provider: %w", err)
	}

	utils.Info("OAuth provider created: %s", req.ID)

	return OAuthProviderInfo{
		ID:        provider.ID,
		ClientID:  provider.ClientID,
		AuthURL:   provider.AuthURL,
		TokenURL:  provider.TokenURL,
		Scopes:    provider.Scopes,
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func handleGetOAuthProvider(ctx context.Context, args any) (any, error) {
	var req GetOAuthProviderArgs
	switch v := args.(type) {
	case GetOAuthProviderArgs:
		req = v
	case *GetOAuthProviderArgs:
		req = *v
	default:
		return nil, utils.Errorf("invalid argument type for get OAuth provider: %T", args)
	}

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	provider, err := storage.GetOAuthProvider(ctx, req.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.Errorf("OAuth provider %q not found", req.ID)
		}
		return nil, utils.Errorf("failed to get OAuth provider: %w", err)
	}

	return OAuthProviderInfo{
		ID:       provider.ID,
		ClientID: provider.ClientID,
		AuthURL:  provider.AuthURL,
		TokenURL: provider.TokenURL,
		Scopes:   provider.Scopes,
		// Note: timestamps would need to be stored in the model to return here
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func handleListOAuthProviders(ctx context.Context, args any) (any, error) {
	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	providers, err := storage.ListOAuthProviders(ctx)
	if err != nil {
		return nil, utils.Errorf("failed to list OAuth providers: %w", err)
	}

	var providerInfos []OAuthProviderInfo
	for _, provider := range providers {
		providerInfos = append(providerInfos, OAuthProviderInfo{
			ID:       provider.ID,
			ClientID: provider.ClientID,
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
			Scopes:   provider.Scopes,
			// Note: timestamps would need to be stored in the model to return here
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		})
	}

	return ListOAuthProvidersResponse{
		Providers: providerInfos,
	}, nil
}

func handleUpdateOAuthProvider(ctx context.Context, args any) (any, error) {
	var req UpdateOAuthProviderArgs
	switch v := args.(type) {
	case UpdateOAuthProviderArgs:
		req = v
	case *UpdateOAuthProviderArgs:
		req = *v
	default:
		return nil, utils.Errorf("invalid argument type for update OAuth provider: %T", args)
	}

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	// Get existing provider
	existing, err := storage.GetOAuthProvider(ctx, req.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.Errorf("OAuth provider %q not found", req.ID)
		}
		return nil, utils.Errorf("failed to get OAuth provider: %w", err)
	}

	// Update fields if provided
	if req.ClientID != "" {
		existing.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		existing.ClientSecret = req.ClientSecret
	}
	if req.AuthURL != "" {
		existing.AuthURL = req.AuthURL
	}
	if req.TokenURL != "" {
		existing.TokenURL = req.TokenURL
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}

	if err := storage.SaveOAuthProvider(ctx, existing); err != nil {
		return nil, utils.Errorf("failed to update OAuth provider: %w", err)
	}

	utils.Info("OAuth provider updated: %s", req.ID)

	return OAuthProviderInfo{
		ID:        existing.ID,
		ClientID:  existing.ClientID,
		AuthURL:   existing.AuthURL,
		TokenURL:  existing.TokenURL,
		Scopes:    existing.Scopes,
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func handleDeleteOAuthProvider(ctx context.Context, args any) (any, error) {
	var req DeleteOAuthProviderArgs
	switch v := args.(type) {
	case DeleteOAuthProviderArgs:
		req = v
	case *DeleteOAuthProviderArgs:
		req = *v
	default:
		return nil, utils.Errorf("invalid argument type for delete OAuth provider: %T", args)
	}

	storage := GetStoreFromContext(ctx)
	if storage == nil {
		return nil, utils.Errorf("storage not available")
	}

	if err := storage.DeleteOAuthProvider(ctx, req.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.Errorf("OAuth provider %q not found", req.ID)
		}
		return nil, utils.Errorf("failed to delete OAuth provider: %w", err)
	}

	utils.Info("OAuth provider deleted: %s", req.ID)

	return map[string]any{
		"success": true,
		"message": fmt.Sprintf("OAuth provider %q deleted successfully", req.ID),
	}, nil
}
