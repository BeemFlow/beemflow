package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/awantoch/beemflow/config"
	"github.com/awantoch/beemflow/utils"
)

type SmitheryRegistry struct {
	APIKey  string
	BaseURL string // e.g. https://registry.smithery.ai/servers
}

func NewSmitheryRegistry(apiKey, baseURL string) *SmitheryRegistry {
	if baseURL == "" {
		baseURL = "https://registry.smithery.ai/servers"
	}
	return &SmitheryRegistry{APIKey: apiKey, BaseURL: baseURL}
}

func (s *SmitheryRegistry) ListServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	params := url.Values{}
	if opts.PageSize > 0 {
		params.Set("pageSize", fmt.Sprintf("%d", opts.PageSize))
	} else {
		params.Set("pageSize", "50")
	}
	if opts.Query != "" {
		params.Set("q", opts.Query)
	}
	endpoint := fmt.Sprintf("%s?%s", s.BaseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	if s.APIKey == "" {
		s.APIKey = os.Getenv("SMITHERY_API_KEY")
	}
	if s.APIKey == "" {
		return nil, fmt.Errorf("smithery API key not set")
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			utils.Warn("Failed to close Smithery response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smithery registry returned status %s", resp.Status)
	}
	var data struct {
		Servers []struct {
			QualifiedName string `json:"qualifiedName"`
			DisplayName   string `json:"displayName"`
			Description   string `json:"description"`
			Homepage      string `json:"homepage"`
			IsDeployed    bool   `json:"isDeployed"`
		} `json:"servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	var entries []RegistryEntry
	for _, s := range data.Servers {
		entries = append(entries, RegistryEntry{
			Registry:    "smithery",
			Type:        "mcp_server",
			Name:        s.QualifiedName,
			Description: s.Description,
			Kind:        "smithery",
			Endpoint:    s.Homepage,
		})
	}
	return entries, nil
}

func (s *SmitheryRegistry) GetServer(ctx context.Context, name string) (*RegistryEntry, error) {
	endpoint := fmt.Sprintf("%s/%s", strings.TrimSuffix(s.BaseURL, "/"), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	if s.APIKey == "" {
		s.APIKey = os.Getenv("SMITHERY_API_KEY")
	}
	if s.APIKey == "" {
		return nil, fmt.Errorf("smithery API key not set")
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get server %s: %w", name, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			utils.Warn("Failed to close Smithery server response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smithery registry returned status %s", resp.Status)
	}
	var data struct {
		QualifiedName string `json:"qualifiedName"`
		DisplayName   string `json:"displayName"`
		Description   string `json:"description"`
		Homepage      string `json:"homepage"`
		Connections   []struct {
			Type          string         `json:"type"`
			Url           string         `json:"url"`
			ConfigSchema  map[string]any `json:"configSchema"`
			Published     bool           `json:"published"`
			StdioFunction string         `json:"stdioFunction"`
		} `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	// Find HTTP or stdio connection if available
	for _, conn := range data.Connections {
		if (conn.Type == "http" || conn.Type == "stdio") && conn.Url != "" {
			return &RegistryEntry{
				Registry:    "smithery",
				Type:        "mcp_server",
				Name:        data.QualifiedName,
				Description: data.Description,
				Kind:        conn.Type,
				Endpoint:    conn.Url,
				Parameters:  conn.ConfigSchema,
			}, nil
		}
	}
	return nil, fmt.Errorf("no suitable connection found for server %s", name)
}

// GetServerSpec fetches a server and parses its stdioFunction into MCPServerConfig.
func (s *SmitheryRegistry) GetServerSpec(ctx context.Context, name string) (config.MCPServerConfig, error) {
	endpoint := fmt.Sprintf("%s/%s", strings.TrimSuffix(s.BaseURL, "/"), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, http.NoBody)
	if err != nil {
		return config.MCPServerConfig{}, err
	}
	if s.APIKey == "" {
		s.APIKey = os.Getenv("SMITHERY_API_KEY")
	}
	if s.APIKey == "" {
		return config.MCPServerConfig{}, fmt.Errorf("smithery API key not set")
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return config.MCPServerConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return config.MCPServerConfig{}, fmt.Errorf("smithery registry returned status %s", resp.Status)
	}
	var data struct {
		Connections []struct {
			Type          string         `json:"type"`
			ConfigSchema  map[string]any `json:"configSchema"`
			Published     bool           `json:"published"`
			StdioFunction string         `json:"stdioFunction"`
		} `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return config.MCPServerConfig{}, err
	}
	for _, c := range data.Connections {
		if c.Type != "stdio" || !c.Published {
			continue
		}

		fn := c.StdioFunction
		start := strings.Index(fn, "({")
		end := strings.LastIndex(fn, "})")
		if start < 0 || end < 0 || end <= start+1 {
			return config.MCPServerConfig{}, fmt.Errorf("invalid stdioFunction format: %s", fn)
		}
		obj := fn[start+1 : end+1]
		interim := strings.ReplaceAll(obj, "'", "\"")
		re := regexp.MustCompile(`(\w+)\s*:`)
		jsonObj := re.ReplaceAllString(interim, `"$1":`)
		var m map[string]any
		if err := json.Unmarshal([]byte(jsonObj), &m); err != nil {
			return config.MCPServerConfig{}, fmt.Errorf("failed to parse stdioFunction object: %w", err)
		}
		cmdVal, ok := m["command"].(string)
		if !ok {
			return config.MCPServerConfig{}, fmt.Errorf("stdioFunction object missing command")
		}
		var argsList []string
		if arr, ok2 := m["args"].([]any); ok2 {
			for _, ai := range arr {
				if s, sok := ai.(string); sok {
					argsList = append(argsList, s)
				}
			}
		}
		return config.MCPServerConfig{
			Command: cmdVal,
			Args:    argsList,
		}, nil
	}
	return config.MCPServerConfig{}, fmt.Errorf("no stdio connection found for server %s", name)
}

// ListMCPServers returns only entries of type 'mcp_server' from the local registry.
func (l *LocalRegistry) ListMCPServers(ctx context.Context, opts ListOptions) ([]RegistryEntry, error) {
	entries, err := l.ListServers(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := []RegistryEntry{} // Initialize as empty slice instead of nil
	for _, e := range entries {
		if e.Type == "mcp_server" {
			out = append(out, e)
		}
	}
	return out, nil
}
