package mcp

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/utils"
	mcp "github.com/metoro-io/mcp-golang"
	mcphttp "github.com/metoro-io/mcp-golang/transport/http"
	mcpstdio "github.com/metoro-io/mcp-golang/transport/stdio"
)

// ServerConfig holds configuration for MCP server startup
type ServerConfig struct {
	Transport string // "stdio" or "http"
	Address   string // HTTP server address when transport is "http"
	Debug     bool   // Enable debug mode
}

// ToolRegistration holds a tool's registration info for the MCP server.
type ToolRegistration struct {
	Name        string
	Description string
	Handler     any // must be a func(ctx, args) (*mcp.ToolResponse, error)
}

// GetServerConfig creates a server configuration from environment variables and defaults
func GetServerConfig() *ServerConfig {
	config := &ServerConfig{
		Transport: getEnvWithDefault(constants.EnvMCPTransport, constants.DefaultMCPTransport),
		Address:   getMCPAddress(),
		Debug:     os.Getenv("BEEMFLOW_DEBUG") != "",
	}

	return config
}

// getMCPAddress determines the MCP server address from environment or defaults
func getMCPAddress() string {
	// Check for explicit MCP port
	if portStr := os.Getenv(constants.EnvMCPServerPort); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			return fmt.Sprintf("%s:%d", constants.DefaultServerHost, port)
		}
	}

	// Default MCP port
	return fmt.Sprintf("%s:%d", constants.DefaultServerHost, constants.DefaultMCPServerPort)
}

// getEnvWithDefault gets an environment variable with a fallback default
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ServeWithConfig starts an MCP server with the provided configuration
func ServeWithConfig(config *ServerConfig, tools []ToolRegistration) error {
	// Validate and normalize transport mode
	if config.Transport != "stdio" && config.Transport != "http" {
		config.Transport = "stdio" // Default to stdio for safety
	}

	// If HTTP mode but no address provided, use default
	if config.Transport == "http" && config.Address == "" {
		config.Address = getMCPAddress()
	}

	if config.Transport == "stdio" && config.Debug {
		utils.SetUserOutput(io.Discard)
	}

	// Create MCP server transport
	var server *mcp.Server
	if config.Transport == "http" {
		utils.Info("Starting MCP server on HTTP at %s...", config.Address)
		transport := mcphttp.NewHTTPTransport("/mcp").WithAddr(config.Address)
		server = mcp.NewServer(transport)
	} else {
		utils.Info("Starting MCP server on stdio...")
		transport := mcpstdio.NewStdioServerTransport()
		server = mcp.NewServer(transport)
	}

	// Register all tools
	RegisterAllTools(server, tools)

	// Start serving
	if err := server.Serve(); err != nil {
		return err
	}

	// For stdio transport, wait for termination signals and exit gracefully
	if config.Transport == "stdio" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		sig := <-sigCh
		utils.Info("Received signal %v, shutting down MCP stdio server", sig)
	}
	return nil
}

// RegisterAllTools registers all provided tools with the MCP server.
// This function is generic and does not import any business logic.
func RegisterAllTools(server *mcp.Server, tools []ToolRegistration) {
	for _, t := range tools {
		if err := server.RegisterTool(t.Name, t.Description, t.Handler); err != nil {
			utils.Error("Failed to register MCP tool %s: %v", t.Name, err)
		}
	}
}
