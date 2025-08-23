package mcp

import (
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/awantoch/beemflow/utils"
	mcp "github.com/metoro-io/mcp-golang"
	mcphttp "github.com/metoro-io/mcp-golang/transport/http"
	mcpstdio "github.com/metoro-io/mcp-golang/transport/stdio"
)

// ToolRegistration holds a tool's registration info for the MCP server.
type ToolRegistration struct {
	Name        string
	Description string
	Handler     any // must be a func(ctx, args) (*mcp.ToolResponse, error)
}

// Serve starts an MCP server with the given configuration.
func Serve(debug, stdio bool, addr string, tools []ToolRegistration) error {
	if stdio && !debug {
		utils.SetUserOutput(io.Discard)
	}

	// Create MCP server transport
	var server *mcp.Server
	if stdio {
		utils.Info("Starting MCP server on stdio...")
		transport := mcpstdio.NewStdioServerTransport()
		server = mcp.NewServer(transport)
	} else {
		utils.Info("Starting MCP server on HTTP at %s...", addr)
		transport := mcphttp.NewHTTPTransport("/mcp").WithAddr(addr)
		server = mcp.NewServer(transport)
	}

	// Register all tools
	RegisterAllTools(server, tools)

	// Start serving
	if err := server.Serve(); err != nil {
		return err
	}

	// For stdio transport, wait for termination signals and exit gracefully
	if stdio {
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
