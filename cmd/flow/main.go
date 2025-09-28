package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	// Load environment variables from .env file.
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	_ "github.com/beemflow/beemflow/adapter"
	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	api "github.com/beemflow/beemflow/core"
	"github.com/beemflow/beemflow/dsl"
	beemhttp "github.com/beemflow/beemflow/http"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

var (
	exit              = os.Exit
	configPath        string
	debug             bool
	mcpStartupTimeout time.Duration
	flowsDir          string
)

func main() {
	// Load .env as early as possible!
	_ = godotenv.Load()

	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// NewRootCmd creates the root 'flow' command with persistent flags and subcommands.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{Use: "flow"}
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", constants.ConfigFileName, "Path to flow config JSON")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logs")
	rootCmd.PersistentFlags().DurationVar(&mcpStartupTimeout, "mcp-timeout", 60*time.Second, "Timeout for MCP server startup")
	rootCmd.PersistentFlags().StringVar(&flowsDir, "flows-dir", "", "Path to flows directory (overrides config file)")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Load environment variables from .env file, if present
		_ = godotenv.Load()

		// Initialize config and set global state
		_, err := api.InitializeConfig(configPath, flowsDir)
		if err != nil {
			utils.Error("Failed to initialize config: %v", err)
			os.Exit(1)
		}
	}

	// Add all subcommands directly (no more need for CommandConstructors)
	rootCmd.AddCommand(
		newServeCmd(),
		newRunCmd(),
		newOAuthCmd(),
		// Other commands handled via operations framework
	)

	// Add auto-generated commands from the unified system
	commands := api.GenerateCLICommands()
	for _, cmd := range commands {
		rootCmd.AddCommand(cmd)
	}

	return rootCmd
}

// ============================================================================
// SERVE COMMAND (from serve.go)
// ============================================================================

// newServeCmd creates the 'serve' subcommand.
func newServeCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the BeemFlow runtime HTTP server",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := api.GetConfig()
			if err != nil {
				utils.Error("Failed to get config: %v", err)
				exit(1)
			}

			if err := cfg.Validate(); err != nil {
				utils.Error("Config validation failed: %v", err)
				exit(1)
			}

			// Apply the addr flag if provided
			if addr != "" {
				if cfg.HTTP == nil {
					cfg.HTTP = &config.HTTPConfig{}
				}

				// Parse host:port format
				host, portStr, found := strings.Cut(addr, ":")
				if !found {
					utils.Error("Invalid address format: %s (expected host:port)", addr)
					exit(1)
				}

				port, err := strconv.Atoi(portStr)
				if err != nil {
					utils.Error("Invalid port number: %v", err)
					exit(1)
				}

				cfg.HTTP.Host = host
				cfg.HTTP.Port = port
			}

			utils.Info("Starting BeemFlow HTTP server...")
			if err := beemhttp.StartServer(cfg); err != nil {
				utils.Error("Failed to start server: %v", err)
				exit(1)
			}
		},
	}

	// Add local flags
	cmd.Flags().StringVar(&addr, "addr", "", "Listen address in the format host:port")

	return cmd
}

// ============================================================================
// RUN COMMAND (from run.go)
// ============================================================================

// newRunCmd creates the 'run' subcommand.
func newRunCmd() *cobra.Command {
	var eventPath, eventJSON string
	cmd := &cobra.Command{
		Use:   constants.CmdRun + " [file]",
		Short: constants.DescRunFlow,
		Args:  cobra.RangeArgs(0, 1),
		Run: func(cmd *cobra.Command, args []string) {
			runFlowExecution(cmd, args, eventPath, eventJSON)
		},
	}
	cmd.Flags().StringVar(&eventPath, "event", "", "Path to event JSON file")
	cmd.Flags().StringVar(&eventJSON, "event-json", "", "Event as inline JSON string")
	return cmd
}

// runFlowExecution handles the main flow execution logic using the API service
func runFlowExecution(cmd *cobra.Command, args []string, eventPath, eventJSON string) {
	// Handle stub behavior when no file argument is provided
	if len(args) == 0 {
		utils.User(constants.StubFlowRun)
		return
	}

	// Parse the flow file
	flow, err := dsl.Parse(args[0])
	if err != nil {
		utils.Error("YAML parse error: %v", err)
		exit(1)
	}

	// Load event data
	event, err := loadEvent(eventPath, eventJSON)
	if err != nil {
		utils.Error("Failed to load event: %v", err)
		exit(4)
	}

	// Inject dependencies into context for OAuth token access
	ctx := cmd.Context()

	// Get config and inject into context
	if cfg, err := api.GetConfig(); err == nil && cfg != nil {
		ctx = api.WithConfig(ctx, cfg)

		// Get storage and inject into context using both keys
		if store, err := api.GetStoreFromConfig(cfg); err == nil && store != nil {
			ctx = api.WithStore(ctx, store)
			// Also inject using HTTP adapter's expected key
			type contextKeyType string
			const httpAdapterStorageKey contextKeyType = "storage"
			ctx = context.WithValue(ctx, httpAdapterStorageKey, store)
		}
	}

	// Use the API service instead of direct engine access
	runID, outputs, err := api.RunSpec(ctx, flow, event)
	if err != nil {
		utils.Error(constants.ErrFlowExecutionFailed, err)
		exit(5)
	}

	// Output results
	utils.Info("Run ID: %s", runID.String())
	outputFlowResults(outputs)
}

// outputFlowResults handles the output of flow execution results
func outputFlowResults(outputs map[string]any) {
	if debug {
		outputDebugResults(outputs)
	} else {
		outputEchoResults(outputs)
	}
}

// outputDebugResults outputs all results as JSON for debugging
func outputDebugResults(outputs map[string]any) {
	outJSONBytes, _ := json.MarshalIndent(outputs, "", constants.JSONIndent)
	utils.User("%s", string(outJSONBytes))
	utils.Info(constants.MsgFlowExecuted)
	utils.Info(constants.MsgStepOutputs, string(outJSONBytes))
}

// outputEchoResults outputs all step results for normal operation
func outputEchoResults(outputs map[string]any) {
	// Track what we've already output to avoid duplicates
	displayed := make(map[string]bool)

	// Output step results in a clean, user-friendly format
	for stepID, stepOutput := range outputs {
		if stepOutput == nil || displayed[stepID] {
			continue
		}

		// Try different output format handlers in order
		if outputHandled := tryOutputSpecificFormats(stepID, stepOutput, displayed); outputHandled {
			continue
		}

		// Fallback: show compact JSON for anything else
		outputFallbackJSON(stepID, stepOutput, displayed)
	}
}

// tryOutputSpecificFormats attempts to handle known output formats
func tryOutputSpecificFormats(stepID string, stepOutput any, displayed map[string]bool) bool {
	outMap, ok := stepOutput.(map[string]any)
	if !ok {
		return false
	}

	// Try each specific format handler
	if tryOutputEchoText(stepID, outMap, displayed) {
		return true
	}
	if tryOutputOpenAIResponse(stepID, outMap, displayed) {
		return true
	}
	if tryOutputMCPResponse(stepID, outMap, displayed) {
		return true
	}
	if tryOutputHTTPResponse(stepID, outMap, displayed) {
		return true
	}
	if tryOutputParallelResults(stepID, outMap, displayed) {
		return true
	}

	return false
}

// tryOutputEchoText handles core.echo outputs - just show the text
func tryOutputEchoText(stepID string, outMap map[string]any, displayed map[string]bool) bool {
	if text, ok := outMap[constants.OutputKeyText]; ok {
		utils.User("%s", text)
		displayed[stepID] = true
		return true
	}
	return false
}

// tryOutputOpenAIResponse handles OpenAI chat completions - extract the message content
func tryOutputOpenAIResponse(stepID string, outMap map[string]any, displayed map[string]bool) bool {
	choices, ok := outMap[constants.OutputKeyChoices].([]interface{})
	if !ok || len(choices) == 0 {
		return false
	}

	choice, ok := choices[0].(map[string]any)
	if !ok {
		return false
	}

	message, ok := choice[constants.OutputKeyMessage].(map[string]any)
	if !ok {
		return false
	}

	content, ok := message[constants.OutputKeyContent].(string)
	if !ok {
		return false
	}

	utils.User(constants.OutputPrefixAI+"%s: %s", stepID, content)
	displayed[stepID] = true
	return true
}

// tryOutputMCPResponse handles MCP responses with content array - extract text
func tryOutputMCPResponse(stepID string, outMap map[string]any, displayed map[string]bool) bool {
	content, ok := outMap[constants.OutputKeyContent].([]interface{})
	if !ok || len(content) == 0 {
		return false
	}

	contentItem, ok := content[0].(map[string]any)
	if !ok {
		return false
	}

	text, ok := contentItem[constants.OutputKeyText].(string)
	if !ok {
		return false
	}

	utils.User(constants.OutputPrefixMCP+"%s: %s", stepID, text)
	displayed[stepID] = true
	return true
}

// tryOutputHTTPResponse handles HTTP fetch responses - show just the body preview
func tryOutputHTTPResponse(stepID string, outMap map[string]any, displayed map[string]bool) bool {
	body, ok := outMap[constants.OutputKeyBody].(string)
	if !ok {
		return false
	}

	preview := body
	if len(preview) > constants.OutputPreviewLimit {
		preview = preview[:constants.OutputPreviewLimit] + constants.OutputTruncationSuffix
	}

	utils.User(constants.OutputPrefixHTTP+"%s: %s", stepID, preview)
	displayed[stepID] = true
	return true
}

// tryOutputParallelResults handles parallel step outputs - extract individual step results
func tryOutputParallelResults(stepID string, outMap map[string]any, displayed map[string]bool) bool {
	foundParallelOutputs := false

	for subStepID, subOutput := range outMap {
		if displayed[subStepID] {
			continue
		}

		if handleParallelSubstep(subStepID, subOutput, displayed) {
			foundParallelOutputs = true
		}
	}

	if foundParallelOutputs {
		displayed[stepID] = true
		return true
	}

	return false
}

// handleParallelSubstep processes individual parallel substeps
func handleParallelSubstep(subStepID string, subOutput any, displayed map[string]bool) bool {
	subOutputMap, ok := subOutput.(map[string]any)
	if !ok {
		return false
	}

	// Check if this looks like an OpenAI response
	return tryOutputOpenAIResponse(subStepID, subOutputMap, displayed)
}

// outputFallbackJSON handles fallback JSON output for unrecognized formats
func outputFallbackJSON(stepID string, stepOutput any, displayed map[string]bool) {
	outJSONBytes, err := json.MarshalIndent(stepOutput, "", "  ")
	if err == nil && len(outJSONBytes) < constants.OutputJSONSizeLimit {
		utils.User(constants.OutputPrefixJSON+"%s: %s", stepID, string(outJSONBytes))
	} else {
		utils.User(constants.OutputPrefixJSON+"%s: %s", stepID, constants.OutputTooLargeMessage)
	}
	displayed[stepID] = true
}

// loadEvent loads event data from a file or an inline JSON string.
func loadEvent(path, inline string) (map[string]any, error) {
	var event map[string]any
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		return event, nil
	}
	if inline != "" {
		if err := json.Unmarshal([]byte(inline), &event); err != nil {
			return nil, err
		}
		return event, nil
	}
	// No event provided: return empty event for flows that don't use event data
	return map[string]any{}, nil
}

// ============================================================================
// OAUTH COMMAND
// ============================================================================

func newOAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oauth",
		Short: "Manage OAuth providers and credentials",
		Long:  "Manage OAuth providers and credentials for connecting BeemFlow to external services like Google, Slack, GitHub, etc.",
	}

	cmd.AddCommand(
		newOAuthProvidersCmd(),
		newOAuthCredentialsCmd(),
	)

	return cmd
}

func newOAuthProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "Manage OAuth providers",
		Long:  "Manage OAuth provider configurations (Google, GitHub, Slack, etc.)",
	}

	cmd.AddCommand(
		newOAuthProvidersListCmd(),
		newOAuthProvidersAddCmd(),
		newOAuthProvidersRemoveCmd(),
	)

	return cmd
}

func newOAuthCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Manage OAuth credentials",
		Long:  "Manage OAuth credentials for connecting to external services",
	}

	cmd.AddCommand(
		newOAuthCredentialsListCmd(),
		newOAuthCredentialsAddCmd(),
		newOAuthCredentialsRemoveCmd(),
	)

	return cmd
}

func newOAuthProvidersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured OAuth providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			providers, err := store.ListOAuthProviders(ctx)
			if err != nil {
				return fmt.Errorf("failed to list OAuth providers: %w", err)
			}

			if len(providers) == 0 {
				fmt.Println("No OAuth providers configured")
				return nil
			}

			fmt.Println("Configured OAuth providers:")
			for _, p := range providers {
				fmt.Printf("  %s: %s (%s)\n", p.ID, p.Name, p.AuthURL)
			}

			return nil
		},
	}
}

func newOAuthProvidersAddCmd() *cobra.Command {
	var name, clientID, clientSecret, authURL, tokenURL string

	cmd := &cobra.Command{
		Use:   "add <provider-id>",
		Short: "Add an OAuth provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			providerID := args[0]

			// Validate required fields
			if name == "" || clientID == "" || clientSecret == "" || authURL == "" || tokenURL == "" {
				return fmt.Errorf("all fields are required: --name, --client-id, --client-secret, --auth-url, --token-url")
			}

			provider := &model.OAuthProvider{
				ID:           providerID,
				Name:         name,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				AuthURL:      authURL,
				TokenURL:     tokenURL,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			if err := store.SaveOAuthProvider(ctx, provider); err != nil {
				return fmt.Errorf("failed to save OAuth provider: %w", err)
			}

			fmt.Printf("Added OAuth provider: %s\n", providerID)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Provider display name")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "OAuth client secret")
	cmd.Flags().StringVar(&authURL, "auth-url", "", "OAuth authorization URL")
	cmd.Flags().StringVar(&tokenURL, "token-url", "", "OAuth token URL")

	return cmd
}

func newOAuthProvidersRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <provider-id>",
		Short: "Remove an OAuth provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			providerID := args[0]

			if err := store.DeleteOAuthProvider(ctx, providerID); err != nil {
				return fmt.Errorf("failed to remove OAuth provider: %w", err)
			}

			fmt.Printf("Removed OAuth provider: %s\n", providerID)
			return nil
		},
	}
}

func newOAuthCredentialsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List OAuth credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			creds, err := store.ListOAuthCredentials(ctx)
			if err != nil {
				return fmt.Errorf("failed to list OAuth credentials: %w", err)
			}

			if len(creds) == 0 {
				fmt.Println("No OAuth credentials configured")
				return nil
			}

			fmt.Println("Configured OAuth credentials:")
			for _, c := range creds {
				status := "valid"
				if c.IsExpired() {
					status = "expired"
				}
				fmt.Printf("  %s:%s (%s)\n", c.Provider, c.Integration, status)
			}

			return nil
		},
	}
}

func newOAuthCredentialsAddCmd() *cobra.Command {
	var accessToken, refreshToken string
	var expiresIn int

	cmd := &cobra.Command{
		Use:   "add <provider> <integration>",
		Short: "Add OAuth credentials",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			providerID := args[0]
			integrationID := args[1]

			// Check if provider exists
			providerInfo, err := store.GetOAuthProvider(ctx, providerID)
			if err != nil {
				return fmt.Errorf("OAuth provider '%s' not found. Add it first with 'flow oauth providers add'", providerID)
			}

			var expiresAt *time.Time
			if expiresIn > 0 {
				t := time.Now().Add(time.Duration(expiresIn) * time.Second)
				expiresAt = &t
			}

			cred := &model.OAuthCredential{
				ID:           uuid.New().String(),
				Provider:     providerID,
				Integration:  integrationID,
				AccessToken:  accessToken,
				RefreshToken: &refreshToken,
				ExpiresAt:    expiresAt,
				Scope:        "https://www.googleapis.com/auth/spreadsheets", // Default scope, should be configurable
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			if err := store.SaveOAuthCredential(ctx, cred); err != nil {
				return fmt.Errorf("failed to save OAuth credentials: %w", err)
			}

			fmt.Printf("Added OAuth credentials for %s:%s\n", providerID, integrationID)
			fmt.Printf("Provider: %s (%s)\n", providerInfo.Name, providerInfo.AuthURL)
			return nil
		},
	}

	cmd.Flags().StringVar(&accessToken, "access-token", "", "OAuth access token")
	cmd.Flags().StringVar(&refreshToken, "refresh-token", "", "OAuth refresh token")
	cmd.Flags().IntVar(&expiresIn, "expires-in", 3600, "Token expiration time in seconds")

	_ = cmd.MarkFlagRequired("access-token")
	_ = cmd.MarkFlagRequired("refresh-token")

	return cmd
}

func newOAuthCredentialsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <provider> <integration>",
		Short: "Remove OAuth credentials",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := getStoreFromConfig()
			if err != nil {
				return err
			}

			providerID := args[0]
			integrationID := args[1]

			// Find the credential by provider:integration
			creds, err := store.ListOAuthCredentials(ctx)
			if err != nil {
				return fmt.Errorf("failed to list credentials: %w", err)
			}

			var credID string
			for _, c := range creds {
				if c.Provider == providerID && c.Integration == integrationID {
					credID = c.ID
					break
				}
			}

			if credID == "" {
				return fmt.Errorf("credentials not found for %s:%s", providerID, integrationID)
			}

			if err := store.DeleteOAuthCredential(ctx, credID); err != nil {
				return fmt.Errorf("failed to remove OAuth credentials: %w", err)
			}

			fmt.Printf("Removed OAuth credentials for %s:%s\n", providerID, integrationID)
			return nil
		},
	}
}

// getStoreFromConfig creates a storage instance from the current config
func getStoreFromConfig() (storage.Storage, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return api.GetStoreFromConfig(cfg)
}
