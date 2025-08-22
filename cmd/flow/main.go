package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	// Load environment variables from .env file.
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	_ "github.com/awantoch/beemflow/adapter"
	"github.com/awantoch/beemflow/config"
	"github.com/awantoch/beemflow/constants"
	api "github.com/awantoch/beemflow/core"
	"github.com/awantoch/beemflow/dsl"
	beemhttp "github.com/awantoch/beemflow/http"
	"github.com/awantoch/beemflow/utils"
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

		// Load config JSON to pick up default flowsDir
		cfg, err := config.LoadConfig(configPath)
		if err == nil && cfg.FlowsDir != "" {
			api.SetFlowsDir(cfg.FlowsDir)
		}

		// CLI flag overrides config file
		if flowsDir != "" {
			api.SetFlowsDir(flowsDir)
		}
	}

	// Add all subcommands directly (no more need for CommandConstructors)
	rootCmd.AddCommand(
		newServeCmd(),
		newRunCmd(),
		// MCP commands now handled via operations framework
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

			cfg, err := config.LoadConfig(constants.ConfigFileName)
			if err != nil {
				if os.IsNotExist(err) {
					cfg = &config.Config{}
				} else {
					utils.Error("Failed to load config: %v", err)
					exit(1)
				}
			}
			// Set default storage if not configured
			if cfg.Storage.Driver == "" {
				cfg.Storage.Driver = "sqlite"
				cfg.Storage.DSN = config.DefaultSQLiteDSN
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

	// Use the API service instead of direct engine access
	runID, outputs, err := api.RunSpec(cmd.Context(), flow, event)
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
