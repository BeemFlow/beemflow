package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/beemflow/beemflow/adapter"
	"github.com/beemflow/beemflow/blob"
	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	"github.com/beemflow/beemflow/dsl"
	"github.com/beemflow/beemflow/event"
	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/storage"
	"github.com/beemflow/beemflow/utils"
	"github.com/google/uuid"
)

// Define a custom type for context keys.
type runIDKeyType struct{}

var runIDKey = runIDKeyType{}

// generateDeterministicRunID creates a deterministic UUID based on flow name and event data
// This enables deduplication of runs with identical inputs within a time window
func generateDeterministicRunID(flowName string, event map[string]any) uuid.UUID {
	// Build raw data for UUID v5 generation
	var data []byte
	data = append(data, []byte(flowName)...)

	// Add time window (1 minute buckets) to allow same workflow to run again after window
	now := time.Now().UTC()
	timeBucket := now.Truncate(1 * time.Minute).Unix()
	data = append(data, []byte(fmt.Sprintf(":%d", timeBucket))...)

	// Sort map keys for deterministic ordering
	keys := make([]string, 0, len(event))
	for k := range event {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Add event data in sorted order
	for _, k := range keys {
		data = append(data, []byte(k)...)
		if v, err := json.Marshal(event[k]); err == nil {
			data = append(data, v...)
		} else {
			// Fallback for unmarshalable values
			data = append(data, []byte(fmt.Sprintf("%v", event[k]))...)
		}
	}

	// Generate UUID v5 (deterministic) using SHA1 internally
	// uuid.NewSHA1 will hash the raw data with SHA1
	return uuid.NewSHA1(uuid.NameSpaceDNS, data)
}

// Type aliases for better readability and type safety
type (
	StepInputs  = map[string]any
	StepOutputs = map[string]any
	EventData   = map[string]any
	SecretsData = map[string]any
)

// Result types for better error handling and type safety
type ExecutionResult struct {
	Outputs StepOutputs
	Error   error
}

type StepResult struct {
	StepID  string
	Outputs StepOutputs
	Error   error
}

// Template data structure for type safety
type TemplateData struct {
	Event   EventData
	Vars    map[string]any
	Outputs StepOutputs
	Secrets SecretsData
	Env     map[string]string
	Runs    *RunsAccess // Simple access to run history
}

// RunsAccess provides template access to previous run outputs
type RunsAccess struct {
	storage      storage.Storage
	ctx          context.Context
	currentRunID uuid.UUID
	flowName     string
}

// Previous returns outputs from the most recent previous run of the same workflow
func (r *RunsAccess) Previous() map[string]any {
	runs, err := r.storage.ListRuns(r.ctx)
	if err != nil || len(runs) == 0 {
		return map[string]any{}
	}

	// Find the most recent successful run from the same workflow
	for _, run := range runs {
		// Only consider runs from the same workflow
		if run.FlowName != r.flowName {
			continue
		}

		// Skip the current run
		if r.currentRunID != uuid.Nil && run.ID == r.currentRunID {
			continue
		}

		// Only return successful runs
		if run.Status != model.RunSucceeded {
			continue
		}

		// Get step outputs for this run
		steps, err := r.storage.GetSteps(r.ctx, run.ID)
		if err != nil {
			continue
		}

		// Aggregate step outputs
		outputs := map[string]any{}
		for _, step := range steps {
			if step.Outputs != nil {
				outputs[step.StepName] = step.Outputs
			}
		}

		return map[string]any{
			"id":      run.ID.String(),
			"outputs": outputs,
			"status":  string(run.Status),
			"flow":    run.FlowName,
		}
	}

	return map[string]any{}
}

// validIdentifierRegex matches valid Go-style identifiers
var validIdentifierRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Engine is the core runtime for executing BeemFlow flows. It manages adapters, templating, event bus, and in-memory state.
type Engine struct {
	Adapters  *adapter.Registry
	Templater *dsl.Templater
	EventBus  event.EventBus
	BlobStore blob.BlobStore
	Storage   storage.Storage
	// In-memory state for waiting runs: token -> *PausedRun
	waiting map[string]*PausedRun
	mu      sync.Mutex
	// Store completed outputs for resumed runs (token -> outputs)
	completedOutputs map[string]map[string]any
	// Current execution context (set during Execute)
	currentFlow  *model.Flow
	currentRunID uuid.UUID
	// NOTE: Storage, blob, eventbus, and cron are pluggable; in-memory is the default for now.
	// Call Close() to clean up resources (e.g., MCPAdapter subprocesses) when done.
}

type PausedRun struct {
	Flow    *model.Flow
	StepIdx int
	StepCtx *StepContext
	Outputs map[string]any
	Token   string
	RunID   uuid.UUID
}

// NewDefaultAdapterRegistry creates and returns a default adapter registry with core and registry tools.
//
// - Loads the curated registry (repo-managed, read-only) from registry/index.json.
// - Loads the local registry (user-writable) from config (registries[].path) or .beemflow/registry.json.
// - Merges both, with local entries taking precedence over curated ones.
// - Any tool installed via the CLI is written to the local registry file.
// - This is future-proofed for remote/community registries.
func NewDefaultAdapterRegistry(ctx context.Context) *adapter.Registry {
	reg := adapter.NewRegistry()

	// Register core adapters
	reg.Register(&adapter.CoreAdapter{})
	reg.Register(adapter.NewMCPAdapter())
	reg.Register(&adapter.HTTPAdapter{AdapterID: constants.HTTPAdapterID}) // Unified HTTP adapter

	// Load and merge registry tools
	loadRegistryTools(ctx, reg)

	return reg
}

// loadRegistryTools loads tools from all standard registries using the factory
func loadRegistryTools(ctx context.Context, reg *adapter.Registry) {
	// Load config to get custom registry configuration
	cfg, _ := config.LoadConfig(constants.ConfigFileName)

	// Create standard registry manager using the factory
	factory := registry.NewFactory()
	mgr := factory.CreateStandardManager(ctx, cfg)

	// Load all tools and register HTTP adapters
	if tools, err := mgr.ListAllServers(ctx, registry.ListOptions{}); err == nil {
		utils.Debug("Successfully loaded %d tools from registries", len(tools))
		for _, entry := range tools {
			if entry.Type == "tool" {
				manifest := &registry.ToolManifest{
					Name:        entry.Name,
					Description: entry.Description,
					Kind:        entry.Kind,
					Parameters:  entry.Parameters,
					Endpoint:    entry.Endpoint,
					Method:      entry.Method,
					Headers:     entry.Headers,
				}
				reg.Register(&adapter.HTTPAdapter{AdapterID: entry.Name, ToolManifest: manifest})
				utils.Debug("Registered tool: %s (registry: %s)", entry.Name, entry.Registry)
			}
		}
	} else {
		utils.Warn("Registry loading failed: %v", err)
	}
}

// NewEngineWithBlobStore creates a new Engine with a custom BlobStore.
func NewEngineWithBlobStore(ctx context.Context, blobStore blob.BlobStore) *Engine {
	return &Engine{
		Adapters:         NewDefaultAdapterRegistry(ctx),
		Templater:        dsl.NewTemplater(),
		EventBus:         event.NewInProcEventBus(),
		BlobStore:        blobStore,
		waiting:          make(map[string]*PausedRun),
		completedOutputs: make(map[string]map[string]any),
		Storage:          storage.NewMemoryStorage(),
	}
}

// NewEngine creates a new Engine with all dependencies injected.
func NewEngine(
	adapters *adapter.Registry,
	templater *dsl.Templater,
	eventBus event.EventBus,
	blobStore blob.BlobStore,
	storage storage.Storage,
) *Engine {
	return &Engine{
		Adapters:         adapters,
		Templater:        templater,
		EventBus:         eventBus,
		BlobStore:        blobStore,
		Storage:          storage,
		waiting:          make(map[string]*PausedRun),
		completedOutputs: make(map[string]map[string]any),
	}
}

// Execute now supports pausing and resuming at await_event.
func (e *Engine) Execute(ctx context.Context, flow *model.Flow, event map[string]any) (map[string]any, error) {
	if flow == nil {
		return nil, nil
	}

	// Initialize outputs and handle empty flow as no-op
	outputs := make(map[string]any)
	if len(flow.Steps) == 0 {
		return outputs, nil
	}

	// Setup execution context
	stepCtx, runID := e.setupExecutionContext(ctx, flow, event)

	// Check if this is a duplicate run
	if runID == uuid.Nil {
		// Duplicate detected - return empty outputs and no error to signal successful deduplication
		return map[string]any{}, nil
	}

	// Set current execution context for template access
	e.mu.Lock()
	e.currentFlow = flow
	e.currentRunID = runID
	e.mu.Unlock()

	// Execute the flow steps
	outputs, err := e.executeStepsWithPersistence(ctx, flow, stepCtx, 0, runID)

	// Handle completion and error cases
	return e.finalizeExecution(ctx, flow, event, outputs, err, runID)
}

// setupExecutionContext prepares the execution environment
func (e *Engine) setupExecutionContext(ctx context.Context, flow *model.Flow, event map[string]any) (*StepContext, uuid.UUID) {
	// Collect env secrets and merge with event-supplied secrets
	secretsMap := e.collectSecrets(event)

	// Create step context using the new constructor
	stepCtx := NewStepContext(event, flow.Vars, secretsMap)

	// Create deterministic run ID based on flow name, event data, and time window
	runID := generateDeterministicRunID(flow.Name, event)

	// Check if this run already exists (deduplication)
	existingRun, err := e.Storage.GetRun(ctx, runID)
	if err == nil && existingRun != nil {
		// Run already exists, check if it's recent (within 1 minute)
		if time.Since(existingRun.StartedAt) < 1*time.Minute {
			// This is a duplicate run within the deduplication window
			utils.Info("Duplicate run detected for %s, skipping (existing run: %s)", flow.Name, existingRun.ID)
			return stepCtx, uuid.Nil // Return nil ID to signal duplicate
		}
		// Older run with same ID, generate a new unique ID
		runID = uuid.New()
	}

	run := &model.Run{
		ID:        runID,
		FlowName:  flow.Name,
		Event:     event,
		Vars:      flow.Vars,
		Status:    model.RunRunning,
		StartedAt: time.Now(),
	}

	if err := e.Storage.SaveRun(ctx, run); err != nil {
		utils.ErrorCtx(ctx, "SaveRun failed: %v", "error", err)
	}

	return stepCtx, runID
}

// finalizeExecution handles completion, error cases, and catch blocks
func (e *Engine) finalizeExecution(ctx context.Context, flow *model.Flow, event map[string]any, outputs map[string]any, err error, runID uuid.UUID) (map[string]any, error) {
	// Determine final status
	status := model.RunSucceeded
	if err != nil {
		if strings.Contains(err.Error(), constants.ErrAwaitEventPause) {
			status = model.RunWaiting
		} else {
			status = model.RunFailed
		}
	}

	// Update final run status
	run := &model.Run{
		ID:        runID,
		FlowName:  flow.Name,
		Event:     event,
		Vars:      flow.Vars,
		Status:    status,
		StartedAt: time.Now(),
		EndedAt:   ptrTime(time.Now()),
	}
	if saveErr := e.Storage.SaveRun(ctx, run); saveErr != nil {
		utils.ErrorCtx(ctx, constants.ErrSaveRunFailed, "error", saveErr)
	}

	// Handle catch blocks if there was an error
	if err != nil && len(flow.Catch) > 0 {
		return e.executeCatchBlocks(ctx, flow, event, err)
	}

	return outputs, err
}

// executeCatchBlocks runs catch steps when an error occurs
func (e *Engine) executeCatchBlocks(ctx context.Context, flow *model.Flow, event map[string]any, originalErr error) (map[string]any, error) {
	// Recreate step context for catch blocks
	secretsMap := e.collectSecrets(event)
	stepCtx := NewStepContext(event, flow.Vars, secretsMap)

	// Run catch steps in defined order
	catchOutputs := map[string]any{}
	for _, step := range flow.Catch {
		if execErr := e.executeStep(ctx, &step, stepCtx, step.ID); execErr == nil {
			if output, ok := stepCtx.GetOutput(step.ID); ok {
				catchOutputs[step.ID] = output
			}
		}
	}
	return catchOutputs, originalErr
}

// collectSecrets extracts secrets from event data and environment variables
func (e *Engine) collectSecrets(event map[string]any) SecretsData {
	secretsMap := make(SecretsData)

	// Extract secrets from event using new constant
	if eventSecrets, ok := utils.SafeMapAssert(event[constants.SecretsKey]); ok {
		for k, v := range eventSecrets {
			secretsMap[k] = v
		}
	}

	// Collect environment variables starting with $env prefix
	for k, v := range event {
		if strings.HasPrefix(k, constants.EnvVarPrefix) {
			envVar := strings.TrimPrefix(k, constants.EnvVarPrefix)
			secretsMap[envVar] = v
		}
	}

	return secretsMap
}

// Helper to get pointer to time.Time.
func ptrTime(t time.Time) *time.Time {
	return &t
}

// executeStepsWithPersistence executes steps, persisting each step after execution.
func (e *Engine) executeStepsWithPersistence(ctx context.Context, flow *model.Flow, stepCtx *StepContext, startIdx int, runID uuid.UUID) (map[string]any, error) {
	if runID == uuid.Nil {
		runID = runIDFromContext(ctx)
	}

	// Execute steps sequentially from startIdx
	// Note: Future enhancement could add dependency mapping for more sophisticated
	// parallel execution patterns
	for i := startIdx; i < len(flow.Steps); i++ {
		step := &flow.Steps[i]

		// Handle await_event steps
		if step.AwaitEvent != nil {
			return e.handleAwaitEventStep(ctx, step, flow, stepCtx, i, runID)
		}

		// Execute regular step
		err := e.executeStep(ctx, step, stepCtx, step.ID)

		// Persist the step after execution
		if persistErr := e.persistStepResult(ctx, step, stepCtx, err, runID); persistErr != nil {
			utils.Error(constants.ErrFailedToPersistStep, persistErr)
		}

		if err != nil {
			return stepCtx.Snapshot().Outputs, err
		}
	}

	return stepCtx.Snapshot().Outputs, nil
}

// handleAwaitEventStep processes await_event steps and sets up pause/resume logic
func (e *Engine) handleAwaitEventStep(ctx context.Context, step *model.Step, flow *model.Flow, stepCtx *StepContext, stepIdx int, runID uuid.UUID) (map[string]any, error) {
	// Extract and render token
	token, err := e.extractAndRenderAwaitToken(step, stepCtx)
	if err != nil {
		return nil, err
	}

	// Handle existing paused run with same token
	e.handleExistingPausedRun(ctx, token)

	// Register new paused run
	e.registerPausedRun(ctx, token, flow, stepCtx, stepIdx, runID)

	// Setup event subscription for resume
	e.setupResumeEventSubscription(ctx, token)

	return nil, utils.Errorf(constants.ErrStepWaitingForEvent, step.ID)
}

// extractAndRenderAwaitToken validates and renders the await event token
func (e *Engine) extractAndRenderAwaitToken(step *model.Step, stepCtx *StepContext) (string, error) {
	// Extract token from match configuration
	match := step.AwaitEvent.Match
	tokenRaw, ok := utils.SafeStringAssert(match[constants.MatchKeyToken])
	if !ok || tokenRaw == constants.EmptyString {
		return constants.EmptyString, utils.Errorf(constants.ErrAwaitEventMissingToken)
	}

	// Prepare template data and render token
	data := e.prepareTemplateDataAsMap(stepCtx)
	utils.Debug("About to render template for step %s: data = %#v", step.ID, data)

	renderedToken, err := e.Templater.Render(tokenRaw, data)
	if err != nil {
		return constants.EmptyString, utils.Errorf(constants.ErrFailedToRenderToken, err)
	}

	return renderedToken, nil
}

// setupResumeEventSubscription configures event bus subscription for resume events
func (e *Engine) setupResumeEventSubscription(ctx context.Context, token string) {
	e.EventBus.Subscribe(ctx, constants.EventTopicResumePrefix+token, func(payload any) {
		resumeEvent, ok := payload.(map[string]any)
		if !ok {
			return
		}
		e.Resume(ctx, token, resumeEvent)
	})
}

// handleExistingPausedRun manages cleanup of existing paused runs with the same token
func (e *Engine) handleExistingPausedRun(ctx context.Context, token string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if old, exists := e.waiting[token]; exists {
		if e.Storage != nil {
			if existingRun, err := e.Storage.GetRun(ctx, old.RunID); err == nil {
				existingRun.Status = model.RunSkipped
				existingRun.EndedAt = ptrTime(time.Now())
				if err := e.Storage.SaveRun(ctx, existingRun); err != nil {
					utils.ErrorCtx(ctx, "Failed to mark existing run as skipped: %v", "error", err)
				}
			}
			if err := e.Storage.DeletePausedRun(ctx, token); err != nil {
				utils.ErrorCtx(ctx, constants.ErrFailedToDeletePausedRun, "error", err)
			}
		}
		delete(e.waiting, token)
	}
}

// registerPausedRun stores a new paused run for later resumption
func (e *Engine) registerPausedRun(ctx context.Context, token string, flow *model.Flow, stepCtx *StepContext, stepIdx int, runID uuid.UUID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Register new paused run using snapshot
	snapshot := stepCtx.Snapshot()
	e.waiting[token] = &PausedRun{
		Flow:    flow,
		StepIdx: stepIdx,
		StepCtx: stepCtx,
		Outputs: snapshot.Outputs,
		Token:   token,
		RunID:   runID,
	}

	if e.Storage != nil {
		if err := e.Storage.SavePausedRun(ctx, token, pausedRunToMap(e.waiting[token])); err != nil {
			utils.ErrorCtx(ctx, "Failed to save paused run: %v", "error", err)
		}
	}
}

// persistStepResult saves step execution results to storage
func (e *Engine) persistStepResult(ctx context.Context, step *model.Step, stepCtx *StepContext, execErr error, runID uuid.UUID) error {
	if e.Storage == nil {
		return nil
	}

	var stepOutputs map[string]any
	if output, ok := stepCtx.GetOutput(step.ID); ok {
		if out, ok := output.(map[string]any); ok {
			stepOutputs = out
		}
	}

	status := model.StepSucceeded
	var errorMsg string
	if execErr != nil {
		status = model.StepFailed
		errorMsg = execErr.Error()
	}

	srun := &model.StepRun{
		ID:        uuid.New(),
		RunID:     runID,
		StepName:  step.ID,
		Status:    status,
		StartedAt: time.Now(),
		EndedAt:   ptrTime(time.Now()),
		Outputs:   stepOutputs,
		Error:     errorMsg,
	}

	return e.Storage.SaveStep(ctx, srun)
}

// Resume resumes a paused run with the given token and event.
func (e *Engine) Resume(ctx context.Context, token string, resumeEvent map[string]any) {
	utils.Debug("Resume called for token %s with event: %+v", token, resumeEvent)

	// Retrieve and remove paused run
	paused := e.retrieveAndRemovePausedRun(ctx, token)
	if paused == nil {
		return
	}

	// Prepare context for resumption
	e.prepareResumeContext(paused, resumeEvent)

	// Continue execution and handle results
	e.continueExecutionAndStoreResults(ctx, token, paused)
}

// retrieveAndRemovePausedRun safely gets and removes a paused run
func (e *Engine) retrieveAndRemovePausedRun(ctx context.Context, token string) *PausedRun {
	e.mu.Lock()
	defer e.mu.Unlock()

	paused, ok := e.waiting[token]
	if !ok {
		return nil
	}

	delete(e.waiting, token)
	if e.Storage != nil {
		if err := e.Storage.DeletePausedRun(ctx, token); err != nil {
			utils.ErrorCtx(ctx, constants.ErrFailedToDeletePausedRun, "error", err)
		}
	}

	return paused
}

// prepareResumeContext updates the step context with resume event data
func (e *Engine) prepareResumeContext(paused *PausedRun, resumeEvent map[string]any) {
	// Update event context safely
	for k, v := range resumeEvent {
		paused.StepCtx.SetEvent(k, v)
	}

	// Log outputs map before resume (with safe access)
	utils.Debug("Outputs map before resume for token %s: %+v", paused.Token, paused.StepCtx.Snapshot().Outputs)
}

// continueExecutionAndStoreResults handles execution continuation and result storage
func (e *Engine) continueExecutionAndStoreResults(ctx context.Context, token string, paused *PausedRun) {
	// Continue execution from next step
	ctx = context.WithValue(ctx, runIDKey, paused.RunID)
	outputs, err := e.executeStepsWithPersistence(ctx, paused.Flow, paused.StepCtx, paused.StepIdx+1, paused.RunID)

	// Merge and store results
	allOutputs := e.mergeResumeOutputs(paused, outputs)
	e.storeCompletedOutputs(token, allOutputs)

	// Update storage with final run status
	e.updateRunStatusAfterResume(ctx, paused, err)
}

// mergeResumeOutputs combines outputs from before and after resume
func (e *Engine) mergeResumeOutputs(paused *PausedRun, newOutputs map[string]any) map[string]any {
	snapshot := paused.StepCtx.Snapshot()
	allOutputs := make(map[string]any)
	maps.Copy(allOutputs, snapshot.Outputs)

	// Add new outputs
	if newOutputs != nil {
		maps.Copy(allOutputs, newOutputs)
	} else if len(allOutputs) == 0 {
		// If both are nil/empty, ensure we store at least an empty map
		allOutputs = map[string]any{}
	}

	utils.Debug("Outputs map after resume for token %s: %+v", paused.Token, allOutputs)
	return allOutputs
}

// storeCompletedOutputs safely stores the completed outputs for retrieval
func (e *Engine) storeCompletedOutputs(token string, allOutputs map[string]any) {
	e.mu.Lock()
	e.completedOutputs[token] = allOutputs
	e.mu.Unlock()
}

// updateRunStatusAfterResume updates the run status in storage after resumption
func (e *Engine) updateRunStatusAfterResume(ctx context.Context, paused *PausedRun, err error) {
	if e.Storage == nil {
		return
	}

	status := model.RunSucceeded
	if err != nil {
		status = model.RunFailed
	}

	snapshot := paused.StepCtx.Snapshot()
	run := &model.Run{
		ID:        paused.RunID,
		FlowName:  paused.Flow.Name,
		Event:     snapshot.Event,
		Vars:      snapshot.Vars,
		Status:    status,
		StartedAt: time.Now(),
		EndedAt:   ptrTime(time.Now()),
	}

	if err := e.Storage.SaveRun(ctx, run); err != nil {
		utils.ErrorCtx(ctx, "SaveRun failed: %v", "error", err)
	}
}

// GetCompletedOutputs returns and clears the outputs for a completed resumed run.
func (e *Engine) GetCompletedOutputs(token string) map[string]any {
	utils.Debug("GetCompletedOutputs called for token %s", token)
	e.mu.Lock()
	defer e.mu.Unlock()
	outputs := e.completedOutputs[token]
	utils.Debug("GetCompletedOutputs for token %s returns: %+v", token, outputs)
	delete(e.completedOutputs, token)
	return outputs
}

// executeStep runs a single step (use/with) and stores output.
func (e *Engine) executeStep(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string) error {
	// Check if condition first - skip step if condition is false
	if step.If != "" {
		utils.Debug("Evaluating condition for step %s: %s", stepID, step.If)
		shouldExecute, err := e.evaluateCondition(step.If, stepCtx)
		if err != nil {
			return utils.Errorf("failed to evaluate condition '%s': %w", step.If, err)
		}
		utils.Debug("Condition result for step %s: %v", stepID, shouldExecute)
		if !shouldExecute {
			// Skip this step - condition not met
			utils.Debug("Skipping step %s - condition not met: %s", stepID, step.If)
			return nil
		}
	}

	// Nested parallel block logic
	if step.Parallel && len(step.Steps) > 0 {
		return e.executeParallelBlock(ctx, step, stepCtx, stepID)
	}

	// Sequential block (non-parallel) for steps
	if !step.Parallel && len(step.Steps) > 0 {
		return e.executeSequentialBlock(ctx, step, stepCtx, stepID)
	}

	// Foreach logic: handle steps with Foreach and Do
	if step.Foreach != "" {
		return e.executeForeachBlock(ctx, step, stepCtx, stepID)
	}

	// Tool execution
	return e.executeToolCall(ctx, step, stepCtx, stepID)
}

// executeParallelBlock handles parallel execution of nested steps
func (e *Engine) executeParallelBlock(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(step.Steps))
	outputs := make(map[string]any)
	var outputsMu sync.Mutex // Protect concurrent access to outputs map

	for i := range step.Steps {
		child := &step.Steps[i]
		wg.Add(1)
		go func(child *model.Step) {
			defer wg.Done()
			if err := e.executeStep(ctx, child, stepCtx, child.ID); err != nil {
				errChan <- err
				return
			}
			// Safely get the output using StepContext
			if childOutput, ok := stepCtx.GetOutput(child.ID); ok {
				outputsMu.Lock()
				outputs[child.ID] = childOutput
				outputsMu.Unlock()
			}
		}(child)
	}
	wg.Wait()
	close(errChan)
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	// Store the combined outputs
	stepCtx.SetOutput(stepID, outputs)
	return nil
}

// executeSequentialBlock handles sequential execution of nested steps
func (e *Engine) executeSequentialBlock(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string) error {
	outputs := make(map[string]any)
	for i := range step.Steps {
		child := &step.Steps[i]
		if err := e.executeStep(ctx, child, stepCtx, child.ID); err != nil {
			return err
		}
		childOutput, ok := stepCtx.GetOutput(child.ID)
		if ok {
			outputs[child.ID] = childOutput
		}
	}
	stepCtx.SetOutput(stepID, outputs)
	return nil
}

// executeForeachBlock handles foreach loop execution
func (e *Engine) executeForeachBlock(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string) error {
	// Prepare template data for expression evaluation
	data := e.prepareTemplateDataAsMap(stepCtx)

	// Evaluate the foreach expression to get the actual value (not rendered as string)
	rendered, err := e.Templater.EvaluateExpression(step.Foreach, data)
	if err != nil {
		return utils.Errorf(constants.ErrTemplateErrorForeach, err)
	}

	// The rendered result should be a list - handle different slice types
	var list []any
	switch v := rendered.(type) {
	case []any:
		list = v
	case []map[string]any:
		// Convert []map[string]any to []any
		list = make([]any, len(v))
		for i, item := range v {
			list[i] = item
		}
	case []string:
		// Convert []string to []any
		list = make([]any, len(v))
		for i, item := range v {
			list[i] = item
		}
	default:
		return utils.Errorf(constants.ErrForeachNotList, rendered)
	}

	if len(list) == 0 {
		stepCtx.SetOutput(stepID, make(map[string]any))
		return nil
	}

	if step.Parallel {
		return e.executeForeachParallel(ctx, step, stepCtx, stepID, list)
	}
	return e.executeForeachSequential(ctx, step, stepCtx, stepID, list)
}

// executeForeachParallel handles parallel foreach execution
func (e *Engine) executeForeachParallel(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string, list []any) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(list))

	// Process each item in parallel
	for index, item := range list {
		wg.Add(1)
		go e.processParallelForeachItem(ctx, step, stepCtx, item, index, &wg, errChan)
	}

	// Wait for all goroutines and collect errors
	return e.collectParallelErrors(&wg, errChan, stepCtx, stepID)
}

// processParallelForeachItem processes a single item in a parallel foreach loop
func (e *Engine) processParallelForeachItem(ctx context.Context, step *model.Step, stepCtx *StepContext, item any, index int, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	// Create iteration context for this item
	iterStepCtx := e.createIterationContext(stepCtx, step.As, item, index)

	// Execute all steps for this iteration
	if err := e.executeIterationSteps(ctx, step.Do, iterStepCtx, stepCtx); err != nil {
		errChan <- err
	}
}

// executeIterationSteps executes all steps for a single foreach iteration
func (e *Engine) executeIterationSteps(ctx context.Context, steps []model.Step, iterStepCtx, mainStepCtx *StepContext) error {
	for _, inner := range steps {
		// Create a copy to avoid race conditions
		innerCopy := inner

		// Render the step ID as a template
		renderedStepID, err := e.renderStepID(inner.ID, iterStepCtx)
		if err != nil {
			return err
		}

		// Execute the step with iteration context
		if err := e.executeStep(ctx, &innerCopy, iterStepCtx, renderedStepID); err != nil {
			return err
		}

		// Copy outputs back to main context
		e.copyIterationOutput(iterStepCtx, mainStepCtx, renderedStepID)
	}
	return nil
}

// renderStepID renders a step ID with templating support
func (e *Engine) renderStepID(stepID string, stepCtx *StepContext) (string, error) {
	data := e.prepareTemplateDataAsMap(stepCtx)
	rendered, err := e.renderValue(stepID, data)
	if err != nil {
		return constants.EmptyString, utils.Errorf(constants.ErrTemplateErrorStepID, stepID, err)
	}

	renderedStr, ok := utils.SafeStringAssert(rendered)
	if !ok {
		return stepID, nil // fallback to original stepID if not a string
	}
	return renderedStr, nil
}

// copyIterationOutput safely copies output from iteration context to main context
func (e *Engine) copyIterationOutput(iterStepCtx, mainStepCtx *StepContext, renderedStepID string) {
	if output, ok := iterStepCtx.GetOutput(renderedStepID); ok {
		mainStepCtx.SetOutput(renderedStepID, output)
	}
}

// collectParallelErrors waits for parallel operations and collects any errors
func (e *Engine) collectParallelErrors(wg *sync.WaitGroup, errChan chan error, stepCtx *StepContext, stepID string) error {
	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	// Set output if stepID is non-empty
	if stepID != "" {
		stepCtx.SetOutput(stepID, make(map[string]any))
	}
	return nil
}

// executeForeachSequential handles sequential foreach execution
func (e *Engine) executeForeachSequential(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string, list []any) error {
	for index, item := range list {
		// Set the loop variable for this iteration
		if step.As != "" {
			stepCtx.SetVar(step.As, item)
			// Also expose the index (0-based)
			stepCtx.SetVar(step.As+"_index", index)
			// And 1-based index for row numbers
			stepCtx.SetVar(step.As+"_row", index+1)
		}

		// Execute all steps for this iteration
		if err := e.executeSequentialIterationSteps(ctx, step.Do, stepCtx); err != nil {
			return err
		}
	}

	// Set output if stepID is non-empty
	if stepID != "" {
		stepCtx.SetOutput(stepID, make(map[string]any))
	}
	return nil
}

// executeSequentialIterationSteps executes all steps for a single sequential foreach iteration
func (e *Engine) executeSequentialIterationSteps(ctx context.Context, steps []model.Step, stepCtx *StepContext) error {
	for _, inner := range steps {
		// Render the step ID as a template
		renderedStepID, err := e.renderStepID(inner.ID, stepCtx)
		if err != nil {
			return err
		}

		// Execute the step
		if err := e.executeStep(ctx, &inner, stepCtx, renderedStepID); err != nil {
			return err
		}
	}
	return nil
}

// executeToolCall handles individual tool execution
func (e *Engine) executeToolCall(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string) error {
	if step.Use == "" {
		return nil
	}

	// Resolve the appropriate adapter for this tool
	adapterInst, err := e.resolveAdapter(step.Use, stepCtx, stepID)
	if err != nil {
		return err
	}

	// Prepare inputs and execute the tool
	return e.executeToolWithInputs(ctx, step, stepCtx, stepID, adapterInst)
}

// resolveAdapter finds and returns the appropriate adapter for a tool
func (e *Engine) resolveAdapter(toolName string, stepCtx *StepContext, stepID string) (adapter.Adapter, error) {
	adapterInst, ok := e.Adapters.Get(toolName)
	if !ok {
		switch {
		case strings.HasPrefix(toolName, constants.AdapterPrefixMCP):
			adapterInst, ok = e.Adapters.Get(constants.AdapterIDMCP)
			if !ok {
				return nil, setEmptyOutputAndError(stepCtx, stepID, constants.ErrMCPAdapterNotRegistered)
			}
		case strings.HasPrefix(toolName, constants.AdapterPrefixCore):
			adapterInst, ok = e.Adapters.Get(constants.AdapterIDCore)
			if !ok {
				return nil, setEmptyOutputAndError(stepCtx, stepID, constants.ErrCoreAdapterNotRegistered)
			}
		default:
			return nil, setEmptyOutputAndError(stepCtx, stepID, constants.ErrAdapterNotFound, toolName)
		}
	}
	return adapterInst, nil
}

// executeToolWithInputs prepares inputs and executes the tool
func (e *Engine) executeToolWithInputs(ctx context.Context, step *model.Step, stepCtx *StepContext, stepID string, adapterInst adapter.Adapter) error {
	// Prepare inputs for the tool
	inputs, err := e.prepareToolInputs(step, stepCtx, stepID)
	if err != nil {
		return err
	}

	// Auto-fill missing required parameters from manifest defaults
	e.autoFillRequiredParams(adapterInst, inputs, stepCtx)

	// Add special use parameter for specific tool types
	e.addSpecialUseParameter(step.Use, inputs)

	// Execute the tool and handle results
	return e.handleToolExecution(ctx, step.Use, stepID, stepCtx, adapterInst, inputs)
}

// addSpecialUseParameter adds the __use parameter for MCP and core tools
func (e *Engine) addSpecialUseParameter(toolName string, inputs map[string]any) {
	if strings.HasPrefix(toolName, constants.AdapterPrefixMCP) || strings.HasPrefix(toolName, constants.AdapterPrefixCore) {
		inputs[constants.ParamSpecialUse] = toolName
	}
}

// handleToolExecution executes the tool and processes outputs
func (e *Engine) handleToolExecution(ctx context.Context, toolName, stepID string, stepCtx *StepContext, adapterInst adapter.Adapter, inputs map[string]any) error {
	// Log payload for debugging using our helper
	logToolPayload(ctx, toolName, inputs)

	// Execute the tool
	outputs, err := adapterInst.Execute(ctx, inputs)
	if err != nil {
		stepCtx.SetOutput(stepID, outputs)
		return utils.Errorf(constants.ErrStepFailed, stepID, err)
	}

	// Store outputs and log success using our helper
	stepCtx.SetOutput(stepID, outputs)
	logToolOutputs(stepID, outputs)
	return nil
}

// prepareTemplateData creates template data from step context
func (e *Engine) prepareTemplateData(stepCtx *StepContext) TemplateData {
	snapshot := stepCtx.Snapshot()

	// Get environment variables but with lazy loading for security
	// We create a proxy map that loads values on demand
	env := createEnvProxy()

	// Get current execution context
	e.mu.Lock()
	currentFlow := e.currentFlow
	currentRunID := e.currentRunID
	e.mu.Unlock()

	flowName := ""
	if currentFlow != nil {
		flowName = currentFlow.Name
	}

	return TemplateData{
		Event:   snapshot.Event,
		Vars:    snapshot.Vars,
		Outputs: snapshot.Outputs,
		Secrets: snapshot.Secrets,
		Env:     env,
		Runs: &RunsAccess{
			storage:      e.Storage,
			ctx:          context.Background(),
			currentRunID: currentRunID,
			flowName:     flowName,
		},
	}
}

// createEnvProxy creates a map that loads environment variables on demand
// This is more secure as it only exposes variables that are explicitly accessed
func createEnvProxy() map[string]string {
	// TODO: Future improvement - scan templates for {{ env.VARNAME }} patterns
	// and only load those specific environment variables. This would prevent
	// any potential information leakage through template introspection.
	// For now, we load all env vars as users control their own environment.
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			env[pair[0]] = pair[1]
		}
	}
	return env
}

// prepareTemplateDataAsMap creates template data as map for templating system
func (e *Engine) prepareTemplateDataAsMap(stepCtx *StepContext) map[string]any {
	templateData := e.prepareTemplateData(stepCtx)
	return flattenTemplateDataToMap(templateData)
}

// isValidIdentifier checks if a string is a valid template identifier
// Valid identifiers are Go-style identifiers without template syntax
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}

	// Check for template syntax that would make this an invalid identifier
	if strings.Contains(s, "{{") || strings.Contains(s, "}}") ||
		strings.Contains(s, "{%") || strings.Contains(s, "%}") {
		return false
	}

	// Use regex for simple, clear validation
	return validIdentifierRegex.MatchString(s)
}

// evaluateCondition evaluates a condition expression and returns whether it's true
func (e *Engine) evaluateCondition(condition string, stepCtx *StepContext) (bool, error) {
	// Condition MUST be in {{ }} format
	trimmed := strings.TrimSpace(condition)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
		return false, utils.Errorf("condition must use template syntax: {{ expression }}, got: %s", condition)
	}

	// Extract the inner expression
	innerExpr := strings.TrimSpace(trimmed[2 : len(trimmed)-2])

	// Prepare template data
	data := e.prepareTemplateDataAsMap(stepCtx)

	// Use {% if %} to evaluate as boolean
	wrappedCondition := fmt.Sprintf("{%% if %s %%}true{%% else %%}false{%% endif %%}", innerExpr)

	// Render and return result
	rendered, err := e.Templater.Render(wrappedCondition, data)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(rendered) == "true", nil
}

// createIterationContext creates a new context for foreach iterations
func (e *Engine) createIterationContext(stepCtx *StepContext, asVar string, item any, index int) *StepContext {
	snapshot := stepCtx.Snapshot()
	iterStepCtx := NewStepContext(snapshot.Event, snapshot.Vars, snapshot.Secrets)

	// Copy existing outputs
	for k, v := range snapshot.Outputs {
		iterStepCtx.SetOutput(k, v)
	}

	// Set the loop variable to the current item
	if asVar != "" {
		iterStepCtx.SetVar(asVar, item)
		// Also expose the index (0-based)
		iterStepCtx.SetVar(asVar+"_index", index)
		// And 1-based index for row numbers
		iterStepCtx.SetVar(asVar+"_row", index+1)
	}

	return iterStepCtx
}

// prepareToolInputs prepares inputs for tool execution
func (e *Engine) prepareToolInputs(step *model.Step, stepCtx *StepContext, stepID string) (map[string]any, error) {
	data := e.prepareTemplateDataAsMap(stepCtx)
	inputs := make(map[string]any)

	// Log debug information for template context
	e.logTemplateDebugInfo(data, stepID)

	// Render each input parameter
	for k, v := range step.With {
		rendered, err := e.renderValue(v, data)
		if err != nil {
			return nil, utils.Errorf(constants.ErrTemplateError, stepID, err)
		}
		inputs[k] = rendered
	}

	return inputs, nil
}

// logTemplateDebugInfo logs debug information about template context
func (e *Engine) logTemplateDebugInfo(data map[string]any, stepID string) {
	varsKeys := extractVarsKeysForDebug(data)
	utils.Debug("Template context keys: %v, vars keys: %v, vars: %+v",
		mapKeys(data), varsKeys, data[constants.TemplateFieldVars])
	utils.Debug("About to render template for step %s: data = %#v", stepID, data)
}

// autoFillRequiredParams fills missing required parameters from manifest defaults
func (e *Engine) autoFillRequiredParams(adapterInst adapter.Adapter, inputs map[string]any, stepCtx *StepContext) {
	manifest := adapterInst.Manifest()
	if manifest == nil {
		return
	}

	params, required := e.extractManifestParameters(manifest)
	if params == nil || required == nil {
		return
	}

	secrets := stepCtx.Snapshot().Secrets
	e.fillMissingRequiredParameters(inputs, params, required, secrets)
}

// extractManifestParameters extracts parameters and required fields from adapter manifest
func (e *Engine) extractManifestParameters(manifest *registry.ToolManifest) (map[string]any, []any) {
	params, ok := utils.SafeMapAssert(manifest.Parameters[constants.DefaultKeyProperties])
	if !ok {
		return nil, nil
	}

	required, ok := utils.SafeSliceAssert(manifest.Parameters[constants.DefaultKeyRequired])
	if !ok {
		return nil, nil
	}

	return params, required
}

// fillMissingRequiredParameters iterates through required parameters and fills missing ones
func (e *Engine) fillMissingRequiredParameters(inputs, params map[string]any, required []any, secrets SecretsData) {
	for _, req := range required {
		key, ok := utils.SafeStringAssert(req)
		if !ok {
			continue
		}

		if _, present := inputs[key]; !present {
			if defaultValue := e.resolveParameterDefault(params[key], secrets); defaultValue != nil {
				inputs[key] = defaultValue
			}
		}
	}
}

// resolveParameterDefault resolves default value from parameter definition and secrets
func (e *Engine) resolveParameterDefault(paramDef any, secrets SecretsData) any {
	prop, ok := utils.SafeMapAssert(paramDef)
	if !ok {
		return nil
	}

	def, ok := utils.SafeMapAssert(prop[constants.DefaultKeyDefault])
	if !ok {
		return nil
	}

	envVar, ok := utils.SafeStringAssert(def[constants.EnvVarPrefix])
	if !ok {
		return nil
	}

	if val, ok := secrets[envVar]; ok {
		return val
	}

	return nil
}

// StepContext holds context for step execution (event, vars, outputs, secrets).
type StepContext struct {
	mu      sync.RWMutex
	Event   EventData
	Vars    map[string]any
	Outputs StepOutputs
	Secrets SecretsData
}

// ContextSnapshot returns immutable copies of all context data
type ContextSnapshot struct {
	Event   EventData
	Vars    map[string]any
	Outputs StepOutputs
	Secrets SecretsData
}

// NewStepContext creates a new StepContext with the provided data
func NewStepContext(event EventData, vars map[string]any, secrets SecretsData) *StepContext {
	return &StepContext{
		Event:   copyMap(event),
		Vars:    copyMap(vars),
		Outputs: make(StepOutputs),
		Secrets: copyMap(secrets),
	}
}

// GetOutput retrieves a stored step output in a thread-safe manner.
func (sc *StepContext) GetOutput(key string) (any, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	val, ok := sc.Outputs[key]
	return val, ok
}

// SetOutput stores a step output in a thread-safe manner.
func (sc *StepContext) SetOutput(key string, val any) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Outputs[key] = val
}

// SetEvent stores a value in the Event map in a thread-safe manner.
func (sc *StepContext) SetEvent(key string, val any) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Event[key] = val
}

// SetVar stores a value in the Vars map in a thread-safe manner.
func (sc *StepContext) SetVar(key string, val any) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Vars[key] = val
}

// SetSecret stores a value in the Secrets map in a thread-safe manner.
func (sc *StepContext) SetSecret(key string, val any) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Secrets[key] = val
}

// Snapshot returns a complete snapshot of the context in a thread-safe manner
func (sc *StepContext) Snapshot() ContextSnapshot {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return ContextSnapshot{
		Event:   copyMap(sc.Event),
		Vars:    copyMap(sc.Vars),
		Outputs: copyMap(sc.Outputs),
		Secrets: copyMap(sc.Secrets),
	}
}

// CronScheduler is a stub for cron-based triggers.
type CronScheduler struct {
	// Extend this struct to support cron-based triggers (see SPEC.md for ideas).
}

func NewCronScheduler() *CronScheduler {
	return &CronScheduler{}
}

// Close cleans up all adapters and resources managed by the Engine.
func (e *Engine) Close() error {
	if e.Adapters != nil {
		return e.Adapters.CloseAll()
	}
	return nil
}

// Helper to convert PausedRun to map[string]any for storage.
func pausedRunToMap(pr *PausedRun) map[string]any {
	return map[string]any{
		constants.PausedRunKeyFlow:    pr.Flow,
		constants.PausedRunKeyStepIdx: pr.StepIdx,
		constants.PausedRunKeyStepCtx: pr.StepCtx,
		constants.PausedRunKeyOutputs: pr.Outputs,
		constants.PausedRunKeyToken:   pr.Token,
		constants.PausedRunKeyRunID:   pr.RunID.String(),
	}
}

// Add a helper to extract runID from context (or use a global if needed).
func runIDFromContext(ctx context.Context) uuid.UUID {
	if v := ctx.Value(runIDKey); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id
		}
	}
	return uuid.Nil
}

// ListRuns returns all runs, using storage if available, otherwise in-memory.
func (e *Engine) ListRuns(ctx context.Context) ([]*model.Run, error) {
	return e.Storage.ListRuns(ctx)
}

// GetRunByID returns a run by ID, using storage if available.
func (e *Engine) GetRunByID(ctx context.Context, id uuid.UUID) (*model.Run, error) {
	run, err := e.Storage.GetRun(ctx, id)
	if err != nil {
		return nil, err
	}
	steps, err := e.Storage.GetSteps(ctx, id)
	if err == nil {
		var persisted []model.StepRun
		for _, s := range steps {
			persisted = append(persisted, *s)
		}
		run.Steps = persisted
	}
	return run, nil
}

// ListMCPServers returns all MCP servers from the registry, using the provided context.
type MCPServerWithName struct {
	Name   string
	Config *config.MCPServerConfig
}

func (e *Engine) ListMCPServers(ctx context.Context) ([]*MCPServerWithName, error) {
	// Load tools from registry
	tools, err := e.loadRegistryTools(ctx)
	if err != nil {
		return nil, err
	}

	// Filter and convert MCP tools to server configs
	return e.convertToMCPServers(tools), nil
}

// loadRegistryTools loads all tools from the registry
func (e *Engine) loadRegistryTools(ctx context.Context) ([]registry.RegistryEntry, error) {
	localReg := registry.NewLocalRegistry("")
	regMgr := registry.NewRegistryManager(localReg)
	return regMgr.ListAllServers(ctx, registry.ListOptions{})
}

// convertToMCPServers filters and converts registry entries to MCP server configs
func (e *Engine) convertToMCPServers(tools []registry.RegistryEntry) []*MCPServerWithName {
	var mcps []*MCPServerWithName
	for _, entry := range tools {
		if strings.HasPrefix(entry.Name, constants.AdapterPrefixMCP) {
			mcps = append(mcps, e.createMCPServerConfig(entry))
		}
	}
	return mcps
}

// createMCPServerConfig creates an MCP server configuration from a registry entry
func (e *Engine) createMCPServerConfig(entry registry.RegistryEntry) *MCPServerWithName {
	return &MCPServerWithName{
		Name: entry.Name,
		Config: &config.MCPServerConfig{
			Command:   entry.Command,
			Args:      entry.Args,
			Env:       entry.Env,
			Port:      entry.Port,
			Transport: entry.Transport,
			Endpoint:  entry.Endpoint,
		},
	}
}

// renderValue recursively renders template strings in nested values.
func (e *Engine) renderValue(val any, data map[string]any) (any, error) {
	switch x := val.(type) {
	case string:
		return e.Templater.Render(x, data)
	case []any:
		// Create a copy to avoid race conditions
		result := make([]any, len(x))
		for i, elem := range x {
			rendered, err := e.renderValue(elem, data)
			if err != nil {
				return nil, err
			}
			result[i] = rendered
		}
		return result, nil
	case map[string]any:
		// Create a copy to avoid race conditions
		result := make(map[string]any, len(x))
		for k, elem := range x {
			rendered, err := e.renderValue(elem, data)
			if err != nil {
				return nil, err
			}
			result[k] = rendered
		}
		return result, nil
	default:
		return val, nil
	}
}

// NewDefaultEngine creates a new Engine with default dependencies (adapter registry, templater, in-process event bus, default blob store, in-memory storage).
func NewDefaultEngine(ctx context.Context) *Engine {
	// Default BlobStore
	bs, err := blob.NewDefaultBlobStore(ctx, nil)
	if err != nil {
		utils.WarnCtx(ctx, "Failed to create default blob store: %v, using nil fallback", "error", err)
		bs = nil
	}
	return NewEngine(
		NewDefaultAdapterRegistry(ctx),
		dsl.NewTemplater(),
		event.NewInProcEventBus(),
		bs,
		storage.NewMemoryStorage(),
	)
}

// copyMap creates a shallow copy of a map[string]any.
func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// =============================================================================
// BEAUTIFICATION HELPERS
// =============================================================================

// setEmptyOutputAndError sets an empty output for a step and returns an error
// This helper eliminates repetitive error handling patterns throughout the engine
func setEmptyOutputAndError(stepCtx *StepContext, stepID, errMsg string, args ...any) error {
	stepCtx.SetOutput(stepID, make(map[string]any))
	return utils.Errorf(errMsg, args...)
}

// logToolPayload logs the tool payload for debugging, handling marshal errors gracefully
// It masks sensitive fields to prevent secret exposure in logs
func logToolPayload(ctx context.Context, toolName string, inputs map[string]any) {
	// Create a copy and mask sensitive fields
	masked := maskSensitiveFields(inputs)

	result := utils.MarshalJSON(masked)
	if result.Err == nil {
		utils.Debug("tool %s payload: %s", toolName, result.Data)
	} else {
		utils.ErrorCtx(ctx, "Failed to marshal tool inputs: %v", "error", result.Err)
	}
}

// maskSensitiveFields creates a copy of the input map with sensitive values masked
func maskSensitiveFields(inputs map[string]any) map[string]any {
	masked := make(map[string]any)

	for k, v := range inputs {
		// Check if this is a sensitive field
		if isSensitiveField(k) {
			// Mask the value but show it exists
			if str, ok := v.(string); ok && len(str) > 0 {
				masked[k] = "***MASKED***"
			} else if m, ok := v.(map[string]any); ok {
				// Recursively mask nested maps (like headers)
				masked[k] = maskSensitiveFields(m)
			} else {
				masked[k] = "***MASKED***"
			}
		} else if m, ok := v.(map[string]any); ok {
			// Recursively check nested maps
			masked[k] = maskSensitiveFields(m)
		} else {
			// Keep non-sensitive values as-is
			masked[k] = v
		}
	}

	return masked
}

// isSensitiveField checks if a field name indicates sensitive data
func isSensitiveField(fieldName string) bool {
	lower := strings.ToLower(fieldName)

	// List of sensitive field patterns
	sensitivePatterns := []string{
		"authorization",
		"auth",
		"token",
		"key",
		"secret",
		"password",
		"pwd",
		"api_key",
		"apikey",
		"access_token",
		"refresh_token",
		"bearer",
		"credential",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// logToolOutputs logs tool execution outputs for debugging
func logToolOutputs(stepID string, outputs map[string]any) {
	// Mask sensitive fields in outputs too
	masked := maskSensitiveFields(outputs)
	utils.Debug("Writing outputs for step %s: %+v", stepID, masked)
	utils.Debug("Outputs map after step %s: %+v", stepID, masked)
}

// flattenTemplateDataToMap creates a flattened map for template rendering
// This encapsulates complex template data preparation logic
func flattenTemplateDataToMap(templateData TemplateData) map[string]any {
	data := make(map[string]any)

	// Set structured template fields
	data[constants.TemplateFieldEvent] = templateData.Event
	data[constants.TemplateFieldVars] = templateData.Vars
	data[constants.TemplateFieldOutputs] = templateData.Outputs
	data[constants.TemplateFieldSecrets] = templateData.Secrets
	data[constants.TemplateFieldSteps] = templateData.Outputs // Add steps namespace for step output access
	data[constants.TemplateFieldEnv] = templateData.Env
	data["runs"] = templateData.Runs // Add runs access for history

	// Flatten vars and event into context for template rendering
	for k, v := range templateData.Vars {
		data[k] = v
	}
	for k, v := range templateData.Event {
		data[k] = v // For foreach expressions like {{list}}
	}

	// Only flatten outputs that have valid identifier names (no template syntax)
	for k, v := range templateData.Outputs {
		if isValidIdentifier(k) {
			data[k] = v
		}
	}

	return data
}

// extractVarsKeysForDebug extracts variable keys for debug logging
func extractVarsKeysForDebug(data map[string]any) []string {
	varsKeys := []string{}
	if vars, ok := data[constants.TemplateFieldVars].(map[string]any); ok {
		for key := range vars {
			varsKeys = append(varsKeys, key)
		}
	}
	return varsKeys
}

// mapKeys returns all keys from a map for debug logging
func mapKeys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
