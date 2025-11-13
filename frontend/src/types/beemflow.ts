// TypeScript types matching Rust models from src/model.rs

export type FlowName = string;
export type StepId = string;
export type ResumeToken = string;
export type RunId = string;

export type Trigger = string | string[];

// Generic JSON value type for dynamic flow data
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface Flow {
  name: FlowName;
  description?: string;
  version?: string;
  on: Trigger;
  cron?: string;
  vars?: Record<string, JsonValue>;
  steps: Step[];
  catch?: Step[];
}

export interface Step {
  id: StepId;
  use?: string;
  with?: Record<string, JsonValue>;
  if?: string;
  depends_on?: StepId[];
  parallel?: boolean;
  steps?: Step[];
  await_event?: AwaitEvent;
  foreach?: string;
  as?: string;
  do?: Step[];
  retry?: RetryConfig;
  timeout?: string;
}

export interface AwaitEvent {
  source: string;
  match?: Record<string, JsonValue>;
  timeout?: string;
}

export interface RetryConfig {
  max_attempts: number;
  backoff?: 'fixed' | 'exponential';
  initial_delay?: string;
  max_delay?: string;
}

export type RunStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'awaiting_event'
  | 'cancelled';

export interface Run {
  id: RunId;
  flow_name: FlowName;
  flow_version?: string;
  status: RunStatus;
  started_at: string; // ISO 8601
  completed_at?: string;
  error?: string;
  step_outputs?: Record<StepId, JsonValue>;
  current_step?: StepId;
  resume_token?: ResumeToken;
  event_source?: string;
  event_match?: Record<string, JsonValue>;
  vars?: Record<string, JsonValue>;
  context?: Record<string, JsonValue>;
}

export interface StepExecution {
  step_id: StepId;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  output?: JsonValue;
  error?: string;
}

export interface RegistryEntry {
  type: string; // 'tool', 'mcp_server', 'oauth_provider'
  name: string;
  display_name?: string;
  icon?: string;
  description?: string;
  kind?: string;
  version?: string;
  registry?: string;
  parameters?: JsonSchema;
  endpoint?: string;
  method?: string;
  headers?: Record<string, string>;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  transport?: string;
  port?: number;
}

// Legacy Tool interface - keeping for backwards compatibility
export interface Tool {
  type: 'tool';
  name: string;
  description?: string;
  parameters?: JsonSchema;
  endpoint?: string;
  method?: string;
  headers?: Record<string, string>;
}

export interface JsonSchema {
  type: string;
  required?: string[];
  properties?: Record<string, JsonSchemaProperty>;
  // Allow additional JSON Schema properties
  items?: JsonSchema | JsonSchema[];
  additionalProperties?: boolean | JsonSchema;
  enum?: JsonValue[];
  const?: JsonValue;
  allOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  not?: JsonSchema;
  $ref?: string;
  $id?: string;
  $schema?: string;
  title?: string;
  description?: string;
  default?: JsonValue;
  examples?: JsonValue[];
}

export interface JsonSchemaProperty {
  type: string;
  description?: string;
  enum?: string[];
  default?: JsonValue;
  // Allow additional JSON Schema property attributes
  items?: JsonSchema | JsonSchema[];
  properties?: Record<string, JsonSchemaProperty>;
  additionalProperties?: boolean | JsonSchemaProperty;
  required?: string[];
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
}

export interface McpServer {
  name: string;
  description?: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface DashboardStats {
  total_flows: number;
  total_runs: number;
  active_runs: number;
  awaiting_events: number;
  success_rate: number;
  recent_activity: Array<{
    timestamp: string;
    flow_name: string;
    status: RunStatus;
  }>;
}

export interface OAuthProvider {
  id: string;
  name: string;
  icon?: string;
  scopes: Array<{
    scope: string;
    description?: string;
  }>;
  connected: boolean;
}

export interface FlowListItem {
  name: FlowName;
  description?: string;
  version?: string;
  trigger: Trigger;
  last_run?: {
    status: RunStatus;
    timestamp: string;
  };
  created_at?: string;
  updated_at?: string;
}

export interface RunListItem {
  id: RunId;
  flow_name: FlowName;
  status: RunStatus;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  error?: string;
}

// API Request/Response types
export interface StartRunRequest {
  flow_name: FlowName;
  draft?: boolean;
  vars?: Record<string, JsonValue>;
}

export interface StartRunResponse {
  run_id: RunId;
  status: RunStatus;
}

export interface SaveFlowRequest {
  flow: Flow;
}

export interface DeployFlowRequest {
  name: FlowName;
}

export interface ResumeRunRequest {
  token: ResumeToken;
  event: Record<string, JsonValue>;
}

export interface PublishEventRequest {
  topic: string;
  data: Record<string, JsonValue>;
}

// Graph representation for visual editor
export interface GraphNode {
  id: string;
  type: 'trigger' | 'step' | 'parallel' | 'conditional' | 'awaitEvent' | 'catch';
  position: { x: number; y: number };
  data: {
    label?: string;
    step?: Step;
    trigger?: Trigger;
    // Execution state (for visualization)
    status?: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
    output?: JsonValue;
    error?: string;
    duration_ms?: number;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type?: 'default' | 'dependency' | 'conditional';
  animated?: boolean;
  label?: string;
}

export interface FlowGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    name: FlowName;
    description?: string;
    version?: string;
    trigger: Trigger;
    vars?: Record<string, JsonValue>;
  };
}

// Error types
export interface ApiError {
  error: {
    type: string;
    message: string;
    status: number;
  };
}

// OAuth types
export interface OAuthProviderInfo {
  id: string;
  name: string;
  display_name?: string;
  icon?: string;
  description?: string;
  scopes: ScopeInfo[];
  connected: boolean;
  connection_status?: OAuthConnectionStatus;
}

export interface ScopeInfo {
  scope: string;
  description: string;
}

export interface OAuthConnectionStatus {
  connected_at: string;
  expires_at?: string;
  scopes_granted?: string[];
}

export interface OAuthConnection {
  provider_id: string;
  provider_name: string;
  connected_at: string;
  expires_at?: string;
  scopes?: string[];
}

export interface ConnectOAuthProviderResponse {
  auth_url: string;
  provider_id: string;
}
