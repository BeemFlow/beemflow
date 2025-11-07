import axios, { type AxiosInstance, type AxiosError } from 'axios';
import * as yaml from 'yaml';
import type {
  Flow,
  FlowListItem,
  Run,
  RunListItem,
  RunStatus,
  Tool,
  RegistryEntry,
  McpServer,
  StartRunRequest,
  StartRunResponse,
  PublishEventRequest,
  DashboardStats,
  OAuthProviderInfo,
  OAuthConnection,
  ConnectOAuthProviderResponse,
  FlowGraph,
  ApiError,
  JsonValue,
} from '../types/beemflow';

// API base URL - defaults to /api prefix for proxied requests
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

class BeemFlowAPI {
  private client: AxiosInstance;

  constructor(baseURL: string = API_BASE_URL) {
    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true, // For session cookies (OAuth)
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ApiError>) => {
        if (error.response?.data?.error) {
          // Throw the API error with structured format
          throw new ApiErrorClass(
            error.response.data.error.message,
            error.response.data.error.type,
            error.response.data.error.status
          );
        }
        // Generic error
        throw new ApiErrorClass(
          error.message || 'An unexpected error occurred',
          'network_error',
          error.response?.status || 500
        );
      }
    );
  }

  // ============================================================================
  // Flows
  // ============================================================================

  async listFlows(): Promise<FlowListItem[]> {
    // Fetch both flows and recent runs to correlate last run data
    const [flowsResponse, runsResponse] = await Promise.all([
      this.client.get<{ flows: string[] }>('/flows'),
      this.client.get<RunListItem[]>('/runs', { params: { limit: 100 } }),
    ]);

    const runs = runsResponse.data;

    // Build a map of flow name -> most recent run
    const lastRunMap = new Map<string, { status: RunStatus; timestamp: string }>();
    runs.forEach((run) => {
      if (!lastRunMap.has(run.flow_name)) {
        lastRunMap.set(run.flow_name, {
          status: run.status,
          timestamp: run.started_at,
        });
      }
    });

    // Convert flow names to FlowListItem objects with last run data
    return flowsResponse.data.flows.map((name) => ({
      name,
      trigger: 'cli.manual' as const,
      last_run: lastRunMap.get(name),
    }));
  }

  async getFlow(name: string): Promise<Flow> {
    const response = await this.client.get<{ name: string; content: string; version: string }>(`/flows/${encodeURIComponent(name)}`);
    // Parse the YAML content to get the Flow object
    return yaml.parse(response.data.content) as Flow;
  }

  async saveFlow(flow: Flow): Promise<void> {
    // Convert Flow object to YAML string
    const content = yaml.stringify(flow);

    await this.client.post('/flows', {
      name: flow.name,
      content,
    }, {
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async deleteFlow(name: string): Promise<void> {
    await this.client.delete(`/flows/${encodeURIComponent(name)}`);
  }

  async deployFlow(name: string): Promise<void> {
    await this.client.post(`/flows/${encodeURIComponent(name)}/deploy`, {});
  }

  async rollbackFlow(name: string, version: string): Promise<void> {
    await this.client.post(`/flows/${encodeURIComponent(name)}/rollback`, { version });
  }

  async getFlowHistory(name: string): Promise<Array<{ version: string; deployed_at: string }>> {
    const response = await this.client.get(`/flows/${encodeURIComponent(name)}/history`);
    return response.data;
  }

  async validateFlow(flow: Flow): Promise<{ valid: boolean; errors?: string[] }> {
    const response = await this.client.post('/flows/validate', { flow });
    return response.data;
  }

  // Graph representation (for visual editor)
  async getFlowGraph(name: string): Promise<FlowGraph> {
    const response = await this.client.get<FlowGraph>(`/flows/${encodeURIComponent(name)}/graph`);
    return response.data;
  }

  async saveFlowFromGraph(graph: FlowGraph): Promise<void> {
    await this.client.post('/flows/from-graph', graph);
  }

  // ============================================================================
  // Runs
  // ============================================================================

  async listRuns(params?: {
    limit?: number;
    offset?: number;
    flow_name?: string;
    status?: string;
  }): Promise<{ runs: RunListItem[]; total: number }> {
    const response = await this.client.get<RunListItem[]>('/runs', { params });
    // Backend returns array directly, wrap it for consistency
    return { runs: response.data, total: response.data.length };
  }

  async getRun(id: string): Promise<Run> {
    const response = await this.client.get<Run>(`/runs/${id}`);
    return response.data;
  }

  async startRun(request: StartRunRequest): Promise<StartRunResponse> {
    const response = await this.client.post<StartRunResponse>('/runs', request);
    return response.data;
  }

  async resumeRun(token: string, event: Record<string, JsonValue>): Promise<void> {
    await this.client.post(`/runs/resume/${token}`, { event });
  }

  async cancelRun(id: string): Promise<void> {
    await this.client.post(`/runs/${id}/cancel`);
  }

  // ============================================================================
  // Tools
  // ============================================================================

  async listTools(): Promise<RegistryEntry[]> {
    const response = await this.client.get<{ tools: RegistryEntry[] }>('/tools');
    return response.data.tools;
  }

  async getTool(name: string): Promise<RegistryEntry> {
    const response = await this.client.get<RegistryEntry>(`/tools/${encodeURIComponent(name)}`);
    return response.data;
  }

  async searchTools(query?: string): Promise<Tool[]> {
    const response = await this.client.get<Tool[]>('/tools/search', {
      params: { query },
    });
    return response.data;
  }

  async installTool(tool: string): Promise<void> {
    await this.client.post('/tools/install', { tool });
  }

  async executeTool(toolName: string, parameters: Record<string, JsonValue>): Promise<JsonValue> {
    const response = await this.client.post(`/tools/${encodeURIComponent(toolName)}/execute`, parameters);
    return response.data;
  }

  // ============================================================================
  // MCP Servers
  // ============================================================================

  async listMcpServers(): Promise<McpServer[]> {
    const response = await this.client.get<McpServer[]>('/mcp');
    return response.data;
  }

  async searchMcpServers(query?: string): Promise<McpServer[]> {
    const response = await this.client.get<McpServer[]>('/mcp/search', {
      params: { query },
    });
    return response.data;
  }

  async installMcpServer(server: string): Promise<void> {
    await this.client.post('/mcp/install', { server });
  }

  // ============================================================================
  // Events
  // ============================================================================

  async publishEvent(request: PublishEventRequest): Promise<void> {
    await this.client.post('/events', request);
  }

  // ============================================================================
  // OAuth Providers
  // ============================================================================

  async listOAuthProviders(): Promise<OAuthProviderInfo[]> {
    const response = await this.client.get<{ providers: OAuthProviderInfo[] }>('/oauth/providers');
    return response.data.providers;
  }

  async getOAuthProvider(providerId: string): Promise<OAuthProviderInfo> {
    const response = await this.client.get<{ provider: OAuthProviderInfo }>(`/oauth/providers/${providerId}`);
    return response.data.provider;
  }

  async connectOAuthProvider(providerId: string, scopes?: string[]): Promise<ConnectOAuthProviderResponse> {
    const response = await this.client.post<ConnectOAuthProviderResponse>(
      `/oauth/providers/${providerId}/connect`,
      { scopes }
    );
    return response.data;
  }

  async disconnectOAuthProvider(providerId: string): Promise<void> {
    await this.client.delete(`/oauth/providers/${providerId}`);
  }

  async listOAuthConnections(): Promise<OAuthConnection[]> {
    const response = await this.client.get<{ connections: OAuthConnection[] }>('/oauth/connections');
    return response.data.connections;
  }

  // ============================================================================
  // Dashboard
  // ============================================================================

  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.client.get<DashboardStats>('/dashboard/stats');
    return response.data;
  }

  // ============================================================================
  // System
  // ============================================================================

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    const response = await this.client.get('/healthz');
    return response.data;
  }

  async getMetrics(): Promise<string> {
    const response = await this.client.get('/metrics', {
      headers: { Accept: 'text/plain' },
    });
    return response.data;
  }
}

// Custom error class for structured API errors
export class ApiErrorClass extends Error {
  public type: string;
  public status: number;

  constructor(message: string, type: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.type = type;
    this.status = status;
  }
}

// Export singleton instance
export const api = new BeemFlowAPI();

// Export class for custom instances
export { BeemFlowAPI };
