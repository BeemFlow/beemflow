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
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  User,
  Organization,
  OrganizationMember,
  AuditLog,
} from '../types/beemflow';

// API base URL - defaults to /api prefix for proxied requests
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

class BeemFlowAPI {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private currentOrganizationId: string | null = null;
  private refreshPromise: Promise<void> | null = null;

  constructor(baseURL: string = API_BASE_URL) {
    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true, // For session cookies (OAuth)
    });

    // Request interceptor to inject auth token and org header
    this.client.interceptors.request.use(
      (config) => {
        if (this.accessToken && !config.url?.startsWith('/auth/')) {
          config.headers.Authorization = `Bearer ${this.accessToken}`;
        }

        // Add organization header for all protected API calls
        if (this.currentOrganizationId && !config.url?.startsWith('/auth/')) {
          config.headers['X-Organization-ID'] = this.currentOrganizationId;
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling and token refresh
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError<ApiError>) => {
        const originalRequest = error.config;

        // Handle 401 unauthorized - attempt token refresh
        if (error.response?.status === 401 && this.refreshToken && originalRequest && !originalRequest.url?.includes('/auth/refresh')) {
          try {
            // Prevent multiple simultaneous refresh requests
            if (!this.refreshPromise) {
              this.refreshPromise = this.performTokenRefresh();
            }
            await this.refreshPromise;
            this.refreshPromise = null;

            // Retry original request with new token
            if (this.accessToken) {
              originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
              return this.client(originalRequest);
            }
          } catch (refreshError) {
            // Refresh failed - clear tokens and redirect to login
            this.clearTokens();
            throw refreshError;
          }
        }

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

  private async performTokenRefresh(): Promise<void> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await this.client.post<LoginResponse>('/auth/refresh', {
      refresh_token: this.refreshToken,
    });

    this.setTokens(response.data.access_token, response.data.refresh_token);
  }

  private setTokens(accessToken: string, refreshToken: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  private clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
  }

  public isAuthenticated(): boolean {
    return this.accessToken !== null;
  }

  public setOrganization(organizationId: string): void {
    this.currentOrganizationId = organizationId;
  }

  public getSelectedOrganizationId(): string | null {
    return this.currentOrganizationId;
  }

  // ============================================================================
  // Authentication
  // ============================================================================

  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await this.client.post<LoginResponse>('/auth/login', credentials);
    this.setTokens(response.data.access_token, response.data.refresh_token);

    // Set default organization (from login response)
    if (response.data.organization?.id) {
      this.setOrganization(response.data.organization.id);
    }

    return response.data;
  }

  async register(data: RegisterRequest): Promise<LoginResponse> {
    const response = await this.client.post<LoginResponse>('/auth/register', data);
    this.setTokens(response.data.access_token, response.data.refresh_token);

    // Set default organization (from registration response)
    if (response.data.organization?.id) {
      this.setOrganization(response.data.organization.id);
    }

    return response.data;
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } finally {
      this.clearTokens();
      this.currentOrganizationId = null;
    }
  }

  // ============================================================================
  // User Management
  // ============================================================================

  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<User>('/v1/users/me');
    return response.data;
  }

  async updateProfile(data: { name?: string; avatar_url?: string }): Promise<User> {
    const response = await this.client.put<User>('/v1/users/me', data);
    return response.data;
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.client.post('/v1/users/me/password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  // ============================================================================
  // Organization Management
  // ============================================================================

  async listOrganizations(): Promise<Organization[]> {
    const response = await this.client.get<Organization[]>('/v1/organizations');
    return response.data;
  }

  async getCurrentOrganization(): Promise<Organization> {
    const response = await this.client.get<Organization>('/v1/organizations/current');
    return response.data;
  }

  async updateOrganization(data: { name?: string; slug?: string }): Promise<Organization> {
    const response = await this.client.put<Organization>('/v1/organizations/current', data);
    return response.data;
  }

  // ============================================================================
  // Member Management
  // ============================================================================

  async listMembers(): Promise<OrganizationMember[]> {
    const response = await this.client.get<OrganizationMember[]>('/v1/organizations/current/members');
    return response.data;
  }

  async inviteMember(email: string, role: string): Promise<OrganizationMember> {
    const response = await this.client.post<OrganizationMember>('/v1/organizations/current/members', {
      email,
      role,
    });
    return response.data;
  }

  async updateMemberRole(userId: string, role: string): Promise<OrganizationMember> {
    const response = await this.client.put<OrganizationMember>(
      `/v1/organizations/current/members/${encodeURIComponent(userId)}`,
      { role }
    );
    return response.data;
  }

  async removeMember(userId: string): Promise<void> {
    await this.client.delete(`/v1/organizations/current/members/${encodeURIComponent(userId)}`);
  }

  // ============================================================================
  // Audit Logs
  // ============================================================================

  async listAuditLogs(params?: {
    limit?: number;
    offset?: number;
    user_id?: string;
    action?: string;
  }): Promise<{ logs: AuditLog[]; total: number }> {
    const response = await this.client.get<AuditLog[]>('/v1/audit-logs', { params });
    return { logs: response.data, total: response.data.length };
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

  async connectOAuthProvider(providerId: string, scopes?: string[]): Promise<ConnectOAuthProviderResponse> {
    const response = await this.client.post<ConnectOAuthProviderResponse>(
      `/oauth/providers/${providerId}/connect`,
      { scopes }
    );
    return response.data;
  }

  async disconnectOAuthProvider(providerId: string): Promise<void> {
    await this.client.delete(`/oauth/providers/${providerId}/disconnect`);
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
