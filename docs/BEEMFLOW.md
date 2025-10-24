# BeemFlow Technical Specification

## Overview

BeemFlow is a universal workflow orchestration runtime written in Rust. It enables text-first automation through YAML-defined workflows that execute consistently across CLI, HTTP REST API, and Model Context Protocol (MCP) interfaces.

### Core Value Proposition

- **Text-First Workflows**: YAML/JSON definitions that are version-controllable, AI-readable, and auditable
- **Universal Protocol**: Single workflow definition executes across all interfaces (CLI, HTTP, MCP)
- **Composable Tools**: Registry-based tool system with automatic discovery and OAuth integration
- **Durable Execution**: State persistence enabling workflows that pause and resume across webhook events

### Design Philosophy

1. **Protocol Over Platform**: BeemFlow is a protocol specification, not a vendor platform. Workflows are portable and can be implemented natively in any language.

2. **Declarative DAG Construction**: Workflows define steps with dependencies automatically inferred from template references, eliminating manual DAG specification.

3. **Separation of Concerns**: Tool inputs remain JSON-serializable while execution context provides system capabilities (storage, secrets, OAuth) separately.

## Architecture

### System Components

```
┌─────────────────────────────────────────────────┐
│              Interface Layer                    │
├───────────────┬──────────────┬──────────────────┤
│   CLI Tool    │   HTTP API   │   MCP Server     │
│   (Axum)      │   (Axum)     │   (rmcp)         │
└───────────────┴──────────────┴──────────────────┘
         ↓              ↓              ↓
┌─────────────────────────────────────────────────┐
│          Operations Layer                       │
│  - Flows (create, deploy, validate)             │
│  - Runs (execute, list, resume)                 │
│  - Tools (search, install, list)                │
│  - System (status, spec)                        │
└─────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────┐
│          Execution Engine                       │
│  ┌───────────────────────────────────────────┐  │
│  │ Executor: Step orchestration, parallel    │  │
│  │ blocks, loops, conditionals, retries      │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Templater: Minijinja2 variable expansion  │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Analyzer: Automatic DAG from templates    │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────┐
│          Adapter System                         │
│  ┌─────────┬──────────┬──────────────────────┐  │
│  │  Core   │   HTTP   │   MCP Servers        │  │
│  │  Tools  │ Adapter  │   Adapter            │  │
│  └─────────┴──────────┴──────────────────────┘  │
└─────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│    Infrastructure & Services                   │
├──────────┬──────────┬────────┬─────────────────┤
│ Storage  │ Registry │ OAuth  │ Webhooks/Cron   │
│ (SQLite/ │ (Tool    │ Client │ Scheduler       │
│  PG)     │  Discovery)│      │                 │
└──────────┴──────────┴────────┴─────────────────┘
```

### Module Organization

| Module | Responsibility | Key Files |
|--------|----------------|-----------|
| `src/core/` | Business logic operations exposed uniformly | `flows.rs`, `runs.rs`, `tools.rs` |
| `src/engine/` | Workflow execution orchestration | `executor.rs`, `context.rs` |
| `src/dsl/` | Parsing, validation, templating | `mod.rs`, `template.rs`, `analyzer.rs` |
| `src/adapter/` | Pluggable tool execution | `core.rs`, `http.rs`, `mcp.rs` |
| `src/http/` | REST API server and webhooks | `mod.rs`, `webhook.rs` |
| `src/auth/` | OAuth 2.0 client/server | `client.rs`, `server.rs` |
| `src/mcp/` | Model Context Protocol integration | `server.rs`, `manager.rs` |
| `src/registry/` | Tool discovery and resolution | `manager.rs`, `default.rs` |
| `src/storage/` | Multi-backend persistence | `sqlite.rs`, `postgres.rs` |
| `src/secrets/` | Environment variable and secret access | `env.rs` |

### Request Flow

**HTTP API Request** (`POST /api/operations/runs.start_run`):
1. Axum router receives request
2. Operation name extracted from path
3. OperationRegistry.execute_json() invoked
4. Operation trait impl called (StartRun)
5. Storage layer accessed with tenant scoping
6. JSON response serialized and returned

**CLI Command** (`flow runs start`):
1. Clap parses command-line arguments
2. Dependencies initialized (engine, storage, registry)
3. Same Operation trait impl invoked
4. Results formatted as YAML/JSON
5. Output to stdout

**MCP Tool Call** (`beemflow_start_run()`):
1. AI agent calls MCP tool
2. MCP server handler receives JSON-RPC request
3. Same Operation trait impl invoked
4. Results returned as MCP tool response

This unified operations layer ensures interface parity across all access methods.

## Technology Stack

### Language & Runtime

- **Rust** (2024 edition): Type safety, zero-cost abstractions, memory safety, concurrency
- **Tokio** (1.47): Async runtime with full feature set
- **Axum** (0.8): Modern async web framework

### Key Dependencies

**Serialization & Templating**:
- `serde` + `serde_json`: JSON serialization with order preservation
- `serde_yaml`: YAML parsing for flow definitions
- `minijinja` (2.12): Jinja2-compatible templating

**Database**:
- `sqlx` (0.8): Compile-time checked SQL with SQLite and PostgreSQL backends
- `aws-sdk-s3`: S3 blob storage

**Authentication**:
- `jsonwebtoken` (10.0): JWT generation/validation
- `oauth2` (5.0): OAuth 2.0 client flows
- `hmac` + `sha2`: Webhook signature verification

**MCP Integration**:
- `rmcp` (0.8): Official Rust SDK for Model Context Protocol

**Observability**:
- `tracing` + `tracing-subscriber`: Structured logging
- `prometheus`: Metrics
- `opentelemetry` + `opentelemetry-otlp`: Distributed tracing

### Storage Architecture

**Multi-Backend Support**:
- **SQLite**: Default for single-instance deployments (file-based, zero-config)
- **PostgreSQL**: Production multi-instance with connection pooling

**Key Tables**:
- `runs`: Workflow execution records with status and timing
- `steps`: Individual step execution results
- `flows`: Workflow definitions (optional, can be filesystem-based)
- `oauth_credentials`: Encrypted external OAuth tokens
- `paused_runs`: Serialized context for durable execution resumption
- `webhooks`: Webhook configurations and handlers

## Core Features

### 1. Flow Definition

Workflows are declarative YAML documents describing a directed acyclic graph of steps:

```yaml
name: payment_processor
version: 1.0.0
description: Process payments and send notifications
on: webhook
vars:
  currency: USD
  timeout: 30

steps:
  - id: validate_payment
    use: http.fetch
    with:
      url: "{{ vars.api_url }}/validate"

  - id: process_payment
    use: stripe.charge
    with:
      amount: "{{ event.amount }}"
      currency: "{{ vars.currency }}"

  - id: notify_customer
    use: email.send
    with:
      to: "{{ event.email }}"
      body: "Payment processed: {{ steps.process_payment.id }}"
```

### 2. Execution Model

**DAG Construction**: Dependency analyzer parses template references to build execution graph automatically.

**Topological Execution**: Steps execute in dependency order with automatic parallelization of independent steps.

**Context Propagation**: Each step receives immutable access to:
- `event`: Trigger data (webhook payload, CLI args, HTTP request)
- `vars`: Workflow-level variables
- `outputs` / `steps`: Results from completed steps
- `secrets`: Environment variables
- `runs.previous`: Prior execution outputs (organizational memory)

**State Management**: For durable waits (`await_event`), execution context is serialized to database, returning a resume token. Later webhook delivery or manual resume continues from that point.

### 3. Step Types

Each step has exactly one action (mutually exclusive):

**Tool Execution**:
```yaml
- id: call_api
  use: http.fetch
  with:
    url: "https://api.example.com"
  if: "{{ event.type == 'critical' }}"
  retry:
    attempts: 3
    delay_sec: 5
```

**Parallel Block**:
```yaml
- id: fetch_all
  parallel: true
  steps:
    - id: fetch_users
      use: http.fetch
    - id: fetch_posts
      use: http.fetch
```

**Loop (foreach)**:
```yaml
- id: process_items
  foreach: "{{ event.items }}"
  as: item
  do:
    - id: process_item
      use: api.process
      with:
        data: "{{ item }}"
```

**Durable Wait**:
```yaml
- id: wait_for_approval
  await_event:
    source: slack
    match:
      token: "{{ vars.approval_token }}"
    timeout: 24h
```

**Time Delay**:
```yaml
- id: pause
  wait:
    seconds: 30
```

### 4. Tool System

Tools are reusable atomic operations exposed through a unified adapter interface.

**Tool Manifest Example**:
```json
{
  "type": "tool",
  "name": "stripe.charge",
  "description": "Charge a payment method",
  "parameters": {
    "type": "object",
    "required": ["amount", "currency"],
    "properties": {
      "amount": {"type": "number"},
      "currency": {"type": "string"}
    }
  },
  "endpoint": "https://api.stripe.com/v1/charges",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer $oauth:stripe:default"
  }
}
```

**Adapter Pattern**:

All tool execution implements the `Adapter` trait:

```rust
#[async_trait]
pub trait Adapter: Send + Sync {
    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> Result<HashMap<String, Value>>;
}
```

Three concrete implementations:

1. **CoreAdapter**: Built-in tools (echo, wait, log, convert_openapi) with no external dependencies
2. **HttpAdapter**: HTTP-based tools from registry with automatic OAuth token and environment variable expansion
3. **McpAdapter**: Model Context Protocol servers with automatic tool discovery

**ExecutionContext Design**:

Passed separately from inputs to maintain JSON-serializability while providing:
- Storage access
- Secrets provider
- OAuth client manager
- Future: user_id, permissions, audit logging

### 5. Registry System

**Three-Tier Discovery**:

1. **Default Registry**: Embedded tools in `/registry/default.json` (OpenAI, Stripe, GitHub, Slack, etc.)
2. **Local Registry**: User-defined tools in `.beemflow/registry.json` for custom APIs and overrides
3. **Remote Registry**: Hub for community tools (Smithery integration, future BeemFlow Hub)

**Tool Resolution**:
```
use: stripe.charge
    ↓
1. Check if "stripe" adapter cached
2. Search registries for "stripe.charge"
3. Load manifest
4. Create HttpAdapter instance
5. Execute with OAuth token expansion ($oauth:stripe:default)
```

### 6. Webhook Handling

**Flow**:
1. External service posts to `/webhooks/{topic}`
2. System matches flows with `on: webhook` trigger
3. For durable execution, workflow pauses at `await_event`
4. Event stored in database
5. Workflow resumes with event data in context
6. HMAC-SHA256 signature verification supported

### 7. OAuth Integration

**OAuthClientManager** handles:
- Token storage/retrieval per provider per integration
- Automatic refresh before expiration
- Header expansion in HTTP requests (`$oauth:provider:integration`)

**OAuthServer** provides:
- Authorization code flow for external OAuth
- Pending flow storage
- Token generation and validation

### 8. HTTP API

**Unified Operations Interface**:

All business logic exposed via:
```
POST /api/operations/{operation_name}
{
  "input": {...}
}
```

**Examples**:
- `POST /api/operations/flows.create_flow`
- `POST /api/operations/runs.start_run`
- `GET /api/operations/runs.list_runs`
- `POST /api/operations/tools.search_tools`

**OpenAPI Support**: JSON schemas auto-generated for all operations via schemars.

### 9. MCP Integration

**Dual Role**:
1. **MCP Server**: Exposes all BeemFlow operations as MCP tools, enabling AI agents to manage workflows
2. **MCP Client**: Connects to external MCP servers (Postgres, filesystem, etc.) and exposes their tools in workflows

**Example MCP Server Config**:
```json
{
  "type": "mcp_server",
  "name": "postgres",
  "command": "npx",
  "args": ["@modelcontextprotocol/server-postgres"],
  "env": {
    "DATABASE_URL": "$env:PG_CONNECTION_STRING"
  }
}
```

## Flow Specification

### Required Fields

```yaml
name: string          # Alphanumeric, _, -, . only
steps: array          # At least one step
on: trigger_type      # cli.manual, webhook, schedule.cron, http.request
```

### Optional Fields

```yaml
version: string       # Semantic version
description: string   # Natural language specification
vars: object          # Workflow variables
catch: array          # Error handler steps
cron: string          # Required if on: schedule.cron
```

### Template Namespaces

Available in all `{{ }}` expressions:

- `vars.*`: Workflow variables
- `secrets.*`: Environment variables
- `event.*`: Trigger data
- `outputs.*` / `steps.*`: Step results
- `runs.previous.*`: Prior execution outputs

### Template Filters (Minijinja)

```yaml
{{ text | upper }}              # UPPERCASE
{{ items | length }}            # Count
{{ items | join(", ") }}        # Join array
{{ value | default("n/a") }}    # Fallback
```

### Control Flow

**Conditional Execution**:
```yaml
- id: notify_error
  if: "{{ status.code >= 400 }}"
  use: slack.post
```

**Automatic Dependencies**:
Dependencies inferred from template references:
```yaml
- id: step_c
  # Implicitly depends on step_a and step_b
  use: echo
  with:
    text: "{{ step_a.result }} + {{ step_b.result }}"
```

**Explicit Dependencies**:
```yaml
- id: finalize
  depends_on: [process_all, validate_all]
  use: echo
  with:
    text: "Complete"
```

### Retry Logic

```yaml
- id: unreliable_api
  use: http.fetch
  with:
    url: "https://api.example.com"
  retry:
    attempts: 3
    delay_sec: 5
    backoff: exponential  # or linear
```

### Error Handling

```yaml
name: resilient_flow
steps:
  - id: risky_operation
    use: external.api

catch:
  - id: log_error
    use: core.log
    with:
      level: error
      message: "Flow failed: {{ error }}"

  - id: notify_admin
    use: email.send
    with:
      to: "admin@example.com"
```

## Tool/Adapter System

### Adapter Interface

All adapters implement:

```rust
#[async_trait]
pub trait Adapter: Send + Sync {
    async fn execute(
        &self,
        inputs: HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> Result<HashMap<String, Value>>;
}
```

### Built-in Tools (CoreAdapter)

| Tool | Description |
|------|-------------|
| `core.echo` | Returns input text |
| `core.wait` | Sleeps for duration |
| `core.log` | Structured logging |
| `core.convert_openapi` | Generates tool from OpenAPI spec |

### HTTP Tools (HttpAdapter)

Defined by JSON manifest with:
- `endpoint`: URL template with `{param}` placeholders
- `method`: HTTP method
- `headers`: Headers with `$oauth:` and `$env:` expansion
- `parameters`: JSON Schema for validation

**Variable Expansion**:
- `$oauth:provider:integration`: Replaced with OAuth token
- `$env:VAR_NAME`: Replaced with environment variable

### MCP Tools (McpAdapter)

Automatically discovered from MCP server process:
- Server spawned as child process
- JSON-RPC communication over stdio
- Tools registered dynamically
- Namespace: `mcp://server-name/tool-name`

### OpenAPI Integration

Convert any OpenAPI spec to BeemFlow tools:

```bash
flow convert openapi-spec.json > custom-tools.json
```

Tools can then be registered in local registry and used in workflows with automatic parameter validation.

## Security Architecture

### Current State (Single-User)

- No authentication on HTTP API
- OAuth tokens stored encrypted in database
- Secrets sourced from environment variables
- Webhook signature verification via HMAC-SHA256
- SQL injection prevention via parameterized queries (sqlx)

### Planned Multi-User Features

From design documents, planned implementation includes:

**Phase 1: User Isolation**
- JWT-based authentication middleware
- `users` and `tenants` tables
- `tenant_id` and `user_id` on all resources
- Query filtering by tenant scope

**Phase 2: RBAC**
- Role-based access control (Owner, Admin, Member, Viewer)
- Per-user OAuth credential scoping
- Secrets encryption at rest

**Phase 3: Advanced**
- Audit logging of all operations
- Usage quotas and rate limiting
- Two-factor authentication (TOTP)

## Concurrency Model

### Tokio-Based Execution

- Each workflow runs in separate async task
- Parallel steps use `tokio::join_all` for concurrent execution
- CPU-bound work delegated to `tokio::spawn_blocking`

### Thread-Safe State

- `Arc<Mutex<>>` for shared mutable state
- `DashMap` for concurrent hash maps (lock-free reads)
- Immutable event/vars in step context
- Concurrent-safe output storage

**Step Isolation**:
```rust
pub struct StepContext {
    event: Arc<HashMap<String, Value>>,      // Immutable
    vars: Arc<HashMap<String, Value>>,       // Immutable
    outputs: Arc<DashMap<String, Value>>,    // Concurrent
    secrets: Arc<HashMap<String, Value>>,    // Read-only
}
```

No shared mutable state between steps prevents race conditions.

## Deployment

### Single Binary

Rust compilation produces single executable with no runtime dependencies:
- Fast startup (~100ms)
- Low memory footprint
- Cross-platform compilation

### Database

**SQLite** (default):
```bash
DATABASE_URL=sqlite:beemflow.db flow serve
```

**PostgreSQL** (production):
```bash
DATABASE_URL=postgres://user:pass@host/db flow serve
```

### Environment Configuration

Key environment variables:
- `DATABASE_URL`: Database connection string
- `HTTP_HOST` / `HTTP_PORT`: Server binding
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET`: OAuth app credentials
- Custom secrets accessible via `{{ secrets.VAR_NAME }}`

### Observability

**Logging**:
```bash
RUST_LOG=info flow serve
```

**Metrics**: Prometheus endpoint at `/metrics`

**Tracing**: OpenTelemetry OTLP exporter configured via environment:
```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

## Example Workflows

### Hello World

```yaml
name: hello
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, BeemFlow!"
```

### HTTP API Call

```yaml
name: fetch_user
on: http.request
steps:
  - id: get_user
    use: http.fetch
    with:
      url: "https://api.github.com/users/{{ event.username }}"

  - id: log_result
    use: core.log
    with:
      message: "Found user: {{ steps.get_user.body.name }}"
```

### Webhook with Durable Wait

```yaml
name: approval_flow
on: webhook
steps:
  - id: request_approval
    use: slack.post
    with:
      channel: "#approvals"
      text: "Approve request {{ event.id }}?"

  - id: wait_for_response
    await_event:
      source: slack
      match:
        request_id: "{{ event.id }}"
      timeout: 24h

  - id: process_approval
    if: "{{ steps.wait_for_response.approved == true }}"
    use: api.approve
    with:
      id: "{{ event.id }}"
```

### Parallel Execution

```yaml
name: multi_fetch
on: cli.manual
steps:
  - id: fetch_all
    parallel: true
    steps:
      - id: fetch_users
        use: http.fetch
        with:
          url: "{{ vars.api }}/users"

      - id: fetch_posts
        use: http.fetch
        with:
          url: "{{ vars.api }}/posts"

  - id: combine
    use: core.echo
    with:
      text: "Users: {{ steps.fetch_users.body | length }}, Posts: {{ steps.fetch_posts.body | length }}"
```

## Technology Decisions Rationale

### Why Rust?

**Advantages Leveraged**:
- Type safety prevents entire classes of runtime errors
- Zero-cost abstractions yield optimal performance
- Excellent async/await for concurrent workflow execution
- Memory safety without garbage collection pauses
- Single binary deployment with no runtime dependencies

**Tradeoffs Accepted**:
- Steeper learning curve (offset by excellent compiler diagnostics)
- Longer development time (offset by fewer production bugs)

### Why Minijinja over Handlebars?

- Jinja2 compatibility with Python/JavaScript ecosystems
- Superior error messages for template debugging
- Broader feature set (filters, tests, macros)

### Why sqlx over ORM?

- Compile-time SQL query validation
- Simpler for procedural queries without object mapping
- Built-in migration support
- Better performance for complex queries

### Why Axum over Actix?

- Modern async-first design aligned with Tokio
- Composable middleware via Tower
- Type-safe routing with minimal boilerplate
- Excellent error handling ergonomics

## Project Status

### Current Capabilities

- Single-user workflow runtime
- Full YAML specification implemented
- CLI, HTTP API, and MCP interfaces operational
- Default registry with 20+ tools (OpenAI, Stripe, Slack, GitHub, etc.)
- SQLite and PostgreSQL support
- Durable execution with await_event
- OAuth 2.0 client and server
- Webhook handling with signature verification

### Known Gaps

- Multi-user/tenant isolation (design complete, implementation pending)
- Rate limiting (planned)
- Audit logging (planned)
- Two-factor authentication (planned)
- Horizontal scaling documentation

## Conclusion

BeemFlow is a production-grade workflow orchestration runtime designed for the AI era. Its key differentiators are:

1. **Universal Protocol**: Same workflow executes across CLI, HTTP, and MCP interfaces
2. **Text-First Design**: YAML workflows are version-controllable and AI-readable
3. **Automatic DAG Construction**: Dependencies inferred from template references
4. **Composable Tools**: Registry-based discovery with zero-configuration integrations
5. **Durable Execution**: State persistence enables workflows that pause and resume

The architecture reflects strong software engineering practices: trait-based polymorphism, separation of concerns, comprehensive error handling, and a clear extensibility model for enterprise features.
