# BeemFlow: The Complete LLM Reference

> **FOR LLMs**: This is the authoritative, comprehensive reference for BeemFlow. Read this entire document before working with BeemFlow workflows, tools, or architecture. This document is designed for complete understanding and should be ingested in full.

---

## Table of Contents

1. [Core Philosophy & Mission](#core-philosophy--mission)
2. [Architecture Overview](#architecture-overview)
3. [The BeemFlow Protocol](#the-beemflow-protocol)
4. [Workflow Language Specification](#workflow-language-specification)
5. [Template System (Pongo2)](#template-system-pongo2)
6. [Tool System & Registry](#tool-system--registry)
7. [Runtime Execution Model](#runtime-execution-model)
8. [MCP Integration](#mcp-integration)
9. [Event System](#event-system)
10. [Security & Secrets](#security--secrets)
11. [Common Patterns](#common-patterns)
12. [Implementation Guidelines](#implementation-guidelines)
13. [Complete Examples](#complete-examples)
14. [Error Handling](#error-handling)
15. [Testing & Validation](#testing--validation)

---

## Core Philosophy & Mission

### The Vision

BeemFlow is **GitHub Actions for every business process** — a text-first, AI-native, open-source workflow automation protocol that fundamentally reimagines how business processes are automated in the AI age.

### Key Principles

1. **Text > GUI**: Workflows are defined in human and AI-readable YAML/JSON, not drag-and-drop interfaces
2. **Universal Protocol**: One workflow runs everywhere — CLI, HTTP API, or Model Context Protocol
3. **AI-Native**: LLMs can read, write, and execute BeemFlow workflows as first-class citizens
4. **Open Ecosystem**: No vendor lock-in, fully open-source, community-driven
5. **Zero-Config Tools**: Instant access to thousands of tools through registry and MCP
6. **Business-Focused**: Encodes actual business logic, not just data movement

### The Hidden Mission

BeemFlow addresses the **$15 trillion generational wealth transfer** as baby boomers retire:
- **Learn**: Every workflow teaches how a business operates
- **Automate**: Demonstrate value through operational efficiency
- **Acquire**: Use knowledge and relationships to acquire businesses

This "automation-to-acquisition flywheel" enables technical entrepreneurs to own businesses rather than just serve them.

---

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                     BeemFlow Runtime                    │
├───────────────┬──────────────┬──────────────┬───────────┤
│   Protocol    │    Engine    │   Registry   │    MCP    │
├───────────────┼──────────────┼──────────────┼───────────┤
│ YAML/JSON     │ Executor     │ Tool Store   │ Servers   │
│ Validation    │ Scheduler    │ Manifests    │ Bridge    │
│ Templating    │ State Mgmt   │ Resolution   │ Protocol  │
└───────────────┴──────────────┴──────────────┴───────────┘
                            ↓
        ┌──────────┬────────────┬──────────┬──────────┐
        │   CLI    │  HTTP API  │  Events  │  Storage │
        └──────────┴────────────┴──────────┴──────────┘
```

### Execution Contexts

1. **CLI Mode**: Direct execution via `flow run workflow.yaml`
2. **HTTP Mode**: RESTful API for remote execution
3. **MCP Mode**: Model Context Protocol server integration
4. **Event-Driven**: Triggered by events, webhooks, or schedules

---

## The BeemFlow Protocol

### Flow Definition Structure

```yaml
# REQUIRED fields
name: string                    # Unique workflow identifier
on: trigger                     # Trigger type (see Triggers section)
steps: []                       # Array of execution steps

# OPTIONAL fields
version: string                 # Semantic version
vars: {}                       # Workflow-level variables
cron: string                   # Cron expression (if on: schedule.cron)
catch: []                      # Error handling steps
mcpServers: {}                 # MCP server configurations
```

### Triggers

BeemFlow supports multiple trigger types:

```yaml
# Manual CLI execution
on: cli.manual

# Scheduled execution
on: schedule.cron
cron: "0 9 * * 1-5"  # 9 AM weekdays

# Event-driven
on: event:user.signup
on: event:payment.received

# HTTP request
on: http.request

# Multiple triggers
on:
  - cli.manual
  - schedule.cron
  - event:topic.name
```

### Step Definition

Every step MUST have an `id` and ONE primary action:

```yaml
# Tool execution step
- id: unique_identifier
  use: tool.name              # Tool to execute
  with: {}                     # Tool parameters
  
# Parallel execution block
- id: parallel_block
  parallel: true
  steps: []                    # Steps to run in parallel
  
# Loop execution
- id: foreach_block
  foreach: "{{ array }}"       # Array to iterate
  as: item                     # Loop variable name
  do: []                       # Steps to execute per item
  
# Event waiting
- id: wait_for_event
  await_event:
    source: "system"
    match: {key: value}
    timeout: "1h"
    
# Time delay
- id: delay
  wait:
    seconds: 30
```

### Optional Step Modifiers

```yaml
- id: step_with_modifiers
  use: tool.name
  with: {}
  
  # Conditional execution
  if: "{{ condition }}"
  
  # Dependencies
  depends_on: [step1, step2]
  
  # Retry configuration
  retry:
    attempts: 3
    delay_sec: 5
```

### IMPORTANT: Fields That Don't Exist

These fields are commonly hallucinated but **DO NOT EXIST**:

```yaml
# ❌ THESE DON'T EXIST
continue_on_error: true    # Use catch blocks instead
timeout: 30s               # Only in await_event.timeout
on_error: handler          # Use catch blocks
on_success: next          # Doesn't exist
break: true               # No flow control keywords
continue: true            # No flow control keywords
exit: true                # No flow control keywords
```

---

## Workflow Language Specification

### Complete Data Model (Go Source)

This is the EXACT model BeemFlow implements:

```go
type Flow struct {
    Name        string                  `yaml:"name"`        // REQUIRED
    Description string                  `yaml:"description"` // optional
    Version     string                  `yaml:"version"`     
    On          any                     `yaml:"on"`          // REQUIRED
    Cron        string                  `yaml:"cron"`        
    Vars        map[string]any          `yaml:"vars"`        
    Steps       []Step                  `yaml:"steps"`       // REQUIRED
    Catch       []Step                  `yaml:"catch"`       
    MCPServers  map[string]MCPServerCfg `yaml:"mcpServers"`  
}

type Step struct {
    ID         string          `yaml:"id"`          // REQUIRED
    Use        string          `yaml:"use"`         
    With       map[string]any  `yaml:"with"`        
    DependsOn  []string        `yaml:"depends_on"`  
    Parallel   bool            `yaml:"parallel"`    
    If         string          `yaml:"if"`          
    Foreach    string          `yaml:"foreach"`     
    As         string          `yaml:"as"`          
    Do         []Step          `yaml:"do"`          
    Steps      []Step          `yaml:"steps"`       
    Retry      *RetrySpec      `yaml:"retry"`       
    AwaitEvent *AwaitEventSpec `yaml:"await_event"` 
    Wait       *WaitSpec       `yaml:"wait"`        
}

type RetrySpec struct {
    Attempts int `yaml:"attempts"`
    DelaySec int `yaml:"delay_sec"`
}

type AwaitEventSpec struct {
    Source  string         `yaml:"source"`
    Match   map[string]any `yaml:"match"`
    Timeout string         `yaml:"timeout"`
}

type WaitSpec struct {
    Seconds int    `yaml:"seconds"`
    Until   string `yaml:"until"`
}
```

### Validation Rules

1. **Step Requirements**: Every step must have ONE of:
   - `use` → Execute a tool
   - `parallel: true` with `steps` → Parallel block
   - `foreach` with `as` and `do` → Loop
   - `await_event` → Wait for event
   - `wait` → Time delay

2. **Constraints**:
   - `id` is always required and must be unique within scope
   - `parallel: true` REQUIRES `steps` array
   - `foreach` REQUIRES both `as` and `do`
   - Cannot combine `use` with `parallel` or `foreach`
   - Step IDs must be valid identifiers (alphanumeric + underscore)

---

## Template System (Pongo2)

BeemFlow uses **Pongo2** templating (Django-like syntax) for variable interpolation and logic.

### Variable Scopes

Always use explicit scopes for clarity:

```yaml
{{ vars.MY_VAR }}              # Flow variables
{{ env.USER }}                 # Environment variables
{{ secrets.API_KEY }}          # Secrets (from .env or system)
{{ event.field }}              # Event data
{{ outputs.step_id.field }}    # Step outputs (preferred)
{{ step_id.field }}            # Step outputs (shorthand)
{{ runs.Previous.field }}      # Previous run data
```

### Array Access

Pongo2 uses dot notation throughout:

```yaml
{{ array.0 }}                  # First element
{{ array.1 }}                  # Second element
{{ data.rows.0.name }}         # Nested access
{{ array[variable_index] }}    # Variable index
```

### Filters

```yaml
{{ text | upper }}             # Convert to uppercase
{{ text | lower }}             # Convert to lowercase
{{ text | title }}             # Title case
{{ array | length }}           # Array/string length
{{ array | join:", " }}        # Join array elements
{{ number | add:10 }}          # Math operations
{{ text | truncate:50 }}       # Truncate string
{{ value | escape }}           # HTML escape
```

### Default Values

Use the `||` operator (NOT `|default`):

```yaml
{{ value || 'default' }}       # ✅ Correct
{{ value | default:'x' }}      # ❌ Wrong - doesn't exist
```

### Conditionals

```yaml
# In step conditions (must use template syntax)
if: "{{ vars.status == 'active' }}"
if: "{{ vars.count > 5 and env.DEBUG }}"
if: "{{ not (vars.disabled) }}"

# In template content
{% if condition %}
  True branch
{% elif other_condition %}
  Elif branch
{% else %}
  False branch
{% endif %}
```

### Loops in Templates

```yaml
# In template content
{% for item in array %}
  {{ item }}{% if not loop.last %}, {% endif %}
{% endfor %}

# Loop variables
{{ loop.index0 }}    # 0-based index
{{ loop.index }}      # 1-based index
{{ loop.first }}      # True if first iteration
{{ loop.last }}       # True if last iteration
```

### In Foreach Steps

BeemFlow automatically provides these variables:

```yaml
- id: process_items
  foreach: "{{ vars.items }}"
  as: item
  do:
    - id: process_{{ item_index }}    # 0-based index
      use: core.echo
      with:
        text: |
          Item: {{ item }}
          Index: {{ item_index }}      # 0-based
          Row: {{ item_row }}          # 1-based
```

### Functions That Don't Exist

```yaml
{{ now() }}              # ❌ No function calls
{{ date() }}             # ❌ No date function
{{ 'now' | date }}       # ❌ No date filter
{{ uuid() }}             # ❌ No UUID generation
```

---

## Tool System & Registry

### Tool Resolution Order

1. **Core Adapters**: Built-in tools
   - `core.echo` - Print text output
   - `core.wait` - Pause execution
   - `core.log` - Structured logging

2. **Registry Tools**: From registry files
   - Default: `/registry/default.json`
   - User: `.beemflow/registry.json`
   - Federated: Remote registry URLs

3. **MCP Servers**: Model Context Protocol tools
   - Format: `mcp://server_name/tool_name`
   - Configured in `mcpServers` section

4. **HTTP Adapter**: Generic HTTP requests
   - Tool name: `http`
   - Supports all HTTP methods

### Registry Tool Format

```json
{
  "type": "tool",
  "name": "google_sheets.values.get",
  "description": "Read values from a Google Sheet",
  "kind": "task",
  "version": "1.0.0",
  "registry": "default",
  "parameters": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["spreadsheetId", "range"],
    "properties": {
      "spreadsheetId": {
        "type": "string",
        "description": "The ID of the spreadsheet"
      },
      "range": {
        "type": "string",
        "description": "A1 notation range"
      }
    }
  },
  "manifest": {
    "url": "https://sheets.googleapis.com/v4/spreadsheets/{spreadsheetId}/values/{range}",
    "method": "GET",
    "headers": {
      "Authorization": "Bearer $env:GOOGLE_ACCESS_TOKEN"
    }
  }
}
```

### Common Tools

```yaml
# Core Tools
core.echo                      # Print text
core.wait                      # Pause execution
core.log                       # Structured logging

# HTTP
http.fetch                     # Simple GET request
http                          # Full HTTP control

# AI Services
openai.chat_completion        # OpenAI GPT models
anthropic.chat_completion     # Anthropic Claude

# Google Services
google_sheets.values.get      # Read spreadsheet
google_sheets.values.update   # Update cells
google_sheets.values.append   # Add rows
google_sheets.values.clear    # Clear range

# Communication
slack.chat.postMessage        # Send Slack messages
twilio.messages.create        # Send SMS

# Data Processing
jq.transform                  # JSON transformation
csv.parse                     # Parse CSV data
```

### HTTP Adapter

The generic HTTP adapter provides full control:

```yaml
- id: api_call
  use: http
  with:
    url: "https://api.example.com/endpoint"
    method: POST              # GET, POST, PUT, DELETE, PATCH
    headers:
      Authorization: "Bearer {{ secrets.API_TOKEN }}"
      Content-Type: "application/json"
    body:                      # Can be object or string
      query: "{{ vars.search }}"
      limit: 10
    query:                     # URL query parameters
      page: 1
      size: 20
```

---

## Runtime Execution Model

### Execution Flow

1. **Parse**: YAML/JSON → Internal flow structure
2. **Validate**: Schema validation & constraint checking
3. **Template**: Initial variable expansion
4. **Execute**: Step-by-step execution with state tracking
5. **Output**: Results returned or stored

### State Management

```yaml
# Outputs are available immediately after step completion
- id: step1
  use: tool.name
  with: {param: value}
  
- id: step2
  use: another.tool
  with:
    # Access step1's output
    input: "{{ outputs.step1.result }}"
```

### Parallel Execution

```yaml
- id: parallel_operations
  parallel: true
  steps:
    - id: task1
      use: http.fetch
      with: {url: "https://api1.com"}
    - id: task2
      use: http.fetch
      with: {url: "https://api2.com"}
    - id: task3
      use: http.fetch
      with: {url: "https://api3.com"}

# All outputs available after parallel block
- id: combine_results
  use: core.echo
  with:
    text: |
      Task1: {{ outputs.task1.body }}
      Task2: {{ outputs.task2.body }}
      Task3: {{ outputs.task3.body }}
```

### Loop Execution

```yaml
- id: process_items
  foreach: "{{ vars.items }}"
  as: item
  do:
    - id: validate_{{ item_index }}
      use: validation.check
      with:
        data: "{{ item }}"
    
    - id: process_{{ item_index }}
      if: "{{ outputs['validate_' + item_index].valid }}"
      use: processor.run
      with:
        input: "{{ item }}"
```

### Dependency Management

```yaml
# Explicit dependencies
- id: prepare_data
  use: data.prepare
  
- id: analyze
  depends_on: [prepare_data]
  use: ai.analyze
  
- id: report
  depends_on: [analyze]
  use: report.generate

# Implicit dependencies (output references)
- id: fetch
  use: http.fetch
  
- id: process
  use: processor.run
  with:
    # Creates implicit dependency on 'fetch'
    data: "{{ outputs.fetch.body }}"
```

---

## MCP Integration

### MCP Server Configuration

```yaml
name: mcp_workflow
on: cli.manual

# Define MCP servers
mcpServers:
  filesystem:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  
  github:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "{{ env.GITHUB_TOKEN }}"

steps:
  # Use MCP tools
  - id: read_file
    use: mcp://filesystem/read_file
    with:
      path: "/tmp/data.json"
  
  - id: create_issue
    use: mcp://github/create_issue
    with:
      repo: "owner/repo"
      title: "New issue"
      body: "Issue content"
```

### MCP Tool Format

```yaml
# Format: mcp://server_name/tool_name
use: mcp://server/tool

# Examples
use: mcp://filesystem/read_file
use: mcp://github/search_repositories
use: mcp://slack/send_message
```

---

## Event System

### Event-Driven Workflows

```yaml
name: event_driven
on: event:payment.received

steps:
  - id: process_payment
    use: payment.processor
    with:
      amount: "{{ event.amount }}"
      customer: "{{ event.customer_id }}"
```

### Awaiting Events

```yaml
- id: send_approval_request
  use: slack.message
  with:
    text: "Please approve: {{ vars.request }}"
    token: "approval_123"

- id: wait_for_approval
  await_event:
    source: "slack"
    match:
      token: "approval_123"
    timeout: "24h"

- id: process_response
  use: core.echo
  with:
    text: "Response: {{ event.text }}"
```

### Event Publishing

```yaml
- id: publish_event
  use: event.publish
  with:
    topic: "order.completed"
    payload:
      order_id: "{{ vars.order_id }}"
      status: "completed"
```

---

## Security & Secrets

### Secret Management

Secrets are accessed via the `secrets` scope:

```yaml
steps:
  - id: api_call
    use: http
    with:
      url: "https://api.service.com"
      headers:
        Authorization: "Bearer {{ secrets.API_KEY }}"
```

### Secret Sources

1. **Environment Variables**: System environment
2. **`.env` Files**: Local development
3. **Secret Stores**: Production systems
4. **MCP Configuration**: Server-specific secrets

### Security Best Practices

1. **Never hardcode secrets** in workflows
2. **Use explicit secret references** via `{{ secrets.NAME }}`
3. **Mask sensitive outputs** in logs
4. **Validate input data** before processing
5. **Use HTTPS** for all external calls
6. **Implement retry limits** to prevent abuse

---

## Common Patterns

### Pattern: Multi-Source Data Aggregation

```yaml
name: data_aggregation
on: cli.manual

steps:
  - id: fetch_sources
    parallel: true
    steps:
      - id: database
        use: database.query
        with:
          query: "SELECT * FROM metrics"
      
      - id: api
        use: http.fetch
        with:
          url: "https://api.metrics.com/latest"
      
      - id: spreadsheet
        use: google_sheets.values.get
        with:
          spreadsheetId: "{{ vars.SHEET_ID }}"
          range: "Data!A:Z"
  
  - id: combine
    use: ai.analyze
    with:
      database: "{{ outputs.database.results }}"
      api: "{{ outputs.api.body }}"
      sheets: "{{ outputs.spreadsheet.values }}"
```

### Pattern: Conditional Branching

```yaml
name: conditional_flow
on: cli.manual

steps:
  - id: check_condition
    use: data.evaluate
    with:
      expression: "{{ vars.value > 100 }}"
  
  - id: high_value_path
    if: "{{ outputs.check_condition.result == true }}"
    use: premium.processor
    with:
      data: "{{ vars.data }}"
  
  - id: normal_path
    if: "{{ outputs.check_condition.result == false }}"
    use: standard.processor
    with:
      data: "{{ vars.data }}"
```

### Pattern: Error Recovery

```yaml
name: resilient_workflow
on: cli.manual

steps:
  - id: primary_operation
    use: critical.operation
    retry:
      attempts: 3
      delay_sec: 5
    with:
      data: "{{ vars.input }}"

catch:
  - id: handle_error
    use: notification.send
    with:
      message: "Operation failed: {{ error.message }}"
  
  - id: fallback
    use: backup.processor
    with:
      data: "{{ vars.input }}"
```

### Pattern: Human-in-the-Loop

```yaml
name: human_approval
on: cli.manual

steps:
  - id: generate_proposal
    use: ai.generate
    with:
      prompt: "Create proposal for: {{ vars.request }}"
  
  - id: send_for_review
    use: slack.message
    with:
      channel: "#approvals"
      text: |
        Proposal: {{ outputs.generate_proposal.content }}
        Reply 'approve' or 'reject'
      thread_ts: "{{ vars.timestamp }}"
  
  - id: await_response
    await_event:
      source: "slack"
      match:
        thread_ts: "{{ vars.timestamp }}"
      timeout: "2h"
  
  - id: process_approval
    if: "{{ event.text == 'approve' }}"
    use: proposal.execute
    with:
      content: "{{ outputs.generate_proposal.content }}"
```

---

## Implementation Guidelines

### Workflow Design Principles

1. **Single Responsibility**: Each step should do one thing well
2. **Idempotency**: Steps should be safe to retry
3. **Explicit Dependencies**: Use `depends_on` for clarity
4. **Error Boundaries**: Use `catch` blocks for error handling
5. **Resource Cleanup**: Ensure resources are properly released

### Naming Conventions

```yaml
# Workflows
name: snake_case_workflow_name

# Step IDs
- id: snake_case_step_id
- id: fetch_data
- id: process_item_0  # For dynamic IDs

# Variables
vars:
  UPPER_CASE_CONSTANTS: "value"
  lower_case_variables: "value"

# Tools
use: namespace.tool_name
use: google_sheets.values.get
use: core.echo
```

### Performance Optimization

1. **Use Parallel Execution** when steps are independent
2. **Batch Operations** instead of individual calls
3. **Cache Results** in variables for reuse
4. **Limit Retries** to prevent infinite loops
5. **Set Timeouts** on long-running operations

### Testing Workflows

```yaml
# Test workflow with mock data
name: test_workflow
on: cli.manual

vars:
  TEST_MODE: true
  MOCK_DATA: 
    - {id: 1, value: "test1"}
    - {id: 2, value: "test2"}

steps:
  - id: test_step
    use: core.echo
    with:
      text: "Testing with: {{ vars.MOCK_DATA }}"
```

---

## Complete Examples

### Example: Daily Financial Report

```yaml
name: daily_financial_report
on: schedule.cron
cron: "0 7 * * *"  # 7 AM daily

vars:
  ALERT_THRESHOLD: 50000
  RECIPIENTS: ["cfo@company.com", "finance@company.com"]

steps:
  # Gather financial data
  - id: fetch_data
    parallel: true
    steps:
      - id: stripe_balance
        use: stripe.balance.retrieve
        with:
          api_key: "{{ secrets.STRIPE_KEY }}"
      
      - id: bank_balance
        use: banking.balance
        with:
          account: "{{ secrets.BANK_ACCOUNT }}"
      
      - id: pending_invoices
        use: quickbooks.invoices.list
        with:
          status: "pending"
          token: "{{ secrets.QB_TOKEN }}"
  
  # Analyze with AI
  - id: analyze
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: |
            Analyze the financial data and create a summary:
            1. Total available cash
            2. Pending receivables
            3. Key insights
            4. Action items if cash < ${{ vars.ALERT_THRESHOLD }}
        - role: user
          content: |
            Stripe: {{ outputs.stripe_balance }}
            Bank: {{ outputs.bank_balance }}
            Invoices: {{ outputs.pending_invoices }}
  
  # Generate report
  - id: create_report
    use: report.generate
    with:
      template: "financial_daily"
      data:
        summary: "{{ outputs.analyze.choices.0.message.content }}"
        stripe: "{{ outputs.stripe_balance }}"
        bank: "{{ outputs.bank_balance }}"
        invoices: "{{ outputs.pending_invoices }}"
  
  # Send notifications
  - id: notify
    foreach: "{{ vars.RECIPIENTS }}"
    as: recipient
    do:
      - id: send_email_{{ recipient_index }}
        use: email.send
        with:
          to: "{{ recipient }}"
          subject: "Daily Financial Report"
          body: "{{ outputs.create_report.html }}"
          attachments:
            - "{{ outputs.create_report.pdf_url }}"

catch:
  - id: error_notification
    use: slack.message
    with:
      channel: "#finance-alerts"
      text: "⚠️ Daily financial report failed: {{ error.message }}"
```

### Example: Customer Onboarding

```yaml
name: customer_onboarding
on: event:customer.signup

vars:
  ONBOARDING_STEPS:
    - send_welcome_email
    - create_account
    - setup_billing
    - schedule_demo
    - add_to_crm

steps:
  # Validate customer data
  - id: validate
    use: validation.customer
    with:
      email: "{{ event.email }}"
      company: "{{ event.company }}"
  
  # Parallel onboarding tasks
  - id: onboard
    parallel: true
    steps:
      - id: welcome_email
        use: email.send
        with:
          to: "{{ event.email }}"
          template: "welcome"
          vars:
            name: "{{ event.name }}"
            company: "{{ event.company }}"
      
      - id: create_account
        use: api.account.create
        with:
          email: "{{ event.email }}"
          plan: "{{ event.plan }}"
      
      - id: setup_billing
        use: stripe.customer.create
        with:
          email: "{{ event.email }}"
          name: "{{ event.company }}"
      
      - id: add_to_crm
        use: salesforce.lead.create
        with:
          email: "{{ event.email }}"
          company: "{{ event.company }}"
          source: "signup"
  
  # Schedule follow-up
  - id: schedule_demo
    use: calendar.event.create
    with:
      title: "Demo with {{ event.company }}"
      attendees: ["{{ event.email }}", "sales@company.com"]
      duration: "30m"
      days_from_now: 3
  
  # AI-powered personalization
  - id: personalize
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: "Create a personalized onboarding message"
        - role: user
          content: |
            Customer: {{ event.company }}
            Industry: {{ event.industry }}
            Size: {{ event.company_size }}
            Plan: {{ event.plan }}
  
  # Send personalized follow-up
  - id: followup
    use: email.send
    with:
      to: "{{ event.email }}"
      subject: "Your personalized onboarding plan"
      body: "{{ outputs.personalize.choices.0.message.content }}"
  
  # Track completion
  - id: track
    use: analytics.track
    with:
      event: "onboarding_completed"
      properties:
        customer_id: "{{ outputs.create_account.id }}"
        stripe_id: "{{ outputs.setup_billing.id }}"
        crm_id: "{{ outputs.add_to_crm.id }}"
```

---

## Error Handling

### Catch Blocks

```yaml
name: error_handling
on: cli.manual

steps:
  - id: risky_operation
    use: external.api
    with:
      endpoint: "{{ vars.endpoint }}"
    retry:
      attempts: 3
      delay_sec: 5

catch:
  # Catch blocks run if any step fails
  - id: log_error
    use: core.log
    with:
      level: "error"
      message: "Workflow failed: {{ error.message }}"
      context:
        step: "{{ error.step_id }}"
        type: "{{ error.type }}"
  
  - id: notify_ops
    use: slack.message
    with:
      channel: "#ops-alerts"
      text: "🚨 Workflow failed: {{ name }}"
  
  - id: cleanup
    use: resource.cleanup
    with:
      resources: "{{ vars.allocated_resources }}"
```

### Retry Configuration

```yaml
- id: flaky_service
  use: external.service
  retry:
    attempts: 5        # Total attempts (including first)
    delay_sec: 10      # Delay between attempts
  with:
    data: "{{ vars.input }}"
```

### Graceful Degradation

```yaml
steps:
  - id: primary_service
    use: service.primary
    with:
      data: "{{ vars.data }}"
  
  - id: check_primary
    if: "{{ not outputs.primary_service.success }}"
    use: service.fallback
    with:
      data: "{{ vars.data }}"
```

---

## Testing & Validation

### Workflow Validation

```bash
# Validate workflow syntax
flow validate workflow.yaml

# Dry run without execution
flow run workflow.yaml --dry-run

# Run with debug output
flow run workflow.yaml --debug
```

### Test Workflows

```yaml
name: test_integration
on: cli.manual

vars:
  TEST_MODE: true
  TEST_DATA:
    - {id: 1, expected: "result1"}
    - {id: 2, expected: "result2"}

steps:
  - id: test_cases
    foreach: "{{ vars.TEST_DATA }}"
    as: test
    do:
      - id: run_test_{{ test.id }}
        use: function.under.test
        with:
          input: "{{ test.id }}"
      
      - id: assert_{{ test.id }}
        use: test.assert
        with:
          actual: "{{ outputs['run_test_' + test.id].result }}"
          expected: "{{ test.expected }}"
```

### Performance Testing

```yaml
name: performance_test
on: cli.manual

vars:
  ITERATIONS: 100
  PARALLEL_BATCH: 10

steps:
  - id: load_test
    foreach: "{{ range(0, vars.ITERATIONS) }}"
    as: iteration
    parallel: true
    do:
      - id: request_{{ iteration }}
        use: http
        with:
          url: "{{ vars.TARGET_URL }}"
          method: "GET"
  
  - id: analyze_results
    use: performance.analyze
    with:
      results: "{{ outputs }}"
      threshold_ms: 1000
```

---

## Appendix: Quick Reference

### Required Fields by Context

| Context | Required Fields |
|---------|----------------|
| Flow | `name`, `on`, `steps` |
| Step | `id` + one of: `use`, `parallel`, `foreach`, `await_event`, `wait` |
| Tool Step | `id`, `use` |
| Parallel | `id`, `parallel: true`, `steps` |
| Foreach | `id`, `foreach`, `as`, `do` |
| Retry | `attempts`, `delay_sec` |
| Await Event | `source`, `match` |

### Template Variable Scopes

| Scope | Usage | Example |
|-------|-------|---------|
| `vars` | Flow variables | `{{ vars.API_KEY }}` |
| `env` | Environment | `{{ env.USER }}` |
| `secrets` | Secrets | `{{ secrets.TOKEN }}` |
| `event` | Event data | `{{ event.payload }}` |
| `outputs` | Step outputs | `{{ outputs.step1.result }}` |
| `runs` | Run history | `{{ runs.Previous.output }}` |

### Common Tool Patterns

| Pattern | Tool | Purpose |
|---------|------|---------|
| Print output | `core.echo` | Display text |
| HTTP request | `http` | API calls |
| AI completion | `openai.chat_completion` | LLM tasks |
| Read sheets | `google_sheets.values.get` | Get data |
| Send message | `slack.chat.postMessage` | Notifications |
| Wait for event | `await_event` | Async ops |

### Validation Checklist

- [ ] All steps have unique IDs
- [ ] Template syntax uses `{{ }}` not `${}`
- [ ] Arrays use dot notation `array.0`
- [ ] Defaults use `||` not `|default`
- [ ] No hallucinated fields
- [ ] Proper scope prefixes
- [ ] Valid tool names
- [ ] Retry limits set
- [ ] Error handling present

