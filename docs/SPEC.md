# BeemFlow Language Specification

> **FOR LLMs**: This is the authoritative specification for BeemFlow workflows. Read this entire document before generating flows. All features documented here are implemented and tested.

---

## Table of Contents

1. [Quick Reference](#-quick-reference)
2. [Flow Structure](#-flow-structure)
3. [Triggers](#-triggers)
4. [Steps](#-steps)
5. [Templating (Minijinja)](#-templating-minijinja)
6. [Control Flow](#-control-flow)
7. [Parallel Execution](#-parallel-execution)
8. [Dependencies](#-dependencies)
9. [Tools](#-tools)
10. [Error Handling](#-error-handling)
11. [Organizational Memory](#-organizational-memory)
12. [Complete Examples](#-complete-examples)
13. [Validation Rules](#-validation-rules)
14. [LLM Checklist](#-llm-checklist)

---

## 🎯 Quick Reference

### Flow Structure (YAML)
```yaml
name: string                    # REQUIRED - alphanumeric, _, -, . only
description: string             # optional - precise natural language spec
version: string                 # optional - semantic version
on: trigger                     # REQUIRED - see Triggers section
cron: "0 0 9 * * *"            # required if on: schedule.cron (6-field format)
vars: {key: value}             # optional - workflow variables
steps: [...]                   # REQUIRED - array of steps
catch: [...]                   # optional - error handler steps
```

### Step Fields (Complete List)
```yaml
- id: string                   # REQUIRED - unique identifier
  use: tool.name               # Tool to execute
  with: {params}               # Tool input parameters (all values support templates)
  if: "{{ expression }}"       # Conditional execution
  foreach: "{{ array }}"       # Loop over array
  as: item                     # Loop variable name
  do: [steps]                  # Steps to run in loop
  parallel: true               # Run nested steps in parallel
  steps: [steps]               # Steps for parallel block
  depends_on: [step_ids]       # Explicit step dependencies
  retry:                       # Retry configuration
    attempts: 3
    delay_sec: 5
  await_event:                 # Wait for external event
    source: "airtable"
    match: {field: value}
    timeout: "24h"
  wait:                        # Time delay
    seconds: 30
    # OR
    until: "2024-12-31T23:59:59Z"
```

**Constraint**: Each step requires exactly ONE action (choose one option from this list):

1. **Tool execution**: `use: tool.name` + `with: {params}`
2. **Parallel block**: `parallel: true` + `steps: [...]`
3. **Loop**: `foreach: "{{ array }}"` + `as: var` + `do: [...]` (optionally with `parallel: true`)
4. **Event wait**: `await_event: {source, match, timeout}`
5. **Time delay**: `wait: {seconds}` or `wait: {until}`

You cannot combine multiple action types (e.g., a step with `use` cannot also have `foreach`).

---

## 📄 Flow Structure

### Complete Flow Model

```yaml
# Minimal valid flow
name: hello_world
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, BeemFlow!"
```

```yaml
# Full-featured flow
name: social_automation
version: 1.0.0
description: |
  Generate AI content, store in Airtable for review, wait for approval,
  then post to social media. Demonstrates event-driven workflows with
  human-in-the-loop patterns.

on:
  - cli.manual
  - schedule.cron

cron: "0 0 9 * * 1-5"  # Weekdays at 9 AM

vars:
  API_URL: "https://api.example.com"
  MAX_RETRIES: 3
  model_config:
    name: "gpt-4o-mini"
    temperature: 0.7

steps:
  - id: generate
    use: openai.chat_completion
    with:
      model: "{{ vars.model_config.name }}"
      messages:
        - role: user
          content: "Generate content"

  - id: store
    use: mcp://airtable/create_record
    with:
      content: "{{ generate.choices[0].message.content }}"

catch:
  - id: handle_error
    use: core.echo
    with:
      text: "Workflow failed, sending notification"
```

### Field Descriptions

**name** (REQUIRED): Unique workflow identifier
- Valid characters: alphanumeric, `_`, `-`, `.`
- Examples: `hello_world`, `social-automation`, `v1.0.workflow`

**description** (optional): Natural language specification
- Should describe the complete workflow logic precisely
- Used by AI agents to understand and maintain workflows
- Best practice: Describe what happens, why, and error handling

**version** (optional): Semantic version string
- Examples: `"1.0.0"`, `"2.1.3-beta"`

**on** (REQUIRED): Trigger specification (see Triggers section)

**cron** (required if `on: schedule.cron`): 6-field cron expression

**vars** (optional): Workflow-level variables
- Can contain any JSON-serializable data
- Accessed in templates via `{{ vars.key }}`
- Supports nested objects and arrays

**steps** (REQUIRED): Array of step definitions (minimum 1)

**catch** (optional): Error handler steps
- Executed if any step in main workflow fails
- Same structure as regular steps

---

## 🎬 Triggers

Triggers define when a workflow executes. Workflows can have single or multiple triggers.

### Single Trigger

```yaml
on: cli.manual
```

### Multiple Triggers

```yaml
on:
  - cli.manual
  - schedule.cron
  - event: user.created
```

### Trigger Types

**cli.manual** - Manual execution via CLI
```yaml
on: cli.manual
```

**schedule.cron** - Scheduled execution (requires `cron` field)
```yaml
on: schedule.cron
cron: "0 0 9 * * 1-5"  # Weekdays at 9 AM (6 fields: SEC MIN HOUR DAY MONTH DOW)
```

Cron format (6 fields):
```
SEC  MIN  HOUR  DAY  MONTH  DOW
0    0    9     *    *      *     # Daily at 9:00:00 AM
0    30   8     *    *      1-5   # Weekdays at 8:30:00 AM
0    0    */6   *    *      *     # Every 6 hours
0    0    0     1    *      *     # First of month at midnight
*/30 *    *     *    *      *     # Every 30 seconds
```

**event:** - Event-driven execution
```yaml
on:
  - event: user.created
  - event: order.completed
```

Event data available in workflow via `{{ event.field }}`:
```yaml
steps:
  - id: process_user
    use: core.echo
    with:
      text: "New user: {{ event.user_id }}"
```

**http.request** - HTTP webhook trigger
```yaml
on: http.request
```

---

## 📦 Steps

Steps are the building blocks of workflows. Each step must have a unique `id` and exactly ONE primary action.

### Basic Step (Tool Execution)

```yaml
- id: send_message
  use: slack.chat.postMessage
  with:
    channel: "#general"
    text: "Hello from BeemFlow!"
```

### Step with Conditional

```yaml
- id: notify_error
  if: "{{ api_call.status_code >= 400 }}"
  use: slack.chat.postMessage
  with:
    channel: "#alerts"
    text: "API error: {{ api_call.status_code }}"
```

### Step with Dependencies

```yaml
- id: process_data
  depends_on: [fetch_data, validate_input]
  use: core.echo
  with:
    text: "Processing {{ fetch_data.result }}"
```

### Step with Retry

```yaml
- id: fetch_external_api
  use: http
  with:
    url: "{{ vars.API_URL }}/data"
  retry:
    attempts: 3      # Total attempts (including first try)
    delay_sec: 5     # Seconds between retries
```

### Step with Wait

```yaml
# Wait for duration
- id: pause
  wait:
    seconds: 30

# Wait until timestamp
- id: wait_until_midnight
  wait:
    until: "2024-12-31T23:59:59Z"
```

### Step with Await Event

```yaml
- id: await_approval
  await_event:
    source: airtable          # Event source identifier
    match:                     # Match criteria (all must match)
      record_id: "{{ record.id }}"
      field: Status
      equals: Approved
    timeout: 24h              # Optional timeout (h, m, s units)
```

When the step pauses, it returns a resume token. Resume via:
```bash
flow resume <token> --event '{"status": "Approved"}'
```

---

## 🎨 Templating (Minijinja)

BeemFlow uses Minijinja (Jinja2/Django template syntax) for all dynamic values.

### Template Syntax

All templates use `{{ }}` for expressions:
```yaml
text: "Hello, {{ user.name }}!"
url: "{{ vars.base_url }}/api/{{ endpoint }}"
count: "{{ items | length }}"
```

### Namespaces

**vars** - Workflow variables (from `vars:` section)
```yaml
{{ vars.API_URL }}
{{ vars.config.timeout }}
{{ vars.items[0] }}
```

**secrets** - Environment variables (read-only)
```yaml
{{ secrets.API_KEY }}
{{ secrets.DATABASE_URL }}
{{ secrets.USER }}               # System user
{{ secrets.HOME }}               # Home directory
```

**event** - Event data (for event-driven flows)
```yaml
{{ event.user_id }}
{{ event.payload.action }}
{{ event.data.items[0] }}
```

**outputs** - Step outputs (explicit namespace, recommended)
```yaml
{{ outputs.fetch_data.body }}
{{ outputs.api_call.status_code }}
{{ outputs.generate.choices[0].message.content }}
```

**steps** - Step outputs (shorthand, same as outputs)
```yaml
{{ steps.fetch_data.body }}
{{ fetch_data.body }}            # Even shorter (auto-resolved)
```

**runs** - Previous workflow runs (organizational memory)
```yaml
{{ runs.previous.id }}
{{ runs.previous.outputs.step_id.result }}
{{ runs.previous.started_at }}
```

### Array and Object Access

**Bracket notation** (for arrays):
```yaml
{{ items[0] }}                   # First element
{{ items[item_index] }}          # Variable index
{{ data.rows[0].name }}          # Nested access
{{ event.users[0].email }}
```

**Dot notation** (for objects):
```yaml
{{ user.name }}
{{ config.api.endpoint }}
{{ response.data.results }}
```

**Mixed access**:
```yaml
{{ data.rows[0].fields.Email }}
{{ api_response.items[item_index].metadata.created_at }}
```

### Filters

Minijinja provides built-in filters. Common ones:

**String filters**:
```yaml
{{ text | upper }}               # UPPERCASE
{{ text | lower }}               # lowercase
{{ text | title }}               # Title Case
{{ text | trim }}                # Remove whitespace
{{ text | reverse }}             # esreveR
```

**Array filters**:
```yaml
{{ items | length }}             # Count elements
{{ items | join(", ") }}         # "a, b, c"
{{ items | first }}              # First element
{{ items | last }}               # Last element
{{ items | reverse }}            # Reverse order
```

**Fallback/default**:
```yaml
{{ value | default("fallback") }}
{{ user.name | default("Anonymous") }}
{{ null_value | default(0) }}
```

**Chaining filters**:
```yaml
{{ text | upper | reverse }}
{{ items | length | default(0) }}
{{ name | trim | title }}
```

### Mathematical Operations

```yaml
{{ count + 10 }}
{{ price * 1.1 }}
{{ total - discount }}
{{ quantity / 2 }}
{{ items | length * 5 }}
```

### Boolean Operations

```yaml
{{ enabled and active }}
{{ status == "success" or status == "pending" }}
{{ not disabled }}
{{ count > 5 and count < 10 }}
```

### Comparisons

```yaml
{{ status == "active" }}
{{ count > 10 }}
{{ price >= 100 }}
{{ name != "admin" }}
{{ items | length > 0 }}
```

---

## 🔀 Control Flow

### Conditionals (if)

Execute steps only when condition is true.

**Simple condition**:
```yaml
- id: success_only
  if: "{{ api_call.status_code == 200 }}"
  use: core.echo
  with:
    text: "Success!"
```

**Complex conditions**:
```yaml
- id: notify_production_error
  if: "{{ status == 'failed' and secrets.NODE_ENV == 'production' }}"
  use: slack.chat.postMessage
  with:
    channel: "#alerts"
    text: "Production error!"
```

**Using outputs from previous steps**:
```yaml
- id: check_result
  if: "{{ outputs.api_call.data.approved == true }}"
  use: core.echo
  with:
    text: "Approved!"
```

**Checking existence**:
```yaml
- id: has_items
  if: "{{ items | length > 0 }}"
  use: core.echo
  with:
    text: "Found {{ items | length }} items"
```

**Null/undefined checks**:
```yaml
- id: has_value
  if: "{{ value }}"              # Truthy check
  use: core.echo
  with:
    text: "Value exists"

- id: with_default
  if: "{{ data.field | default(false) }}"
  use: core.echo
  with:
    text: "Field is set"
```

### Loops (foreach)

Iterate over arrays with `foreach` + `as` + `do`.

**Basic loop**:
```yaml
- id: process_items
  foreach: "{{ vars.items }}"
  as: item
  do:
    - id: echo_{{ item_index }}
      use: core.echo
      with:
        text: "Item {{ item_row }}: {{ item }}"
```

**Loop variables** (automatically available):
- `{{ item }}` - Current item (or whatever name specified in `as:`)
- `{{ item_index }}` - Zero-based index (0, 1, 2, ...)
- `{{ item_row }}` - One-based index (1, 2, 3, ...)

**Looping over API results**:
```yaml
- id: fetch_users
  use: http.fetch
  with:
    url: "{{ vars.API_URL }}/users"

- id: process_users
  foreach: "{{ fetch_users.users }}"
  as: user
  do:
    - id: greet_{{ user_index }}
      use: core.echo
      with:
        text: "Hello, {{ user.name }}!"
```

**Looping over Google Sheets rows**:
```yaml
- id: read_sheet
  use: google_sheets.values.get
  with:
    spreadsheetId: "{{ vars.SHEET_ID }}"
    range: "Sheet1!A:D"

- id: process_rows
  foreach: "{{ read_sheet.values }}"
  as: row
  do:
    - id: check_{{ row_index }}
      if: "{{ row[0] and row[1] == 'approved' }}"
      use: core.echo
      with:
        text: "Row {{ row_row }}: Processing {{ row[0] }}"
```

**Conditional steps in loops**:
```yaml
- id: filter_and_process
  foreach: "{{ items }}"
  as: item
  do:
    - id: active_only_{{ item_index }}
      if: "{{ item.status == 'active' }}"
      use: core.echo
      with:
        text: "Processing active item: {{ item.name }}"

    - id: premium_only_{{ item_index }}
      if: "{{ item.tier == 'premium' }}"
      use: core.echo
      with:
        text: "Premium item: {{ item.name }}"
```

**Nested loops**:
```yaml
- id: outer_loop
  foreach: "{{ categories }}"
  as: category
  do:
    - id: inner_loop_{{ category_index }}
      foreach: "{{ category.items }}"
      as: item
      do:
        - id: process_{{ category_index }}_{{ item_index }}
          use: core.echo
          with:
            text: "{{ category.name }} -> {{ item.name }}"
```

**Parallel foreach** (each iteration runs in parallel):
```yaml
- id: parallel_processing
  parallel: true
  foreach: "{{ items }}"
  as: item
  do:
    - id: process_{{ item_index }}
      use: http
      with:
        url: "{{ vars.API_URL }}/process"
        method: POST
        body:
          item: "{{ item }}"
```

### Template Control Flow (Minijinja)

For complex logic inside template strings:

**Conditionals in templates**:
```yaml
- id: dynamic_message
  use: core.echo
  with:
    text: |
      {% if items | length > 10 %}
      Many items: {{ items | length }}
      {% elif items | length > 0 %}
      Few items: {{ items | length }}
      {% else %}
      No items
      {% endif %}
```

**Loops in templates**:
```yaml
- id: list_items
  use: core.echo
  with:
    text: |
      Items:
      {% for item in items %}
      - {{ loop.index }}. {{ item.name }}{% if not loop.last %},{% endif %}
      {% endfor %}
```

**Loop variables in templates**:
- `{{ loop.index }}` - 1-based index
- `{{ loop.index0 }}` - 0-based index
- `{{ loop.first }}` - True on first iteration
- `{{ loop.last }}` - True on last iteration

---

## ⚡ Parallel Execution

Execute multiple steps simultaneously for performance.

### Parallel Block

```yaml
- id: parallel_apis
  parallel: true
  steps:
    - id: fetch_users
      use: http.fetch
      with:
        url: "{{ vars.API_URL }}/users"

    - id: fetch_posts
      use: http.fetch
      with:
        url: "{{ vars.API_URL }}/posts"

    - id: fetch_comments
      use: http.fetch
      with:
        url: "{{ vars.API_URL }}/comments"

# Continue after all parallel steps complete
- id: combine_results
  depends_on: [parallel_apis]
  use: core.echo
  with:
    text: |
      Users: {{ fetch_users.users | length }}
      Posts: {{ fetch_posts.posts | length }}
      Comments: {{ fetch_comments.comments | length }}
```

### Parallel Foreach

```yaml
# Each loop iteration runs in parallel
- id: parallel_processing
  parallel: true
  foreach: "{{ items }}"
  as: item
  do:
    - id: process_{{ item_index }}
      use: expensive_api_call
      with:
        data: "{{ item }}"
```

### Nested Parallel in Foreach

```yaml
# Sequential loop with parallel operations inside
- id: process_categories
  foreach: "{{ categories }}"
  as: category
  do:
    - id: parallel_ops_{{ category_index }}
      parallel: true
      steps:
        - id: analyze_{{ category_index }}
          use: openai.chat_completion
          with:
            model: "gpt-4o-mini"
            messages:
              - role: user
                content: "Analyze: {{ category.name }}"

        - id: translate_{{ category_index }}
          use: openai.chat_completion
          with:
            model: "gpt-4o-mini"
            messages:
              - role: user
                content: "Translate to Spanish: {{ category.name }}"
```

---

## 🔗 Dependencies

BeemFlow automatically detects dependencies from template references. Explicit `depends_on` is optional.

### Automatic Dependency Detection

```yaml
steps:
  # Step C references A and B in templates
  - id: step_c
    use: core.echo
    with:
      text: "{{ steps.step_a.text }} + {{ steps.step_b.text }}"

  # Step A (no dependencies)
  - id: step_a
    use: core.echo
    with:
      text: "Hello"

  # Step B (references A)
  - id: step_b
    use: core.echo
    with:
      text: "{{ steps.step_a.text }} World"

# Actual execution order (auto-detected): step_a → step_b → step_c
```

### Explicit Dependencies

```yaml
- id: step_a
  use: core.echo
  with:
    text: "First"

- id: step_b
  use: core.echo
  with:
    text: "Second"

- id: step_c
  depends_on: [step_a, step_b]
  use: core.echo
  with:
    text: "Third (after A and B)"
```

### Diamond Dependency Pattern

```yaml
steps:
  - id: root
    use: core.echo
    with:
      text: "Start"

  - id: branch_a
    depends_on: [root]
    use: core.echo
    with:
      text: "Branch A"

  - id: branch_b
    depends_on: [root]
    use: core.echo
    with:
      text: "Branch B"

  - id: merge
    depends_on: [branch_a, branch_b]
    use: core.echo
    with:
      text: "Merged (after both branches)"

# Execution: root → (branch_a || branch_b) → merge
```

### Parallel with Dependencies

```yaml
- id: prepare
  use: core.echo
  with:
    text: "Preparing..."

# Both parallel branches depend on prepare
- id: parallel_work
  depends_on: [prepare]
  parallel: true
  steps:
    - id: task1
      use: core.echo
      with:
        text: "Task 1"

    - id: task2
      use: core.echo
      with:
        text: "Task 2"

# Finalize depends on parallel completion
- id: finalize
  depends_on: [parallel_work]
  use: core.echo
  with:
    text: "All done!"
```

---

## 🧰 Tools

Tools are the actions that steps execute. BeemFlow supports multiple tool types.

**⚠️ IMPORTANT - ALWAYS QUERY FIRST ⚠️**

Before using any tool in your flows (except `core.*`), **you MUST query the registry** to verify it's installed:
- Use `mcp__beemflow__beemflow_list_tools()` to see all available tools
- Use `mcp__beemflow__beemflow_search_tools({ query: "keyword" })` to search for specific tools

The examples below show tools that are **commonly available** in the default registry, but availability varies by installation. **Do not assume any tool is available without querying first.**

### Core Tools

**core.echo** - Print text output
```yaml
- id: hello
  use: core.echo
  with:
    text: "Hello, world!"
```

**core.wait** - Pause execution
```yaml
- id: pause
  use: core.wait
  with:
    seconds: 5
```

**core.log** - Log message (for internal use)
```yaml
- id: log_info
  use: core.log
  with:
    message: "Processing started"
```

### HTTP Tools

**http.fetch** - Simple GET request
```yaml
- id: get_data
  use: http.fetch
  with:
    url: "{{ vars.API_URL }}/data"
```

**http** - Full HTTP control (any method)
```yaml
- id: create_resource
  use: http
  with:
    url: "{{ vars.API_URL }}/resources"
    method: POST
    headers:
      Authorization: "Bearer {{ secrets.API_TOKEN }}"
      Content-Type: "application/json"
    body:
      name: "{{ resource_name }}"
      type: "document"
```

HTTP methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`

### AI Services

**openai.chat_completion** - OpenAI GPT models
```yaml
- id: generate_content
  use: openai.chat_completion
  with:
    model: "gpt-4o-mini"
    messages:
      - role: system
        content: "You are a helpful assistant."
      - role: user
        content: "{{ user_query }}"
```

**anthropic.chat_completion** - Anthropic Claude
```yaml
- id: analyze_text
  use: anthropic.chat_completion
  with:
    model: "claude-3-7-sonnet-20250219"
    messages:
      - role: user
        content: "Analyze this: {{ text }}"
```

Response access:
- OpenAI: `{{ generate.choices[0].message.content }}`
- Anthropic: `{{ analyze.content[0].text }}`

### Discovering Available Tools

**🔴 CRITICAL - READ THIS FIRST 🔴**

**ALWAYS query the registry BEFORE writing flows** to discover what tools and MCP servers are actually installed in this BeemFlow instance.

**List all installed tools**:
```typescript
// Use the BeemFlow MCP server to query available tools
mcp__beemflow__beemflow_list_tools()
```

**Search for specific tools**:
```typescript
// Search by keyword (e.g., "sheets", "slack", "openai")
mcp__beemflow__beemflow_search_tools({ query: "sheets" })
```

**List all MCP servers**:
```typescript
mcp__beemflow__beemflow_list_mcp_servers()
```

**Get full registry index**:
```typescript
mcp__beemflow__beemflow_registry_index()
```

**The examples below use tools from the DEFAULT registry** (`registry/default.json`). These tools may or may not be available in your instance. **Always query first** to confirm availability before using any tool in your flows.

### Google Sheets

**NOTE**: These tools are typically available in the default registry. Query `mcp__beemflow__beemflow_search_tools({ query: "google_sheets" })` to confirm they're installed.

**google_sheets.values.get** - Read spreadsheet data
```yaml
- id: read_sheet
  use: google_sheets.values.get
  with:
    spreadsheetId: "{{ vars.SHEET_ID }}"
    range: "Sheet1!A1:D10"
```

**google_sheets.values.update** - Update cells
```yaml
- id: update_cells
  use: google_sheets.values.update
  with:
    spreadsheetId: "{{ vars.SHEET_ID }}"
    range: "Sheet1!A1:B1"
    values:
      - ["Updated", "Data"]
```

**google_sheets.values.append** - Add new rows
```yaml
- id: add_row
  use: google_sheets.values.append
  with:
    spreadsheetId: "{{ vars.SHEET_ID }}"
    range: "Sheet1!A:D"
    values:
      - ["Cell A", "Cell B", "Cell C", "Cell D"]
```

### Communication Tools

**NOTE**: Query the registry to see which communication tools are installed. Many tools require OAuth configuration via `secrets.*`.

**slack.chat.postMessage** - Send Slack message (if installed)
```yaml
- id: notify
  use: slack.chat.postMessage
  with:
    channel: "#general"
    text: "{{ message }}"
```

**x.post** - Post to X/Twitter (if installed)
```yaml
- id: tweet
  use: x.post
  with:
    text: "{{ tweet_content }}"
```

### MCP Server Tools

MCP (Model Context Protocol) servers provide custom tools via the `mcp://` prefix:

```yaml
- id: create_record
  use: mcp://airtable/create_record
  with:
    baseId: "{{ secrets.AIRTABLE_BASE_ID }}"
    tableId: "{{ secrets.AIRTABLE_TABLE_ID }}"
    fields:
      Name: "{{ item.name }}"
      Status: "Pending"
```

**Format**: `mcp://server-name/tool-name`

**Configuration**: MCP servers are configured globally, not in individual flows:
- **Registry**: Add to `registry/default.json` with `type: "mcp_server"`
- **Global config**: Define in `.mcp.json` or `flow.config.json` under `mcpServers`

Example global config (`.mcp.json`):
```json
{
  "mcpServers": {
    "airtable": {
      "command": "npx",
      "args": ["-y", "@airtable/mcp-server-airtable"],
      "env": {
        "AIRTABLE_API_KEY": "$env:AIRTABLE_API_KEY"
      }
    }
  }
}
```

### Tool Resolution Order

When you specify `use: tool.name`, BeemFlow resolves it in this order:

1. **Exact match**: Check if adapter is already registered for this exact tool name
2. **Prefix routing**:
   - `core.*` → Core adapter (e.g., `core.echo`, `core.wait`)
   - `mcp://*` → MCP adapter (e.g., `mcp://airtable/create_record`)
3. **Lazy load from registry**: Check `registry/default.json` for tool definition
   - Creates HTTP adapter with tool manifest
   - Examples: `http.fetch`, `openai.chat_completion`
   - **Use discovery tools** (see "Discovering Available Tools" section above) to find installed tools
4. **Generic HTTP fallback**: Use generic `http` adapter for any HTTP request

**Key insight**: Most tools (except `core.*` and `mcp://*`) use the HTTP adapter under the hood. The registry just provides pre-configured manifests with endpoints, headers, and parameter schemas.

**Always query the registry first** using `mcp__beemflow__beemflow_list_tools()` to see what tools are actually available before writing flows.

---

## ❌ Error Handling

### Catch Blocks

Handle workflow errors with `catch` at flow level:

```yaml
name: resilient_workflow
on: cli.manual

steps:
  - id: risky_operation
    use: http
    with:
      url: "{{ vars.API_URL }}/risky"

  - id: process_result
    use: core.echo
    with:
      text: "Success: {{ risky_operation.data }}"

catch:
  - id: log_error
    use: core.echo
    with:
      text: "Error occurred in workflow"

  - id: send_alert
    use: slack.chat.postMessage
    with:
      channel: "#alerts"
      text: "Workflow failed - please investigate"
```

### Retry Logic

Retry individual steps on failure:

```yaml
- id: flaky_api
  use: http
  with:
    url: "{{ vars.EXTERNAL_API }}/endpoint"
  retry:
    attempts: 3      # Total attempts (including first)
    delay_sec: 5     # Seconds between retries
```

### Safe Template Access

Use fallbacks for potentially missing data:

```yaml
- id: safe_access
  use: core.echo
  with:
    text: |
      Name: {{ user.name | default("Unknown") }}
      Email: {{ user.email | default("no-email@example.com") }}
      Nested: {{ data.deeply.nested.value | default("N/A") }}
      Array: {{ items[0] | default("Empty") }}
```

### Null/Undefined Handling

```yaml
# Check existence
- id: check_value
  if: "{{ value }}"                    # Truthy check
  use: core.echo
  with:
    text: "Value exists"

# Default value
- id: with_default
  use: core.echo
  with:
    text: "{{ nullable_field | default('default_value') }}"

# Boolean OR
- id: or_operator
  use: core.echo
  with:
    text: "{{ null_value or 'fallback' }}"
```

---

## 💾 Organizational Memory

BeemFlow workflows can access outputs from previous runs of the same workflow.

### Accessing Previous Run

```yaml
name: memory_demo
on: cli.manual

steps:
  - id: check_previous
    use: core.echo
    with:
      text: |
        {% if runs.previous.id %}
        Previous run: {{ runs.previous.id }}
        Previous output: {{ runs.previous.outputs.generate.result }}
        Started at: {{ runs.previous.started_at }}
        {% else %}
        This is the first run
        {% endif %}

  - id: generate
    use: core.echo
    with:
      text: "New result: {{ secrets.USER }}"
```

### Conversation Continuity (AI)

Use previous outputs to maintain context across runs:

```yaml
- id: generate_content
  use: anthropic.chat_completion
  with:
    model: "claude-3-7-sonnet-20250219"
    messages:
      - role: user
        content: "Generate a social media post"
      {% if runs.previous.outputs.generate_content.content[0].text %}
      - role: assistant
        content: "{{ runs.previous.outputs.generate_content.content[0].text }}"
      - role: user
        content: "Now generate a different post on a new topic"
      {% endif %}
```

### Available Fields

```yaml
{{ runs.previous.id }}              # Run UUID
{{ runs.previous.flow_name }}       # Flow name
{{ runs.previous.status }}          # SUCCEEDED, FAILED, etc.
{{ runs.previous.started_at }}      # Timestamp
{{ runs.previous.ended_at }}        # Timestamp
{{ runs.previous.outputs.step_id.field }}  # Step outputs
{{ runs.previous.event.field }}     # Event data
{{ runs.previous.vars.key }}        # Workflow variables
```

---

## 📚 Complete Examples

### Example 1: Basic API Call

```yaml
name: fetch_users
on: cli.manual

vars:
  API_URL: "https://jsonplaceholder.typicode.com"

steps:
  - id: get_users
    use: http.fetch
    with:
      url: "{{ vars.API_URL }}/users"

  - id: display_count
    use: core.echo
    with:
      text: "Found {{ get_users.length }} users"
```

### Example 2: Conditional Processing

```yaml
name: conditional_workflow
on: cli.manual

vars:
  environment: "production"
  threshold: 100

steps:
  - id: fetch_metrics
    use: http.fetch
    with:
      url: "{{ vars.API_URL }}/metrics"

  - id: alert_if_high
    if: "{{ fetch_metrics.value > vars.threshold and vars.environment == 'production' }}"
    use: slack.chat.postMessage
    with:
      channel: "#alerts"
      text: "High metric: {{ fetch_metrics.value }}"

  - id: log_always
    use: core.echo
    with:
      text: "Metric value: {{ fetch_metrics.value }}"
```

### Example 3: Loop with Parallel Processing

```yaml
name: parallel_processing
on: cli.manual

vars:
  items: ["apple", "banana", "cherry"]

steps:
  - id: process_items
    parallel: true
    foreach: "{{ vars.items }}"
    as: item
    do:
      - id: analyze_{{ item_index }}
        use: openai.chat_completion
        with:
          model: "gpt-4o-mini"
          messages:
            - role: user
              content: "Tell me about {{ item }}"

      - id: display_{{ item_index }}
        use: core.echo
        with:
          text: "{{ item }}: {{ outputs.analyze_0.choices[0].message.content }}"
```

### Example 4: Google Sheets Integration

```yaml
name: sheets_workflow
on: cli.manual

vars:
  SHEET_ID: "{{ secrets.GOOGLE_SPREADSHEET_ID }}"

steps:
  - id: read_data
    use: google_sheets.values.get
    with:
      spreadsheetId: "{{ vars.SHEET_ID }}"
      range: "Sheet1!A:D"

  - id: process_rows
    foreach: "{{ read_data.values }}"
    as: row
    do:
      - id: process_{{ row_index }}
        if: "{{ row_index > 0 and row[1] == 'pending' }}"
        use: core.echo
        with:
          text: "Processing row {{ row_row }}: {{ row[0] }}"

  - id: append_new_row
    use: google_sheets.values.append
    with:
      spreadsheetId: "{{ vars.SHEET_ID }}"
      range: "Sheet1!A:D"
      values:
        - ["New Item", "pending", "", ""]
```

### Example 5: Event-Driven with Approval

```yaml
name: approval_workflow
description: |
  Generate content with AI, store in Airtable for review, wait for approval,
  then post to social media. Demonstrates human-in-the-loop workflow patterns.

on:
  - event: content.request

steps:
  - id: generate_content
    use: openai.chat_completion
    with:
      model: "gpt-4o-mini"
      messages:
        - role: user
          content: "Generate a tweet about {{ event.topic }}"

  - id: store_for_review
    use: mcp://airtable/create_record
    with:
      baseId: "{{ secrets.AIRTABLE_BASE_ID }}"
      tableId: "{{ secrets.AIRTABLE_TABLE_ID }}"
      fields:
        Content: "{{ generate_content.choices[0].message.content }}"
        Status: "Pending Review"

  - id: await_approval
    await_event:
      source: airtable
      match:
        record_id: "{{ store_for_review.id }}"
        field: Status
        equals: Approved
      timeout: 24h

  - id: post_to_twitter
    use: x.post
    with:
      text: "{{ generate_content.choices[0].message.content }}"

  - id: mark_posted
    use: mcp://airtable/update_records
    with:
      baseId: "{{ secrets.AIRTABLE_BASE_ID }}"
      tableId: "{{ secrets.AIRTABLE_TABLE_ID }}"
      records:
        - recordId: "{{ store_for_review.id }}"
          fields:
            Status: "Posted"
            Posted_ID: "{{ post_to_twitter.data.id }}"
```

### Example 6: Scheduled Workflow

```yaml
name: daily_report
version: 1.0.0
description: |
  Generate and send daily report every weekday at 9 AM. Fetches metrics,
  generates AI summary, and sends via Slack.

on: schedule.cron
cron: "0 0 9 * * 1-5"  # Weekdays at 9:00:00 AM

vars:
  METRICS_API: "https://api.example.com"

steps:
  - id: fetch_metrics
    use: http.fetch
    with:
      url: "{{ vars.METRICS_API }}/daily"

  - id: generate_summary
    use: openai.chat_completion
    with:
      model: "gpt-4o-mini"
      messages:
        - role: user
          content: "Summarize these metrics: {{ fetch_metrics }}"

  - id: send_report
    use: slack.chat.postMessage
    with:
      channel: "#daily-reports"
      text: |
        *Daily Report*
        {{ generate_summary.choices[0].message.content }}

        Raw metrics: {{ fetch_metrics.total_users }} users
```

### Example 7: Parallel API Calls with Fan-In

```yaml
name: parallel_apis
on: cli.manual

steps:
  - id: parallel_fetch
    parallel: true
    steps:
      - id: fetch_users
        use: http.fetch
        with:
          url: "https://jsonplaceholder.typicode.com/users"

      - id: fetch_posts
        use: http.fetch
        with:
          url: "https://jsonplaceholder.typicode.com/posts"

      - id: fetch_comments
        use: http.fetch
        with:
          url: "https://jsonplaceholder.typicode.com/comments"

  - id: combine_results
    depends_on: [parallel_fetch]
    use: core.echo
    with:
      text: |
        Data Summary:
        - Users: {{ fetch_users | length }}
        - Posts: {{ fetch_posts | length }}
        - Comments: {{ fetch_comments | length }}
```

---

## ✅ Validation Rules

### Flow-Level Rules

1. **name** is REQUIRED
   - Must be non-empty
   - Only alphanumeric, `_`, `-`, `.` allowed

2. **steps** is REQUIRED
   - Must have at least one step

3. **on** is REQUIRED
   - Must be valid trigger type

4. **cron** is REQUIRED if `on: schedule.cron`
   - Must be valid 6-field cron expression

### Step-Level Rules

1. **id** is REQUIRED
   - Must be unique within flow
   - Only alphanumeric, `_`, `-` allowed (or template syntax)

2. Each step requires exactly ONE action (choose one):
   - **Tool execution**: `use: tool.name` (with `with: {params}`)
   - **Parallel block**: `parallel: true` + `steps: [...]`
   - **Loop**: `foreach: "{{ array }}"` + `as: var` + `do: [...]`
   - **Event wait**: `await_event: {source, match, timeout}`
   - **Time delay**: `wait: {seconds}` or `wait: {until}`

   Multiple action types cannot be combined in one step.

3. **Parallel constraints**:
   - `parallel: true` REQUIRES either `steps` OR (`foreach` + `as` + `do`)
   - Cannot combine `parallel` with `use`

4. **Foreach constraints**:
   - `foreach` REQUIRES both `as` and `do`
   - `foreach` expression MUST use template syntax: `{{ }}`
   - `as` must be valid identifier
   - Cannot combine `foreach` with `use`

5. **Conditional constraints**:
   - `if` MUST use template syntax: `{{ }}`

6. **Await event constraints**:
   - REQUIRES `source` (non-empty)
   - REQUIRES `match` (non-empty object)
   - `timeout` is optional

7. **Wait constraints**:
   - REQUIRES either `seconds` OR `until`

8. **Dependencies**:
   - All step IDs in `depends_on` must exist
   - No circular dependencies allowed

---

## 🎓 LLM Checklist

Before generating any BeemFlow workflow, verify:

### Structure
- [ ] Flow has `name` (REQUIRED)
- [ ] Flow has `on` trigger (REQUIRED)
- [ ] Flow has at least one `step` (REQUIRED)
- [ ] If `on: schedule.cron`, flow has `cron` field
- [ ] All step IDs are unique

### Steps
- [ ] Each step has exactly ONE action: tool execution (`use`), parallel block (`parallel` + `steps`), loop (`foreach` + `as` + `do`), event wait (`await_event`), or time delay (`wait`)
- [ ] Cannot combine multiple actions in one step (e.g., cannot have both `use` and `foreach`)
- [ ] Parallel steps have `steps` array OR `foreach`+`as`+`do`
- [ ] Foreach steps have both `as` and `do`
- [ ] Foreach expressions use `{{ }}` syntax
- [ ] Conditional (`if`) expressions use `{{ }}` syntax

### Templates
- [ ] All templates use `{{ }}` syntax (never `${}`)
- [ ] Array access uses bracket notation `[0]` (never `.0`)
- [ ] Use explicit namespaces: `vars.*`, `secrets.*`, `outputs.*`, `event.*`
- [ ] Loop variables: `item`, `item_index`, `item_row` (based on `as:` name)

### Dependencies
- [ ] All step IDs in `depends_on` exist
- [ ] No circular dependencies
- [ ] Understand that template references create implicit dependencies

### Tools
- [ ] Tool names are valid (check registry or use known tools)
- [ ] Tool parameters are correct for the tool
- [ ] OAuth tools use `secrets.*` for credentials

### Cron
- [ ] Cron expressions use 6-field format: `SEC MIN HOUR DAY MONTH DOW`
- [ ] Examples: `"0 0 9 * * *"` (daily 9am), `"0 30 8 * * 1-5"` (weekdays 8:30am)

### Common Mistakes to Avoid
- [ ] ❌ Don't use `${}`  syntax → ✅ Use `{{ }}`
- [ ] ❌ Don't use `.0` for arrays → ✅ Use `[0]`
- [ ] ❌ Don't use `||` for fallback → ✅ Use `or` or `| default()`
- [ ] ❌ Don't use 5-field cron → ✅ Use 6-field (includes seconds)
- [ ] ❌ Don't use `continue_on_error` → ✅ Use `catch` blocks
- [ ] ❌ Don't use `env.*` directly → ✅ Use `secrets.*`
- [ ] ❌ Don't use date filters or `now()` → ✅ Not available in Minijinja

---

## 📖 Additional Resources

- **Examples**: `/flows/examples/` - Production-ready examples
- **Integration Tests**: `/flows/integration/` - Complex patterns and edge cases
- **Registry**: `/registry/default.json` - Available tools
- **Schema**: `/docs/beemflow.schema.json` - JSON Schema validation

---

**Version**: 3.0.0
**Last Updated**: 2025-01-19
**Status**: Authoritative

**Runtime**: BeemFlow implements this spec with:
- YAML parsing (serde_yaml)
- Minijinja templating engine
- Automatic dependency detection
- Parallel execution with tokio
- SQLite/PostgreSQL storage
- OAuth credential management
- MCP server integration
