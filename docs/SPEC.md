# BeemFlow Language Specification

> **FOR LLMs**: Read this entire spec before generating BeemFlow workflows. The Quick Reference section is your primary guide.

---

## 🎯 Quick Reference (Read This First!)

### ✅ Valid YAML Structure
```yaml
name: string                    # REQUIRED
description: string             # optional - precise natural language representation of workflow logic
version: string                 # optional
on: trigger                     # REQUIRED (cli.manual, schedule.cron, event:topic, http.request)
cron: "0 9 * * 1-5"            # if on: schedule.cron
vars: {key: value}             # optional variables
steps: [...]                   # REQUIRED step array
catch: [...]                   # optional error handler
```

### ✅ Valid Step Fields (ONLY THESE EXIST!)
```yaml
- id: string                   # REQUIRED unique identifier
  use: tool.name               # Tool to execute
  with: {params}               # Tool input parameters
  if: "{{ expression }}"       # Conditional execution (GitHub Actions style)
  foreach: "{{ array }}"       # Loop over array
  as: item                     # Loop variable name
  do: [steps]                  # Steps to run in loop
  parallel: true               # Run nested steps in parallel
  steps: [steps]               # Steps for parallel block
  depends_on: [step_ids]       # Step dependencies
  retry: {attempts: 3, delay_sec: 5}  # Retry configuration
  await_event: {source: "x", match: {}, timeout: "24h"}  # Event wait
  wait: {seconds: 30}          # Time delay
```

### 📝 Template Syntax (Minijinja)
```yaml
# Variables & References (Always use explicit scopes!)
{{ vars.MY_VAR }}              # Flow variables
{{ secrets.USER }}                 # Environment variables  
{{ secrets.API_KEY }}          # Secrets
{{ event.field }}              # Event data
{{ outputs.step_id.field }}    # Step outputs (preferred)
{{ step_id.field }}            # Step outputs (shorthand)

# Array Access (Minijinja uses bracket notation)
{{ array[0] }}                  # First element
{{ array[idx] }}                # Variable index
{{ data.rows[0].name }}         # Nested access

# Filters & Operations
{{ text | upper }}             # Uppercase
{{ text | lower }}             # Lowercase
{{ array | length }}           # Length
{{ array | join(", ") }}        # Join array
{{ value | default('default') }}  # Default/fallback
{{ num + 10 }}                 # Math operations

# In Loops (BeemFlow provides these automatically)
{{ item }}                     # Current item (with 'as: item')
{{ item_index }}               # 0-based index (BeemFlow extension)
{{ item_row }}                 # 1-based index (BeemFlow extension)

# Conditions (MUST use template syntax)
if: "{{ vars.status == 'active' }}"           # Required format
if: "{{ vars.count > 5 and secrets.DEBUG }}"      # Complex conditions
if: "{{ not (vars.disabled) }}"               # Negation
```

### 🔧 Common Tools
```yaml
# Core
core.echo                      # Print text
core.wait                      # Pause execution

# HTTP
http.fetch                     # Simple GET request
http                          # Full HTTP control (any method)

# AI Services  
openai.chat_completion        # OpenAI GPT models
anthropic.chat_completion     # Anthropic Claude

# Google Sheets
google_sheets.values.get      # Read spreadsheet data
google_sheets.values.update   # Update cells
google_sheets.values.append   # Add new rows

# Other
slack.chat.postMessage        # Send Slack messages
mcp://server/tool             # MCP server tools
```

---

## 📚 Essential Patterns

### Basic Flow
```yaml
name: hello_world
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, BeemFlow!"
```

### Using Variables and Outputs
```yaml
name: fetch_and_process
on: cli.manual
vars:
  API_URL: "https://api.example.com"
steps:
  - id: fetch
    use: http.fetch
    with:
      url: "{{ vars.API_URL }}/data"
  - id: process
    use: core.echo
    with:
      text: "Result: {{ outputs.fetch.body }}"
```

### Conditional Execution
```yaml
# Simple condition
- id: conditional_step
  if: "{{ vars.status == 'active' }}"
  use: core.echo
  with:
    text: "Status is active"

# Complex conditions
- id: complex_check
  if: "{{ vars.count > 10 and secrets.NODE_ENV == 'production' }}"
  use: core.echo
  with:
    text: "Multiple conditions"

# Using outputs from previous steps
- id: check_result
  if: "{{ outputs.api_call.status_code == 200 }}"
  use: core.echo
  with:
    text: "API call succeeded"
```

### Loops (Foreach)
```yaml
- id: process_items
  foreach: "{{ vars.items }}"
  as: item
  do:
    - id: process_{{ item_index }}
      use: core.echo
      with:
        text: "Row {{ item_row }}: Processing {{ item }}"
    
    # Conditional processing in loops
    - id: conditional_{{ item_index }}
      if: "{{ item.status == 'active' }}"
      use: core.echo
      with:
        text: "Item {{ item.name }} is active"

# Array element access in loops
- id: process_rows
  foreach: "{{ sheet_data.values }}"
  as: row
  do:
    - id: check_row_{{ row_index }}
      if: "{{ row[0] and row[1] == 'approved' }}"
      use: core.echo
      with:
        text: "Processing: {{ row[0] }}"
```

### Parallel Execution
```yaml
- id: parallel_block
  parallel: true
  steps:
    - id: task1
      use: core.echo
      with:
        text: "Running in parallel"
    - id: task2
      use: http.fetch
      with:
        url: "https://api.example.com"
```

### Error Handling
```yaml
name: with_error_handling
on: cli.manual
steps:
  - id: risky_operation
    use: might.fail
    with:
      param: value
catch:
  - id: handle_error
    use: core.echo
    with:
      text: "Error occurred, cleaning up"
```

### API Integration
```yaml
- id: api_call
  use: http
  with:
    url: "https://api.example.com/endpoint"
    method: POST
    headers:
      Authorization: "Bearer {{ secrets.API_TOKEN }}"
      Content-Type: "application/json"
    body:
      query: "{{ vars.search_term }}"
      limit: 10
```

### Scheduled Flows (Cron)
```yaml
name: daily_report
version: 1.0.0
on: schedule.cron
cron: "0 0 9 * * *"  # 6-field format: SEC MIN HOUR DAY MONTH DOW
steps:
  - id: generate_report
    use: core.echo
    with:
      text: "Generating daily report at 9 AM"

# Multiple triggers (manual + scheduled)
name: flexible_flow
version: 1.0.0
on:
  - cli.manual
  - schedule.cron
cron: "0 0 */6 * * *"  # Every 6 hours
steps:
  - id: sync
    use: core.echo
    with:
      text: "Syncing data"
```

**Cron Expression Format (6 fields):**
```
SEC  MIN  HOUR  DAY  MONTH  DOW
0    0    9     *    *      *     # Daily at 9:00 AM
0    0    */6   *    *      *     # Every 6 hours
0    30   8     *    *      1-5   # Weekdays at 8:30 AM
0    0    0     1    *      *     # First of month at midnight
```

**Important:** Cron jobs only run when `flow serve` HTTP server is running.

### Google Sheets Example
```yaml
name: sheets_integration
on: cli.manual
vars:
  SHEET_ID: "{{ secrets.GOOGLE_SPREADSHEET_ID }}"
steps:
  - id: read_data
    use: google_sheets.values.get
    with:
      spreadsheetId: "{{ vars.SHEET_ID }}"
      range: "Sheet1!A1:D10"

  - id: append_row
    use: google_sheets.values.append
    with:
      spreadsheetId: "{{ vars.SHEET_ID }}"
      range: "Sheet1!A:D"
      valueInputOption: "USER_ENTERED"
      values:
        - ["Cell A", "Cell B", "Cell C", "Cell D"]
```

---

## 🏗️ Complete Data Model

This is the EXACT model BeemFlow supports (from Rust source):

```rust
pub struct Flow {
    pub name: String,                                  // REQUIRED
    pub description: Option<String>,                   // optional
    pub version: Option<String>,                       // optional
    pub on: Option<Trigger>,                           // REQUIRED
    pub cron: Option<String>,                          // for schedule.cron
    pub vars: Option<HashMap<String, Value>>,          // optional
    pub steps: Vec<Step>,                              // REQUIRED
    pub catch: Option<Vec<Step>>,                      // optional
}

pub struct Step {
    pub id: String,                                    // REQUIRED
    pub use_: Option<String>,                          // tool name (use)
    pub with: Option<HashMap<String, Value>>,          // tool inputs
    pub depends_on: Option<Vec<String>>,               // dependencies
    pub parallel: Option<bool>,                        // parallel block
    pub if_: Option<String>,                           // conditional (if)
    pub foreach: Option<String>,                       // loop array
    pub as_: Option<String>,                           // loop variable (as)
    pub do_: Option<Vec<Step>>,                        // loop steps (do)
    pub steps: Option<Vec<Step>>,                      // parallel steps
    pub retry: Option<RetrySpec>,                      // retry config
    pub await_event: Option<AwaitEventSpec>,           // event wait
    pub wait: Option<WaitSpec>,                        // time wait
}
// NO OTHER FIELDS EXIST!
```

---

## ✅ Validation Rules

A step must have ONE of:
- `use` - Execute a tool
- `parallel: true` with `steps` - Parallel block
- `foreach` with `as` and `do` - Loop
- `await_event` - Wait for event
- `wait` - Time delay

Constraints:
- `parallel: true` REQUIRES `steps` array
- `foreach` REQUIRES both `as` and `do`
- Cannot combine `use` with `parallel` or `foreach`
- `id` is always required and must be unique

---

## 🎓 LLM Checklist

Before generating any BeemFlow workflow:

- [ ] Check all step fields exist in the model above
- [ ] Use `{{ }}` for ALL templating (never `${}`)
- [ ] Array access uses bracket notation `[0]` (never `.0`)
- [ ] Use `catch` blocks for error handling (no `continue_on_error`)
- [ ] Use `or` operator or `| default()` filter for defaults (never `||`)
- [ ] Check tool names exist in registry
- [ ] Verify parallel blocks have `steps` array
- [ ] Confirm foreach has both `as` and `do`
- [ ] No date filters or now() function
- [ ] No timeout except in await_event

---

## 📝 Description Field Guidelines

The optional `description` field provides a precise natural language representation of the workflow logic. This is not just documentation—it's an exact specification that mirrors the workflow implementation.

### Purpose
- **Executable Documentation**: Someone should be able to implement the workflow from the description alone
- **AI Integration**: Enables AI agents (like BeemBeem) to understand and maintain workflows
- **Human Interface**: Provides clear business logic for non-technical stakeholders
- **Sync Validation**: Future tooling will verify description matches implementation

### Writing Guidelines

**✅ Good Description:**
```yaml
name: social_media_approval
description: |
  Generate social media content using AI, store it in Airtable for human review, 
  wait for approval status change, then post to Twitter and mark as completed.
  Handle timeout by notifying team via Slack.
```

**❌ Poor Description:**
```yaml
description: "This workflow handles social media posting"  # Too vague
description: "Uses OpenAI and Airtable"                    # Lists tools, not logic
```

### Best Practices
1. **Be Precise**: Describe the exact sequence and conditions
2. **Include Error Handling**: Mention catch blocks and timeouts
3. **Explain Business Logic**: Why steps happen, not just what happens
4. **Use Active Voice**: "Generate content" not "Content is generated"
5. **Mention Key Integrations**: Important external systems and their role

### Future Evolution
The BeemBeem AI agent will eventually:
- Validate description matches implementation
- Suggest updates when logic changes
- Generate workflows from descriptions
- Maintain sync between description and steps

---

## 📊 Tool Resolution Order

1. **Core adapters**: `core.echo`, `core.wait`
2. **Registry tools**: From `registry/default.json` or `.beemflow/registry.json`
3. **MCP servers**: `mcp://server/tool`
4. **HTTP adapter**: Generic `http` tool

Environment variables in tool manifests use: `$env:VAR_NAME`

---

## 🔗 Additional Resources

- **Examples**: `/flows/examples/` - Working examples
- **Tests**: `/flows/integration/` - Complex patterns
- **Registry**: `/registry/default.json` - Available tools
- **Schema**: `/docs/beemflow.schema.json` - JSON Schema validation

---

**Version**: 2.0.0 | **Last Updated**: 2024 | **Status**: Authoritative