# BeemFlow Language Specification

> **FOR LLMs**: Read this entire spec before generating BeemFlow workflows. The Quick Reference section is your primary guide.

---

## 🎯 Quick Reference (Read This First!)

### ✅ Valid CUE Structure
```cue
package beemflow

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
```cue
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

### ❌ THESE DON'T EXIST (Common Hallucinations)
```cue
continue_on_error: true  # ❌ NO - Use catch blocks instead
timeout: 30s            # ❌ NO - Only exists in await_event.timeout
on_error: handler       # ❌ NO - Use catch blocks
on_success: next        # ❌ NO - Doesn't exist
${ variable }           # ❌ NO - Use {{ variable }}
{{ now() }}             # ❌ NO - No function calls
{{ 'now' | date }}      # ❌ NO - No date filter
{{ var | default:'x' }} # ❌ NO - Use {{ var || 'x' }}
break, continue, exit   # ❌ NO - No flow control keywords
```

### 📝 Template Syntax (Consistent `{{ }}` for all runtime values)

**Note:** BeemFlow uses `{{ }}` for ALL runtime template resolution. While CUE also supports `\(expr)` for static interpolation, we recommend using `{{ }}` consistently for better readability and a unified syntax.

```cue
# Variables & References (Always use explicit scopes!)
{{ vars.MY_VAR }}              # Flow variables
{{ env.USER }}                 # Environment variables  
{{ secrets.API_KEY }}          # Secrets
{{ event.field }}              # Event data
{{ outputs.step_id.field }}    # Step outputs (preferred)
{{ step_id.field }}            # Step outputs (shorthand)

# Array Access (CUE uses square brackets)
{{ array[0] }}                 # First element
{{ array[idx] }}               # Variable index
{{ data.rows[0].name }}        # Nested access (square brackets for arrays)

# Filters & Operations
{{ text | upper }}             # Uppercase
{{ text | lower }}             # Lowercase
{{ array | length }}           # Length
{{ array | join:", " }}        # Join array
{{ value || 'default' }}       # Default/fallback (NOT |default)
{{ num + 10 }}                 # Math operations

# In Loops (BeemFlow provides these automatically)
{{ item }}                     # Current item (with 'as: item')
{{ item_index }}               # 0-based index (BeemFlow extension)
{{ item_row }}                 # 1-based index (BeemFlow extension)

# Conditions (MUST use template syntax)
if: "{{ vars.status == 'active' }}"           # Required format
if: "{{ vars.count > 5 and env.DEBUG }}"      # Complex conditions
if: "{{ not (vars.disabled) }}"               # Negation
```

### 🔧 Common Tools
```cue
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
```cue
package beemflow

name: hello_world
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, BeemFlow!"
```

### Using Variables and Outputs
```cue
package beemflow

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
```cue
# Simple condition
- id: conditional_step
  if: "{{ vars.status == 'active' }}"
  use: core.echo
  with:
    text: "Status is active"

# Complex conditions
- id: complex_check
  if: "{{ vars.count > 10 and env.NODE_ENV == 'production' }}"
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
```cue
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
      if: "{{ row.0 and row.1 == 'approved' }}"
      use: core.echo
      with:
        text: "Processing: {{ row.0 }}"
```

### Parallel Execution
```cue
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
```cue
package beemflow

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
```cue
- id: api_call
  use: http
  with:
    url: "https://api.example.com/endpoint"
    method: POST
    headers:
      Authorization: "Bearer {{ env.API_TOKEN }}"
      Content-Type: "application/json"
    body:
      query: "{{ vars.search_term }}"
      limit: 10
```

### Google Sheets Example
```cue
package beemflow

name: sheets_integration
on: cli.manual
vars:
  SHEET_ID: "{{ env.GOOGLE_SPREADSHEET_ID }}"
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

## 🚫 Common Mistakes to Avoid

| Wrong | Right | Explanation |
|-------|-------|-------------|
| `${ var }` | `{{ var }}` | BeemFlow uses Pongo2 syntax |
| `if: "status == 'active'"` | `if: "{{ vars.status == 'active' }}"` | Must use template syntax & explicit scopes |
| `{{ data.rows[0].name }}` | `{{ data.rows.0.name }}` | Pongo2 uses dot notation throughout |
| `continue_on_error: true` | Use `catch` blocks | Field doesn't exist |
| `{{ now() }}` | Use a variable | No function calls |
| `{{ item \| default:'x' }}` | `{{ item \|\| 'x' }}` | Use \|\| operator |
| `timeout: 30` on step | Only in `await_event` | Not a general step field |
| `on_error: cleanup` | Use `catch` blocks | No step-level error handlers |

---

## 🏗️ Complete Data Model

This is the EXACT model BeemFlow supports (from Go source):

```go
type Flow struct {
    Name        string         `yaml:"name"`        // REQUIRED
    Description string         `yaml:"description"` // optional
    Version     string         `yaml:"version"`     // optional
    On          any            `yaml:"on"`          // REQUIRED
    Cron        string         `yaml:"cron"`        // for schedule.cron
    Vars        map[string]any `yaml:"vars"`        // optional
    Steps       []Step         `yaml:"steps"`       // REQUIRED
    Catch       []Step         `yaml:"catch"`       // optional
}

type Step struct {
    ID         string          `yaml:"id"`         // REQUIRED
    Use        string          `yaml:"use"`        // tool name
    With       map[string]any  `yaml:"with"`       // tool inputs
    DependsOn  []string        `yaml:"depends_on"` // dependencies
    Parallel   bool            `yaml:"parallel"`   // parallel block
    If         string          `yaml:"if"`         // conditional
    Foreach    string          `yaml:"foreach"`    // loop array
    As         string          `yaml:"as"`         // loop variable
    Do         []Step          `yaml:"do"`         // loop steps
    Steps      []Step          `yaml:"steps"`      // parallel steps
    Retry      *RetrySpec      `yaml:"retry"`      // retry config
    AwaitEvent *AwaitEventSpec `yaml:"await_event"` // event wait
    Wait       *WaitSpec       `yaml:"wait"`       // time wait
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
- [ ] Use `catch` blocks for error handling (no `continue_on_error`)
- [ ] Use `||` for defaults (not `|default` filter)
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
```cue
package beemflow

name: social_media_approval
description: |
  Generate social media content using AI, store it in Airtable for human review,
  wait for approval status change, then post to Twitter and mark as completed.
  Handle timeout by notifying team via Slack.
```

**❌ Poor Description:**
```cue
package beemflow

name: social_media_approval
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