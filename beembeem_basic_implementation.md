# BeemBeem Basic Slack Bot Implementation

## 🎯 **MVP Goal: Conversational Workflow Generation**

Let's start with the core value: a Slack bot that can chat with users to understand their needs and generate BeemFlow workflows.

## 🛠️ **What We Need to Build**

### 1. **Basic Slack Integration** (Leverage existing patterns)
- Slack webhook endpoint for receiving messages
- Slack API calls using existing HTTP adapter
- Event bus integration for message handling

### 2. **Conversational Workflow Engine** (Pure BeemFlow workflows)
- Multi-turn conversation using `await_event`
- Context tracking between messages
- LLM-powered workflow generation

### 3. **Workflow Deployment** (File-based for now)
- Save generated workflows to `flows/` directory
- Basic workflow validation
- Success confirmation to user

## 🏗️ **Implementation Plan**

### Step 1: Slack Webhook Handler (New HTTP endpoint)

```go
// Add to existing HTTP server
func (s *Server) handleSlackEvents(w http.ResponseWriter, r *http.Request) {
    var event slack.EventsAPIEvent
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // URL verification for Slack app setup
    if event.Type == slack.URLVerification {
        w.Header().Set("Content-Type", "text/plain")
        w.Write([]byte(event.Challenge))
        return
    }
    
    // Convert Slack event to BeemFlow event
    if event.Type == slack.CallbackEvent {
        beemflowEvent := convertSlackToBeemFlowEvent(event)
        s.engine.EventBus.Publish("slack.message", beemflowEvent)
    }
    
    w.WriteHeader(http.StatusOK)
}

func convertSlackToBeemFlowEvent(slackEvent slack.EventsAPIEvent) map[string]any {
    if msgEvent, ok := slackEvent.InnerEvent.Data.(*slack.MessageEvent); ok {
        return map[string]any{
            "type":      "slack.message",
            "user":      msgEvent.User,
            "channel":   msgEvent.Channel,
            "text":      msgEvent.Text,
            "timestamp": msgEvent.TimeStamp,
            "thread_ts": msgEvent.ThreadTimeStamp,
        }
    }
    return nil
}
```

### Step 2: BeemBeem Conversation Workflow

```yaml
# flows/beembeem/conversation.flow.yaml
name: beembeem_conversation
on: 
  - event: slack.message
steps:
  # Only respond to @BeemBeem mentions
  - id: check_mention
    if: "{{ event.text | contains '@BeemBeem' or event.text | contains 'beembeem' }}"
    use: core.echo
    with:
      text: "BeemBeem mentioned!"
  
  # Extract user intent
  - id: understand_intent
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: |
            You are BeemBeem, a friendly AI assistant that helps create workflow automations.
            
            Your goal is to understand what the user wants to automate and help them build it.
            
            Respond in a conversational, helpful tone. Ask clarifying questions to understand:
            - What process they want to automate
            - What tools/systems are involved
            - What triggers should start the automation
            - What the desired outcome is
            
            Keep responses concise and focused.
        - role: user
          content: "{{ event.text }}"
  
  # Respond to user
  - id: respond_to_user
    use: slack.chat.postMessage
    with:
      channel: "{{ event.channel }}"
      text: "{{ understand_intent.choices.0.message.content }}"
      thread_ts: "{{ event.thread_ts or event.timestamp }}"
  
  # Wait for user response (if this is the start of a conversation)
  - id: await_response
    if: "{{ not event.thread_ts }}"  # Only if not already in thread
    await_event:
      source: slack.message
      match:
        channel: "{{ event.channel }}"
        thread_ts: "{{ event.timestamp }}"  # Now we're in a thread
      timeout: 30m
  
  # Continue conversation recursively
  - id: continue_conversation
    if: "{{ await_response }}"
    use: beembeem.continue_chat
    with:
      conversation_context: |
        Previous messages:
        User: {{ event.text }}
        BeemBeem: {{ understand_intent.choices.0.message.content }}
        User: {{ await_response.text }}
      channel: "{{ event.channel }}"
      thread_ts: "{{ event.timestamp }}"
```

### Step 3: Workflow Generation Tool

```yaml
# flows/beembeem/generate_workflow.flow.yaml  
name: beembeem_generate_workflow
on: manual  # Triggered by conversation flow
steps:
  - id: generate_workflow_yaml
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: |
            You are an expert at creating BeemFlow workflows. Generate a complete, valid YAML workflow based on the user's requirements.
            
            Use this template structure:
            ```yaml
            name: workflow_name
            on: [trigger_type]
            vars:
              key: value
            steps:
              - id: step_id
                use: tool_name
                with:
                  param: value
            ```
            
            Available tools include:
            - openai.chat_completion (AI/LLM tasks)
            - http.fetch (HTTP requests)
            - slack.chat.postMessage (Slack messaging)
            - core.echo (simple output)
            
            Make sure the workflow is:
            1. Syntactically correct YAML
            2. Uses real BeemFlow tools
            3. Includes proper templating with {{ }}
            4. Has descriptive step IDs
            
            Only return the YAML workflow, no other text.
        - role: user
          content: "{{ inputs.user_requirements }}"
  
  - id: validate_workflow
    use: beembeem.validate_workflow
    with:
      workflow_yaml: "{{ generate_workflow_yaml.choices.0.message.content }}"
  
  - id: save_workflow
    if: "{{ validate_workflow.valid }}"
    use: beembeem.save_workflow
    with:
      workflow_yaml: "{{ generate_workflow_yaml.choices.0.message.content }}"
      workflow_name: "{{ inputs.workflow_name }}"
  
  - id: respond_success
    if: "{{ validate_workflow.valid }}"
    use: slack.chat.postMessage
    with:
      channel: "{{ inputs.channel }}"
      thread_ts: "{{ inputs.thread_ts }}"
      text: |
        🎉 Workflow created successfully!
        
        **{{ inputs.workflow_name }}**
        ```yaml
        {{ generate_workflow_yaml.choices.0.message.content }}
        ```
        
        You can now run it with: `flow run {{ inputs.workflow_name }}`
  
  - id: respond_error
    if: "{{ not validate_workflow.valid }}"
    use: slack.chat.postMessage
    with:
      channel: "{{ inputs.channel }}"
      thread_ts: "{{ inputs.thread_ts }}"
      text: |
        ❌ Workflow validation failed: {{ validate_workflow.error }}
        Let me try again with your requirements.
```

### Step 4: BeemBeem Adapter (New)

```go
// adapter/beembeem_adapter.go
package adapter

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    
    "github.com/awantoch/beemflow/registry"
    "gopkg.in/yaml.v2"
)

type BeemBeemAdapter struct {
    AdapterID string
}

func (b *BeemBeemAdapter) ID() string {
    return "beembeem"
}

func (b *BeemBeemAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    action := inputs["__use"].(string)
    
    switch action {
    case "beembeem.continue_chat":
        return b.continueChat(inputs)
    case "beembeem.validate_workflow":
        return b.validateWorkflow(inputs)
    case "beembeem.save_workflow":
        return b.saveWorkflow(inputs)
    default:
        return nil, fmt.Errorf("unknown BeemBeem action: %s", action)
    }
}

func (b *BeemBeemAdapter) continueChat(inputs map[string]any) (map[string]any, error) {
    // For now, just trigger the conversation workflow again
    // TODO: Implement proper context management
    return map[string]any{
        "status": "continued",
        "message": "Conversation continued",
    }, nil
}

func (b *BeemBeemAdapter) validateWorkflow(inputs map[string]any) (map[string]any, error) {
    workflowYAML := inputs["workflow_yaml"].(string)
    
    // Basic YAML validation
    var workflow map[string]any
    if err := yaml.Unmarshal([]byte(workflowYAML), &workflow); err != nil {
        return map[string]any{
            "valid": false,
            "error": fmt.Sprintf("Invalid YAML: %v", err),
        }, nil
    }
    
    // Check required fields
    if _, ok := workflow["name"]; !ok {
        return map[string]any{
            "valid": false,
            "error": "Missing required field: name",
        }, nil
    }
    
    if _, ok := workflow["steps"]; !ok {
        return map[string]any{
            "valid": false,
            "error": "Missing required field: steps",
        }, nil
    }
    
    return map[string]any{
        "valid": true,
    }, nil
}

func (b *BeemBeemAdapter) saveWorkflow(inputs map[string]any) (map[string]any, error) {
    workflowYAML := inputs["workflow_yaml"].(string)
    workflowName := inputs["workflow_name"].(string)
    
    // Clean up workflow name for filename
    filename := strings.ReplaceAll(workflowName, " ", "_")
    filename = strings.ToLower(filename) + ".flow.yaml"
    
    // Save to flows directory
    flowsDir := "flows/generated"
    if err := os.MkdirAll(flowsDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create flows directory: %v", err)
    }
    
    filepath := filepath.Join(flowsDir, filename)
    if err := os.WriteFile(filepath, []byte(workflowYAML), 0644); err != nil {
        return nil, fmt.Errorf("failed to save workflow: %v", err)
    }
    
    return map[string]any{
        "saved": true,
        "filepath": filepath,
        "filename": filename,
    }, nil
}

func (b *BeemBeemAdapter) Manifest() *registry.ToolManifest {
    return &registry.ToolManifest{
        Name:        "beembeem",
        Description: "BeemBeem AI assistant for workflow creation and management",
        Kind:        "assistant",
    }
}
```

### Step 5: Slack Tools in Registry

```json
// Add to registry/index.json
{
  "tools": [
    {
      "name": "slack.chat.postMessage",
      "description": "Post a message to a Slack channel",
      "kind": "communication",
      "parameters": {
        "type": "object",
        "properties": {
          "channel": {
            "type": "string",
            "description": "Channel ID or name"
          },
          "text": {
            "type": "string", 
            "description": "Message text"
          },
          "thread_ts": {
            "type": "string",
            "description": "Thread timestamp for replies"
          }
        },
        "required": ["channel", "text"]
      },
      "endpoint": "https://slack.com/api/chat.postMessage",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer {{ secrets.SLACK_BOT_TOKEN }}",
        "Content-Type": "application/json"
      }
    }
  ]
}
```

## 🔧 **Setup Instructions**

### 1. Create Slack App
```bash
# Create new Slack app at api.slack.com
# Add Bot Token Scopes: chat:write, app_mentions:read, channels:read
# Add Event Subscriptions: app_mention, message.channels
# Set Request URL: https://your-beemflow-server.com/slack/events
```

### 2. Add Environment Variables
```bash
# Add to .env
SLACK_BOT_TOKEN=xoxb-your-bot-token
OPENAI_API_KEY=sk-your-openai-key
```

### 3. Register BeemBeem Adapter
```go
// In engine/engine.go NewDefaultAdapterRegistry()
reg.Register(&adapter.BeemBeemAdapter{})
```

### 4. Add Slack Events Endpoint
```go
// In http/http.go or similar
mux.HandleFunc("/slack/events", handleSlackEvents)
```

## 🎯 **User Experience**

```
User: "@BeemBeem help me automate our daily standup reports"

BeemBeem: "I'd love to help automate your standup reports! 🚀 

A few questions to get started:
- What info should be included? (blockers, progress, goals?)
- Where does the data come from? (Jira, GitHub, manual input?)
- When should it run? (daily at 9am, on-demand?)
- Where should it post? (this channel, #standup?)"

User: "Daily at 9am, pull from Jira for blockers and post to #standup"

BeemBeem: "Perfect! Creating a workflow that:
✅ Runs daily at 9am
✅ Fetches blockers from Jira  
✅ Posts formatted standup to #standup

One moment while I generate this..."

[Generates and saves workflow]

BeemBeem: "🎉 Workflow created: daily_standup_report.flow.yaml
You can test it with: `flow run daily_standup_report`"
```

## 📊 **Success Criteria**

- [ ] User can @mention BeemBeem in Slack
- [ ] BeemBeem responds conversationally 
- [ ] Multi-turn conversations work (threading)
- [ ] BeemBeem can generate valid workflow YAML
- [ ] Generated workflows are saved to files
- [ ] Basic error handling and validation

This gives us a solid foundation that's immediately useful and can be extended later with bot deployment capabilities!