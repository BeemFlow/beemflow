# Dynamic Bot Deployment Implementation Plan

## 🏗️ **Leveraging Existing BeemFlow Infrastructure**

Good news: BeemFlow already has most of what we need! Let's build on existing patterns:

### ✅ **Already Working:**
- `{{ secrets.SLACK_TOKEN }}` templating
- HTTP adapter for Slack API calls  
- Event-driven workflows with `await_event`
- MCP adapter for external integrations
- SQLite storage for state persistence

## 🚀 **Implementation: 4 Key Components**

### 1. **BeemBeem Chat Interface** (New Adapter)

```go
// Add to existing adapter system
type BeemBeemAdapter struct {
    engine      *engine.Engine
    slackClient *slack.Client
    botManager  *BotManager
}

func (b *BeemBeemAdapter) Execute(ctx context.Context, inputs map[string]any) (map[string]any, error) {
    action := inputs["__use"].(string)
    
    switch action {
    case "beembeem.chat":
        return b.handleConversation(inputs)
    case "beembeem.create_workflow":
        return b.createWorkflow(inputs)
    case "beembeem.deploy_bot":
        return b.deployBot(inputs)
    case "beembeem.manage_bots":
        return b.manageBots(inputs)
    }
}
```

### 2. **Bot Management Storage** (Extend existing SQLite)

```sql
-- Add to existing BeemFlow database
CREATE TABLE deployed_bots (
    id TEXT PRIMARY KEY,
    workflow_name TEXT NOT NULL,
    slack_app_id TEXT NOT NULL,
    bot_token_secret_key TEXT NOT NULL,  -- Points to secrets system
    bot_user_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bot_conversations (
    id TEXT PRIMARY KEY,
    bot_id TEXT REFERENCES deployed_bots(id),
    slack_channel TEXT NOT NULL,
    conversation_context TEXT, -- JSON blob
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 3. **Slack Management Integration** (New HTTP Tools)

```yaml
# Add to registry/index.json (reuse existing HTTP pattern)
tools:
  - name: slack.management.create_app
    endpoint: "https://api.slack.com/api/apps.manifest.create"
    method: POST
    headers:
      Authorization: "Bearer {{ secrets.SLACK_MANAGEMENT_TOKEN }}"
      Content-Type: "application/json"
    
  - name: slack.management.update_app  
    endpoint: "https://api.slack.com/api/apps.manifest.update"
    method: POST
    headers:
      Authorization: "Bearer {{ secrets.SLACK_MANAGEMENT_TOKEN }}"
      Content-Type: "application/json"
```

### 4. **Dynamic Workflow-Bot Creation** (New Core Functions)

```go
type BotManager struct {
    storage     storage.Storage
    slackClient *slack.Client
    engine      *engine.Engine
}

func (bm *BotManager) DeployWorkflowBot(workflow *model.Flow, userID string) (*DeployedBot, error) {
    // 1. Generate Slack app manifest
    manifest := bm.generateAppManifest(workflow)
    
    // 2. Create app via existing HTTP adapter pattern
    createAppFlow := &model.Flow{
        Name: "create_slack_app",
        Steps: []model.Step{
            {
                ID:  "create_app",
                Use: "slack.management.create_app",
                With: map[string]any{
                    "manifest": manifest,
                },
            },
        },
    }
    
    // 3. Execute via existing engine
    result, err := bm.engine.Run(context.Background(), createAppFlow, nil)
    if err != nil {
        return nil, err
    }
    
    // 4. Store in database
    bot := &DeployedBot{
        ID:           uuid.New().String(),
        WorkflowName: workflow.Name,
        SlackAppID:   result["create_app"].(map[string]any)["app_id"].(string),
        CreatedBy:    userID,
    }
    
    return bot, bm.storage.SaveDeployedBot(bot)
}
```

## 📝 **BeemBeem Conversation Workflows**

Instead of building a custom chat system, use BeemFlow workflows for conversations:

```yaml
# beembeem_create_workflow.flow.yaml
name: beembeem_create_workflow
on: slack.mention
steps:
  - id: understand_intent
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: |
            You are BeemBeem, a helpful AI assistant. The user wants to create a workflow.
            Ask clarifying questions to understand what they want to automate.
            Keep responses friendly and conversational.
        - role: user
          content: "{{ event.text }}"
  
  - id: respond_to_user
    use: slack.chat.postMessage
    with:
      channel: "{{ event.channel }}"
      text: "{{ understand_intent.choices.0.message.content }}"
      thread_ts: "{{ event.ts }}"
  
  - id: await_user_response
    await_event:
      source: slack
      match:
        channel: "{{ event.channel }}"
        thread_ts: "{{ event.ts }}"
      timeout: 10m
  
  - id: continue_conversation
    use: beembeem.chat
    with:
      conversation_history: "{{ outputs }}"
      user_message: "{{ event.text }}"
```

## 🔧 **Secret Management Integration**

Extend existing secrets system to handle dynamic bot tokens:

```go
// Extend existing secrets system
func (bm *BotManager) StoreBotToken(botID, token string) error {
    secretKey := fmt.Sprintf("DEPLOYED_BOT_%s_TOKEN", botID)
    
    // Use existing secrets backend (will be AWS vault)
    return bm.secretsManager.Store(secretKey, token)
}

// In workflows, reference dynamically
func (bm *BotManager) generateBotWorkflow(botID string) *model.Flow {
    return &model.Flow{
        Steps: []model.Step{
            {
                ID:  "post_message",
                Use: "slack.chat.postMessage",
                With: map[string]any{
                    "token": fmt.Sprintf("{{ secrets.DEPLOYED_BOT_%s_TOKEN }}", botID),
                    "channel": "{{ event.channel }}",
                    "text": "{{ generated_content }}",
                },
            },
        },
    }
}
```

## 🎯 **User Experience Flow Implementation**

### Step 1: BeemBeem Conversation
```yaml
# User: "@BeemBeem create a CFO bot"
# Triggers: beembeem_create_workflow.flow.yaml

- id: extract_intent
  use: openai.chat_completion
  with:
    messages:
      - role: system
        content: "Extract what type of bot the user wants: {{ event.text }}"

- id: start_workflow_creation
  if: "{{ extract_intent.choices.0.message.content | contains 'CFO' }}"
  use: beembeem.create_workflow
  with:
    bot_type: "CFO"
    user_id: "{{ event.user }}"
    channel: "{{ event.channel }}"
```

### Step 2: Dynamic Bot Deployment
```yaml
# When workflow is complete, deploy the bot
- id: deploy_cfo_bot
  use: beembeem.deploy_bot
  with:
    workflow_name: "cfo_daily_reports"
    bot_name: "CFO-Bot"
    created_by: "{{ event.user }}"

- id: send_install_link
  use: slack.chat.postMessage
  with:
    channel: "{{ event.channel }}"
    text: |
      🎉 CFO-Bot is ready! Click to install: {{ deploy_cfo_bot.install_url }}
      
      After installing, try: @CFO-Bot run daily report
```

### Step 3: Bot Management
```yaml
# User: "@BeemBeem list my bots"
name: beembeem_list_bots
steps:
  - id: get_user_bots
    use: beembeem.manage_bots
    with:
      action: "list"
      user_id: "{{ event.user }}"
  
  - id: format_bot_list
    use: openai.chat_completion
    with:
      messages:
        - role: system
          content: "Format this bot list nicely: {{ get_user_bots.bots }}"
  
  - id: respond
    use: slack.chat.postMessage
    with:
      channel: "{{ event.channel }}"
      text: "{{ format_bot_list.choices.0.message.content }}"
```

## 🗂️ **File Structure Integration**

```
beemflow/
├── adapter/
│   ├── beembeem_adapter.go     # New: conversation handling
│   ├── slack_management.go     # New: Slack Management API
│   └── ... existing adapters
├── storage/
│   ├── bot_storage.go          # New: deployed bot persistence
│   └── ... existing storage
├── flows/
│   ├── beembeem/               # New: BeemBeem conversation flows
│   │   ├── create_workflow.flow.yaml
│   │   ├── deploy_bot.flow.yaml
│   │   └── manage_bots.flow.yaml
│   └── ... existing flows
└── registry/
    ├── beembeem_tools.json     # New: BeemBeem-specific tools
    └── ... existing registry
```

## 🔑 **Required Secrets (AWS Vault Integration)**

```bash
# Secrets that will be stored in AWS vault
SLACK_MANAGEMENT_TOKEN=xoxp-...           # For creating apps
BEEMBEEM_BOT_TOKEN=xoxb-...              # Main BeemBeem bot
DEPLOYED_BOT_{BOT_ID}_TOKEN=xoxb-...     # Dynamic bot tokens
OPENAI_API_KEY=sk-...                    # For conversations
```

## 📊 **Implementation Timeline**

### Week 1: Foundation
- [ ] Extend storage with bot tables
- [ ] Create BeemBeem adapter skeleton
- [ ] Add Slack Management API tools to registry
- [ ] Basic conversation workflow

### Week 2: Dynamic Deployment
- [ ] Bot manager implementation
- [ ] Slack app manifest generation
- [ ] Dynamic bot creation pipeline
- [ ] Token storage integration

### Week 3: Conversation System
- [ ] Multi-turn conversation workflows
- [ ] Workflow creation assistance
- [ ] Bot deployment user experience
- [ ] Error handling and recovery

### Week 4: Bot Management
- [ ] List/update/delete deployed bots
- [ ] Bot workflow updating
- [ ] Demo scenarios and testing
- [ ] Documentation

## ✅ **Success Criteria**

- [ ] User can chat with @BeemBeem to create workflows
- [ ] @BeemBeem can deploy real @mentionable bots
- [ ] Deployed bots can be updated via @BeemBeem
- [ ] All secrets handled securely via existing system
- [ ] Zero changes needed to core BeemFlow engine

This approach maximally reuses existing BeemFlow infrastructure while adding the conversational AI and dynamic deployment capabilities you want!