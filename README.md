# BeemFlow 🚀
### The Open Protocol for AI-Powered, Event-Driven Automations

[![Star](https://img.shields.io/github/stars/awantoch/beemflow?style=social)](https://github.com/awantoch/beemflow) [![Join our Discord](https://img.shields.io/discord/000000000000000000?label=Community)](https://discord.gg/your-invite)

**TL;DR:** Write, share, and run AI-driven workflows in YAML. 100% open, Git-friendly, vendor-neutral.

---

## 🌟 Why Now?

AI is everywhere. APIs are everywhere. Yet automation is still stuck in siloed, proprietary platforms. It's time for a revolution.

Meet **BeemFlow** – the *Dockerfile* for AI workflows:

- Text-first, Git-diffable, versioned in Git
- Vendor-neutral: run on cloud, self-hosted, or embed anywhere
- Community-driven: remix, share, and build on top
- Extensible: plug in LLMs, webhooks, cron, custom adapters

**Stop clicking drag-n-drop—start coding powerful flows!**

---

## 🔥 Key Highlights

1. **YAML-First**: Human-readable, Git-friendly, zero-lock-in
2. **AI-Native**: LLM chat, function calls, code executions
3. **Control Flow**: `if`, `foreach`, `parallel`, retries & back-offs
4. **Durable Waits**: Pause for external callbacks, resume seamlessly
5. **Pluggable Tools**: JSON-Schema–based manifests, local & hub discovery
6. **MCP Client**: **BeemFlow is a true MCP client**—it can connect to any MCP server (Node.js, Python, Go, etc.), dynamically discover tools at runtime via the `tools/list` method, and invoke them via `tools/call`, supporting both HTTP and stdio transports. Configure server installation, environment variables, and ports under the `mcp_servers` section of your runtime config for transparent auto-installation and startup. No static manifest is required for MCP tools; BeemFlow uses the schema provided by the server, or allows raw JSON if none is present.
7. **Any Backend**: Postgres, S3, Redis, SQLite, in-memory
8. **CLI & API**: Lint, run, serve, graph, scaffold—dev workflow optimized

---

## 🔍 Spec Primer

BeemFlow flows are defined in a single YAML file with a concise, expressive grammar:

Top-level keys:
- **name** (string, required)
- **version** (semver, optional)
- **on** (trigger list or object): supports `event`, `cron`, `eventbus`, `cli`
- **vars** (map): static constants or secret references
- **steps** (ordered map): label → step definition
- **catch** (map): global error handlers

Step definition keys:
- `use`: tool identifier (JSON-Schema manifest)
- `with`: input arguments for the tool
- `if`: conditional expression to skip or branch
- `foreach`: loop over an array
  - `as`: loop variable
  - `do`: nested sequence of steps
- `parallel`: fan-out / fan-in list of step paths
- `retry`: `{ attempts: n, delay_sec: m }`
- `await_event`: durable wait on external callback
  - `source`, `match`, `timeout`
- `wait`: sleep for `{ seconds: n }` or `{ until: ts }`

Templating & helpers:
- Interpolate values with `{{ … }}` (access `event`, `vars`, previous outputs)
- Built-in functions: `now()`, `duration(n,'unit')`, `join()`, `map()`, `length()`, `base64()`, etc.

Tool identifier resolution (in order):
1. Local manifests (`tools/<name>.json`)
2. Community hub indexes (e.g. https://hub.beemflow.com)
3. MCP servers (`mcp://server/tool`)
4. GitHub shorthand (`github:owner/repo[/path][@ref]`)

### MCP Tool Example (No Manifest Required)

You can use any MCP tool directly, even if no static manifest is present. BeemFlow will discover the tool and its schema at runtime:

```yaml
steps:
  - query_supabase:
      use: mcp://supabase-mcp.cursor.directory/supabase.query
      with:
        sql: "SELECT * FROM users"
```

BeemFlow will:
1. Connect to the MCP server at `supabase-mcp.cursor.directory`.
2. Call `tools/list` to discover available tools and their schemas.
3. Call `tools/call` with the tool name and arguments.
4. Return the result as the step output.

---

## 💡 25 High-Value Use Cases
- Automate Shopify order fulfillment: payment → shipping label → CRM update → customer notification
- Proactively prevent customer churn: daily risk scoring → personalized win-back emails → CRM flags
- Launch multi-channel marketing from one spec: Airtable → Twitter, Instagram, Facebook
- Publish GitHub release notes to Notion, CMS, Twitter & email
- Syndicate tweets to Instagram with AI-tailored captions
- Process e-commerce returns & refunds: webhook → Stripe refund → email & Slack alert
- Close books monthly: pull bank transactions → draft Xero journals → send reminders
- Dispatch field technicians: geo-match on-call tech → calendar invite → status update
- Onboard new users: create accounts → send welcome emails → Slack notifications
- Roll out feature flags: schedule toggles → monitor metrics → auto-roll back
- Auto-remediate incidents: detect errors → trigger fix script → report results
- Monitor social sentiment: analyze tweets → classify sentiment → alert teams
- Run NPS surveys: send surveys → collect responses → summarize insights
- Triage support tickets: classify requests → assign priority → notify teams
- Qualify leads: enrich via Clearbit → score leads → generate CRM tasks
- Adjust pricing in real time: analyze demand signals → update price → notify ops
- Automate billing & reminders: generate invoices → send emails → update records
- Generate compliance reports: extract data → format PDF → archive logs
- Streamline KYC flows: collect documents → verify identity → update user status
- Orchestrate data pipelines: ETL on schedule → transform → load into warehouse
- Automate HR onboarding: create accounts → assign permissions → send orientation materials
- Manage webinars: handle registrations → calendar invites → follow-up email series
- Monitor IoT devices: collect telemetry → detect anomalies → trigger alerts
- AI-powered code review: analyze PRs → post comments → notify authors
- Q&A chatbot for internal docs: fetch docs → answer Slack queries

## 💰 Cost Savings & ROI
- Replace 6–10 automation services (Zapier, Make, n8n, etc.) at $200/mo each with one BeemFlow stack: save $14K–$17K per department/year.
- Consolidating 10 custom connectors saves $150K–$300K in engineering costs.
- Eliminates per-tool security and maintenance overhead: ~$50K in annual ops savings.
- **Total First-Year Savings** for a 5-team org: $300K–$500K; ROI in under 3 months.

---

## 🛑 Consolidate & Orchestrate Core Services
- **Integration & Orchestration** (Zapier, Make, n8n, Workato): Consolidate multi-API workflows into version-controlled YAML flows with built-in retries, parallelism, and durable waits.
- **Data Ingestion & ETL** (Fivetran, Stitch, Matillion, Talend): Schedule SQL extracts, apply LLM-powered transforms, and load into your data warehouse—no more separate ETL pipelines or ETL tool subscriptions.
- **CRM & Marketing Workflows** (Salesforce Flow, HubSpot Workflows, Pardot): Automate lead routing, scoring, nurture sequences, and record updates as code, with full audit trails and no extra automation seats.
- **Billing & Invoicing** (Stripe Billing, QuickBooks, Xero): Create invoices, capture payments, reconcile records, and trigger follow-up notifications—all with one central flow.
- **Monitoring & Auto-Remediation** (Datadog, Prometheus, Grafana): Query metrics, detect anomalies, auto-scale or rollback services, and alert on-call engineers automatically.
- **Incident Response & Alerts** (PagerDuty, Opsgenie, VictorOps): Route alerts based on dynamic thresholds, invoke remediation scripts, and notify stakeholders via Slack or email.
- **Email Campaign Automation** (Mailchimp, SendGrid, Campaign Monitor): Generate, personalize, and schedule targeted email campaigns programmatically via your ESP API—no builders required.
- **Social Media Automation** (Hootsuite, Buffer, Sprout Social): Cross-post to multiple platforms with AI-generated captions and track engagement within a single flow.
- **Report Automation** (Metabase, Looker, Mode Analytics): Execute scheduled queries, format results into PDFs or dashboards, and distribute to stakeholders without manual intervention.
- **CI/CD Job Orchestration** (GitHub Actions, Jenkins, CircleCI): Trigger builds, monitor test outcomes, and notify teams—while specialized runners handle compilation and deployment.
- **Contract & Document Workflows** (DocuSign, PandaDoc, HelloSign): Generate agreements from JSON/Schema, send for signature, and track signing status in one cohesive pipeline.
- **Bot & Chat Automation** (Intercom, Drift, HubSpot Chatbot): Define event-driven chat sequences, leverage LLMs for context-aware responses, and escalate to human agents seamlessly.
- **CMS Content Sync** (Contentful, Strapi, Sanity, Ghost): Sync documentation or content updates, generate drafts, and publish changes—eliminating manual sync processes.
- **Form & Survey Processing** (Typeform, JotForm, SurveyMonkey): Ingest submissions, perform enrichment or sentiment analysis, and trigger customized follow-up workflows instantly.
- **Feedback & NPS Surveys** (Delighted, Wootric, Typeform NPS): Automate survey distribution, collect responses, analyze sentiment with AI, and summarize insights—no spreadsheets needed.

---

## 🛠️ Quickstart: Hello World

1. **Install** the CLI (coming soon)
2. **Create** `flows/hello.flow.yaml`:
   ```yaml
   name: hello
   on: cli.manual
   steps:
     - greet:
         use: agent.llm.chat
         with:
           system: "Hey BeemFlow!"
           text: "Hello, world!"
     - print:
         use: core.echo
         with:
           text: "{{greet.text}}"
   ```
3. **Run & Visualize**:
   ```bash
   flow serve --config flow.config.json
   flow run --config flow.config.json hello --event event.json
   flow graph flows/hello.flow.yaml -o hello.svg
   ```

## 🔐 Authentication & Secrets

BeemFlow uses a unified `secrets` scope to inject credentials, API keys, and HMAC keys into your flows securely. No special syntax—just load them into the runtime environment and reference via `{{secrets.KEY}}`.

1. **Load your secrets**
   - Create a `.env` file or configure your runtime to read from Vault/AWS Secrets Manager:
     ```dotenv
     SLACK_TOKEN=xoxb-…
     GITHUB_TOKEN=ghp_…
     STRIPE_KEY=sk_…
     AWS_ACCESS_KEY_ID=AKIA…
     AWS_SECRET_ACCESS_KEY=…
     WEBHOOK_HMAC_KEY=supersecret
     ```

2. **Reference in your flow steps**
   ```yaml
   steps:
     - notify_ops:
         use: slack.chat.postMessage
         with:
           channel: "#ops"
           text:    "All systems go!"
           token:   "{{secrets.SLACK_TOKEN}}"

     - create_pr:
         use: github.api.create_pull_request
         with:
           repo:      "my-org/repo"
           title:     "Automated update"
           head:      "dep-update-2025-05-17"
           base:      "main"
           body:      "Dependency bump"
           token:     "{{secrets.GITHUB_TOKEN}}"
   ```

3. **Adapter defaults**
   Many adapter manifests declare default parameters from environment variables. If your Slack adapter sets `token: { "default": { "$env": "SLACK_TOKEN" } }`, you can omit `token:` entirely in the flow.

4. **Shell steps**
   Shell commands inherit the same environment:
   ```yaml
   - step_id: deploy
     use: shell.exec
     with:
       command: |
         aws s3 cp build/ s3://my-bucket/ --recursive
   ```
   Credentials like `AWS_ACCESS_KEY_ID` will be picked up automatically.

5. **Durable wait callbacks**
   For `await_event`, configure your HTTP adapter to verify HMAC signatures using `WEBHOOK_HMAC_KEY` from `secrets`, ensuring only valid resume requests succeed.

6. **AWS Secrets Manager**
   Instead of loading from `.env`, you can configure AWS Secrets Manager as a secrets backend:
   ```json
   {
     "secrets": {
       "driver": "aws-secrets-manager",
       "region": "us-east-1",
       "prefix": "/beemflow/"
     }
   }
   ```
   - Ensure the runtime host has AWS credentials (IAM role, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` and `AWS_REGION` env vars).
   - Secrets are looked up by name under the given prefix, e.g. `{{secrets.DB_PASSWORD}}` fetches the secret at `/beemflow/DB_PASSWORD`.

## 💼 Runtime Configuration

BeemFlow is driven by a JSON configuration file (default `flow.config.json`). You can also pass a custom path via `flow serve --config path/to/config.json`. Key sections:

```json
{
  "storage": { "driver": "postgres", "dsn": "postgres://user:pw@host/db" },
  "blob":    { "driver": "s3",       "bucket": "beemflow-files" },
  "event":   { "driver": "redis",    "url": "redis://host:6379" },
  "secrets": { "driver": "aws-secrets-manager", "region": "us-east-1", "prefix": "/beemflow/" },
  "registries": [
    "https://hub.beemflow.com/index.json",
    "https://raw.githubusercontent.com/my-org/tools/main/index.json"
  ],
  "http": { "host": "0.0.0.0", "port": 8080 },
  "log":  { "level": "info" },
  "mcp_servers": {
    "supabase-mcp.cursor.directory": {
      "install_cmd": ["npx", "supabase-mcp-server"],
      "required_env": ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"],
      "port": 3030
    }
  }
}
```

- **storage**: choose from `memory` (dev), `sqlite`, `postgres`, `dynamo`, `cockroachdb`.
- **blob**: choose from `inline-base64` (dev), `s3`, `gcs`, `minio`.
- **event**: choose from `in-proc` (local), `redis`, `nats`, `sns`.
- **secrets**: configure how `{{secrets.KEY}}` is resolved (supported drivers: `env`, `aws-secrets-manager`, `vault`).
- **registries**: list of manifest index URLs for discovering community tools.
- **http**: server binding for the runtime's HTTP API (`/runs`, `/resume`, `/graph`, etc.).
- **log**: set log level (`debug`, `info`, `warn`, `error`).
- **mcp_servers**: map of MCP server addresses to their install commands, required environment variables, and optional ports.

Omit any section to use sensible defaults (in-memory adapters, built-in hubs, console logging). For development, you can skip `flow.config.json` entirely and BeemFlow will fall back to in-memory storage, inline blob encoding, an in-process event bus, and no registries.

---

## 🖥️ CLI Commands

flow serve --config flow.config.json    # start the BeemFlow runtime
flow run [--config flow.config.json] <flow> --event <event.json>    # execute a flow once (with optional config)
flow lint <file>                        # validate your .flow.yaml against the spec
flow graph <file> -o <diagram.svg>      # visualize your flow as a DAG
flow tool scaffold <tool.name>          # generate a tool manifest + stub
flow validate <file> [--dry-run]        # validate and simulate a flow without executing adapters
flow test <file>                        # run unit tests for a flow using mock adapters

---

## 🧪 Featured Example Flows

Below are real-world workflows to inspire your own automations.

### 1. Twitter → Instagram

Sync tweets to Instagram posts as images arrive:
```yaml
name: tweet_to_instagram
on:
  - event: webhook.twitter.tweet

steps:
  - fetch_tweet:
      use: twitter.tweet.get
      with:
        id: "{{event.id}}"

  - rewrite:
      use: agent.llm.rewrite
      with:
        text: "{{fetch_tweet.text}}"
        style: "instagram"

  - post_instagram:
      use: instagram.media.create
      with:
        caption: "{{rewrite.text}}"
        image_url: "{{fetch_tweet.media_url}}"
```

---

### 2. Multi-Channel Marketing Blast

Automatically generate and publish marketing copy across Airtable, Twitter, Instagram, and Facebook:
```yaml
name: launch_blast
on:
  - event: webhook.product_feature

vars:
  wait_between_polls: 30

steps:
  - search_docs:
      use: docs.search
      with:
        query: "{{event.feature}}"
        top_k: 5

  - marketing_context:
      use: agent.llm.summarize
      with:
        system: "You are product marketing."
        text: |
          ### Feature
          {{event.feature}}
          ### Docs
          {{search_docs.results | join("\n\n")}}
        max_tokens: 400

  - gen_copy:
      use: agent.llm.function_call
      with:
        function_schema: |
          { "name": "mk_copy", "parameters": {
            "type": "object", "properties": {
              "twitter": {"type": "array", "items": {"type": "string"}},
              "instagram": {"type": "string"},
              "facebook": {"type": "string"}
          }}}
        prompt: |
          Write 3 Tweets, 1 IG caption, and 1 FB post about:
          {{marketing_context.summary}}

  - airtable_row:
      use: airtable.records.create
      with:
        base_id: "{{secrets.AIR_BASE}}"
        table: "Launch Copy"
        fields:
          Feature: "{{event.feature}}"
          Twitter: "{{gen_copy.twitter | join("\n\n---\n\n")}}"
          Instagram: "{{gen_copy.instagram}}"
          Facebook: "{{gen_copy.facebook}}"
          Status: "Pending"

  - await_approval:
      await_event:
        source: airtable
        match:
          record_id: "{{airtable_row.id}}"
          field: Status
          equals: Approved

  - parallel:
      - path: push_twitter
      - path: push_instagram
      - path: push_facebook

  - push_twitter:
      foreach: "{{gen_copy.twitter}}"
      as: tweet
      do:
        - step_id: post_tw
          use: twitter.tweet.create
          with:
            text: "{{tweet}}"

  - push_instagram:
      use: instagram.media.create
      with:
        caption: "{{gen_copy.instagram}}"
        image_url: "{{event.image_url}}"

  - push_facebook:
      use: facebook.post.create
      with:
        message: "{{gen_copy.facebook}}"
```

---

### 3. SaaS Release Notes Pipeline

Generate release notes on GitHub push, publish to Notion, CMS, and tweet:
```yaml
name: release_notes
on:
  - event: github.push
    branch: main

steps:
  - list_commits:
      use: github.api.list_commits
      with:
        range: "{{event.before}}..{{event.after}}"

  - summarise:
      use: agent.llm.chat
      with:
        system: "Rewrite commit messages into a user-friendly changelog."
        text: "{{list_commits.commits | map('message') | join('\n')}}"

  - notion_page:
      use: notion.page.create
      with:
        database_id: "{{secrets.NOTION_CHANGELOG_DB}}"
        title: "Release {{event.after | short_sha}} — {{today()}}"
        content: "{{summarise.text}}"

  - cms_post:
      use: github:my-org/cms-adapter@main/tools/cms.post.json
      with:
        slug: "{{today() | date_slug}}"
        title: "Release Notes — {{today()}}"
        body: "{{summarise.text}}"

  - tweet:
      use: twitter.tweet.create
      with:
        text: "{{summarise.text | first_240_chars}} 🚀"

  - email_draft:
      use: mailchimp.campaign.create_draft
      with:
        list_id: "{{secrets.MC_LIST}}"
        subject: "What's new — {{today()}}"
        html_body: "{{summarise.text | markdown_to_html}}"
```

---

### 4. E-Commerce Order Processing & Fulfillment

Automate the entire order-to-shipment lifecycle for your e-commerce store:

```yaml
name: ecommerce_order_processing
on:
  - event: webhook.shopify.order_created

vars:
  warehouse_name: "Acme Warehouse"
  warehouse_address:
    street: "123 Commerce St"
    city:   "Metropolis"
    zip:    "12345"

steps:
  - await_payment:
      await_event:
        source: stripe
        match:
          payment_intent_id: "{{event.payment_intent_id}}"
          status: succeeded
        timeout: 1h

  - generate_label:
      use: shippo.label.create
      with:
        order_id: "{{event.id}}"
        ship_from:
          name:   "{{vars.warehouse_name}}"
          street: "{{vars.warehouse_address.street}}"
          city:   "{{vars.warehouse_address.city}}"
          zip:    "{{vars.warehouse_address.zip}}"
        ship_to:
          name:   "{{event.shipping_address.name}}"
          street: "{{event.shipping_address.street}}"
          city:   "{{event.shipping_address.city}}"
          zip:    "{{event.shipping_address.zip}}"

  - create_fulfillment:
      use: shopify.fulfillment.create
      with:
        order_id:        "{{event.id}}"
        tracking_number: "{{generate_label.tracking_number}}"
        notify_customer: true

  - update_crm_contact:
      use: hubspot.contact.upsert
      with:
        email: "{{event.customer_email}}"
        properties:
          first_name: "{{event.shipping_address.name}}"
          order_id:   "{{event.id}}"
          tracking:   "{{generate_label.tracking_number}}"

  - update_crm_deal:
      use: hubspot.deal.create
      with:
        properties:
          dealname:   "Order #{{event.id}}"
          amount:     "{{event.total_price}}"
          pipeline:   "ecommerce"
          dealstage:  "fulfilled"

  - send_email:
      use: email.send
      with:
        to:      "{{event.customer_email}}"
        subject: "Your order #{{event.id}} is on its way!"
        body: |
          Hi {{event.shipping_address.name}},

          Your order #{{event.id}} has been shipped!
          Tracking: {{generate_label.tracking_number}}
          Label URL: {{generate_label.label_url}}

          Thanks for shopping with us.

  - log_success:
      use: core.log.info
      with:
        message: "Order {{event.id}} processed and shipped: {{generate_label.tracking_number}}"

catch:
  - notify_ops:
      use: slack.chat.postMessage
      with:
        channel: "#ecommerce-ops"
        text:    "Error processing order {{event.id}}: {{error.message}}"
```

---

### 5. AI-Driven Customer Churn Prevention

Proactively identify high-risk users and automatically send personalized win-back campaigns:

```yaml
name: churn_prevention
on:
  - cron: "0 8 * * *"   # Every day at 08:00 UTC

vars:
  crm_table: "Customers"
  churn_threshold: 0.7

steps:
  - fetch_usage:
      use: analytics.query
      with:
        sql: |
          SELECT user_id, name, email, last_login, purchase_history
          FROM user_metrics

  - predict_churn:
      use: agent.llm.function_call
      with:
        function_schema: |
          { "name": "predict_churn", "parameters": { "type": "object", "properties": { "users": { "type": "array", "items": { "type": "object", "properties": { "user_id": {"type":"string"}, "name": {"type":"string"}, "email": {"type":"string"}, "last_login": {"type":"string"}, "purchase_history": {"type":"array","items":{"type":"object"}} } } } } } }
        prompt: |
          Given the following user data, predict a churn risk score (0.0–1.0) for each:
          {{fetch_usage.results}}

  - foreach: "{{predict_churn.churn_predictions}}"
    as: prediction
    do:
      - maybe_retain:
          if: "{{prediction.risk >= vars.churn_threshold}}"
          do:
            - gen_offer:
                use: agent.llm.chat
                with:
                  system: "Retention Specialist"
                  text: |
                    Compose a personalized 20% discount win-back email for {{prediction.name}} ({{prediction.email}}).
            - send_email:
                use: email.send
                with:
                  to: "{{prediction.email}}"
                  subject: "We miss you, {{prediction.name}}!"
                  body: "{{gen_offer.text}}"
            - crm_update:
                use: crm.contact.update
                with:
                  table: "{{vars.crm_table}}"
                  record_id: "{{prediction.user_id}}"
                  fields:
                    churn_alerted: true
                    last_contacted: "{{today()}}"

  - summary_alert:
      use: slack.chat.postMessage
      with:
        channel: "#churn-alerts"
        text: |
          Sent win-back offers to {{length(predict_churn.churn_predictions | select(p => p.risk >= vars.churn_threshold))}} at-risk users.

catch:
  - notify_ops_churn:
      use: slack.chat.postMessage
      with:
        channel: "#churn-alerts"
        text: "Churn prevention pipeline failed: {{error.message}}"
```

---

### 6. Developer SaaS Marketing Agent

Plug your developer docs into a CMO-grade agent that generates marketing strategy, website copy, social posts, design briefs, and creates GitHub issues + Slack alerts:

```yaml
name: marketing_agent
on:
  - cli.manual

vars:
  product_name: "MySaaS"
  docs_url:     "https://docs.mysaas.com"
  github_repo:  "my-org/mysaas"

steps:
  - fetch_docs:
      use: docs.search
      with:
        query: "{{vars.product_name}} developer documentation"
        top_k: 50

  - marketing_strategy:
      use: agent.llm.chat
      with:
        system: "You are a CMO-level marketing strategist."
        text: |
          Analyze the following developer docs and propose a high-impact marketing plan for {{vars.product_name}}:
          {{fetch_docs.results | join("\n\n")}}

  - website_copy:
      use: agent.llm.chat
      with:
        system: "You are a UX copywriter."
        text: |
          Based on the marketing plan, write hero section copy, feature bullet points, and a memorable tagline for {{vars.product_name}}.

  - twitter_posts:
      use: agent.llm.function_call
      with:
        function_schema: |
          { "name": "mk_social", "parameters": {
            "type": "object", "properties": {
              "twitter": {"type":"array","items":{"type":"string"}},
              "linkedin": {"type":"string"}
            }
          }}
        prompt: |
          Generate 5 tweet threads and 1 LinkedIn post based on this marketing plan:
          {{marketing_strategy.text}}

  - design_brief:
      use: agent.llm.chat
      with:
        system: "You are a UI/UX design expert."
        text: |
          Create a design brief for a Figma mockup of the homepage hero section, including color palette, style, and imagery recommendations to match the copy:
          {{website_copy.text}}

  - create_website_issue:
      use: github.api.create_issue
      with:
        repo:  "{{vars.github_repo}}"
        title: "Marketing: Update homepage copy for {{vars.product_name}}"
        body: |
          **Hero & Features**
          {{website_copy.text}}

          **Design Brief**
          {{design_brief.text}}

  - create_social_issue:
      use: github.api.create_issue
      with:
        repo:  "{{vars.github_repo}}"
        title: "Marketing: Schedule social media content"
        body: |
          **Twitter Threads**
          {{twitter_posts.twitter | join("\n\n")}}

          **LinkedIn Post**
          {{twitter_posts.linkedin}}

  - notify_team:
      use: slack.chat.postMessage
      with:
        channel: "#marketing"
        text: |
          Marketing assets ready for *{{vars.product_name}}*:
          • Homepage issue: {{create_website_issue.html_url}}
          • Social issue:   {{create_social_issue.html_url}}

catch:
  - notify_ops_marketing:
      use: slack.chat.postMessage
      with:
        channel: "#marketing"
        text: "Marketing agent failed: {{error.message}}"
```

### 7. Automated Dependency Updater (Dependabot Replacement)

Automatically bump, commit, and PR your repo's dependencies with an AI-generated changelog:

```yaml
name: dependency_updater
on:
  - cron: "0 5 * * *"    # daily at 05:00 UTC

vars:
  repo_url:  "https://github.com/awantoch/your-repo.git"
  workdir:   "/tmp/repo"
  branch:    "dep-update-{{today()}}"

steps:
  - checkout:
      use: shell.exec
      with:
        command: git clone {{vars.repo_url}} {{vars.workdir}}

  - bump_deps:
      use: shell.exec
      with:
        command: |
          cd {{vars.workdir}}
          npx npm-check-updates -u
          npm install

  - show_diff:
      use: shell.exec
      with:
        command: |
          cd {{vars.workdir}}
          git diff
      # captured as show_diff.stdout

  - commit_and_push:
      use: shell.exec
      with:
        command: |
          cd {{vars.workdir}}
          git checkout -b {{vars.branch}}
          git add package.json package-lock.json
          git commit -m "chore(deps): bump to latest versions"
          git push origin {{vars.branch}}

  - create_pr:
      use: github.api.create_pull_request
      with:
        repo: "awantoch/your-repo"
        title: "Automated dependency update — {{today()}}"
        head: "{{vars.branch}}"
        base: "main"
        body: "Updating dependencies to the latest versions."

  - pr_description:
      use: agent.llm.chat
      with:
        system: "Release Note Assistant"
        text: |
          Here's the diff of the update:
          {{show_diff.stdout}}

  - update_pr:
      use: github.api.update_pull_request
      with:
        repo: "awantoch/your-repo"
        pr_number: "{{create_pr.number}}"
        body: "{{pr_description.text}}"

catch:
  - notify_ops_depbot:
      use: slack.chat.postMessage
      with:
        channel: "#devops"
        text: "Dependency updater failed: {{error.message}}"
```

*(Full spec & more examples in `beemflow_ultra_spec.txt`)*

---

## 🗂️ Project Layout

```
my-beemflow/
├── flows/                 # .flow.yaml files
├── tools/                 # JSON-Schema tool manifests
├── adapters/              # custom adapter implementations
├── flow.config.json    # backend & registry settings
└── README.md              # 👈 You're here
```

---

## 🤝 Join the Movement

BeemFlow is 100% **open**. We need YOU:

- Shape the spec
- Build adapters & UIs
- Share and remix flows
- Launch a SaaS or plugin on top

🌐 GitHub: https://github.com/awantoch/beemflow  
💬 Discord: https://discord.gg/your-invite  
📚 Docs: https://beemflow.com/docs

---

## 📜 License

MIT. Use it, remix it, ship it.

---

**BeemFlow: Power the AI automation revolution.** 