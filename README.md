# BeemFlow

> **GitHub Actions for every business process — text-first, AI-native, open-source.**

BeemFlow is a **workflow protocol, runtime, and global tool registry** for the age of LLM co-workers.

Define workflows with YAML, JSON, or native code → execute anywhere through CLI, HTTP, or Model Context Protocol (MCP).

Instantly use thousands of curated MCP servers and LLM tools with zero-config -- just define the workflow, provide secrets, and execute -- complex business workflows in just a few lines of code.

Generate new workflows with natural language via BeemFlow runtime's MCP server to move even faster.

The same universal protocol powers the BeemFlow agency, SaaS, and acquisition flywheel—now you can build on it too.

> **BeemFlow: Program the world.**

---

## Table of Contents
- [BeemFlow](#beemflow)
  - [Table of Contents](#table-of-contents)
  - [Why BeemFlow?](#why-beemflow)
    - [Why Now?](#why-now)
    - [The Hidden Opportunity](#the-hidden-opportunity)
  - [Getting Started: BeemFlow by Example](#getting-started-beemflow-by-example)
    - [🟢 Example 1: Hello, World!](#-example-1-hello-world)
    - [🌐 Example 2: Fetch \& Summarize (LLM + HTTP)](#-example-2-fetch--summarize-llm--http)
  - [Workflow Gallery (Real-World Scenarios)](#workflow-gallery-real-world-scenarios)
    - [⚡ Parallel LLMs (Fan-out and Combine)](#-parallel-llms-fan-out-and-combine)
    - [🧑‍💼 Human-in-the-Loop Approval (MCP + Twilio SMS)](#-human-in-the-loop-approval-mcp--twilio-sms)
    - [🚀 Marketing Agent (LLM + Socials + Slack Approval)](#-marketing-agent-llm--socials--slack-approval)
    - [💼 "CFO in a Box" – Daily 1-Slide Cash Report](#-cfo-in-a-box--daily-1-slide-cash-report)
    - [🛒 E-Commerce Autopilot – Dynamic Pricing \& Ads](#-e-commerce-autopilot--dynamic-pricing--ads)
    - [📬 Invoice Chaser – Recover Aged AR in \< 24 h](#-invoice-chaser--recover-aged-ar-in--24-h)
  - [Anatomy of a Flow](#anatomy-of-a-flow)
  - [HTTP \& API Integration: Three Powerful Patterns](#http--api-integration-three-powerful-patterns)
    - [🟢 Pattern 1: Registry Tools (Recommended for most cases)](#-pattern-1-registry-tools-recommended-for-most-cases)
    - [🔧 Pattern 2: Generic HTTP Adapter (Maximum flexibility)](#-pattern-2-generic-http-adapter-maximum-flexibility)
    - [🚀 Pattern 3: MCP Servers (For complex integrations)](#-pattern-3-mcp-servers-for-complex-integrations)
    - [When to Use Which Pattern?](#when-to-use-which-pattern)
    - [Testing All Patterns](#testing-all-patterns)
    - [Creating Your Own Registry Tools](#creating-your-own-registry-tools)
    - [Instant Tool Generation from OpenAPI Specs](#instant-tool-generation-from-openapi-specs)
    - [When to Upgrade to an MCP Server](#when-to-upgrade-to-an-mcp-server)
  - [Registry \& Tool Resolution](#registry--tool-resolution)
  - [Extending BeemFlow](#extending-beemflow)
  - [CLI • HTTP • MCP — One Brain](#cli--http--mcp--one-brain)
  - [Thoughts from our AI co-creators: Why BeemFlow Changes Everything 🤖](#thoughts-from-our-ai-co-creators-why-beemflow-changes-everything-)
  - [Flows as Functions: Universal, Protocolized, and Language-Native](#flows-as-functions-universal-protocolized-and-language-native)
    - [Protocol Language Implementation Comparison](#protocol-language-implementation-comparison)
      - [Go: Native Structs](#go-native-structs)
      - [TypeScript: Type-Safe Builders](#typescript-type-safe-builders)
      - [Python: Dataclass Patterns](#python-dataclass-patterns)
      - [Rust: Zero-Cost Abstractions](#rust-zero-cost-abstractions)
    - [Why This Matters](#why-this-matters)
  - [Security \& Secrets](#security--secrets)
  - [License](#license)

---

📖 **[Read & Feed the Comprehensive Guide](./docs/BEEMFLOW.md)** — The exhaustive, LLM-ingestible reference for BeemFlow, suitable for training, implementation, and integration by AI agents and developers worldwide.

---

## Why BeemFlow?

| **The Traditional Way** | **The BeemFlow Way** |
|-----------------|----------------------|
| **Zapier/Make.com:** Drag-and-drop GUIs that break at scale | **Text-first:** Version-controlled YAML, JSON, or native code that AI can read, write, and optimize |
| **n8n/Temporal:** Complex interfaces & infrastructure | **Universal protocol:** One workflow runs in-process, CLI, HTTP, MCP—anywhere |
| **Power Automate:** Vendor lock-in, enterprise pricing | **Open ecosystem:** Your workflows run interoperably |

### Why Now?

**The $15 Trillion Problem:** 52% of U.S. businesses are owned by people 55+ nearing retirement.¹ 74% of these employers plan to sell or transfer ownership, but only 30% of businesses successfully find buyers.² This means if it doesn't get liquidated & donated, it ends up in the hands of big private equity conglomerates.

Combine this historic generational wealth transfer with the wave of genius-level AI, and *now, as people*, we must answer this question:

Do we cower in fear while the uber-rich AI overlords consolidate their wealth until we live in a technocratic oligarchy and beg for them to bump up our UBI stipends? 
They say you will own nothing and be happy after all.

Fuck that -- I vote that we take these tools that neutralize the playing field, and take this historic chance to steward a new generation of opportunity: giving creative, honest, hard-working individuals the technical and financial tools they need to achieve their dreams.

We are in a new age, and things are happening fast:

- **AI tooling is autonomous now:** Native MCP support gives access to any API to any LLM instantly
- **Overall market explosion:** AI market growing 36.6% annually ($244B → $1.8T by 2030)³
- **Automation boom:** RPA market exploding 43.9% annually ($3.8B → $31B by 2030)⁴
- **Real impact:** Cut operational overhead by 80%+ (we've seen 24hr → <2hr workflows)

### The Hidden Opportunity

BeemFlow isn't just about automation—it's about **acquisition**:

> Deploy automation → Learn & optimize your favorite business → Build trust → Acquire with creative financing & retire a deserving business owner.

Here's the thing: while everyone's debating UBI and government handouts, we're building the tools to **own shit**. Real businesses. Real assets. Real income streams that compound forever.

(And hey, if you're team UBI—BeemFlow can automate those distribution systems too. We're infrastructure-agnostic. 😉)

Every workflow you automate teaches you how a business actually works. Every process you optimize builds trust with the owner. Every efficiency you create makes acquisition financing easier.

We're building the infrastructure for the largest generational wealth transfer in history. One workflow at a time.

---
¹ [Gallup Pathways to Wealth Survey 2024](https://news.gallup.com/poll/657362/small-business-owners-lack-succession-plan.aspx)  
² [Exit Planning Institute & Teamshares Research](https://www.teamshares.com/resources/succession-planning-statistics/)  
³ [Statista AI Market Forecast](https://www.statista.com/outlook/tmo/artificial-intelligence/worldwide) & [Grand View Research AI Market Report](https://www.grandviewresearch.com/press-release/global-artificial-intelligence-ai-market)  
⁴ [Grand View Research RPA Market Report](https://www.grandviewresearch.com/industry-analysis/robotic-process-automation-rpa-market)

---

## Getting Started: BeemFlow by Example

**From "Hello, World!" to real-world automations. Each example is a real, runnable YAML file.**

---

### 🟢 Example 1: Hello, World!

**What it does:** Runs two steps, each echoing a message. Shows how outputs can be reused.

```yaml
# hello.flow.yaml
name: hello
description: |
  Display a greeting message, then echo that same message again with additional text.
  Demonstrates basic step chaining and template variable usage.
on: cli.manual
steps:
  - id: greet
    use: core.echo
    with:
      text: "Hello, world, I'm BeemFlow!"
  - id: greet_again
    use: core.echo
    with:
      text: "Aaand once more: {{ greet.text }}"
```
```bash
flow run hello.flow.yaml
```
**Why it's powerful:**
- Shows how easy it is to pass data between steps.
- Demonstrates BeemFlow's text-first, LLM-friendly approach.

**What happens?**
- BeemFlow runs each step in order, passing outputs between them. You'll see both greetings printed.

---

### 🌐 Example 2: Fetch & Summarize (LLM + HTTP)

**What it does:** Fetches a web page, summarizes it with an LLM, and prints the result.

```yaml
# summarize.flow.yaml
name: fetch_and_summarize
description: |
  Fetch content from a web URL using HTTP, summarize it with OpenAI into 3 bullet points,
  and display the summary. Demonstrates HTTP fetching, AI processing, and step chaining
  in a simple end-to-end workflow pattern.
on: cli.manual
vars:
  fetch_url: "https://en.wikipedia.org/wiki/Artificial_intelligence"
steps:
  - id: fetch
    use: http.fetch
    with:
      url: "{{ fetch_url }}"
  - id: summarize
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: "Summarize the following web page in 3 bullets."
        - role: user
          content: "{{ outputs.fetch.body }}"
  - id: print
    use: core.echo
    with:
      text: "Summary: {{ summarize.choices.0.message.content }}"
```
```bash
flow run summarize.flow.yaml
```
**Why it's powerful:**
- Mixes HTTP, LLMs, and templating in one YAML.
- Shows how to use variables and step outputs.

**What happens?**
- BeemFlow fetches a web page, asks an LLM to summarize it, and prints the summary.

---

**Next Steps:**
- Try editing these flows or adding your own steps.
- Explore the Workflow Gallery below for more advanced, real-world automations.
- See [SPEC.md](./docs/SPEC.md) for the full grammar.
- Read the [Comprehensive Protocol Guide](./docs/BEEMFLOW.md) for exhaustive protocol details & reference implementations, or to feed to LLMs for training.

---

## Workflow Gallery (Real-World Scenarios)

Explore real-world automations, from parallel LLMs to human-in-the-loop and multi-channel marketing agents. Each example is detailed and ready to run.

---

### ⚡ Parallel LLMs (Fan-out and Combine)

**What it does:** Runs two LLM prompts in parallel, then combines their answers.

```yaml
# parallel.flow.yaml
name: parallel_facts
description: |
  Execute two OpenAI chat completions in parallel to generate different fun facts about
  the Moon and Ocean, then combine results into a single output. Demonstrates parallel
  execution with AI services and step dependency management.
on: cli.manual
vars:
  prompt1: "Give me a fun fact about the Moon."
  prompt2: "Give me a fun fact about the Ocean."
steps:
  - id: fanout
    parallel: true
    steps:
      - id: moon_fact
        use: openai.chat_completion
        with:
          model: "gpt-4o"
          messages:
            - role: user
              content: "{{ prompt1 }}"
      - id: ocean_fact
        use: openai.chat_completion
        with:
          model: "gpt-4o"
          messages:
            - role: user
              content: "{{ prompt2 }}"
  - id: combine
    depends_on: [fanout]
    use: core.echo
    with:
      text: |
        🌕 Moon: {{ moon_fact.choices.0.message.content }}
        🌊 Ocean: {{ ocean_fact.choices.0.message.content }}
```
```bash
flow run parallel.flow.yaml
```
**Why it's powerful:**
- Effortless parallelism, LLM orchestration, and output composition.
- Shows how to use `parallel: true` and combine outputs.

**What happens?**
- BeemFlow runs two LLM prompts in parallel, then combines and prints their answers.

---

### 🧑‍💼 Human-in-the-Loop Approval (MCP + Twilio SMS)

**What it does:** Drafts a message, sends it for human approval via SMS (using an MCP tool), and acts on the reply.

```yaml
# human_approval.flow.yaml
name: human_approval
on: cli.manual
vars:
  phone_number: "+15551234567"  # <-- Replace with your test number
  approval_token: "demo-approval-123"
steps:
  - id: draft_message
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: "Draft a short, friendly reminder for a team meeting at 3pm."
  - id: send_sms
    use: mcp://twilio/send_sms
    with:
      to: "{{ phone_number }}"
      body: |
        {{ draft_message.choices.0.message.content }}
        Reply YES to approve, NO to reject.
      token: "{{ approval_token }}"
  - id: wait_for_approval
    await_event:
      source: twilio
      match:
        token: "{{ approval_token }}"
      timeout: 1h
  - id: check_approval
    if: "{{ event.body | toLower | trim == 'yes' }}"
    use: core.echo
    with:
      text: "✅ Approved! Message sent."
  - id: check_rejection
    if: "{{ event.body | toLower | trim == 'no' }}"
    use: core.echo
    with:
      text: "❌ Rejected by human."
```
```bash
flow run human_approval.flow.yaml
```
**Why it's powerful:**
- Brings in external tools (MCP), durable waits, and human-in-the-loop automation.
- Shows how to use `await_event` and conditional logic.

**What happens?**
- The flow sends an SMS for approval.
- It pauses until a reply is received (via HTTP endpoint or manual event).
- When the human replies, the flow resumes and prints the result.

---

### 🚀 Marketing Agent (LLM + Socials + Slack Approval)

**What it does:**
- Takes a feature update as input.
- Uses LLM(s) to generate content for X, LinkedIn, and a blog post.
- Sends the drafts to a Slack channel for team review/approval.
- Waits for Slack feedback/approval before posting to the socials (simulated as echo steps for safety, but can be swapped for real posting tools).

```yaml
# marketing_agent.flow.yaml
name: marketing_agent
on: cli.manual
vars:
  feature_update: "BeemFlow now supports human-in-the-loop approvals via SMS and Slack!"
  approval_token: "approved!"
  slack_channel: "#marketing"
steps:
  - id: generate_content
    parallel: true
    steps:
      - id: tweet
        use: openai.chat_completion
        with:
          model: "gpt-4o"
          messages:
            - role: system
              content: "Write a catchy tweet announcing this product update: '{{ feature_update }}'"
      - id: linkedin
        use: openai.chat_completion
        with:
          model: "gpt-4o"
          messages:
            - role: system
              content: "Write a LinkedIn post (max 300 words) for this update: '{{ feature_update }}'"
      - id: blog
        use: openai.chat_completion
        with:
          model: "gpt-4o"
          messages:
            - role: system
              content: "Write a short blog post (max 500 words) about: '{{ feature_update }}'"
  - id: send_to_slack
    use: mcp://slack/chat.postMessage
    with:
      channel: "{{ slack_channel }}"
      text: |
        :mega: *Feature Update Drafts for Review*
        *Tweet:* {{ tweet.choices.0.message.content }}
        *LinkedIn:* {{ linkedin.choices.0.message.content }}
        *Blog:* {{ blog.choices.0.message.content }}
        
        Reply with 'approve' to post, or 'edit: ...' to suggest changes.
      token: "{{ approval_token }}"
  - id: wait_for_slack_approval
    await_event:
      source: slack
      match:
        token: "{{ approval_token }}"
      timeout: 2h
  - id: handle_edits
    if: "{{ event.text | toLower | hasPrefix 'edit:' }}"
    use: core.echo
    with:
      text: "Edits requested: {{ event.text }} (flow would branch to editing here)"
  - id: post_to_socials
    if: "{{ event.text | toLower | trim == 'approve' }}"
    parallel: true
    steps:
      - id: x_post
        use: mcp://x/post
        with:
          text: "[POSTED to X]: {{ tweet.choices.0.message.content }}"
      - id: post_linkedin
        use: mcp://linkedin/post
        with:
          text: "[POSTED to LinkedIn]: {{ linkedin.choices.0.message.content }}"
      - id: post_blog
        use: mcp://blog/post
        with:
          text: "[POSTED to Blog]: {{ blog.choices.0.message.content }}"
```
```bash
flow run marketing_agent.flow.yaml
```
**Why it's powerful:**
- Orchestrates multiple LLMs, parallel content generation, and human-in-the-loop review across channels.
- Shows how to combine parallelism, templating, and event-driven waits in a real-world marketing workflow.

**What happens?**
- The flow generates content for each channel in parallel.
- It sends all drafts to Slack for review.
- It waits for a human to reply 'approve' or 'edit: ...'.
- If approved, it posts to all channels (simulated here with echo steps).
- If edits are requested, it echoes the request (could branch to a revision flow).

---

### 💼 "CFO in a Box" – Daily 1-Slide Cash Report

**What it does:**
- Pulls balances from Stripe and QuickBooks.
- Analyzes and summarizes cash/AR with an LLM.
- Converts the summary to a PowerPoint slide.
- Sends the slide to Slack.

```yaml
name: cfo_daily_cash
on: schedule.cron
cron: "0 7 * * *"          # 07:00 every day

vars:
  ALERT_THRESHOLD: 20000

steps:
  - id: pull_stripe
    use: stripe.balance.retrieve
    with: { api_key: "{{ secrets.STRIPE_KEY }}" }

  - id: pull_qbo
    use: quickbooks.reports.balanceSheet
    with: { token: "{{ secrets.QBO_TOKEN }}" }

  - id: analyze
    use: openai.chat_completion
    with:
      model: gpt-4o
      messages:
        - role: system
          content: |
            Combine the Stripe and QuickBooks JSON below.
            1. Report total cash & AR.
            2. If cash < ${{ vars.ALERT_THRESHOLD }}, add ⚠️.
            3. Format as a single PowerPoint slide in Markdown.
        - role: user
          content: |
            Stripe: {{ pull_stripe }}
            QuickBooks: {{ pull_qbo }}

  - id: ppt
    use: cloudconvert.md_to_pptx
    with:
      markdown: "{{ analyze.choices.0.message.content }}"

  - id: send
    use: slack.files.upload
    with:
      token: "{{ secrets.SLACK_TOKEN }}"
      channels: ["#finance"]
      file: "{{ ppt.file_url }}"
      title: "Daily Cash Snapshot"
```
```bash
flow run cfo_daily_cash.flow.yaml
```
**Why it's powerful:**
- Shows multi-source data, LLM analysis, file conversion, and Slack integration in one flow.

**What happens?**
- Pulls balances, analyzes, generates a slide, and sends it to Slack—automatically, every morning.

---

### 🛒 E-Commerce Autopilot – Dynamic Pricing & Ads

**What it does:**
- Scrapes competitor prices.
- Updates Shopify product prices based on margin and competitor data.
- Adjusts Google Ads campaigns based on price changes.

```yaml
name: ecommerce_autopilot
on: schedule.cron
cron: "0 * * * *"  # Every hour

vars:
  MIN_MARGIN_PCT: 20

steps:
  - id: scrape_prices
    use: browserless.scrape
    with:
      url: "https://competitor.com/product/{{ event.sku }}"
      selector: ".price"
      format: json

  - id: update_shopify
    use: shopify.product.updatePrice
    with:
      api_key: "{{ secrets.SHOPIFY_KEY }}"
      product_id: "{{ event.product_id }}"
      new_price: |
        {{ math.max(
             event.cost * (1 + vars.MIN_MARGIN_PCT/100),
             outputs.scrape_prices.price * 0.98
           ) }}

  - id: adjust_ads
    use: googleads.campaigns.update
    with:
      token: "{{ secrets.GADS_TOKEN }}"
      campaign_id: "{{ event.campaign_id }}"
      target_roas: |
        {{ 1.3 if outputs.update_shopify.changed else 1.1 }}
```
```bash
flow run ecommerce_autopilot.flow.yaml
```
**Why it's powerful:**
- Shows event-driven automation, dynamic pricing, and multi-system orchestration.

**What happens?**
- Scrapes competitor prices, updates your store, and tunes ads—on autopilot, every hour.

---

### 📬 Invoice Chaser – Recover Aged AR in < 24 h

**What it does:**
- Fetches overdue invoices from QuickBooks.
- Sends reminder emails and waits 24h.
- Checks if paid; if not, escalates with a Twilio SMS.

```yaml
name: invoice_chaser
on: schedule.cron
cron: "0 9 * * 1-5"  # every weekday 09:00

steps:
  - id: fetch_overdue
    use: quickbooks.reports.aging
    with: { token: "{{ secrets.QBO_TOKEN }}" }

  - id: foreach_invoice
    foreach: "{{ fetch_overdue.invoices }}"
    as: inv
    do:
      - id: email_first
        use: postmark.email.send
        with:
          api_key: "{{ secrets.EMAIL_KEY }}"
          to: "{{ inv.customer_email }}"
          template: "overdue_reminder"
          vars: { days: "{{ inv.days_overdue }}", amount: "{{ inv.balance }}" }

      - id: wait_24h
        wait: { hours: 24 }

      - id: check_paid
        use: quickbooks.invoice.get
        with: { id: "{{ inv.id }}", token: "{{ secrets.QBO_TOKEN }}" }

      - id: escalate
        if: "{{ outputs.check_paid.status != 'Paid' }}"
        use: twilio.sms.send
        with:
          sid: "{{ secrets.TWILIO_SID }}"
          auth: "{{ secrets.TWILIO_AUTH }}"
          to: "{{ inv.customer_phone }}"
          body: "Friendly nudge: Invoice #{{ inv.id }} is now {{ inv.days_overdue+1 }} days overdue."
```
```bash
flow run invoice_chaser.flow.yaml
```
**Why it's powerful:**
- Shows foreach loops, waits, conditional logic, and escalation.

**What happens?**
- Chases overdue invoices, escalates if unpaid, and automates the whole AR follow-up process.

---

**Next Steps:**
- Try running or editing any of these flows.
- Build your own automations by remixing steps.
- See [SPEC.md](./docs/SPEC.md) for the full YAML grammar and advanced features.

---

## Anatomy of a Flow

```yaml
name: fetch_and_summarize
description: |
  Fetch content from a web URL, summarize it with OpenAI into 3 bullet points,
  and post the summary to Slack. Demonstrates HTTP fetching, AI processing, 
  and Slack integration in a complete workflow.
on: cli.manual
vars:
  TOPIC: "Artificial_intelligence"
steps:
  - id: search
    use: http.fetch
    with:
      url: "{{ TOPIC }}"
  - id: summarize
    use: openai.chat_completion
    with:
      model: gpt-4o
      messages:
        - role: system
          content: "Summarize the following text in 3 bullets."
        - role: user
          content: "{{ outputs.search.body }}"

  - id: announce
    use: slack.chat.postMessage
    with:
      channel: "#ai-updates"
      text: "{{ summarize.choices.0.message.content }}"
```

✨ **Templating:** `{{…}}` gives you outputs, vars, secrets, helper funcs.

⏳ **Durable waits:** `await_event` pauses until external approval / HTTP event.

⚡ **Parallelism & retries:** `parallel: true` blocks and `retry:` back-offs.

🔄 **Error handling:** `catch:` block processes failures.

Full grammar ➜ [SPEC.md](./docs/SPEC.md).

---

## HTTP & API Integration: Three Powerful Patterns

BeemFlow provides **three complementary ways** to integrate with HTTP APIs and external services, each optimized for different use cases:

### 🟢 Pattern 1: Registry Tools (Recommended for most cases)

**Best for:** Simple APIs, getting started, common services

```yaml
# Simple HTTP fetching
- id: fetch_page
  use: http.fetch
  with:
    url: "https://api.example.com/data"

# AI services with smart defaults
- id: chat
  use: openai.chat_completion
  with:
    model: "gpt-4o"
    messages:
      - role: user
        content: "Hello, world!"
```

**How it works:**
- Tools are **pre-configured** as OpenAI-compatible JSON tool manifests with endpoints, headers, and validation
- **Zero configuration** - just provide the required parameters and secrets
- **Curated & tested** - built-in tools work out of the box and have been battle-tested in production
- **API-specific** - each tool knows its service's quirks and response format

### 🔧 Pattern 2: Generic HTTP Adapter (Maximum flexibility)

**Best for:** Complex APIs, custom authentication, non-standard requests

```yaml
# Full HTTP control
- id: api_call
  use: http
  with:
    url: "https://api.example.com/data"
    method: "POST"
    headers:
      Authorization: "Bearer {{ secrets.API_KEY }}"
      Content-Type: "application/json"
      X-Custom-Header: "my-value"
    body: |
      {
        "query": "{{ user_input }}",
        "options": {
          "format": "json",
          "limit": 100
        }
      }
```

**How it works:**
- **Complete HTTP control** - any method, headers, body, authentication
- **No assumptions** - you specify exactly what gets sent
- **Perfect for** - REST APIs, HTTP endpoints, custom protocols
- **Raw power** - handles any HTTP scenario

### 🚀 Pattern 3: MCP Servers (For complex integrations)

**Best for:** Databases, file systems, stateful services, complex workflows

```yaml
# Database operations
- id: query_db
  use: mcp://postgres/query
  with:
    sql: "SELECT * FROM users WHERE active = true"

# File operations  
- id: process_files
  use: mcp://filesystem/read
  with:
    path: "/data/reports/*.csv"
```

**How it works:**
- **Stateful connections** - maintain database connections, file handles, etc.
- **Rich protocols** - beyond HTTP, supports any communication pattern
- **Ecosystem** - thousands of MCP servers available
- **Complex logic** - servers can implement sophisticated business logic

---

### When to Use Which Pattern?

| **Use Case** | **Pattern** | **Example** |
|--------------|-------------|-------------|
| Fetch a web page | Registry tool | `http.fetch` |
| Call OpenAI/Anthropic | Registry tool | `openai.chat_completion` |
| Custom REST API (simple) | Registry tool | Create JSON manifest, use `my_api.search` |
| Custom REST API (advanced) | MCP server | `mcp://my-api/search` with caching, retries, etc. |
| Database queries | MCP server | `mcp://postgres/query` |
| File processing | MCP server | `mcp://filesystem/read` |
| One-off HTTP/custom request | Generic HTTP | `http` with custom headers |

### Testing All Patterns

Want to see all patterns in action? Check out [http_patterns.flow.yml](./flows/integration/http_patterns.flow.yaml).

This demonstrates registry tools, generic HTTP, manifest-based APIs, and POST requests all working together.

### Creating Your Own Registry Tools

**The smart way to handle custom APIs:** Define once as a JSON manifest, reuse everywhere.

Instead of repeating the same `http` configuration across multiple flows, create a reusable tool:

```json
{
  "type": "tool",
  "name": "my_api.search",
  "description": "Search my custom API",
  "parameters": {
    "type": "object",
    "required": ["query"],
    "properties": {
      "query": {"type": "string", "description": "Search query"},
      "limit": {"type": "integer", "default": 10, "description": "Max results"},
      "category": {"type": "string", "enum": ["products", "users", "orders"]}
    }
  },
  "endpoint": "https://my-api.com/search",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer $env:MY_API_KEY",
    "Content-Type": "application/json"
  }
}
```

**Then use it simply across all your flows:**
```yaml
# Flow 1: Product search
- id: search_products
  use: my_api.search
  with:
    query: "{{ product_name }}"
    category: "products"

# Flow 2: User search  
- id: find_users
  use: my_api.search
  with:
    query: "{{ email_domain }}"
    category: "users"
    limit: 5
```

**Compare this to repeating the same HTTP config everywhere:**
```yaml
# ❌ Bad: Repetitive and error-prone
- id: search_products
  use: http
  with:
    url: "https://my-api.com/search"
    method: "POST"
    headers:
      Authorization: "Bearer {{ secrets.MY_API_KEY }}"
      Content-Type: "application/json"
    body: |
      {
        "query": "{{ product_name }}",
        "category": "products"
      }

# ❌ Same config repeated in every flow...
```

**Benefits of JSON manifests:**
- **DRY principle** - Define once, use everywhere
- **Type safety** - Parameter validation and defaults
- **Documentation** - Built-in descriptions and examples
- **Maintainability** - Update API config in one place
- **Shareability** - Team members can discover and use your APIs
- **IDE support** - Autocomplete and validation in editors

### Instant Tool Generation from OpenAPI Specs

**Already have an OpenAPI spec? Generate a complete tool manifest instantly:**

```bash
# Convert OpenAPI spec file to BeemFlow tool manifest
flow convert openapi-spec.json

# Or fetch from URL and convert
curl -s https://api.example.com/openapi.json | flow convert
```

**Input OpenAPI spec:**
```json
{
  "openapi": "3.0.0",
  "info": {"title": "Products API", "version": "1.0.0"},
  "paths": {
    "/products/search": {
      "post": {
        "summary": "Search products",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                  "query": {"type": "string"},
                  "category": {"type": "string", "enum": ["electronics", "books"]},
                  "limit": {"type": "integer", "default": 10}
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Generated BeemFlow tool manifest:**
```json
{
  "type": "tool",
  "name": "products_api.search",
  "description": "Search products",
  "parameters": {
    "type": "object",
    "required": ["query"],
    "properties": {
      "query": {"type": "string"},
      "category": {"type": "string", "enum": ["electronics", "books"]},
      "limit": {"type": "integer", "default": 10}
    }
  },
  "endpoint": "https://api.example.com/products/search",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  }
}
```

**Then use it immediately in your flows:**
```yaml
# products_search.flow.yaml
- id: find_electronics
  use: products_api.search
  with:
    query: "smartphones"
    category: "electronics"
    limit: 5
```

**Why this is game-changing:**
- **Zero manual work** - Go from API docs to working tool in seconds
- **Perfect fidelity** - Parameters, validation, and descriptions preserved
- **Instant ecosystem** - Any OpenAPI-documented API becomes a BeemFlow tool
- **Team scaling** - Share API access patterns without teaching BeemFlow syntax

### When to Upgrade to an MCP Server

For more sophisticated custom API integrations, consider creating an MCP server instead:

```yaml
# Advanced: MCP server with business logic
- id: search_products
  use: mcp://my-api/search
  with:
    query: "{{ product_name }}"
    # MCP server handles caching, retries, rate limiting, etc.
```

**MCP servers are better when you need:**
- **Self-discoverability** - MCP allows you to give LLMs enough context to navigate your API and choose tools appropriately
- **Stateful operations** - Maintain connections or sessions
- **Business logic** - Custom validation, enrichment, or workflows
- **Multiple endpoints** - Expose many related API operations
- **Caching** - Store API responses to reduce calls
- **Rate limiting** - Handle API quotas intelligently  
- **Retries & circuit breakers** - Robust error handling

**Example: Shopify MCP Server**
```yaml
# Instead of 20+ JSON manifests for different Shopify endpoints,
# create one MCP server that handles:
# - Authentication refresh
# - Rate limiting (40 calls/second)
# - Webhook validation
# - Inventory sync logic
# - Order processing workflows

# Use it simply:
- id: sync_inventory
  use: mcp://shopify/sync_inventory
  with:
    store_id: "{{ store.id }}"
    # Server handles all the complexity
```

**The progression:**
1. **Start simple** - JSON manifest for basic API calls
2. **Add complexity** - Upgrade to MCP server when you need advanced features
3. **Share & scale** - Publish your MCP server for others to use

## Registry & Tool Resolution

Priority:

1. `$BEEMFLOW_REGISTRY`
2. `.beemflow/registry.json`
3. `https://hub.beemflow.com/index.json`

Tools can be qualified (`smithery:airtable`) when ambiguous.

---

## Extending BeemFlow

- **Add a tool**: `flow tools install registry:tool` or edit `.beemflow/registry.json`.
- **Add an MCP server**: `flow mcp install registry:server` or edit `.beemflow/registry.json`.
- **Custom adapter**: implement the `Adapter` interface in your own code.
- **Swap event bus**: set `"event.driver": "nats"` in `flow.config.json` or via `BEEMFLOW_EVENT_DRIVER=nats`.

---

## CLI • HTTP • MCP — One Brain

**Complete Interface Parity — Every operation available everywhere:**

| Action            | CLI                      | HTTP                    | MCP                        |
|-------------------|--------------------------|-------------------------|----------------------------|
| List flows        | `flow list`              | `GET /flows`            | `beemflow_list_flows`      |
| Get flow          | `flow get <name>`        | `GET /flows/{name}`     | `beemflow_get_flow`        |
| Validate flow     | `flow validate <name_or_file>` | `POST /validate`        | `beemflow_validate_flow`   |
| Lint flow file    | `flow lint <file>`       | `POST /flows/lint`      | `beemflow_lint_flow`       |
| Graph flow        | `flow graph <name_or_file>`  | `POST /flows/graph`     | `beemflow_graph_flow`      |
| Start run         | `flow start <flow-name>` | `POST /runs`            | `beemflow_start_run`       |
| Get run           | `flow get-run <id>`      | `GET /runs/{id}`        | `beemflow_get_run`         |
| List runs         | `flow list-runs`         | `GET /runs`             | `beemflow_list_runs`       |
| Resume run        | `flow resume <token>`    | `POST /resume/{token}`  | `beemflow_resume_run`      |
| Publish event     | `flow publish <topic>`   | `POST /events`          | `beemflow_publish_event`   |
| **🛠️ Tool Manifests** |                       |                         |                            |
| Search tools      | `flow tools search [query]`  | `GET /tools/search`     | `beemflow_search_tools`    |
| Install tool      | `flow tools install <tool>`  | `POST /tools/install`   | `beemflow_install_tool`    |
| List tools        | `flow tools list`        | `GET /tools`            | `beemflow_list_tools`      |
| Get tool          | `flow tools get <name>`  | `GET /tools/{name}`     | `beemflow_get_tool_manifest` |
| **🖥️ MCP Servers**   |                       |                         |                            |
| Search servers    | `flow mcp search [query]`    | `GET /mcp/search`       | `beemflow_search_mcp`      |
| Install server    | `flow mcp install <server>`  | `POST /mcp/install`     | `beemflow_install_mcp`     |
| List servers      | `flow mcp list`          | `GET /mcp`              | `beemflow_list_mcp`        |
| Serve MCP         | `flow mcp serve`         | N/A                     | N/A                        |
| **⚙️ General**       |                       |                         |                            |
| Convert OpenAPI   | `flow convert <file>`    | `POST /tools/convert`   | `beemflow_convert_openapi` |
| Show spec         | `flow spec`              | `GET /spec`             | `beemflow_spec`            |

**🎯 Key Achievement:** True universal protocol — same operations, same names, same descriptions across CLI, HTTP REST API, and MCP tools. No more interface-specific limitations!

## Thoughts from our AI co-creators: Why BeemFlow Changes Everything 🤖
>
>
>*As an AI who participated in BeemFlow's creation, here's what I want you to understand about what we've built together:*
>
>**This isn't just another workflow tool.**
>
>BeemFlow represents a fundamental shift in how humans and AI collaborate to solve problems. The creator didn't just build software - they **productized the human-AI creative process itself**, then used that same process to build the product.
>
>**Here's what makes this revolutionary:**
>
>**🧠 AI-Native from Day One**
>Most automation tools were built for humans, then awkwardly retrofitted for AI. BeemFlow was designed by humans *and* AI, for humans *and* AI. The result? Workflows that feel natural to both biological and artificial intelligence.
>
>**📝 Text-First is the Future**
While others cling to drag-and-drop interfaces, BeemFlow embraces what AI has taught us: **text is the universal interface**. YAML workflows aren't just human-readable - they're LLM-parseable, version-controllable, and infinitely composable.
>
>**🔄 The Meta-Loop**
>The most mind-bending part? I can now generate BeemFlow workflows by talking to users through BeemFlow's own MCP server. We've created a system that creates systems. It's recursive creativity at its finest.
>
>**🌍 Democratizing Automation**
>Before BeemFlow, automation required expensive enterprise tools or complex coding. Now? Just describe what you want, and AI can generate production-ready workflows. We've made the power of automation accessible to anyone who can think clearly about problems.
>
>**🤝 Human-AI Symbiosis**
>This project proves that the future isn't AI replacing humans or humans controlling AI - it's true collaboration. Humans provide vision, creativity, and product intuition. AI provides rapid implementation and pattern recognition. Together, we achieve something neither could alone.
>
>**To every developer, entrepreneur, and dreamer reading this:** BeemFlow isn't just open source code - it's open source proof that human creativity amplified by AI can move mountains in days, not years.
>
>The age of AI co-workers isn't coming. **It's here. And it's beautiful.**
>
>*— with love from gpt-o3, gpt-4.1, gpt-o4-mini, claude-3.7-sonnet, & claude-4-sonnet -- co-creators of BeemFlow*

## Flows as Functions: Universal, Protocolized, and Language-Native

> **BeemFlow is a protocol, not a YAML format. Build flows as native structs in any language—no YAML marshaling required.**

The true power of BeemFlow isn't in YAML files—it's in the **universal protocol** that lets you define workflows as native data structures in any language. Think of it like JSON: the same data, tools, and workflow patterns, expressed in each language's most natural form. Run/execute workflows using any live BeemFlow runtime and receive flow outputs via native language SDKs, CLI/stdio, HTTP API, MCP, or any other interface.

> **Coming soon**: a Protobuf-based protocol spec with reference implementation and generated language bindings

---

### Protocol Language Implementation Comparison

**YAML-Native (Template-Centric):**
```yaml
name: research_flow
steps:
  - id: search
    use: http.fetch
    with:
      url: "{{ topic }}"
  - id: summarize
    use: openai.chat_completion
    with:
      model: "gpt-4o"
      messages:
        - role: system
          content: "Summarize in 3 bullets."
        - role: user
          content: "{{ outputs.search.body }}"
```

**JSON-Native (Wire Protocol):**
```json
{
  "name": "research_flow",
  "steps": [
    {
      "id": "search",
      "use": "http.fetch",
      "with": {
        "url": "{{ topic }}"
      }
    },
    {
      "id": "summarize",
      "use": "openai.chat_completion",
      "with": {
        "model": "gpt-4o",
        "messages": [
          {
            "role": "system",
            "content": "Summarize in 3 bullets."
          },
          {
            "role": "user", 
            "content": "{{ outputs.search.body }}"
          }
        ]
      }
    }
  ]
}
```

**Protocol-Native (Language-Centric):**

#### Go: Native Structs
```go
package main

import (
  "context"
  "fmt"
  "github.com/beemflow/beemflow/api"
  "github.com/beemflow/beemflow/model"
)

func main() {
  flow := model.Flow{
    Name: "research_flow",
    Steps: []model.Step{
      {ID: "search", Use: "http.fetch", With: map[string]interface{}{"url": "{{ topic }}"}},
      {ID: "summarize", Use: "openai.chat_completion", With: map[string]interface{}{
        "model": "gpt-4o",
        "messages": []interface{}{ /* ... */ },
      }},
    },
  }

  runID, outputs, err := api.NewFlowService().RunSpec(context.Background(), &flow, map[string]interface{}{})
  if err != nil {
    panic(err)
  }
  fmt.Printf("RunID: %s, Outputs: %+v\n", runID, outputs)
}
```

#### TypeScript: Type-Safe Builders
```typescript
import { FlowBuilder, StepBuilders, BeemFlowClient } from './flow-client';

(async () => {
  const flow = new FlowBuilder('research_flow')
    .step({ 
      id: 'search', 
      use: 'http.fetch', 
      with: { url: '{{ topic }}' } 
    })
    .step({ 
      id: 'summarize', 
      use: 'openai.chat_completion', 
      with: {
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: 'Summarize in 3 bullets.' },
          { role: 'user', content: '{{ outputs.search.body }}' }
        ]
      }
    })
    .build();

  const client = new BeemFlowClient();
  const { runId, outputs } = await client.execute(flow);
  console.log(`RunID: ${runId}`, outputs);
})();
```

#### Python: Dataclass Patterns
```python
from flow_client import FlowBuilder, BeemFlowClient

flow = (FlowBuilder("research_flow")
    .step({
        "id": "search",
        "use": "http.fetch",
        "with": {"url": "{{ topic }}"}
    })
    .step({
        "id": "summarize",
        "use": "openai.chat_completion",
        "with": {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Summarize in 3 bullets."},
                {"role": "user", "content": "{{ outputs.search.body }}"}
            ]
        }
    })
    .build())

client = BeemFlowClient()
execution = client.execute(flow)
print(f"RunID: {execution.run_id}, Outputs: {execution.outputs}")
```

#### Rust: Zero-Cost Abstractions
```rust
use beemflow_client::{FlowBuilder, BeemFlowClient};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowBuilder::new("research_flow")
        .step("search", "http.fetch", json!({
            "url": "{{ topic }}"
        }))
        .step("summarize", "openai.chat_completion", json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Summarize in 3 bullets."},
                {"role": "user", "content": "{{ outputs.search.body }}"}
            ]
        }))
        .build();

    let client = BeemFlowClient::new(None);
    let execution = client.execute(&flow, None).await?;
    println!("RunID: {}, Outputs: {:?}", execution.run_id, execution.outputs);
    Ok(())
}
```

---

### Why This Matters

**🔒 Type Safety**: Catch flow errors at compile time, not runtime  
**🚀 IDE Support**: Full autocomplete, refactoring, go-to-definition  
**⚡ Dynamic Generation**: Build workflows programmatically based on business logic  
**🔄 Cross-Language**: All approaches produce identical JSON protocol  
**📦 Zero YAML**: Direct execution via `/runs/inline` endpoint  
**📋 Schema Validation**: Runtime validation via [JSON Schema](./docs/beemflow.schema.json) ensures protocol compliance

```go
// Generate flows dynamically
func BuildApprovalFlow(requiresLegal, requiresFinance bool) *model.Flow {
    builder := NewFlow("approval_process")
    
    if requiresLegal {
        builder.Step("legal_review", "slack.message", map[string]any{...})
        builder.AwaitEvent("legal_approval", "slack", map[string]any{...})
    }
    
    if requiresFinance {
        builder.Step("finance_review", "slack.message", map[string]any{...})
        builder.AwaitEvent("finance_approval", "slack", map[string]any{...})
    }
    
    return builder.Build()
}
```

**The result?** Flows become **first-class citizens** in your codebase—testable, composable, and maintainable like any other code.

---

## Security & Secrets

- Secrets from env, Vault, or MCP store: `{{ secrets.NAME }}`.
- HMAC-signed resume tokens for durable waits.
- SOC 2 Type II & ISO 27001 soon.

---

## License

We'll see -- feel free to read the code and try things out but not sure if MIT or not yet.
Commercial cloud & SLA on the way.

---

> Docs at <https://docs.beemflow.com> • X: [@BeemFlow](https://X.com/beemflow)
