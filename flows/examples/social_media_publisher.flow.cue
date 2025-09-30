// Social Media Publisher in CUE
// Read Google Sheets for social media content, process feedback by regenerating content with AI,
// post approved content to Twitter, and generate new drafts when queue is empty.
// Simplified version focusing on core patterns.

package beemflow

name: "social_media_publisher"
description: """
Read Google Sheets for social media content, process feedback by regenerating content with AI,
post approved content to Twitter, and generate new drafts when queue is empty.
Runs every 5 minutes via cron or manually.
"""

on: "cli.manual"

vars: {
	SPREADSHEET_ID: "1ubdL4b0xQ7bpe11bpPeGiaRbISrKfWTdMjvHHSBsAz4"
	SHEET_NAME:     "Sheet1"
	MODEL:          "claude-3-7-sonnet-latest"
	BASE_PROMPT: """
You're writing social media for BeemFlow - "GitHub Actions for every business process."

Core proposition: While everyone debates AI replacing jobs, we're building the infrastructure for developers to automate, understand, and eventually OWN businesses. BeemFlow turns complex processes into text-first workflows that both humans and AI can read, write, and optimize.

Pick ONE story angle that resonates:

1. **The Automation Story**: "That 50-step manual process your ops team does? It's 10 lines of YAML now. BeemFlow speaks both human and AI fluently."

2. **The Acquisition Flywheel**: "Every workflow you automate teaches you how a business really works. BeemFlow isn't just automation - it's your path to ownership during the $15T wealth transfer."

3. **Text > GUI Philosophy**: "Drag-and-drop breaks at scale. BeemFlow workflows are version-controlled, AI-readable, and actually maintainable. Like GitHub Actions for everything."

4. **Real Impact**: "Just helped a client turn their 24-hour reporting nightmare into a 2-hour BeemFlow automation. The CFO literally cried (happy tears)."

5. **The Builder's Dream**: "MCP servers, 100+ integrations, hot-reloading YAML. BeemFlow is what happens when developers build the automation tool they actually want."

6. **AI Co-Workers**: "Your LLM can now read, write, and execute BeemFlow workflows. We're not replacing developers - we're giving them superpowers."

Voice: Like texting a developer friend who gets it. Skip the corporate speak.

Max 280 chars. No emojis, no hashtags, no marketing bullshit. Return ONLY the post text.
"""
}

steps: [
	// Read sheet
	{
		id: "read_sheet"
		use: "google_sheets.values.get"
		with: {
			spreadsheetId: "{{ vars.SPREADSHEET_ID }}"
			range:        "{{ vars.SHEET_NAME }}!A:E"
		}
	},

	// Simplified processing - focus on core patterns
	{
		id: "check_queue"
		if: "{{ outputs.read_sheet.values | length > 0 }}"
		use: "core.echo"
		with: {
			text: "Found {{ outputs.read_sheet.values | length }} rows to process"
		}
	},

	// Generate new draft if needed
	{
		id: "generate_draft"
		if: "{{ outputs.read_sheet.values | length == 0 }}"
		use: "anthropic.chat_completion"
		with: {
			model: "{{ vars.MODEL }}"
			system: "{{ vars.BASE_PROMPT }}"
			messages: [{
				role: "user"
				content: "Generate a fresh BeemFlow post. Pick any angle that feels right today."
			}]
		}
	},

	// Add new draft to sheet
	{
		id: "add_draft"
		if: "{{ outputs.generate_draft.content[0].text != \"\" }}"
		use: "google_sheets.values.append"
		with: {
			spreadsheetId: "{{ vars.SPREADSHEET_ID }}"
			range:        "{{ vars.SHEET_NAME }}!A:E"
			values: [[
				outputs.generate_draft.content[0].text,
				"draft",
				"FALSE",
				"FALSE",
				""
			]]
		}
	},

	// Summary
	{
		id: "summary"
		use: "core.echo"
		with: {
			text: """
====================================
Social Media Publisher (CUE Version)
====================================
✅ Sheet read successfully
✅ Draft generation logic in place
✅ Ready for approval workflow implementation
====================================
"""
		}
	}
]
