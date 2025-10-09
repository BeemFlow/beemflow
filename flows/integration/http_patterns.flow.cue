// HTTP Patterns Test in CUE
// Test different HTTP integration patterns: registry tools (http.fetch), generic HTTP adapter,
// OpenAI/Anthropic manifest tools, and POST requests. Demonstrates tool resolution hierarchy
// and various approaches to HTTP-based integrations with their trade-offs.

package beemflow

name: "http_patterns_test"
description: """
Test different HTTP integration patterns: registry tools (http.fetch), generic HTTP adapter,
OpenAI/Anthropic manifest tools, and POST requests. Demonstrates tool resolution hierarchy
and various approaches to HTTP-based integrations with their trade-offs.
"""

on: "cli.manual"

vars: {
	test_url: "https://postman-echo.com/get"
}

steps: [
	// Test 1: Registry-defined http.fetch tool (simple, GET-only)
	{
		id: "test_http_fetch"
		use: "http.fetch"
		with: {
			url: vars.test_url
		}
	},

	// Test 2: Generic HTTP adapter (flexible, all methods)
	{
		id: "test_generic_http"
		use: "http"
		with: {
			url:     vars.test_url
			method:  "GET"
			headers: {
				"User-Agent":    "BeemFlow/1.0"
				"X-Test-Header": "integration-test"
			}
		}
	},

	// Test 3: OpenAI manifest-based tool (API-specific defaults)
	{
		id: "test_openai_manifest"
		use: "openai.chat_completion"
		with: {
			model: "gpt-4o-mini"
			messages: [{
				role:    "user"
				content: "Say exactly: 'OpenAI manifest tool works!'"
			}]
		}
	},

	// Test 4: Anthropic manifest-based tool (different API structure)
	{
		id: "test_anthropic_manifest"
		use: "anthropic.chat_completion"
		with: {
			model: "claude-3-haiku-20240307"
			messages: [{
				role:    "user"
				content: "Say exactly: 'Anthropic manifest tool works!'"
			}]
		}
	},

	// Test 5: HTTP POST with body (only possible with generic adapter)
	{
		id: "test_http_post"
		use: "http"
		with: {
			url:    "https://postman-echo.com/post"
			method: "POST"
			headers: {
				"Content-Type": "application/json"
			}
			body: """
{
  "message": "Testing POST with BeemFlow",
  "timestamp": "2025-01-01T00:00:00Z"
}
"""
		}
	},

	// Test 6: Verify all patterns work and show differences
	{
		id: "verify_results"
		use: "core.echo"
		with: {
			text: """
🧪 HTTP Patterns Test Results:

📡 Registry Tool (http.fetch):
- URL: {{ outputs.test_http_fetch.url }}
- Simple GET-only syntax
- Perfect for basic fetching

🔧 Generic HTTP Adapter:
- URL: {{ outputs.test_generic_http.url }}
- Custom headers supported
- Supports all HTTP methods

🤖 OpenAI Manifest Tool:
- Response: {{ outputs.test_openai_manifest.choices[0].message.content }}
- API-specific defaults and validation

🧠 Anthropic Manifest Tool:
- Response: {{ outputs.test_anthropic_manifest.content[0].text }}
- Different response structure handled automatically

📤 HTTP POST Example:
- Posted to: {{ outputs.test_http_post.url }}
- Body sent successfully

✅ All HTTP patterns working correctly!
"""
		}
	}
]
