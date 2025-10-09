// Fetch and Summarize Flow in CUE
// Fetch content from a web URL using HTTP, summarize it with OpenAI into 3 bullet points,
// and display the summary. Demonstrates HTTP fetching, AI processing, and step chaining
// in a simple end-to-end workflow pattern.

package beemflow

name: "fetch_and_summarize"
description: """
Fetch content from a web URL using HTTP, summarize it with OpenAI into 3 bullet points,
and display the summary. Demonstrates HTTP fetching, AI processing, and step chaining
in a simple end-to-end workflow pattern.
"""

on: "cli.manual"

vars: {
	fetch_url: "https://raw.githubusercontent.com/beemflow/beemflow/refs/heads/main/README.md"
}

steps: [
	{
		id: "fetch_page"
		use: "http.fetch"
		with: {
			url: vars.fetch_url
		}
	},
	{
		id: "summarize"
		use: "openai.chat_completion"
		with: {
			model: "gpt-4o"
			messages: [
				{
					role: "system"
					content: "Summarize the following web page in 3 bullets."
				},
				{
					role: "user"
					content: "{{ outputs.fetch_page.body }}"
				}
			]
		}
	},
	{
		id: "print"
		use: "core.echo"
		with: {
			text: "Summary: {{ outputs.summarize.choices[0].message.content }}"
		}
	}
]
