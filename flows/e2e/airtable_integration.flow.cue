// Airtable Integration Flow in CUE
// List available Airtable bases using MCP server integration. Demonstrates MCP server
// connectivity and external service integration patterns for database operations.

package beemflow

name: "list_airtable_tables"
description: """
List available Airtable bases using MCP server integration. Demonstrates MCP server
connectivity and external service integration patterns for database operations.
"""

on: "cli.manual"

steps: [
	{
		id: "list_bases"
		use: "mcp://airtable/list_bases"
	}
]
