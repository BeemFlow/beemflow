// Hello World Flow in CUE
// This demonstrates the basic structure of a BeemFlow workflow in CUE

package beemflow

name: "hello"
description: """
Display a greeting message, then echo that same message again with additional text.
Demonstrates basic step chaining and template variable usage.
"""

on: "cli.manual"

steps: [
	{
		id: "greet"
		use: "core.echo"
		with: {
			text: "Hello, world, I'm BeemFlow!"
		}
	},
	{
		id: "greet_again"
		use: "core.echo"
		with: {
			// Access the output from the previous step using runtime template
			text: "Aaand once more: {{ outputs.greet.text }}"
		}
	}
]
