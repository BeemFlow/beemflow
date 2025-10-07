// Conditional Logic Example
// Demonstrates conditionals, loops, and complex expressions

package beemflow

name: "conditional_logic_demo"
description: """
Demonstrates conditional logic, loops, and complex expressions.
Shows how to use runtime templates for dynamic behavior.
"""

on: "cli.manual"

vars: {
	user_name: "testuser"
	items: ["apple", "banana", "cherry"]
	count: 3
	should_process: true
}

steps: [
	// Basic templating
	{
		id: "basic_templating"
		use: "core.echo"
		with: {
			text: "Hello {{ vars.user_name }}, you have {{ vars.count }} items"
		}
	},

	// Conditional logic
	{
		id: "conditional_step"
		if: "{{ vars.should_process }}"
		use: "core.echo"
		with: {
			text: "Processing is enabled!"
		}
	},

	// Foreach loop
	{
		id: "loop_over_items"
		foreach: "{{ vars.items }}"
		steps: [
			{
				id: "echo_item"
				use: "core.echo"
				with: {
					text: "Item {{ item_index }}: {{ item }}"
				}
			}
		]
	},

	// Reference previous step output
	{
		id: "step_reference"
		use: "core.echo"
		with: {
			text: "Previous step said: {{ outputs.basic_templating.text }}"
		}
	},

	// Conditional based on count
	{
		id: "check_count"
		if: "{{ vars.count > 2 }}"
		use: "core.echo"
		with: {
			text: "We have many items: {{ vars.count }}"
		}
	},

	// Summary
	{
		id: "summary"
		use: "core.echo"
		with: {
			text: "Processed {{ vars.count }} items for {{ vars.user_name }}"
		}
	}
]