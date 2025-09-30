// Nested Parallel Test in CUE
// Simple test to debug nested parallel issue

package beemflow

name: "test_nested_parallel"
description: "Simple test to debug nested parallel issue"
on: "cli.manual"

vars: {
	items: ["alpha", "beta"]
}

steps: [
	// Test nested parallel within foreach
	{
		id: "process_items"
		foreach: "{{ vars.items }}"
		parallel: true
		steps: [
			{
				id: "upper"
				use: "core.echo"
				with: {
					text: "UPPER: {{ item }}"
				}
			},
			{
				id: "length"
				use: "core.echo"
				with: {
					text: "Length: 5"
				}
			},
			{
				id: "reverse"
				use: "core.echo"
				with: {
					text: "Reversed: {{ item }}"
				}
			}
		]
	}
]
