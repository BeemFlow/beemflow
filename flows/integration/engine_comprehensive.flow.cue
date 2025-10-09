// Engine Comprehensive Integration Test in CUE
// Comprehensive integration test for engine functionality

package beemflow

name: "test_engine_integration"
description: "Comprehensive integration test for engine functionality"
on: "cli.manual"

vars: {
	test_items: ["alpha", "beta", "gamma"]
	base_number: 42
	text: "hello world"
	array: ["a", "b", "c"]
	nested: {
		level1: {
			level2: "deep value"
		}
	}
}

steps: [
	// Test basic execution
	{
		id: "test_basic"
		use: "core.echo"
		with: {
			text: "Engine test starting..."
		}
	},

	// Test foreach
	{
		id: "test_foreach"
		foreach: "{{ vars.test_items }}"
		steps: [
			{
				id: "process_item"
				use: "core.echo"
				with: {
					text: "Processing {{ item }}"
				}
			}
		]
	},

	// Test conditions
	{
		id: "test_condition"
		if: "{{ vars.base_number == 42 }}"
		use: "core.echo"
		with: {
			text: "Condition passed!"
		}
	},

	// Test complex conditions
	{
		id: "test_complex_condition"
		if: "{{ vars.base_number > 40 && len(vars.test_items) > 2 }}"
		use: "core.echo"
		with: {
			text: "Complex condition passed!"
		}
	},

	// Test template operations
	{
		id: "test_template_ops"
		use: "core.echo"
		with: {
			text: "Text: {{ vars.text }}, Length: {{ len(vars.text) }}, Array length: {{ len(vars.array) }}"
		}
	},

	// Test nested access
	{
		id: "test_nested_access"
		use: "core.echo"
		with: {
			text: "Nested value: {{ vars.nested.level1.level2 }}"
		}
	},

	// Test existing variables only (CUE doesn't support || operator for defaults)
	{
		id: "test_existing_vars"
		use: "core.echo"
		with: {
			text: "Existing var: {{ vars.text }}"
		}
	},

	// Test parallel
	{
		id: "test_parallel"
		parallel: true
		steps: [
			{
				id: "parallel1"
				use: "core.echo"
				with: {
					text: "Parallel 1"
				}
			},
			{
				id: "parallel2"
				use: "core.echo"
				with: {
					text: "Parallel 2"
				}
			}
		]
	},

	// Test nested parallel in foreach
	{
		id: "test_nested_parallel"
		foreach: "{{ vars.test_items }}"
		parallel: true
		steps: [
			{
				id: "nested_parallel_{{ item_index }}"
				use: "core.echo"
				with: {
					text: "Processing {{ item }} in parallel"
				}
			}
		]
	},

	// Final summary
	{
		id: "engine_summary"
		use: "core.echo"
		with: {
			text: "Engine comprehensive test completed!"
		}
	}
]
