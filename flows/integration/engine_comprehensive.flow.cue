// Engine Comprehensive Integration Test in CUE
// Comprehensive integration test for engine functionality

package beemflow

name: "test_engine_integration"
description: "Comprehensive integration test for engine functionality"
on: "cli.manual"

vars: {
	test_items: ["alpha", "beta", "gamma"]
	base_number: 42
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
		use: "core.echo"
		with: {
			text: "Processing {{ item }}"
		}
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

	// Final summary
	{
		id: "engine_summary"
		use: "core.echo"
		with: {
			text: "Engine comprehensive test completed!"
		}
	}
]
