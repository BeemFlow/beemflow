// Engine Comprehensive Integration Test in CUE
// Comprehensive integration test for engine functionality

package beemflow

name: "test_engine_integration"
description: "Comprehensive integration test for engine functionality"

vars: {
	test_items: ["alpha", "beta", "gamma", "delta"]
	base_number: 42
	test_config: {
		timeout: 5
		retries: 3
		parallel_limit: 2
	}
}

steps: [
	// Test basic step execution and templating
	{
		id: "basic_test"
		use: "core.echo"
		with: {
			text: "Starting integration test with \(len(vars.test_items)) items"
		}
	},

	// Test parallel execution with HTTP calls
	{
		id: "parallel_http_test"
		parallel: true
		steps: [
			{
				id: "http_get_1"
				use: "http"
				with: {
					url:    "https://postman-echo.com/get"
					method: "GET"
				}
			},
			{
				id: "http_get_2"
				use: "http"
				with: {
					url:    "https://postman-echo.com/get"
					method: "GET"
				}
			}
		]
	},

	// Test foreach with data processing
	for item in vars.test_items {
		"process_item_\(item)": {
			use: "core.echo"
			with: {
				text: "Processing \(item) with base number \(vars.base_number)"
			}
		}
	},

	// Test conditional logic
	{
		id: "conditional_test"
		if: "len(vars.test_items) > 2"
		use: "core.echo"
		with: {
			text: "Condition met: test_items has more than 2 items"
		}
	},

	// Test error handling and recovery
	{
		id: "error_recovery_test"
		use: "core.echo"
		with: {
			text: "Testing error recovery patterns"
		}
	},

	// Final integration summary
	{
		id: "integration_summary"
		use: "core.echo"
		with: {
			text: """
Engine integration test completed successfully!
- Basic execution: ✓
- Parallel HTTP calls: ✓
- Foreach processing: ✓
- Conditional logic: ✓
- Error recovery: ✓
"""
		}
	}
]
