// Parallel Execution Integration Test in CUE
// Integration test for parallel execution with real scenarios

package beemflow

name: "test_parallel_integration"
description: "Integration test for parallel execution with real scenarios"

vars: {
	test_data: ["apple", "banana", "cherry", "date", "elderberry"]
	base_url: "https://postman-echo.com"
}

steps: [
	// Test parallel HTTP requests
	{
		id: "parallel_http_requests"
		parallel: true
		steps: [
			{
				id: "get_ip"
				use: "http"
				with: {
					url:    vars.base_url + "/ip"
					method: "GET"
				}
			},
			{
				id: "get_headers"
				use: "http"
				with: {
					url:    vars.base_url + "/headers"
					method: "GET"
				}
			},
			{
				id: "get_user_agent"
				use: "http"
				with: {
					url:    vars.base_url + "/headers"
					method: "GET"
				}
			}
		]
	},

	// Test foreach with parallel processing using CUE comprehensions
	for item in vars.test_data {
		"process_data_parallel_\(item)": {
			use: "core.echo"
			with: {
				text: "Processing \(item) in parallel"
			}
		}
	},

	// Test foreach with sequential processing for comparison
	for item in vars.test_data {
		"process_data_sequential_\(item)": {
			use: "core.echo"
			with: {
				text: "Processing \(item) sequentially"
			}
		}
	},

	// Test nested parallel within foreach using CUE comprehensions
	for fruit in vars.test_data {
		"nested_parallel_test_\(fruit)": {
			parallel: true
			steps: [
				{
					id: "uppercase_\(fruit)"
					use: "core.echo"
					with: {
						text: strings.ToUpper(fruit)
					}
				},
				{
					id: "length_\(fruit)"
					use: "core.echo"
					with: {
						text: "\(fruit) has \(len(fruit)) characters"
					}
				}
			]
		}
	},

	// Final verification step
	{
		id: "verify_results"
		use: "core.echo"
		with: {
			text: """
Parallel test completed!
HTTP requests: \(len(vars.test_data))
Parallel items: \(len(vars.test_data))
Sequential items: \(len(vars.test_data))
Nested operations: \(len(vars.test_data))
"""
		}
	}
]
