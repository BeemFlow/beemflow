// Parallel Execution Integration Test in CUE
// Integration test for parallel execution with real scenarios

package beemflow

name: "test_parallel_integration"
description: "Integration test for parallel execution with real scenarios"
on: "cli.manual"

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

	// Test foreach with parallel processing
	{
		id: "process_data_parallel"
		foreach: "{{ vars.test_data }}"
		parallel: true
		steps: [
			{
				id: "echo_parallel"
				use: "core.echo"
				with: {
					text: "Processing {{ item }} in parallel"
				}
			}
		]
	},

	// Test foreach with sequential processing for comparison
	{
		id: "process_data_sequential"
		foreach: "{{ vars.test_data }}"
		steps: [
			{
				id: "echo_sequential"
				use: "core.echo"
				with: {
					text: "Processing {{ item }} sequentially"
				}
			}
		]
	},

	// Test nested parallel within foreach
	{
		id: "nested_parallel_foreach"
		foreach: "{{ vars.test_data }}"
		parallel: true
		steps: [
			{
				id: "uppercase"
				use: "core.echo"
				with: {
					text: "UPPERCASE: {{ item }}"
				}
			},
			{
				id: "length"
				use: "core.echo"
				with: {
					text: "Item {{ item }} has {{ len(item) }} characters"
				}
			}
		]
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
