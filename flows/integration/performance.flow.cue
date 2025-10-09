// Performance Test in CUE
// Performance and load testing for scalability

package beemflow

name: "test_performance"
description: "Performance and load testing for scalability"
on: "cli.manual"

vars: {
	large_dataset: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
	small_array: [1, 2, 3]
}

steps: [
	// Test parallel processing
	{
		id: "large_parallel_test"
		foreach: "{{ vars.large_dataset }}"
		steps: [
			{
				id: "process_item"
				use: "core.echo"
				with: {
					text: "Processing item {{ item }} in parallel"
				}
			}
		]
	},

	// Test sequential processing
	{
		id: "sequential_test"
		foreach: "{{ vars.small_array }}"
		steps: [
			{
				id: "process_item"
				use: "core.echo"
				with: {
					text: "Sequential: {{ item }}"
				}
			}
		]
	},

	// Final summary
	{
		id: "performance_summary"
		use: "core.echo"
		with: {
			text: "Performance testing completed successfully!"
		}
	}
]
