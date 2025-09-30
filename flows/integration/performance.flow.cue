// Performance Test in CUE
// Performance and load testing for scalability

package beemflow

name: "test_performance"
description: "Performance and load testing for scalability"

vars: {
	large_dataset: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
	stress_iterations: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
	small_array: [1, 2, 3]
}

steps: [
	// Test large parallel processing using CUE comprehensions
	for item in vars.large_dataset {
		"large_parallel_test_\(item)": {
			use: "core.echo"
			with: {
				text: "Processing item \(item) in parallel - simulating work"
			}
		}
	},

	// Test nested parallel operations
	for iteration in vars.stress_iterations {
		"stress_test_\(iteration)": {
			parallel: true
			steps: [
				for item in vars.small_array {
					"nested_work_\(iteration)_\(item)": {
						use: "core.echo"
						with: {
							text: "Stress iteration \(iteration), item \(item)"
						}
					}
				}
			]
		}
	},

	// Performance summary
	{
		id: "performance_summary"
		use: "core.echo"
		with: {
			text: """
Performance test completed!
Dataset size: \(len(vars.large_dataset))
Stress iterations: \(len(vars.stress_iterations))
Total operations: \(len(vars.large_dataset) + (len(vars.stress_iterations) * len(vars.small_array)))
"""
		}
	}
]
