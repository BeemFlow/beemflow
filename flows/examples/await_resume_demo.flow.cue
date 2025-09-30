// Await Resume Demo in CUE
// Demonstrate event-driven workflow with pause/resume capability.
// Shows human-in-the-loop patterns and event matching.

package beemflow

name: "echo_await_resume"
description: """
Demonstrate event-driven workflow with pause/resume capability. Echo start message,
wait up to 1 hour for a test event with matching token, then resume and echo the
received event data. Shows human-in-the-loop patterns and event matching.
"""

on: ["event: test.manual"]

vars: {
	token: "abc123"
}

steps: [
	{
		id: "echo_start"
		use: "core.echo"
		with: {
			text: "Started (token: \(vars.token))"
		}
	},

	{
		id: "wait_for_resume"
		await_event: {
			source: "test"
			match: {
				token: "{{ vars.token }}"
			}
			timeout: "1h"
		}
	},

	{
		id: "echo_resumed"
		use: "core.echo"
		with: {
			text: "Resumed with: {{ event.resume_value }} (token: \(vars.token))"
		}
	}
]
