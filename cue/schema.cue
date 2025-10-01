// BeemFlow CUE Schema
// This defines the structure of BeemFlow workflows in CUE

package beemflow

import (
	"strings"
)

// Flow represents a complete workflow
#Flow: {
	name:        string
	description?: string
	version?:     string
	on:           #Trigger | [#Trigger, ...#Trigger]
	cron?:        string // Cron expression for schedule.cron
	vars?:        #Vars
	steps:        [#Step, ...#Step]
	catch?:       [#Step, ...#Step]
	mcpServers?:  #MCPServers
}

// Trigger defines when a flow should execute
#Trigger: string | #TriggerObject

#TriggerObject: {
	type:    string
	schedule?: string
	manual?:  bool
	event?:   string
	match?:   #Match
}

// Vars holds workflow-level variables
#Vars: [string]: _

// Step represents a single execution step
#Step: {
	id:         string
	use?:       string
	with?:      #StepWith
	depends_on?: [...string]
	parallel?:   bool
	if?:         string | bool // CUE expression or boolean
	foreach?:    string | _    // CUE expression or value
	as?:         string
	do?:         [#Step, ...#Step]
	steps?:      [#Step, ...#Step] // For parallel blocks
	retry?:      #RetrySpec
	await_event?: #AwaitEventSpec
	wait?:       #WaitSpec
}

// StepWith holds parameters for tool execution
#StepWith: [string]: _

#RetrySpec: {
	attempts: int
	delay_sec: int
}

#AwaitEventSpec: {
	source:  string
	match:   #Match
	timeout?: string
}

#WaitSpec: {
	seconds?: int
	until?:    string
}

// Match defines event matching criteria
#Match: [string]: _

#MCPServers: [string]: #MCPServerConfig

#MCPServerConfig: {
	command:   string
	args?:     [...string]
	env?:      [string]: string
	port?:     int
	transport?: string
	endpoint?:  string
}

// Helper functions for common operations
#stringJoin: strings.Join
#stringContains: strings.Contains
#stringHasPrefix: strings.HasPrefix
#stringHasSuffix: strings.HasSuffix

// Template filter functions (available in {{ }} expressions)
#templateFilters: {
	// String filters
	upper: strings.ToUpper
	lower: strings.ToLower
	title: strings.ToTitle
	trim: strings.TrimSpace
	length: len

	// Array filters
	join: #stringJoin

	// Utility functions
	now: #now
	base64: #base64Encode
	duration: #durationFormat
}

// Utility for accessing previous run outputs
#previousRun: {
	flow: string
	outputs: [string]: _
	id: string
	status: string
}

// Environment access (populated at runtime)
#env: [string]: string

// Built-in functions available in expressions
#len: len
#now: string // Current timestamp (populated at runtime)

// Helper functions for template filters (implemented in Go)
#base64Encode: func(s) { "base64_encode_placeholder" }
#durationFormat: func(n, unit) { "duration_format_placeholder" }
