package docs

import _ "embed"

//go:embed SPEC.md
var BeemflowSpec string

//go:embed BEEMFLOW.md
var BeemflowComprehensive string

//go:embed flow.config.schema.json
var FlowConfigSchema string
