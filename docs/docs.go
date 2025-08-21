package docs

import _ "embed"

// BeemflowSpec is the embedded BeemFlow spec document.
//
// This is the canonical, up-to-date protocol and config spec, including event bus config and schema references.
//
//go:embed SPEC.md
var BeemflowSpec string

// BeemflowComprehensive is the ultimate comprehensive BeemFlow documentation.
// Currently disabled until BEEMFLOW.md is created.
// var BeemflowComprehensive string

//go:embed beemflow.schema.json
var BeemflowSchema string

//go:embed flow.config.schema.json
var FlowConfigSchema string
