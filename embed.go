package runnerguard

import "embed"

//go:embed rules
var RulesFS embed.FS

//go:embed demo/vulnerable/workflows/*.yml
var DemoFS embed.FS
