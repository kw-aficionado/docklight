package yggdrasil

import "embed"

//go:embed web/index.html web/app.js web/ui-utils.mjs web/style.css web/config-editor.css web/brand.svg web/service-worker.js web/status.html web/status.js
var WebFS embed.FS

//go:embed builtin-runes/*.yaml
var BuiltinRunes embed.FS

//go:embed docs/getting-started.md docs/guides/*.md docs/*.md
var DocsFS embed.FS
