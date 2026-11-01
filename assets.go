package yggdrasil

import "embed"

//go:embed web/*
var WebFS embed.FS

//go:embed builtin-runes/*.yaml
var BuiltinRunes embed.FS

//go:embed docs/getting-started.md docs/guides/*.md docs/*.md
var DocsFS embed.FS
