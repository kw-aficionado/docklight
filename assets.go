package yggdrasil

import "embed"

//go:embed web/*
var WebFS embed.FS

//go:embed builtin-runes/*.yaml
var BuiltinRunes embed.FS
