package main

import (
	"fmt"
	"os"

	"example.com/yggdrasil-panel/internal/sitegen"
)

func main() {
	root, err := os.Getwd()
	if err == nil {
		err = sitegen.GenerateDocs(root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "docs-gen:", err)
		os.Exit(1)
	}
}
