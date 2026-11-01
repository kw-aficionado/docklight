package runeimport

import (
	"fmt"

	"example.com/yggdrasil-panel/internal/rune"
)

const YggdrasilRuneMaxSize = 512 << 10

// ImportYggdrasil translates an upstream Yggdrasil YAML Rune into the
// Docklight template model and returns notes for features that cannot carry
// over.
func ImportYggdrasil(input []byte) (rune.Rune, []string, error) {
	if len(input) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("Yggdrasil Rune file is empty")
	}
	if len(input) > YggdrasilRuneMaxSize {
		return rune.Rune{}, nil, fmt.Errorf("Yggdrasil Rune exceeds the 512 KiB upload limit")
	}
	return rune.ImportYggdrasil(string(input))
}
