package runeimport

import (
	"strings"
	"testing"
)

func TestImportYggdrasilEnforcesUploadLimitAndRejectsEmptyInput(t *testing.T) {
	if _, _, err := ImportYggdrasil(nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty Rune error = %v, want empty-file error", err)
	}
	if _, _, err := ImportYggdrasil([]byte(strings.Repeat("#", YggdrasilRuneMaxSize+1))); err == nil || !strings.Contains(err.Error(), "512 KiB") {
		t.Fatalf("oversized Rune error = %v, want 512 KiB limit", err)
	}
}
