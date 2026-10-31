package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOverlayReplacesArchivedFilesAndPreservesOtherData(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	target := filepath.Join(root, "server-data")
	writeOverlayFile(t, filepath.Join(stage, "world", "level.dat"), "backup world")
	writeOverlayFile(t, filepath.Join(stage, "settings.json"), "backup settings")
	writeOverlayFile(t, filepath.Join(target, "world", "level.dat"), "newer world")
	writeOverlayFile(t, filepath.Join(target, "world", "player.dat"), "player data created after backup")
	writeOverlayFile(t, filepath.Join(target, "notes", "keep.txt"), "unarchived directory contents")
	writeOverlayFile(t, filepath.Join(target, "settings.json"), "newer settings")

	warning, err := Overlay(stage, target)
	if err != nil || warning != "" {
		t.Fatalf("Overlay() warning=%q err=%v", warning, err)
	}
	assertOverlayFile(t, filepath.Join(target, "world", "level.dat"), "backup world")
	assertOverlayFile(t, filepath.Join(target, "settings.json"), "backup settings")
	assertOverlayFile(t, filepath.Join(target, "world", "player.dat"), "player data created after backup")
	assertOverlayFile(t, filepath.Join(target, "notes", "keep.txt"), "unarchived directory contents")
}

func TestOverlayRollsBackEarlierReplacementsOnConflict(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	target := filepath.Join(root, "server-data")
	writeOverlayFile(t, filepath.Join(stage, "a.txt"), "archived a")
	writeOverlayFile(t, filepath.Join(stage, "z.txt"), "archived z")
	writeOverlayFile(t, filepath.Join(target, "a.txt"), "original a")
	writeOverlayFile(t, filepath.Join(target, "z.txt", "keep.txt"), "original z directory")

	_, err := Overlay(stage, target)
	if err == nil || !strings.Contains(err.Error(), "rolled back") || !errors.Is(err, ErrOverlayConflict) {
		t.Fatalf("Overlay() error=%v; want a conflict with rollback", err)
	}
	assertOverlayFile(t, filepath.Join(target, "a.txt"), "original a")
	assertOverlayFile(t, filepath.Join(target, "z.txt", "keep.txt"), "original z directory")
}

func TestOverlayRejectsTargetSymlink(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	target := filepath.Join(root, "server-data")
	outside := filepath.Join(root, "outside.txt")
	writeOverlayFile(t, filepath.Join(stage, "link.txt"), "must not overwrite outside")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	writeOverlayFile(t, outside, "outside content")
	if err := os.Symlink(outside, filepath.Join(target, "link.txt")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	_, err := Overlay(stage, target)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") || !errors.Is(err, ErrOverlayConflict) {
		t.Fatalf("Overlay() error=%v; want a symbolic-link rejection", err)
	}
	assertOverlayFile(t, outside, "outside content")
	info, err := os.Lstat(filepath.Join(target, "link.txt"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("target symlink changed: info=%v err=%v", info, err)
	}
}

func writeOverlayFile(t *testing.T, filePath, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertOverlayFile(t *testing.T, filePath, want string) {
	t.Helper()
	got, err := os.ReadFile(filePath)
	if err != nil || string(got) != want {
		t.Fatalf("%s = %q, err=%v; want %q", filePath, got, err, want)
	}
}
