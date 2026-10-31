package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type overlayEntry struct {
	rel string
	dir bool
	src string
}

type overlayChange struct {
	target    string
	rollback  string
	saved     bool
	installed bool
}

var ErrOverlayConflict = errors.New("restore overlay conflicts with existing server data")

// Overlay applies the contents of a verified restore staging directory to an
// existing data directory. Entries absent from the archive are left untouched.
// If an operation fails, files already replaced by this call are restored.
func Overlay(stage, target string) (warning string, err error) {
	stageInfo, err := os.Lstat(stage)
	if err != nil || !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("restore staging path must be a real directory")
		}
		return "", fmt.Errorf("inspect restore staging directory: %w", err)
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		return "", fmt.Errorf("inspect current server data directory: %w", err)
	}
	if !targetInfo.IsDir() || targetInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: current server data path must be a real directory", ErrOverlayConflict)
	}
	stageAbs, err := filepath.Abs(stage)
	if err != nil {
		return "", fmt.Errorf("resolve restore staging directory: %w", err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve current server data directory: %w", err)
	}
	if within(stageAbs, targetAbs) || within(targetAbs, stageAbs) {
		return "", errors.New("restore staging and server data directories must not overlap")
	}

	entries := make([]overlayEntry, 0)
	err = filepath.WalkDir(stage, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read restore staging directory: %w", walkErr)
		}
		if filePath == stage {
			return nil
		}
		info, infoErr := os.Lstat(filePath)
		if infoErr != nil {
			return fmt.Errorf("inspect staged restore entry: %w", infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restore staging contains a symbolic link: %s", filepath.Base(filePath))
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("restore staging contains an unsupported file type: %s", filepath.Base(filePath))
		}
		rel, relErr := filepath.Rel(stage, filePath)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		clean, nameErr := safeArchiveName(rel)
		if nameErr != nil {
			return nameErr
		}
		entries = append(entries, overlayEntry{rel: clean, dir: info.IsDir(), src: filePath})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].dir != entries[j].dir {
			return entries[i].dir
		}
		if entries[i].dir {
			depthI := strings.Count(entries[i].rel, "/")
			depthJ := strings.Count(entries[j].rel, "/")
			if depthI != depthJ {
				return depthI < depthJ
			}
		}
		return entries[i].rel < entries[j].rel
	})

	rollbackRoot, err := os.MkdirTemp(filepath.Dir(target), ".docklight-restore-rollback-")
	if err != nil {
		return "", fmt.Errorf("create restore rollback directory: %w", err)
	}
	if err = os.Chmod(rollbackRoot, 0700); err != nil {
		_ = os.RemoveAll(rollbackRoot)
		return "", fmt.Errorf("secure restore rollback directory: %w", err)
	}
	changes := make([]*overlayChange, 0, len(entries))
	createdDirs := make([]string, 0)
	rollback := func(cause error) error {
		var rollbackErrors []error
		for i := len(changes) - 1; i >= 0; i-- {
			change := changes[i]
			if change.installed {
				if removeErr := os.Remove(change.target); removeErr != nil && !os.IsNotExist(removeErr) {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("remove restored file %q: %w", change.target, removeErr))
				}
			}
			if change.saved {
				if restoreErr := os.Rename(change.rollback, change.target); restoreErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("put original file back at %q: %w", change.target, restoreErr))
				}
			}
		}
		for i := len(createdDirs) - 1; i >= 0; i-- {
			if removeErr := os.Remove(createdDirs[i]); removeErr != nil && !os.IsNotExist(removeErr) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("remove new directory %q: %w", createdDirs[i], removeErr))
			}
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("%v; rollback was incomplete and recovery files remain at %q: %w", cause, rollbackRoot, errors.Join(rollbackErrors...))
		}
		if cleanupErr := os.RemoveAll(rollbackRoot); cleanupErr != nil {
			return fmt.Errorf("%w; original files were restored, but rollback cleanup failed at %q: %v", cause, rollbackRoot, cleanupErr)
		}
		return fmt.Errorf("%w; earlier changes were rolled back", cause)
	}
	fail := func(cause error) (string, error) {
		return "", rollback(cause)
	}

	for _, entry := range entries {
		relPath := filepath.FromSlash(entry.rel)
		destination := filepath.Join(target, relPath)
		if !within(target, destination) {
			return fail(fmt.Errorf("restore entry %q escapes the server data directory", entry.rel))
		}
		if err = checkOverlayParents(target, relPath); err != nil {
			return fail(err)
		}
		info, statErr := os.Lstat(destination)
		if entry.dir {
			if statErr == nil {
				if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
					return fail(fmt.Errorf("%w: restore directory %q conflicts with an existing non-directory", ErrOverlayConflict, entry.rel))
				}
				continue
			}
			if !os.IsNotExist(statErr) {
				return fail(fmt.Errorf("inspect restore directory %q: %w", entry.rel, statErr))
			}
			if err = os.Mkdir(destination, 0700); err != nil {
				return fail(fmt.Errorf("create restored directory %q: %w", entry.rel, err))
			}
			createdDirs = append(createdDirs, destination)
			continue
		}
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fail(fmt.Errorf("%w: restore file %q conflicts with an existing symbolic link", ErrOverlayConflict, entry.rel))
			}
			if !info.Mode().IsRegular() {
				return fail(fmt.Errorf("%w: restore file %q conflicts with an existing unsupported file type", ErrOverlayConflict, entry.rel))
			}
		} else if !os.IsNotExist(statErr) {
			return fail(fmt.Errorf("inspect restore file %q: %w", entry.rel, statErr))
		}
		change := &overlayChange{target: destination}
		changes = append(changes, change)
		if statErr == nil {
			change.rollback = filepath.Join(rollbackRoot, relPath)
			if err = os.MkdirAll(filepath.Dir(change.rollback), 0700); err != nil {
				return fail(fmt.Errorf("prepare rollback for %q: %w", entry.rel, err))
			}
			if err = os.Rename(destination, change.rollback); err != nil {
				return fail(fmt.Errorf("preserve current file %q before restore: %w", entry.rel, err))
			}
			change.saved = true
		}
		if err = os.Rename(entry.src, destination); err != nil {
			return fail(fmt.Errorf("install restored file %q: %w", entry.rel, err))
		}
		change.installed = true
	}
	if err = os.RemoveAll(rollbackRoot); err != nil {
		return "restore completed, but original files remain in rollback directory " + filepath.Base(rollbackRoot), nil
	}
	return "", nil
}

func checkOverlayParents(root, rel string) error {
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			return fmt.Errorf("%w: server data root is not a real directory", ErrOverlayConflict)
		}
		return fmt.Errorf("inspect server data root: %w", err)
	}
	parts := strings.Split(filepath.FromSlash(rel), string(os.PathSeparator))
	current := root
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect parent directory for restore entry %q: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: restore entry %q has an unsafe parent directory", ErrOverlayConflict, rel)
		}
	}
	return nil
}
