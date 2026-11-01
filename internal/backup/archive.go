package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type Summary struct {
	Files       int   `json:"files"`
	Directories int   `json:"directories"`
	Bytes       int64 `json:"bytes"`
}

// Create writes a gzip-compressed tar archive with chunked authenticated encryption.
func Create(dst io.Writer, root string, key []byte) (Summary, error) {
	var summary Summary
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return summary, fmt.Errorf("open server data for backup: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("server data path must be a real directory")
	}
	encrypted, err := NewStreamWriter(dst, key)
	if err != nil {
		return summary, err
	}
	compressed := gzip.NewWriter(encrypted)
	archive := tar.NewWriter(compressed)
	walkErr := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read server data for backup: %w", walkErr)
		}
		if filePath == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect server data %q: %w", filePath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup stopped because server data contains a symbolic link: %s", filepath.Base(filePath))
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("backup stopped because server data contains an unsupported file type: %s", filepath.Base(filePath))
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("describe server data %q: %w", rel, err)
		}
		header.Name = rel
		header.Mode = int64(info.Mode().Perm())
		if err = archive.WriteHeader(header); err != nil {
			return fmt.Errorf("write backup entry %q: %w", rel, err)
		}
		if info.IsDir() {
			summary.Directories++
			return nil
		}
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open server file %q for backup: %w", rel, err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = file.Close()
			return fmt.Errorf("server file %q changed while the backup was being prepared", rel)
		}
		if info.Size() > 0 {
			_, err = io.CopyN(archive, file, info.Size())
		}
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("read server file %q for backup: %w", rel, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close server file %q after backup: %w", rel, closeErr)
		}
		finalInfo, err := os.Stat(filePath)
		if err != nil || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
			return fmt.Errorf("server file %q changed while the backup was being prepared", rel)
		}
		summary.Files++
		summary.Bytes += info.Size()
		return nil
	})
	if walkErr != nil {
		_ = archive.Close()
		_ = compressed.Close()
		_ = encrypted.Close()
		return summary, walkErr
	}
	if err = archive.Close(); err != nil {
		return summary, fmt.Errorf("finish backup archive: %w", err)
	}
	if err = compressed.Close(); err != nil {
		return summary, fmt.Errorf("compress backup archive: %w", err)
	}
	if err = encrypted.Close(); err != nil {
		return summary, fmt.Errorf("encrypt backup archive: %w", err)
	}
	return summary, nil
}

// Summarize validates the server data tree and counts regular files without
// constructing a Docklight archive. Proxmox Backup Client reads this same tree
// directly so its chunk store can deduplicate unchanged file content.
func Summarize(root string) (Summary, error) {
	var summary Summary
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return summary, fmt.Errorf("open server data for backup: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("server data path must be a real directory")
	}
	err = filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read server data for backup: %w", walkErr)
		}
		if filePath == root {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("inspect server data %q: %w", filePath, infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup stopped because server data contains a symbolic link: %s", filepath.Base(filePath))
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("backup stopped because server data contains an unsupported file type: %s", filepath.Base(filePath))
		}
		if info.IsDir() {
			summary.Directories++
			return nil
		}
		file, openErr := os.Open(filePath)
		if openErr != nil {
			return fmt.Errorf("open server file %q for backup: %w", filepath.Base(filePath), openErr)
		}
		openedInfo, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			return fmt.Errorf("server file %q changed while the backup was being prepared", filepath.Base(filePath))
		}
		if closeErr != nil {
			return fmt.Errorf("close server file %q after backup: %w", filepath.Base(filePath), closeErr)
		}
		finalInfo, statErr := os.Stat(filePath)
		if statErr != nil || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
			return fmt.Errorf("server file %q changed while the backup was being prepared", filepath.Base(filePath))
		}
		summary.Files++
		summary.Bytes += info.Size()
		return nil
	})
	return summary, err
}

// Verify authenticates the complete archive, checks the gzip/tar structure,
// and rejects unsafe or unsupported paths without restoring any files.
func Verify(src io.Reader, key []byte) (Summary, error) {
	return walk(src, key, nil)
}

// Extract restores a verified archive into an empty directory owned by the panel.
func Extract(src io.Reader, root string, key []byte) (Summary, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return Summary{}, fmt.Errorf("create restore staging directory: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Summary{}, fmt.Errorf("inspect restore staging directory: %w", err)
	}
	if len(entries) != 0 {
		return Summary{}, errors.New("restore staging directory must be empty")
	}
	directoryModes := map[string]os.FileMode{}
	summary, err := walk(src, key, func(header *tar.Header, body io.Reader) error {
		name, err := safeArchiveName(header.Name)
		if err != nil {
			return err
		}
		destination := filepath.Join(root, filepath.FromSlash(name))
		if !within(root, destination) {
			return fmt.Errorf("backup entry %q escapes the restore directory", header.Name)
		}
		mode := os.FileMode(header.Mode) & 0777
		if header.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(destination, 0700); err != nil {
				return fmt.Errorf("create restored directory %q: %w", name, err)
			}
			directoryModes[destination] = 0700
			return nil
		}
		if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", name, err)
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create restored file %q: %w", name, err)
		}
		if header.Size > 0 {
			_, err = io.CopyN(file, body, header.Size)
		}
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("write restored file %q: %w", name, err)
		}
		if err = os.Chmod(destination, 0600|(mode&0100)); err != nil {
			return fmt.Errorf("set permissions on restored file %q: %w", name, err)
		}
		if !header.ModTime.IsZero() {
			_ = os.Chtimes(destination, header.ModTime, header.ModTime)
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	paths := make([]string, 0, len(directoryModes))
	for destination := range directoryModes {
		paths = append(paths, destination)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, destination := range paths {
		if err = os.Chmod(destination, directoryModes[destination]); err != nil {
			return summary, fmt.Errorf("set permissions on restored directory: %w", err)
		}
	}
	return summary, nil
}

func walk(src io.Reader, key []byte, visit func(*tar.Header, io.Reader) error) (Summary, error) {
	var summary Summary
	seen := map[string]bool{}
	decrypted, err := NewStreamReader(src, key)
	if err != nil {
		return summary, err
	}
	compressed, err := gzip.NewReader(decrypted)
	if err != nil {
		return summary, fmt.Errorf("open compressed backup: %w", err)
	}
	archive := tar.NewReader(compressed)
	for {
		header, nextErr := archive.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			_ = compressed.Close()
			return summary, fmt.Errorf("read backup manifest: %w", nextErr)
		}
		name, nameErr := safeArchiveName(header.Name)
		if nameErr != nil {
			_ = compressed.Close()
			return summary, nameErr
		}
		if seen[name] {
			_ = compressed.Close()
			return summary, fmt.Errorf("backup contains duplicate path %q", header.Name)
		}
		seen[name] = true
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				_ = compressed.Close()
				return summary, fmt.Errorf("backup directory %q has file content", header.Name)
			}
			summary.Directories++
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 {
				_ = compressed.Close()
				return summary, fmt.Errorf("backup file %q has an invalid size", header.Name)
			}
			if visit != nil {
				if err = visit(header, archive); err != nil {
					_ = compressed.Close()
					return summary, err
				}
			} else if header.Size > 0 {
				if _, err = io.CopyN(io.Discard, archive, header.Size); err != nil {
					_ = compressed.Close()
					return summary, fmt.Errorf("read backup file %q: %w", header.Name, err)
				}
			}
			summary.Files++
			summary.Bytes += header.Size
		default:
			_ = compressed.Close()
			return summary, fmt.Errorf("backup contains unsupported file type for %q", header.Name)
		}
	}
	if _, err = io.Copy(zeroValidator{}, compressed); err != nil {
		_ = compressed.Close()
		return summary, fmt.Errorf("finish reading backup: %w", err)
	}
	if err = compressed.Close(); err != nil {
		return summary, fmt.Errorf("close compressed backup: %w", err)
	}
	return summary, nil
}

func safeArchiveName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("backup contains an unsafe path: %q", name)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("backup contains an unsafe path: %q", name)
	}
	return clean, nil
}

type zeroValidator struct{}

func (zeroValidator) Write(p []byte) (int, error) {
	for _, value := range p {
		if value != 0 {
			return 0, errors.New("backup contains data after the tar archive end")
		}
	}
	return len(p), nil
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}
