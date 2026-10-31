package panel

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

func (a *App) authorizeFiles(w http.ResponseWriter, r *http.Request) (Server, bool) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return s, false
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.files") {
		return s, false
	}
	return s, true
}
func (a *App) fileList(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	rel := r.URL.Query().Get("path")
	base, e := safePath(s.DataDir, rel, true)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	info, e := os.Stat(base)
	if e != nil {
		writeError(w, 404, "directory not found")
		return
	}
	if !info.IsDir() {
		writeError(w, 400, "path is not a directory")
		return
	}
	entries, e := os.ReadDir(base)
	if e != nil {
		writeError(w, 403, "panel cannot read this directory; run the server ownership repair or adjust the template data path")
		return
	}
	type item struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		Directory bool   `json:"directory"`
		Size      int64  `json:"size"`
		Modified  string `json:"modified"`
		Mode      string `json:"mode"`
	}
	out := []item{}
	for _, entry := range entries {
		if len(out) >= 5000 {
			break
		}
		fi, e := entry.Info()
		if e != nil {
			continue
		}
		full := entry.Name()
		if rel != "" {
			full = filepath.ToSlash(filepath.Join(rel, entry.Name()))
		}
		out = append(out, item{Name: entry.Name(), Path: full, Directory: entry.IsDir(), Size: fi.Size(), Modified: fi.ModTime().Format(time.RFC3339), Mode: fi.Mode().String()})
	}
	writeJSON(w, 200, map[string]any{"path": filepath.ToSlash(rel), "entries": out})
}
func (a *App) fileRead(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	rel := r.URL.Query().Get("path")
	f, e := safePath(s.DataDir, rel, true)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	info, e := os.Stat(f)
	if e != nil {
		writeError(w, 404, "file not found")
		return
	}
	if info.IsDir() {
		writeError(w, 400, "path is a directory")
		return
	}
	if info.Size() > 5*1024*1024 {
		writeError(w, 413, "files over 5 MiB are available to download but cannot be opened in the editor")
		return
	}
	b, e := os.ReadFile(f)
	if e != nil {
		writeError(w, 403, "panel cannot read this file; run the server ownership repair or adjust the template data path")
		return
	}
	writeJSON(w, 200, map[string]any{"path": filepath.ToSlash(rel), "content": string(b), "size": len(b), "modified": info.ModTime().Format(time.RFC3339)})
}
func (a *App) fileWrite(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if decodeJSON(w, r, &in, 5*1024*1024+4096) != nil {
		return
	}
	if in.Path == "" || len(in.Content) > 5*1024*1024 {
		writeError(w, 413, "file path is required and editor content is limited to 5 MiB")
		return
	}
	target, e := safePath(s.DataDir, in.Path, false)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		writeError(w, 403, "panel cannot write to this directory; run the server ownership repair")
		return
	}
	mode := os.FileMode(0640)
	if fi, err := os.Stat(target); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, e := os.CreateTemp(filepath.Dir(target), ".ygg-save-")
	if e != nil {
		writeError(w, 403, "panel cannot write to this directory; run the server ownership repair")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, e = tmp.WriteString(in.Content); e == nil {
		e = tmp.Chmod(mode)
	}
	if closeErr := tmp.Close(); e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(tmpName, target)
	}
	if e != nil {
		writeError(w, 500, "file could not be saved; check directory permissions and available disk space")
		return
	}
	a.audit(principal(r), "file.write", "server", s.ID, in.Path)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) fileDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		writeError(w, 400, "file path is required")
		return
	}
	target, e := safePath(s.DataDir, rel, true)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if e = os.Remove(target); e != nil {
		if errors.Is(e, os.ErrNotExist) {
			writeError(w, 404, "file not found")
		} else {
			writeError(w, 400, "file or empty directory could not be removed; empty the directory first")
		}
		return
	}
	a.audit(principal(r), "file.delete", "server", s.ID, rel)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) fileMkdir(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	target, e := safePath(s.DataDir, in.Path, false)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if e = os.Mkdir(target, 0750); e != nil {
		writeError(w, 400, "directory could not be created; check that its parent exists and is writable")
		return
	}
	a.audit(principal(r), "file.mkdir", "server", s.ID, in.Path)
	writeJSON(w, 201, map[string]bool{"ok": true})
}
func (a *App) fileUpload(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024*1024)
	if e := r.ParseMultipartForm(64 * 1024 * 1024); e != nil {
		writeError(w, 413, "upload exceeds the 64 MiB request limit")
		return
	}
	f, h, e := r.FormFile("file")
	if e != nil {
		writeError(w, 400, "choose one file to upload")
		return
	}
	defer f.Close()
	name := filepath.Base(h.Filename)
	if name == "." || name == string(filepath.Separator) || strings.Contains(name, "..") || strings.ContainsRune(name, 0) {
		writeError(w, 400, "uploaded filename is not allowed")
		return
	}
	rel := filepath.ToSlash(filepath.Join(r.FormValue("path"), name))
	target, e := safePath(s.DataDir, rel, false)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		writeError(w, 403, "panel cannot write to this directory; run the server ownership repair")
		return
	}
	out, e := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if e != nil {
		writeError(w, 403, "panel cannot write to this directory; run the server ownership repair")
		return
	}
	n, copyErr := io.Copy(out, io.LimitReader(f, 64*1024*1024+1))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || n > 64*1024*1024 {
		_ = os.Remove(target)
		writeError(w, 500, "upload did not finish; check available disk space and directory permissions")
		return
	}
	a.audit(principal(r), "file.upload", "server", s.ID, rel)
	writeJSON(w, 201, map[string]any{"ok": true, "path": rel, "size": n})
}
func (a *App) fileDownload(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizeFiles(w, r)
	if !ok {
		return
	}
	rel := r.URL.Query().Get("path")
	target, e := safePath(s.DataDir, rel, true)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	f, e := os.Open(target)
	if e != nil {
		writeError(w, 404, "file not found")
		return
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.IsDir() {
		writeError(w, 400, "path is not a file")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(target)}))
	http.ServeContent(w, r, filepath.Base(target), info.ModTime(), f)
}

// safePath resolves existing symlinks and proves the resolved object remains under root.
func safePath(root, rel string, mustExist bool) (string, error) {
	if strings.ContainsRune(rel, 0) {
		return "", errors.New("file path contains an invalid character")
	}
	if filepath.IsAbs(rel) {
		return "", errors.New("absolute paths are not allowed")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." {
		clean = ""
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes the server data directory")
	}
	base, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	resolvedRoot, e := filepath.EvalSymlinks(base)
	if e != nil {
		return "", errors.New("server data directory is unavailable")
	}
	candidate := filepath.Join(resolvedRoot, clean)
	probe := candidate
	var rest []string
	for {
		_, e = os.Lstat(probe)
		if e == nil {
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			return "", fmt.Errorf("cannot resolve path: %w", e)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		rest = append([]string{filepath.Base(probe)}, rest...)
		probe = parent
	}
	resolved, e := filepath.EvalSymlinks(probe)
	if e != nil {
		return "", errors.New("path parent does not exist")
	}
	for _, part := range rest {
		resolved = filepath.Join(resolved, part)
	}
	relative, e := filepath.Rel(resolvedRoot, resolved)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes the server data directory")
	}
	if mustExist {
		if _, e = os.Lstat(candidate); e != nil {
			return "", errors.New("file or directory does not exist")
		}
		resolvedFinal, resolveErr := filepath.EvalSymlinks(candidate)
		if resolveErr != nil {
			return "", errors.New("path contains a broken symlink")
		}
		finalRel, relErr := filepath.Rel(resolvedRoot, resolvedFinal)
		if relErr != nil || finalRel == ".." || strings.HasPrefix(finalRel, ".."+string(filepath.Separator)) {
			return "", errors.New("path escapes the server data directory")
		}
		return resolvedFinal, nil
	}
	return candidate, nil
}
