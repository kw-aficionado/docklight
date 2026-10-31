package panel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/backup"
	"github.com/go-chi/chi/v5"
)

const backupExtension = ".dlbak"

type backupRecord struct {
	ID          string `json:"id"`
	ServerID    string `json:"server_id"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Files       int    `json:"files"`
	Directories int    `json:"directories"`
	DataBytes   int64  `json:"data_bytes"`
	CreatedAt   string `json:"created_at"`
}

func (a *App) authorizedBackupServer(w http.ResponseWriter, r *http.Request) (Server, bool) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return Server{}, false
	}
	u := principal(r)
	if !a.allowedServer(u, "server.backup", s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, "server.backup permission is required")
		return Server{}, false
	}
	return s, true
}

func (a *App) listBackups(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	rows, err := a.db.Query(`SELECT id,server_id,size_bytes,sha256,files,directories,data_bytes,created_at FROM server_backups WHERE server_id=? ORDER BY created_at DESC,id DESC`, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list server backups")
		return
	}
	defer rows.Close()
	out := []backupRecord{}
	for rows.Next() {
		var item backupRecord
		if err = rows.Scan(&item.ID, &item.ServerID, &item.SizeBytes, &item.SHA256, &item.Files, &item.Directories, &item.DataBytes, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server backup metadata")
			return
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server backup metadata")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createBackup(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if err = a.confirmServerStopped(s); err != nil {
		if errors.Is(err, errBackupServerRunning) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusServiceUnavailable, err.Error())
		}
		return
	}
	item, pruned, warning, err := a.createBackupSnapshot(s)
	if err != nil {
		var operationErr *backupOperationError
		if errors.As(err, &operationErr) {
			writeError(w, operationErr.status, operationErr.message)
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	u := principal(r)
	a.audit(u, "server.backup.create", "backup", item.ID, fmt.Sprintf("server=%s files=%d bytes=%d", s.ID, item.Files, item.DataBytes))
	response := map[string]any{"backup": item, "pruned": pruned}
	if warning != "" {
		response["warning"] = warning
	}
	writeJSON(w, http.StatusCreated, response)
}

type backupOperationError struct {
	status  int
	message string
}

func (e *backupOperationError) Error() string { return e.message }

func (a *App) createBackupSnapshot(s Server) (backupRecord, int, string, error) {
	fail := func(status int, message string) (backupRecord, int, string, error) {
		return backupRecord{}, 0, "", &backupOperationError{status: status, message: message}
	}
	if pathsOverlap(s.DataDir, a.backupRoot) {
		return fail(http.StatusConflict, "backup directory overlaps this server's data directory; set backups.path outside the servers directory")
	}
	if err := os.MkdirAll(a.backupRoot, 0700); err != nil {
		return fail(http.StatusInternalServerError, "could not create the backup directory; check backups.path and panel storage permissions")
	}
	if err := ensureBackupDirectory(a.backupRoot); err != nil {
		return fail(http.StatusConflict, "backup path must be a real directory without a symbolic link")
	}
	folder := filepath.Join(a.backupRoot, s.ID)
	if err := os.MkdirAll(folder, 0700); err != nil {
		return fail(http.StatusInternalServerError, "could not create the server backup directory; check panel storage permissions")
	}
	if err := ensureBackupDirectory(folder); err != nil {
		return fail(http.StatusConflict, "server backup path must be a real directory without a symbolic link")
	}
	if err := os.Chmod(a.backupRoot, 0700); err != nil {
		return fail(http.StatusInternalServerError, "could not secure the backup directory; check its owner and permissions")
	}
	if err := os.Chmod(folder, 0700); err != nil {
		return fail(http.StatusInternalServerError, "could not secure the server backup directory; check its owner and permissions")
	}
	id, err := newID()
	if err != nil {
		return fail(http.StatusInternalServerError, "could not generate a backup ID")
	}
	temporary := filepath.Join(folder, "."+id+".tmp")
	final := filepath.Join(folder, id+backupExtension)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail(http.StatusInternalServerError, "could not create the backup file; check free disk space and directory permissions")
	}
	summary, createErr := backup.Create(file, s.DataDir, []byte(a.cfg.Auth.SecretKey))
	if createErr == nil {
		createErr = file.Sync()
	}
	closeErr := file.Close()
	if createErr == nil {
		createErr = closeErr
	}
	if createErr != nil {
		_ = os.Remove(temporary)
		return fail(http.StatusInternalServerError, "backup failed: "+createErr.Error())
	}
	checksum, size, err := checksumFile(temporary)
	if err == nil {
		var verify *os.File
		verify, err = os.Open(temporary)
		if err == nil {
			_, err = backup.Verify(verify, []byte(a.cfg.Auth.SecretKey))
			_ = verify.Close()
		}
	}
	if err != nil {
		_ = os.Remove(temporary)
		return fail(http.StatusInternalServerError, "new backup did not pass integrity verification: "+err.Error())
	}
	if err = os.Rename(temporary, final); err != nil {
		_ = os.Remove(temporary)
		return fail(http.StatusInternalServerError, "could not finalize the backup file; check free disk space and directory permissions")
	}
	// Keep fixed-width fractional seconds so SQLite text ordering matches time ordering.
	createdAt := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	if _, err = a.db.Exec(`INSERT INTO server_backups(id,server_id,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, s.ID, size, checksum, summary.Files, summary.Directories, summary.Bytes, createdAt); err != nil {
		_ = os.Remove(final)
		return fail(http.StatusInternalServerError, "backup file was created but its metadata could not be saved; check panel storage and restart the operation")
	}
	item, err := a.getBackup(s.ID, id)
	if err != nil {
		return fail(http.StatusInternalServerError, "backup was saved but its metadata could not be read")
	}
	pruned, _, pruneErr := a.pruneServerBackups(s.ID, a.backupRetention())
	warning := ""
	if pruneErr != nil {
		warning = "backup was saved, but automatic retention cleanup failed; use Prune backups after fixing backup directory permissions"
	}
	return item, pruned, warning, nil
}

func (a *App) verifyBackup(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	item, filePath, err := a.backupFileRecord(s.ID, chi.URLParam(r, "backupID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	summary, err := a.verifyBackupFile(item, filePath)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	a.audit(principal(r), "server.backup.verify", "backup", item.ID, fmt.Sprintf("files=%d bytes=%d", summary.Files, summary.Bytes))
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "files": summary.Files, "directories": summary.Directories, "bytes": summary.Bytes})
}

func (a *App) restoreBackup(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if err = a.confirmServerStopped(s); err != nil {
		if errors.Is(err, errBackupServerRunning) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusServiceUnavailable, err.Error())
		}
		return
	}
	item, filePath, err := a.backupFileRecord(s.ID, chi.URLParam(r, "backupID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	if _, err = a.verifyBackupFile(item, filePath); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "restore stopped before changing server data: "+err.Error())
		return
	}
	if pathsOverlap(s.DataDir, a.backupRoot) {
		writeError(w, http.StatusConflict, "backup directory overlaps this server's data directory; fix backups.path before restoring")
		return
	}
	parent := filepath.Dir(s.DataDir)
	stage, err := os.MkdirTemp(parent, ".yggdrasil-restore-")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a restore staging directory; check panel storage permissions and free disk space")
		return
	}
	defer os.RemoveAll(stage)
	archiveFile, err := os.Open(filePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not open the verified backup for restoration")
		return
	}
	summary, restoreErr := backup.Extract(archiveFile, stage, []byte(a.cfg.Auth.SecretKey))
	_ = archiveFile.Close()
	if restoreErr != nil {
		writeError(w, http.StatusUnprocessableEntity, "restore stopped before replacing server data: "+restoreErr.Error())
		return
	}
	restoreID, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a restore transaction ID")
		return
	}
	oldPath := s.DataDir + ".restore-old-" + restoreID
	info, statErr := os.Lstat(s.DataDir)
	hadOld := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		writeError(w, http.StatusInternalServerError, "could not inspect current server data before restore")
		return
	}
	if hadOld && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		writeError(w, http.StatusConflict, "current server data path is not a real directory; repair it before restoring")
		return
	}
	if hadOld {
		if err = os.Rename(s.DataDir, oldPath); err != nil {
			writeError(w, http.StatusInternalServerError, "could not preserve current server data before restore; check panel storage permissions")
			return
		}
	}
	if err = os.Rename(stage, s.DataDir); err != nil {
		if hadOld {
			_ = os.Rename(oldPath, s.DataDir)
		}
		writeError(w, http.StatusInternalServerError, "could not activate restored server data; the previous data has been preserved")
		return
	}
	cleanupWarning := ""
	if hadOld {
		if err = os.RemoveAll(oldPath); err != nil {
			cleanupWarning = "restore completed, but old data remains at " + filepath.Base(oldPath) + "; remove it after checking the restored server"
		}
	}
	a.audit(principal(r), "server.backup.restore", "backup", item.ID, fmt.Sprintf("server=%s files=%d bytes=%d", s.ID, summary.Files, summary.Bytes))
	response := map[string]any{"restored": true, "files": summary.Files, "directories": summary.Directories, "bytes": summary.Bytes}
	if cleanupWarning != "" {
		response["warning"] = cleanupWarning
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) deleteBackup(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	item, filePath, err := a.backupFileRecord(s.ID, chi.URLParam(r, "backupID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err = os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, "could not delete backup file; check backup directory permissions")
		return
	}
	if _, err = a.db.Exec(`DELETE FROM server_backups WHERE id=? AND server_id=?`, item.ID, s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "backup file was removed but its metadata could not be deleted")
		return
	}
	a.audit(principal(r), "server.backup.delete", "backup", item.ID, "server="+s.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) pruneBackups(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedBackupServer(w, r)
	if !ok {
		return
	}
	var in struct {
		Keep int `json:"keep"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	if in.Keep == 0 {
		in.Keep = a.backupRetention()
	}
	if in.Keep < 1 || in.Keep > 100 {
		writeError(w, http.StatusBadRequest, "keep must be from 1 to 100")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	removed, remaining, err := a.pruneServerBackups(s.ID, in.Keep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit(principal(r), "server.backup.prune", "server", s.ID, fmt.Sprintf("keep=%d removed=%d", in.Keep, removed))
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed, "remaining": remaining})
}

func (a *App) backupRetention() int {
	if a.cfg.Backups.Retention < 1 || a.cfg.Backups.Retention > 100 {
		return 10
	}
	return a.cfg.Backups.Retention
}

func (a *App) backupFileRecord(serverID, backupID string) (backupRecord, string, error) {
	var item backupRecord
	err := a.db.QueryRow(`SELECT id,server_id,size_bytes,sha256,files,directories,data_bytes,created_at FROM server_backups WHERE id=? AND server_id=?`, backupID, serverID).Scan(&item.ID, &item.ServerID, &item.SizeBytes, &item.SHA256, &item.Files, &item.Directories, &item.DataBytes, &item.CreatedAt)
	if err != nil {
		return backupRecord{}, "", err
	}
	if !safePathSegment(serverID) || !safePathSegment(backupID) {
		return backupRecord{}, "", errors.New("backup identifier is invalid")
	}
	if err = ensureBackupDirectory(a.backupRoot); err != nil {
		return backupRecord{}, "", errors.New("backup directory is missing or is not a real directory")
	}
	if err = ensureBackupDirectory(filepath.Join(a.backupRoot, serverID)); err != nil {
		return backupRecord{}, "", errors.New("server backup directory is missing or is not a real directory")
	}
	return item, filepath.Join(a.backupRoot, serverID, backupID+backupExtension), nil
}

func (a *App) getBackup(serverID, backupID string) (backupRecord, error) {
	var item backupRecord
	err := a.db.QueryRow(`SELECT id,server_id,size_bytes,sha256,files,directories,data_bytes,created_at FROM server_backups WHERE id=? AND server_id=?`, backupID, serverID).Scan(&item.ID, &item.ServerID, &item.SizeBytes, &item.SHA256, &item.Files, &item.Directories, &item.DataBytes, &item.CreatedAt)
	return item, err
}

func (a *App) verifyBackupFile(item backupRecord, filePath string) (backup.Summary, error) {
	var summary backup.Summary
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("backup file is missing or is not a regular file")
	}
	checksum, size, err := checksumFile(filePath)
	if err != nil {
		return summary, fmt.Errorf("read backup checksum: %w", err)
	}
	if size != item.SizeBytes || subtle.ConstantTimeCompare([]byte(checksum), []byte(item.SHA256)) != 1 {
		return summary, errors.New("backup checksum does not match its database record")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return summary, errors.New("could not open backup file; check directory permissions")
	}
	summary, err = backup.Verify(file, []byte(a.cfg.Auth.SecretKey))
	_ = file.Close()
	if err != nil {
		return summary, fmt.Errorf("backup verification failed: %w", err)
	}
	if summary.Files != item.Files || summary.Directories != item.Directories || summary.Bytes != item.DataBytes {
		return summary, errors.New("backup contents do not match the saved metadata")
	}
	return summary, nil
}

func (a *App) pruneServerBackups(serverID string, keep int) (int, int, error) {
	rows, err := a.db.Query(`SELECT id FROM server_backups WHERE server_id=? ORDER BY created_at DESC,id DESC`, serverID)
	if err != nil {
		return 0, 0, errors.New("could not read backup retention records")
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, 0, errors.New("could not read backup retention records")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, errors.New("could not read backup retention records")
	}
	_ = rows.Close()
	removed := 0
	if len(ids) <= keep {
		return 0, len(ids), nil
	}
	for _, id := range ids[keep:] {
		item, filePath, findErr := a.backupFileRecord(serverID, id)
		if findErr != nil {
			return removed, len(ids) - removed, errors.New("a backup record changed during retention cleanup")
		}
		if err = os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return removed, len(ids) - removed, fmt.Errorf("could not remove old backup %s; check backup directory permissions", filepath.Base(filePath))
		}
		if _, err = a.db.Exec(`DELETE FROM server_backups WHERE id=? AND server_id=?`, item.ID, serverID); err != nil {
			return removed, len(ids) - removed, errors.New("old backup file was removed but its metadata could not be deleted")
		}
		removed++
	}
	return removed, len(ids) - removed, nil
}

func (a *App) removeServerBackups(serverID string) error {
	if !safePathSegment(serverID) {
		return errors.New("server identifier is invalid; backup cleanup was stopped")
	}
	rootInfo, err := os.Lstat(a.backupRoot)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not inspect local backup directory; fix its permissions and retry: %w", err)
	}
	if err == nil {
		if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("local backup directory is not a real directory; server deletion was stopped")
		}
		serverDir := filepath.Join(a.backupRoot, serverID)
		serverInfo, serverErr := os.Lstat(serverDir)
		if serverErr != nil && !os.IsNotExist(serverErr) {
			return fmt.Errorf("could not inspect local server backups; fix backup directory permissions and retry: %w", serverErr)
		}
		if serverErr == nil {
			if !serverInfo.IsDir() || serverInfo.Mode()&os.ModeSymlink != 0 {
				return errors.New("local server backup path is not a real directory; server deletion was stopped")
			}
			if err = os.RemoveAll(serverDir); err != nil {
				return fmt.Errorf("could not remove local backups; fix backup directory permissions and retry: %w", err)
			}
		}
	}
	if _, err := a.db.Exec(`DELETE FROM server_backups WHERE server_id=?`, serverID); err != nil {
		return errors.New("local backups were removed but their database records could not be deleted")
	}
	return nil
}

func (a *App) confirmServerStopped(s Server) error {
	if s.Status == "starting" || s.Status == "installing" || s.Status == "running" {
		return errBackupServerRunning
	}
	if s.ContainerID == "" {
		if s.Status == "stopped" || s.Status == "created" || s.Status == "error" {
			return nil
		}
		return errors.New("the panel cannot confirm this server is stopped; check its Docker state before creating or restoring a backup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inspection, err := a.engine.Inspect(ctx, s.ContainerID)
	if err != nil {
		return fmt.Errorf("the panel cannot confirm this server is stopped because Docker could not inspect it: %w", err)
	}
	if inspection.State.Running {
		return errBackupServerRunning
	}
	_, _ = a.db.Exec(`UPDATE servers SET status='stopped',updated_at=CURRENT_TIMESTAMP WHERE id=?`, s.ID)
	return nil
}

func checksumFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func safePathSegment(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "/\\\x00")
}

func ensureBackupDirectory(value string) error {
	info, err := os.Lstat(value)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup path is not a real directory")
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	firstAbs, err1 := filepath.Abs(first)
	secondAbs, err2 := filepath.Abs(second)
	if err1 != nil || err2 != nil {
		return true
	}
	return pathContains(firstAbs, secondAbs) || pathContains(secondAbs, firstAbs)
}

func pathContains(root, target string) bool {
	resolvedRoot, err := resolvedPath(root)
	if err != nil {
		return true
	}
	resolvedTarget, err := resolvedPath(target)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func resolvedPath(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	missing := []string{}
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return "", resolveErr
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", statErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

var errBackupServerRunning = errors.New("stop the server before creating or restoring a backup; this keeps database files consistent")
