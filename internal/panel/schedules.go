package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/schedule"
	"github.com/go-chi/chi/v5"
)

const scheduleTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

type backupSchedule struct {
	ID         string `json:"id"`
	ServerID   string `json:"server_id"`
	Name       string `json:"name"`
	Cron       string `json:"cron"`
	Enabled    bool   `json:"enabled"`
	NextRun    string `json:"next_run"`
	LastRun    string `json:"last_run"`
	LastStatus string `json:"last_status"`
	LastError  string `json:"last_error"`
	CreatedAt  string `json:"created_at"`
}

type backupScheduleRun struct {
	ID         string `json:"id"`
	ScheduleID string `json:"schedule_id"`
	ServerID   string `json:"server_id"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
}

func scheduleTimestamp(value time.Time) string {
	return value.UTC().Format(scheduleTimeFormat)
}

func (a *App) authorizedScheduleServer(w http.ResponseWriter, r *http.Request) (Server, bool) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return Server{}, false
	}
	if !a.allowedServer(principal(r), "server.schedule", s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, "server.schedule permission is required")
		return Server{}, false
	}
	return s, true
}

func (a *App) listBackupSchedules(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	rows, err := a.db.Query(`SELECT id,server_id,name,cron,enabled,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE server_id=? ORDER BY created_at DESC,id DESC`, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list backup schedules")
		return
	}
	defer rows.Close()
	out := []backupSchedule{}
	for rows.Next() {
		var item backupSchedule
		var enabled int
		if err = rows.Scan(&item.ID, &item.ServerID, &item.Name, &item.Cron, &enabled, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read backup schedule metadata")
			return
		}
		item.Enabled = enabled != 0
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup schedule metadata")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createBackupSchedule(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.backup", s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, "server.backup permission is also required to schedule backups")
		return
	}
	var in struct {
		Name    string `json:"name"`
		Cron    string `json:"cron"`
		Enabled *bool  `json:"enabled"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = "Scheduled backup"
	}
	if len(in.Name) > 80 {
		writeError(w, http.StatusBadRequest, "schedule name must be 80 characters or fewer")
		return
	}
	parsed, err := schedule.Parse(strings.TrimSpace(in.Cron))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	nextRun := ""
	if enabled {
		next, nextErr := parsed.Next(time.Now())
		if nextErr != nil {
			writeError(w, http.StatusBadRequest, nextErr.Error())
			return
		}
		nextRun = scheduleTimestamp(next)
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a schedule ID")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO backup_schedules(id,server_id,name,cron,enabled,next_run) VALUES(?,?,?,?,?,?)`, id, s.ID, in.Name, strings.TrimSpace(in.Cron), boolInt(enabled), nextRun); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save backup schedule")
		return
	}
	a.audit(u, "server.schedule.create", "backup_schedule", id, "server="+s.ID+" cron="+strings.TrimSpace(in.Cron))
	item, err := a.getBackupSchedule(s.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "schedule was saved but its metadata could not be read")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (a *App) updateBackupSchedule(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "scheduleID")
	item, err := a.getBackupSchedule(s.ID, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "backup schedule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup schedule")
		return
	}
	var in struct {
		Name    *string `json:"name"`
		Cron    *string `json:"cron"`
		Enabled *bool   `json:"enabled"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	u := principal(r)
	if (in.Cron != nil || in.Enabled != nil && *in.Enabled) && !a.allowedServer(u, "server.backup", s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, "server.backup permission is required to enable or change a backup schedule")
		return
	}
	if in.Name != nil {
		item.Name = strings.TrimSpace(*in.Name)
		if item.Name == "" || len(item.Name) > 80 {
			writeError(w, http.StatusBadRequest, "schedule name must contain 1 to 80 characters")
			return
		}
	}
	cronChanged := false
	if in.Cron != nil {
		item.Cron = strings.TrimSpace(*in.Cron)
		cronChanged = true
	}
	if item.Cron == "" {
		writeError(w, http.StatusBadRequest, "cron expression is required")
		return
	}
	parsed, err := schedule.Parse(item.Cron)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wasEnabled := item.Enabled
	if in.Enabled != nil {
		item.Enabled = *in.Enabled
	}
	if !item.Enabled {
		item.NextRun = ""
	} else if !wasEnabled || cronChanged {
		next, nextErr := parsed.Next(time.Now())
		if nextErr != nil {
			writeError(w, http.StatusBadRequest, nextErr.Error())
			return
		}
		item.NextRun = scheduleTimestamp(next)
	}
	if _, err = a.db.Exec(`UPDATE backup_schedules SET name=?,cron=?,enabled=?,next_run=? WHERE id=? AND server_id=?`, item.Name, item.Cron, boolInt(item.Enabled), item.NextRun, id, s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update backup schedule")
		return
	}
	a.audit(u, "server.schedule.update", "backup_schedule", id, fmt.Sprintf("server=%s enabled=%t", s.ID, item.Enabled))
	item, err = a.getBackupSchedule(s.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "schedule was updated but its metadata could not be read")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *App) deleteBackupSchedule(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "scheduleID")
	tx, err := a.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start schedule deletion")
		return
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND server_id=?`, id, s.ID); err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not remove backup schedule history")
		return
	}
	result, err := tx.Exec(`DELETE FROM backup_schedules WHERE id=? AND server_id=?`, id, s.ID)
	if err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not delete backup schedule")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		_ = tx.Rollback()
		writeError(w, http.StatusNotFound, "backup schedule not found")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish schedule deletion")
		return
	}
	a.audit(principal(r), "server.schedule.delete", "backup_schedule", id, "server="+s.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) listBackupScheduleRuns(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "scheduleID")
	if _, err := a.getBackupSchedule(s.ID, id); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "backup schedule not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup schedule")
		return
	}
	rows, err := a.db.Query(`SELECT id,schedule_id,server_id,started_at,finished_at,status,detail FROM backup_schedule_runs WHERE schedule_id=? AND server_id=? ORDER BY started_at DESC,id DESC LIMIT 50`, id, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list schedule runs")
		return
	}
	defer rows.Close()
	out := []backupScheduleRun{}
	for rows.Next() {
		var item backupScheduleRun
		if err = rows.Scan(&item.ID, &item.ScheduleID, &item.ServerID, &item.StartedAt, &item.FinishedAt, &item.Status, &item.Detail); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read schedule run history")
			return
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read schedule run history")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) getBackupSchedule(serverID, id string) (backupSchedule, error) {
	var item backupSchedule
	var enabled int
	err := a.db.QueryRow(`SELECT id,server_id,name,cron,enabled,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE id=? AND server_id=?`, id, serverID).Scan(&item.ID, &item.ServerID, &item.Name, &item.Cron, &enabled, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt)
	item.Enabled = enabled != 0
	return item, err
}

// StartScheduleWorker starts the persistent per-server backup scheduler.
func (a *App) StartScheduleWorker(ctx context.Context) {
	interruptedAt := scheduleTimestamp(time.Now())
	_, err := a.db.Exec(`UPDATE backup_schedule_runs SET status='error',finished_at=?,detail='panel stopped before the scheduled backup finished' WHERE status='running'`, interruptedAt)
	if err != nil {
		log.Printf("could not recover interrupted backup schedule runs: %v", err)
	}
	if _, err = a.db.Exec(`UPDATE backup_schedules SET last_status='error',last_error='panel stopped before the scheduled backup finished' WHERE last_status='running'`); err != nil {
		log.Printf("could not recover interrupted backup schedules: %v", err)
	}
	ticker := time.NewTicker(time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := a.processDueBackupSchedules(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("backup scheduler: %v", err)
				}
			}
		}
	}()
}

func (a *App) processDueBackupSchedules(ctx context.Context, now time.Time) error {
	a.scheduleMu.Lock()
	defer a.scheduleMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	nowStamp := scheduleTimestamp(now)
	rows, err := a.db.Query(`SELECT id FROM backup_schedules WHERE enabled=1 AND next_run<>'' AND next_run<=? ORDER BY next_run,id`, nowStamp)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = a.runDueBackupSchedule(id, now); err != nil {
			log.Printf("backup schedule %s: %v", id, err)
		}
	}
	return nil
}

func (a *App) runDueBackupSchedule(id string, now time.Time) error {
	var serverID, name, expression, nextRun string
	var enabled int
	if err := a.db.QueryRow(`SELECT server_id,name,cron,enabled,next_run FROM backup_schedules WHERE id=?`, id).Scan(&serverID, &name, &expression, &enabled, &nextRun); err != nil {
		return err
	}
	if enabled == 0 || nextRun == "" || nextRun > scheduleTimestamp(now) {
		return nil
	}
	cron, err := schedule.Parse(expression)
	if err != nil {
		message := "invalid stored cron expression: " + err.Error()
		_, _ = a.db.Exec(`UPDATE backup_schedules SET enabled=0,next_run='',last_status='error',last_error=? WHERE id=?`, message, id)
		return errors.New(message)
	}
	next, err := cron.Next(now)
	if err != nil {
		_, _ = a.db.Exec(`UPDATE backup_schedules SET enabled=0,next_run='',last_status='error',last_error=? WHERE id=?`, err.Error(), id)
		return err
	}
	runID, err := newID()
	if err != nil {
		return err
	}
	started := scheduleTimestamp(now)
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE backup_schedules SET next_run=?,last_run=?,last_status='running',last_error='' WHERE id=? AND enabled=1 AND next_run<>'' AND next_run<=?`, scheduleTimestamp(next), started, id, started)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		_ = tx.Rollback()
		return nil
	}
	if _, err = tx.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,status) VALUES(?,?,?,?, 'running')`, runID, id, serverID, started); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	status, detail := "success", ""
	if detail, err = a.executeScheduledBackup(serverID, id, name); err != nil {
		status = "error"
		detail = err.Error()
	}
	finished := scheduleTimestamp(time.Now())
	if _, updateErr := a.db.Exec(`UPDATE backup_schedule_runs SET finished_at=?,status=?,detail=? WHERE id=?`, finished, status, detail, runID); updateErr != nil {
		return fmt.Errorf("backup finished with status %s but run history could not be updated: %w", status, updateErr)
	}
	if _, updateErr := a.db.Exec(`UPDATE backup_schedules SET last_status=?,last_error=? WHERE id=?`, status, scheduleError(status, detail), id); updateErr != nil {
		return fmt.Errorf("backup finished with status %s but schedule status could not be updated: %w", status, updateErr)
	}
	a.audit(User{Username: "scheduler"}, "server.schedule.backup", "backup_schedule", id, fmt.Sprintf("server=%s status=%s detail=%s", serverID, status, detail))
	server, _ := a.getServer(serverID)
	if status == "success" {
		a.dispatchBackupNotification(notificationBackupSuccess, serverID, server.Name, "A scheduled backup completed and passed integrity verification.")
	} else {
		a.dispatchBackupNotification(notificationBackupFailure, serverID, server.Name, "A scheduled backup failed. Review the schedule run history for details.")
	}
	if _, pruneErr := a.db.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND id NOT IN (SELECT id FROM backup_schedule_runs WHERE schedule_id=? ORDER BY started_at DESC,id DESC LIMIT 50)`, id, id); pruneErr != nil {
		log.Printf("could not prune old run history for backup schedule %s", id)
	}
	return nil
}

func (a *App) executeScheduledBackup(serverID, scheduleID, name string) (string, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(serverID)
	if err != nil {
		return "", fmt.Errorf("server no longer exists")
	}
	if err = a.confirmServerStopped(s); err != nil {
		return "", err
	}
	item, pruned, warning, err := a.createBackupSnapshot(s)
	if err != nil {
		return "", err
	}
	detail := fmt.Sprintf("%s: created backup %s with %d files and %d bytes; retention removed %d", name, item.ID, item.Files, item.DataBytes, pruned)
	if warning != "" {
		detail += "; " + warning
	}
	a.audit(User{Username: "scheduler"}, "server.backup.create", "backup", item.ID, fmt.Sprintf("server=%s schedule=%s files=%d bytes=%d", serverID, scheduleID, item.Files, item.DataBytes))
	return detail, nil
}

func scheduleError(status, detail string) string {
	if status == "success" {
		return ""
	}
	return detail
}

func (a *App) removeServerBackupSchedules(serverID string) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedule_runs WHERE server_id=?`, serverID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedules WHERE server_id=?`, serverID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
