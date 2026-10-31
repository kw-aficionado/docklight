package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	gameskill "example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/schedule"
	"github.com/go-chi/chi/v5"
)

const scheduleTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

type backupSchedule struct {
	ID             string `json:"id"`
	ServerID       string `json:"server_id"`
	Name           string `json:"name"`
	Action         string `json:"action"`
	Cron           string `json:"cron"`
	Enabled        bool   `json:"enabled"`
	WarnPlayers    bool   `json:"warn_players"`
	WarningSeconds int    `json:"warning_seconds"`
	NextRun        string `json:"next_run"`
	LastRun        string `json:"last_run"`
	LastStatus     string `json:"last_status"`
	LastError      string `json:"last_error"`
	CreatedAt      string `json:"created_at"`
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

func scheduleActionPermission(action string) (string, bool) {
	switch action {
	case "backup":
		return "server.backup", true
	case "restart":
		return "server.control", true
	default:
		return "", false
	}
}

func (a *App) validateScheduleAction(s Server, action string, warnInput *bool, secondsInput *int) (bool, int, error) {
	if action == "backup" {
		return false, 60, nil
	}
	if action != "restart" {
		return false, 0, errors.New("unsupported schedule action")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return false, 0, fmt.Errorf("could not read the server template: %w", err)
	}
	warn := true
	if warnInput != nil {
		warn = *warnInput
	}
	if !warn {
		return false, 0, nil
	}
	warnings := []gameskill.RestartWarning{}
	if gs.Restart != nil {
		warnings = gs.Restart.Warnings
	}
	available := make(map[int]bool, len(warnings))
	defaultSeconds := 0
	for _, warning := range warnings {
		at, parseErr := time.ParseDuration(warning.At)
		if parseErr != nil || at <= 0 || at > 24*time.Hour || at%time.Second != 0 {
			continue
		}
		seconds := int(at / time.Second)
		available[seconds] = true
		if defaultSeconds == 0 || seconds < defaultSeconds {
			defaultSeconds = seconds
		}
	}
	if defaultSeconds == 0 {
		return false, 0, errors.New("this template has no whole-second restart warnings; turn off player warnings or add restart.warnings to the template")
	}
	seconds := defaultSeconds
	if secondsInput != nil {
		seconds = *secondsInput
	}
	if seconds < 1 || seconds > 24*60*60 || !available[seconds] {
		return false, 0, errors.New("warning_seconds must match a restart.warnings duration in this template")
	}
	return true, seconds, nil
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
	rows, err := a.db.Query(`SELECT id,server_id,name,action,cron,enabled,warn_players,warning_seconds,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE server_id=? ORDER BY created_at DESC,id DESC`, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list backup schedules")
		return
	}
	defer rows.Close()
	out := []backupSchedule{}
	for rows.Next() {
		var item backupSchedule
		var enabled, warnPlayers int
		if err = rows.Scan(&item.ID, &item.ServerID, &item.Name, &item.Action, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read backup schedule metadata")
			return
		}
		item.Enabled = enabled != 0
		item.WarnPlayers = warnPlayers != 0
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup schedule metadata")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) scheduleOptions(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	warnings := []gameskill.RestartWarning{}
	if a.allowedServer(principal(r), "server.control", s.ID, s.GameskillID) {
		gs, err := a.loadRune(s.GameskillID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server template schedule options")
			return
		}
		if gs.Restart != nil {
			warnings = gs.Restart.Warnings
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"restart_warnings": warnings})
}

func (a *App) createBackupSchedule(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	u := principal(r)
	var in struct {
		Name           string `json:"name"`
		Action         string `json:"action"`
		Cron           string `json:"cron"`
		Enabled        *bool  `json:"enabled"`
		WarnPlayers    *bool  `json:"warn_players"`
		WarningSeconds *int   `json:"warning_seconds"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	in.Action = strings.TrimSpace(in.Action)
	if in.Action == "" {
		in.Action = "backup"
	}
	permission, ok := scheduleActionPermission(in.Action)
	if !ok {
		writeError(w, http.StatusBadRequest, "schedule action must be backup or restart")
		return
	}
	if !a.allowedServer(u, permission, s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, permission+" permission is required to schedule this action")
		return
	}
	warnPlayers, warningSeconds, err := a.validateScheduleAction(s, in.Action, in.WarnPlayers, in.WarningSeconds)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		if in.Action == "restart" {
			in.Name = "Scheduled restart"
		} else {
			in.Name = "Scheduled backup"
		}
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
	if _, err = a.db.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,warn_players,warning_seconds,next_run) VALUES(?,?,?,?,?,?,?,?,?)`, id, s.ID, in.Name, in.Action, strings.TrimSpace(in.Cron), boolInt(enabled), boolInt(warnPlayers), warningSeconds, nextRun); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save backup schedule")
		return
	}
	a.audit(u, "server.schedule.create", "backup_schedule", id, fmt.Sprintf("server=%s action=%s cron=%s", s.ID, in.Action, strings.TrimSpace(in.Cron)))
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
	permission, ok := scheduleActionPermission(item.Action)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stored schedule action is invalid")
		return
	}
	if (in.Cron != nil || in.Enabled != nil && *in.Enabled) && !a.allowedServer(u, permission, s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, permission+" permission is required to enable or change this schedule")
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
	var warnPlayers int
	err := a.db.QueryRow(`SELECT id,server_id,name,action,cron,enabled,warn_players,warning_seconds,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE id=? AND server_id=?`, id, serverID).Scan(&item.ID, &item.ServerID, &item.Name, &item.Action, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt)
	item.Enabled = enabled != 0
	item.WarnPlayers = warnPlayers != 0
	return item, err
}

// StartScheduleWorker starts the persistent per-server scheduler.
func (a *App) StartScheduleWorker(ctx context.Context) {
	interruptedAt := scheduleTimestamp(time.Now())
	_, err := a.db.Exec(`UPDATE backup_schedule_runs SET status='error',finished_at=?,detail='panel stopped before the scheduled action finished' WHERE status='running'`, interruptedAt)
	if err != nil {
		log.Printf("could not recover interrupted schedule runs: %v", err)
	}
	if _, err = a.db.Exec(`UPDATE backup_schedules SET last_status='error',last_error='panel stopped before the scheduled action finished' WHERE last_status='running'`); err != nil {
		log.Printf("could not recover interrupted schedules: %v", err)
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
					log.Printf("scheduler: %v", err)
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
		if err = a.runDueBackupSchedule(ctx, id, now); err != nil {
			log.Printf("schedule %s: %v", id, err)
		}
	}
	return nil
}

func (a *App) runDueBackupSchedule(ctx context.Context, id string, now time.Time) error {
	var serverID, name, action, expression, nextRun string
	var enabled, warnPlayers, warningSeconds int
	if err := a.db.QueryRow(`SELECT server_id,name,action,cron,enabled,warn_players,warning_seconds,next_run FROM backup_schedules WHERE id=?`, id).Scan(&serverID, &name, &action, &expression, &enabled, &warnPlayers, &warningSeconds, &nextRun); err != nil {
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
	if action == "restart" {
		warn := warnPlayers != 0
		leadSeconds := warningSeconds
		initiated := "restart initiated"
		if warn {
			initiated = "warned restart initiated"
		}
		if _, err = a.db.Exec(`UPDATE backup_schedule_runs SET detail=? WHERE id=?`, initiated, runID); err != nil {
			return fmt.Errorf("restart was queued but its run history could not be updated: %w", err)
		}
		a.audit(User{Username: "scheduler"}, "server.schedule.restart", "backup_schedule", id, fmt.Sprintf("server=%s detail=%s", serverID, initiated))
		go a.finishScheduledRestart(ctx, serverID, id, name, warn, leadSeconds, runID)
		return nil
	}
	status, detail := "success", ""
	if action != "backup" {
		status = "error"
		detail = "unsupported stored schedule action"
	} else if detail, err = a.executeScheduledBackup(serverID, id, name); err != nil {
		status = "error"
		detail = err.Error()
	}
	return a.finishScheduleRun(id, serverID, action, runID, status, detail)
}

func (a *App) finishScheduledRestart(ctx context.Context, serverID, scheduleID, name string, warn bool, warningSeconds int, runID string) {
	var detail string
	var err error
	if a.scheduleRestart != nil {
		detail, err = a.scheduleRestart(ctx, serverID, warn, warningSeconds)
	} else {
		detail, err = a.executeScheduledRestart(ctx, serverID, warn, warningSeconds)
	}
	status := "success"
	if err != nil {
		status = "error"
		detail = err.Error()
	}
	if strings.TrimSpace(name) != "" && status == "success" {
		detail = name + ": " + detail
	}
	if err = a.finishScheduleRun(scheduleID, serverID, "restart", runID, status, detail); err != nil {
		log.Printf("scheduled restart %s: %v", scheduleID, err)
	}
}

func (a *App) finishScheduleRun(id, serverID, action, runID, status, detail string) error {
	finished := scheduleTimestamp(time.Now())
	if _, updateErr := a.db.Exec(`UPDATE backup_schedule_runs SET finished_at=?,status=?,detail=? WHERE id=?`, finished, status, detail, runID); updateErr != nil {
		return fmt.Errorf("scheduled %s finished with status %s but run history could not be updated: %w", action, status, updateErr)
	}
	if _, updateErr := a.db.Exec(`UPDATE backup_schedules SET last_status=?,last_error=? WHERE id=?`, status, scheduleError(status, detail), id); updateErr != nil {
		return fmt.Errorf("scheduled %s finished with status %s but schedule status could not be updated: %w", action, status, updateErr)
	}
	a.audit(User{Username: "scheduler"}, "server.schedule."+action, "backup_schedule", id, fmt.Sprintf("server=%s status=%s detail=%s", serverID, status, detail))
	if action == "backup" {
		server, _ := a.getServer(serverID)
		if status == "success" {
			a.dispatchBackupNotification(notificationBackupSuccess, serverID, server.Name, "A scheduled backup completed and passed integrity verification.")
		} else {
			a.dispatchBackupNotification(notificationBackupFailure, serverID, server.Name, "A scheduled backup failed. Review the schedule run history for details.")
		}
	}
	if _, pruneErr := a.db.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND id NOT IN (SELECT id FROM backup_schedule_runs WHERE schedule_id=? ORDER BY started_at DESC,id DESC LIMIT 50)`, id, id); pruneErr != nil {
		log.Printf("could not prune run history for schedule %s", id)
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

func (a *App) executeScheduledRestart(ctx context.Context, serverID string, warn bool, warningSeconds int) (string, error) {
	s, err := a.getServer(serverID)
	if err != nil {
		return "", errors.New("server no longer exists")
	}
	if !s.Installed {
		return "", errors.New("install this server before restarting it")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return "", err
	}
	countdown := warn && s.Status == "running" && s.ContainerID != ""
	initialContainer := s.ContainerID
	wait := a.scheduleWait
	if wait == nil {
		wait = waitForSchedule
	}
	send := a.scheduleCommand
	if send == nil {
		send = func(ctx context.Context, current Server, command string) error {
			_, sendErr := a.sendCommand(ctx, current, command)
			return sendErr
		}
	}
	restart := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.dataMu.Lock()
		defer a.dataMu.Unlock()
		current, loadErr := a.getServer(serverID)
		if loadErr != nil {
			return errors.New("server no longer exists")
		}
		if countdown && (current.ContainerID != initialContainer || current.Status != "running") {
			return errors.New("server state changed during restart countdown; scheduled restart was canceled")
		}
		if !current.Installed {
			return errors.New("install this server before restarting it")
		}
		if err := a.recreateAndStart(ctx, current); err != nil {
			return err
		}
		a.resetWatchdog(current.ID)
		return nil
	}
	if countdown {
		lead := time.Duration(warningSeconds) * time.Second
		if err = runScheduledRestartCountdown(ctx, s, gs, lead, wait, send, restart); err != nil {
			return "", err
		}
		return fmt.Sprintf("warned restart completed after a %d-second countdown", warningSeconds), nil
	}
	if err = restart(ctx); err != nil {
		return "", err
	}
	if warn {
		return "restart initiated without a countdown because the server was not running", nil
	}
	return "restart initiated", nil
}

func runScheduledRestartCountdown(
	ctx context.Context,
	s Server,
	gs gameskill.Rune,
	lead time.Duration,
	wait func(context.Context, time.Duration) error,
	send func(context.Context, Server, string) error,
	restart func(context.Context) error,
) error {
	if lead <= 0 || lead > 24*time.Hour {
		return errors.New("restart countdown must be from 1 second to 24 hours")
	}
	warnings := []struct {
		at  time.Duration
		msg string
	}{}
	if gs.Restart != nil {
		for _, warning := range gs.Restart.Warnings {
			at, err := time.ParseDuration(warning.At)
			if err == nil && at > 0 && at <= lead {
				warnings = append(warnings, struct {
					at  time.Duration
					msg string
				}{at: at, msg: warning.Msg})
			}
		}
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].at > warnings[j].at })
	if len(warnings) == 0 || warnings[0].at != lead {
		return errors.New("template does not define a restart warning at the selected countdown duration")
	}
	for i, warning := range warnings {
		if err := ctx.Err(); err != nil {
			return err
		}
		seconds := int(warning.at / time.Second)
		minutes := int((warning.at + time.Minute - 1) / time.Minute)
		command := gameskill.ApplyTemplate(warning.msg, map[string]string{
			"server_name": collapseControl(s.Name),
			"minutes":     strconv.Itoa(minutes),
			"seconds":     strconv.Itoa(seconds),
		})
		if sendErr := send(ctx, s, command); sendErr != nil {
			return fmt.Errorf("could not send restart warning: %w", sendErr)
		}
		remaining := warning.at
		if i+1 < len(warnings) {
			remaining -= warnings[i+1].at
		}
		if remaining > 0 {
			if waitErr := wait(ctx, remaining); waitErr != nil {
				return waitErr
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return restart(ctx)
}

func waitForSchedule(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
