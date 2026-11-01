package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	gameskill "example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/schedule"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const scheduleTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

type backupSchedule struct {
	ID                  string `json:"id"`
	ServerID            string `json:"server_id"`
	ScopeType           string `json:"scope_type"`
	ScopeID             string `json:"scope_id"`
	Name                string `json:"name"`
	Action              string `json:"action"`
	Destination         string `json:"destination"`
	Cron                string `json:"cron"`
	Enabled             bool   `json:"enabled"`
	WarnPlayers         bool   `json:"warn_players"`
	WarningSeconds      int    `json:"warning_seconds"`
	SkipIfPlayersOnline bool   `json:"skip_if_players_online"`
	NextRun             string `json:"next_run"`
	LastRun             string `json:"last_run"`
	LastStatus          string `json:"last_status"`
	LastError           string `json:"last_error"`
	CreatedAt           string `json:"created_at"`
}

type backupScheduleRun struct {
	ID         string `json:"id"`
	ScheduleID string `json:"schedule_id"`
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name,omitempty"`
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
	case "start", "stop", "update":
		return "server.control", true
	case "command":
		return "server.console", true
	case "message":
		return "", true
	default:
		return "", false
	}
}

func (a *App) validateScheduleAction(s Server, action string, warnInput *bool, secondsInput *int) (bool, int, error) {
	switch action {
	case "backup", "start", "stop", "command", "message", "update":
		return false, 60, nil
	case "restart":
	default:
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

func validateScheduledCommand(value string) (string, error) {
	command := strings.TrimSpace(value)
	if command == "" {
		return "", errors.New("enter a console command")
	}
	if len(command) > 4096 {
		return "", errors.New("console command must be 4096 characters or fewer")
	}
	if strings.IndexFunc(command, unicode.IsControl) >= 0 {
		return "", errors.New("console command must be a single line without control characters")
	}
	return command, nil
}

func (a *App) authorizedScheduleServer(w http.ResponseWriter, r *http.Request) (Server, bool) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return Server{}, false
	}
	if !a.allowedServer(principal(r), "server.schedule", s.ID, s.GameskillID, s.RealmID) {
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
	rows, err := a.db.Query(`SELECT id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE scope_type='server' AND scope_id=? ORDER BY created_at DESC,id DESC`, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list backup schedules")
		return
	}
	defer rows.Close()
	out := []backupSchedule{}
	for rows.Next() {
		var item backupSchedule
		var enabled, warnPlayers, skipIfPlayersOnline int
		if err = rows.Scan(&item.ID, &item.ServerID, &item.ScopeType, &item.ScopeID, &item.Name, &item.Action, &item.Destination, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &skipIfPlayersOnline, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read backup schedule metadata")
			return
		}
		item.Enabled = enabled != 0
		item.WarnPlayers = warnPlayers != 0
		item.SkipIfPlayersOnline = skipIfPlayersOnline != 0
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
	canSkipIfPlayersOnline := false
	if a.allowedServer(principal(r), "server.control", s.ID, s.GameskillID, s.RealmID) {
		gs, err := a.loadRune(s.GameskillID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server template schedule options")
			return
		}
		if gs.Restart != nil {
			warnings = gs.Restart.Warnings
		}
		canSkipIfPlayersOnline = gs.Query != nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"restart_warnings": warnings, "can_skip_if_players_online": canSkipIfPlayersOnline})
}

func (a *App) createBackupSchedule(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorizedScheduleServer(w, r)
	if !ok {
		return
	}
	u := principal(r)
	var in struct {
		Name                string         `json:"name"`
		Action              string         `json:"action"`
		Destination         string         `json:"destination"`
		Cron                string         `json:"cron"`
		Enabled             *bool          `json:"enabled"`
		WarnPlayers         *bool          `json:"warn_players"`
		WarningSeconds      *int           `json:"warning_seconds"`
		SkipIfPlayersOnline bool           `json:"skip_if_players_online"`
		Command             string         `json:"command"`
		MessageTemplateID   string         `json:"message_template_id"`
		MessageValues       map[string]int `json:"values"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	in.Action = strings.TrimSpace(in.Action)
	if in.Action == "" {
		in.Action = "backup"
	}
	destination := strings.TrimSpace(in.Destination)
	if destination == "" {
		destination = "local"
	}
	if destination != "local" && destination != "s3" && destination != "sftp" && destination != "smb" && destination != "azure" {
		writeError(w, http.StatusBadRequest, "backup destination must be local, s3, sftp, smb, or azure")
		return
	}
	if in.Action != "backup" && destination != "local" {
		writeError(w, http.StatusBadRequest, "destination is accepted only for backup schedules")
		return
	}
	permission, ok := scheduleActionPermission(in.Action)
	if !ok {
		writeError(w, http.StatusBadRequest, "schedule action must be backup, restart, start, stop, update, command, or message")
		return
	}
	if permission != "" && !a.allowedServer(u, permission, s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, permission+" permission is required to schedule this action")
		return
	}
	if in.Action == "update" && (!s.Installed || s.Status == "installing" || s.Status == "updating" || s.Status == "starting") {
		writeError(w, http.StatusConflict, "scheduled updates require an installed server with no install or update in progress")
		return
	}
	if isRemoteBackupStorage(destination) {
		_, target, targetErr := a.backupStoreForRemote()
		if targetErr != nil || !target.Enabled || target.protocol() != destination {
			if destination == "s3" {
				writeError(w, http.StatusBadRequest, "enable and configure the S3 backup target before scheduling S3 backups")
			} else {
				writeError(w, http.StatusBadRequest, "enable and configure the selected "+strings.ToUpper(destination)+" backup target before scheduling remote backups")
			}
			return
		}
	}
	if in.SkipIfPlayersOnline {
		if in.Action != "restart" && in.Action != "update" {
			writeError(w, http.StatusBadRequest, "skip_if_players_online is supported only for restart and update schedules")
			return
		}
		gs, loadErr := a.loadRune(s.GameskillID)
		if loadErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read the server template to validate its player query")
			return
		}
		if gs.Query == nil {
			writeError(w, http.StatusBadRequest, "skip_if_players_online requires a template with a player query protocol")
			return
		}
	}
	command := ""
	if in.Action == "command" {
		validatedCommand, commandErr := validateScheduledCommand(in.Command)
		if commandErr != nil {
			writeError(w, http.StatusBadRequest, commandErr.Error())
			return
		}
		command = validatedCommand
	} else if strings.TrimSpace(in.Command) != "" {
		writeError(w, http.StatusBadRequest, "command is accepted only for command schedules")
		return
	}
	messagePayload := scheduledMessagePayload{}
	if in.Action == "message" {
		if s.GameskillID != "minecraft-java" && s.GameskillID != "minecraft-bedrock" {
			writeError(w, http.StatusBadRequest, "scheduled player messages are supported by Minecraft Java and Bedrock templates")
			return
		}
		_, templateBody, lookupErr := a.messageTemplateByID(in.MessageTemplateID)
		if errors.Is(lookupErr, sql.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "select an available message template")
			return
		}
		if lookupErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read the selected message template")
			return
		}
		payload, payloadErr := prepareScheduledMessage(templateBody, in.MessageValues)
		if payloadErr != nil {
			writeError(w, http.StatusBadRequest, payloadErr.Error())
			return
		}
		messagePayload = payload
	} else if in.MessageTemplateID != "" || in.MessageValues != nil {
		writeError(w, http.StatusBadRequest, "message_template_id and values are accepted only for message schedules")
		return
	}
	warnPlayers, warningSeconds, err := a.validateScheduleAction(s, in.Action, in.WarnPlayers, in.WarningSeconds)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		switch in.Action {
		case "restart":
			in.Name = "Scheduled restart"
		case "start":
			in.Name = "Scheduled start"
		case "stop":
			in.Name = "Scheduled stop"
		case "update":
			in.Name = "Scheduled update"
		case "command":
			in.Name = "Scheduled command"
		case "message":
			in.Name = "Scheduled message"
		default:
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
	commandEnc := ""
	messagePayloadEnc := ""
	if command != "" {
		commandEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), command)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the scheduled command")
			return
		}
	}
	if in.Action == "message" {
		payload, marshalErr := json.Marshal(messagePayload)
		if marshalErr != nil {
			writeError(w, http.StatusInternalServerError, "could not encode scheduled message")
			return
		}
		messagePayloadEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), string(payload))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt scheduled message")
			return
		}
	}
	if _, err = a.db.Exec(`INSERT INTO backup_schedules(id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,command_enc,message_payload_enc,next_run) VALUES(?,?,'server',?,?,?,?,?,?,?,?,?,?,?,?)`, id, s.ID, s.ID, in.Name, in.Action, destination, strings.TrimSpace(in.Cron), boolInt(enabled), boolInt(warnPlayers), warningSeconds, boolInt(in.SkipIfPlayersOnline), commandEnc, messagePayloadEnc, nextRun); err != nil {
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
	if item.LastStatus == "running" {
		writeError(w, http.StatusConflict, "a running schedule cannot be edited")
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
	if permission != "" && (in.Cron != nil || in.Enabled != nil && *in.Enabled) && !a.allowedServer(u, permission, s.ID, s.GameskillID, s.RealmID) {
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
	result, err := a.db.Exec(`UPDATE backup_schedules SET name=?,cron=?,enabled=?,next_run=?,run_now=0 WHERE id=? AND scope_type='server' AND scope_id=? AND last_status<>'running'`, item.Name, item.Cron, boolInt(item.Enabled), item.NextRun, id, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update backup schedule")
		return
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		writeError(w, http.StatusConflict, "schedule started while it was being edited")
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
	result, err := tx.Exec(`DELETE FROM backup_schedules WHERE id=? AND scope_type='server' AND scope_id=? AND last_status<>'running'`, id, s.ID)
	if err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not delete backup schedule")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var status string
		lookupErr := tx.QueryRow(`SELECT last_status FROM backup_schedules WHERE id=? AND scope_type='server' AND scope_id=?`, id, s.ID).Scan(&status)
		_ = tx.Rollback()
		if errors.Is(lookupErr, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "backup schedule not found")
		} else if lookupErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read schedule status")
		} else {
			writeError(w, http.StatusConflict, "a running schedule cannot be deleted")
		}
		return
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND server_id=?`, id, s.ID); err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not remove backup schedule history")
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
	rows, err := a.db.Query(`SELECT r.id,r.schedule_id,r.server_id,COALESCE(s.name,''),r.started_at,r.finished_at,r.status,r.detail FROM backup_schedule_runs r LEFT JOIN servers s ON s.id=r.server_id WHERE r.schedule_id=? AND r.server_id=? ORDER BY r.started_at DESC,r.id DESC LIMIT 50`, id, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list schedule runs")
		return
	}
	defer rows.Close()
	out := []backupScheduleRun{}
	for rows.Next() {
		var item backupScheduleRun
		if err = rows.Scan(&item.ID, &item.ScheduleID, &item.ServerID, &item.ServerName, &item.StartedAt, &item.FinishedAt, &item.Status, &item.Detail); err != nil {
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
	var skipIfPlayersOnline int
	err := a.db.QueryRow(`SELECT id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE id=? AND scope_type='server' AND scope_id=?`, id, serverID).Scan(&item.ID, &item.ServerID, &item.ScopeType, &item.ScopeID, &item.Name, &item.Action, &item.Destination, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &skipIfPlayersOnline, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt)
	item.Enabled = enabled != 0
	item.WarnPlayers = warnPlayers != 0
	item.SkipIfPlayersOnline = skipIfPlayersOnline != 0
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
	rows, err := a.db.Query(`SELECT id FROM backup_schedules WHERE (enabled=1 OR run_now=1) AND next_run<>'' AND next_run<=? ORDER BY next_run,id`, nowStamp)
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
	var scopeType, serverID, lastStatus string
	if err := a.db.QueryRow(`SELECT scope_type,server_id,last_status FROM backup_schedules WHERE id=?`, id).Scan(&scopeType, &serverID, &lastStatus); err != nil {
		return err
	}
	if lastStatus == "running" {
		skipped, err := a.skipOverlappingScheduleOccurrence(id, serverID, scopeType, now)
		if err != nil || skipped {
			return err
		}
	}
	if scopeType != "server" {
		return a.runDueScopedSchedule(ctx, id, now)
	}
	var name, action, destination, expression, commandEnc, messagePayloadEnc, nextRun string
	var enabled, runNow, warnPlayers, warningSeconds, skipIfPlayersOnline int
	if err := a.db.QueryRow(`SELECT server_id,name,action,destination,cron,enabled,run_now,warn_players,warning_seconds,skip_if_players_online,command_enc,message_payload_enc,next_run FROM backup_schedules WHERE id=?`, id).Scan(&serverID, &name, &action, &destination, &expression, &enabled, &runNow, &warnPlayers, &warningSeconds, &skipIfPlayersOnline, &commandEnc, &messagePayloadEnc, &nextRun); err != nil {
		return err
	}
	if enabled == 0 && runNow == 0 || nextRun == "" || nextRun > scheduleTimestamp(now) {
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
	nextStamp := ""
	if enabled != 0 {
		nextStamp = scheduleTimestamp(next)
	}
	result, err := tx.Exec(`UPDATE backup_schedules SET next_run=?,run_now=0,last_run=?,last_status='running',last_error='' WHERE id=? AND (enabled=1 OR run_now=1) AND next_run<>'' AND next_run<=?`, nextStamp, started, id, started)
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
	if action == "restart" || action == "update" {
		playerCheckDetail := ""
		if skipIfPlayersOnline != 0 {
			players, queryErr := a.scheduledPlayerCount(ctx, serverID)
			if ctx.Err() != nil {
				return a.finishScheduleRun(id, serverID, action, runID, "error", ctx.Err().Error())
			}
			if queryErr == nil && players > 0 {
				return a.finishScheduleRun(id, serverID, action, runID, "skipped", fmt.Sprintf("skipped because players are online (%d online)", players))
			}
			if queryErr != nil {
				playerCheckDetail = "player count unavailable; proceeding with scheduled " + action
			}
		}
		if action == "update" {
			var detail string
			if a.scheduleUpdate != nil {
				detail, err = a.scheduleUpdate(ctx, serverID)
			} else {
				detail, err = a.executeScheduledUpdate(ctx, serverID)
			}
			status := "success"
			if errors.Is(err, errScheduledAppUpdateSkipped) {
				status = "skipped"
				detail = err.Error()
			} else if err != nil {
				status = "error"
				detail = err.Error()
			}
			if playerCheckDetail != "" {
				if detail != "" {
					detail = playerCheckDetail + "; " + detail
				} else {
					detail = playerCheckDetail
				}
			}
			return a.finishScheduleRun(id, serverID, action, runID, status, detail)
		}
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
		go a.finishScheduledRestart(ctx, serverID, id, name, warn, leadSeconds, playerCheckDetail, runID)
		return nil
	}
	status, detail := "success", ""
	if action == "start" || action == "stop" {
		var actionStatus string
		if a.scheduleControl != nil {
			actionStatus, detail, err = a.scheduleControl(ctx, serverID, action)
		} else {
			actionStatus, detail, err = a.executeScheduledControl(ctx, serverID, action)
		}
		if actionStatus != "" {
			status = actionStatus
		}
		if err != nil {
			status = "error"
			detail = err.Error()
		}
	} else if action == "command" {
		command, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), commandEnc)
		if decryptErr != nil {
			status = "error"
			detail = "stored console command could not be decrypted; check auth.secret_key"
		} else if detail, err = a.executeScheduledCommand(ctx, serverID, command); err != nil {
			status = "error"
			detail = err.Error()
		}
	} else if action == "message" {
		payloadJSON, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), messagePayloadEnc)
		if decryptErr != nil {
			status = "error"
			detail = "stored scheduled message could not be decrypted; check auth.secret_key"
		} else {
			var payload scheduledMessagePayload
			if json.Unmarshal([]byte(payloadJSON), &payload) != nil {
				status = "error"
				detail = "stored scheduled message could not be read"
			} else if detail, err = a.executeScheduledMessage(ctx, serverID, payload); err != nil {
				status = "error"
				detail = err.Error()
			}
		}
	} else if action != "backup" {
		status = "error"
		detail = "unsupported stored schedule action"
	} else if detail, err = a.executeScheduledBackup(serverID, id, name, destination); err != nil {
		status = "error"
		detail = err.Error()
	}
	return a.finishScheduleRun(id, serverID, action, runID, status, detail)
}

func (a *App) skipOverlappingScheduleOccurrence(id, serverID, scopeType string, now time.Time) (bool, error) {
	tx, err := a.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var expression, nextRun string
	var enabled int
	if err = tx.QueryRow(`SELECT cron,next_run,enabled FROM backup_schedules WHERE id=? AND last_status='running'`, id).Scan(&expression, &nextRun, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if enabled == 0 || nextRun == "" || nextRun > scheduleTimestamp(now) {
		return false, nil
	}
	parsed, err := schedule.Parse(expression)
	if err != nil {
		return false, err
	}
	next, err := parsed.Next(now)
	if err != nil {
		return false, err
	}
	nextRunStamp := scheduleTimestamp(next)
	started := scheduleTimestamp(now)
	result, err := tx.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=? AND last_status='running' AND enabled=1 AND next_run=? AND next_run<=?`, nextRunStamp, id, nextRun, started)
	if err != nil {
		return false, err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return false, nil
	}
	runID, err := newID()
	if err != nil {
		return false, err
	}
	if scopeType != "server" {
		serverID = ""
	}
	detail := "previous schedule run is still active; this cron occurrence was skipped"
	if _, err = tx.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,finished_at,status,detail) VALUES(?,?,?,?,?,'skipped',?)`, runID, id, serverID, started, started, detail); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (a *App) finishScheduledRestart(ctx context.Context, serverID, scheduleID, name string, warn bool, warningSeconds int, playerCheckDetail, runID string) {
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
	if playerCheckDetail != "" {
		if detail != "" {
			detail = playerCheckDetail + "; " + detail
		} else {
			detail = playerCheckDetail
		}
	}
	if strings.TrimSpace(name) != "" && status == "success" {
		detail = name + ": " + detail
	}
	if err = a.finishScheduleRun(scheduleID, serverID, "restart", runID, status, detail); err != nil {
		log.Printf("scheduled restart %s: %v", scheduleID, err)
	}
}

func (a *App) scheduledPlayerCount(ctx context.Context, serverID string) (int, error) {
	if a.schedulePlayers != nil {
		return a.schedulePlayers(ctx, serverID)
	}
	s, err := a.getServer(serverID)
	if err != nil {
		return 0, errors.New("server no longer exists")
	}
	if s.Status != "running" {
		return 0, errors.New("server is not running")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return 0, err
	}
	if gs.Query == nil {
		return 0, errors.New("server template does not define a player query protocol")
	}
	port, err := queryPort(s, gs)
	if err != nil {
		return 0, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	result, err := queryAtPort(queryCtx, gs, port)
	if err != nil {
		return 0, err
	}
	if result.Online < 0 {
		return 0, errors.New("player query returned a negative count")
	}
	return result.Online, nil
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
	a.dispatchScheduledRunNotification(id, serverID, action, status)
	if _, pruneErr := a.db.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND id NOT IN (SELECT id FROM backup_schedule_runs WHERE schedule_id=? ORDER BY started_at DESC,id DESC LIMIT 100)`, id, id); pruneErr != nil {
		log.Printf("could not prune run history for schedule %s", id)
	}
	return nil
}

func (a *App) executeScheduledBackup(serverID, scheduleID, name, destination string) (string, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(serverID)
	if err != nil {
		return "", fmt.Errorf("server no longer exists")
	}
	if err = a.confirmServerStopped(s); err != nil {
		return "", err
	}
	item, pruned, warning, err := a.createBackupSnapshot(s, destination)
	if err != nil {
		return "", err
	}
	detail := fmt.Sprintf("%s: created backup %s (%s) with %d files and %d bytes; retention removed %d", name, item.ID, item.Storage, item.Files, item.DataBytes, pruned)
	if warning != "" {
		detail += "; " + warning
	}
	a.audit(User{Username: "scheduler"}, "server.backup.create", "backup", item.ID, fmt.Sprintf("server=%s schedule=%s files=%d bytes=%d", serverID, scheduleID, item.Files, item.DataBytes))
	return detail, nil
}

func (a *App) executeScheduledControl(ctx context.Context, serverID, action string) (string, string, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "error", "", err
	}
	s, err := a.getServer(serverID)
	if err != nil {
		return "error", "", errors.New("server no longer exists")
	}
	switch action {
	case "start":
		if s.Status == "running" || s.Status == "starting" {
			return "skipped", "start skipped because the server is already running or starting", nil
		}
		if !s.Installed {
			return "error", "", errors.New("install this server before scheduling a start")
		}
		if err = a.startWithContext(s, ctx); err != nil {
			return "error", "", err
		}
		a.resetWatchdog(s.ID)
		return "success", "start initiated", nil
	case "stop":
		if s.ContainerID == "" {
			return "skipped", "stop skipped because no container exists", nil
		}
		if err = a.stop(s); err != nil {
			return "error", "", err
		}
		a.resetWatchdog(s.ID)
		return "success", "server stopped", nil
	default:
		return "error", "", errors.New("unsupported scheduled control action")
	}
}

func (a *App) executeScheduledCommand(ctx context.Context, serverID, command string) (string, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(serverID)
	if err != nil {
		return "", errors.New("server no longer exists")
	}
	return a.dispatchScheduledConsoleCommand(ctx, s, command, "console command sent", "console command could not be sent")
}

func (a *App) executeScheduledMessage(ctx context.Context, serverID string, payload scheduledMessagePayload) (string, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(serverID)
	if err != nil {
		return "", errors.New("server no longer exists")
	}
	command, err := renderScheduledMessage(payload, s.Name)
	if err != nil {
		return "", err
	}
	return a.dispatchScheduledConsoleCommand(ctx, s, command, "scheduled message sent", "scheduled message could not be sent")
}

func (a *App) dispatchScheduledConsoleCommand(ctx context.Context, s Server, command, successDetail, errorDetail string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.ContainerID == "" || s.Status != "running" {
		return "", errors.New("server is not running; start it before the scheduled console action")
	}
	send := a.scheduleCommand
	if send == nil {
		send = func(ctx context.Context, server Server, value string) error {
			_, sendErr := a.sendCommand(ctx, server, value)
			return sendErr
		}
	}
	if err := send(ctx, s, command); err != nil {
		return "", errors.New(errorDetail)
	}
	return successDetail, nil
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
	if status == "success" || status == "skipped" {
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
