package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/schedule"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

type scopedScheduleInput struct {
	ScopeType           string         `json:"scope_type"`
	ScopeID             string         `json:"scope_id"`
	Name                string         `json:"name"`
	Action              string         `json:"action"`
	Destination         string         `json:"destination"`
	Cron                string         `json:"cron"`
	Enabled             *bool          `json:"enabled"`
	WarnPlayers         bool           `json:"warn_players"`
	WarningSeconds      int            `json:"warning_seconds"`
	SkipIfPlayersOnline bool           `json:"skip_if_players_online"`
	Command             string         `json:"command"`
	MessageTemplateID   string         `json:"message_template_id"`
	MessageValues       map[string]int `json:"values"`
}

type scopedScheduleTargetRun struct {
	serverID string
	runID    string
}

func (a *App) listScopedSchedules(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query(`SELECT id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE scope_type IN ('realm','global') ORDER BY created_at DESC,id DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list scoped schedules")
		return
	}
	defer rows.Close()
	items := []backupSchedule{}
	for rows.Next() {
		var item backupSchedule
		var enabled, warnPlayers, skipPlayers int
		if err = rows.Scan(&item.ID, &item.ServerID, &item.ScopeType, &item.ScopeID, &item.Name, &item.Action, &item.Destination, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &skipPlayers, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read scoped schedule metadata")
			return
		}
		item.Enabled = enabled != 0
		item.WarnPlayers = warnPlayers != 0
		item.SkipIfPlayersOnline = skipPlayers != 0
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read scoped schedule metadata")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *App) createScopedSchedule(w http.ResponseWriter, r *http.Request) {
	var in scopedScheduleInput
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	in.ScopeType = strings.TrimSpace(in.ScopeType)
	in.ScopeID = strings.TrimSpace(in.ScopeID)
	in.Action = strings.TrimSpace(in.Action)
	if in.ScopeType != "global" && in.ScopeType != "realm" {
		writeError(w, http.StatusBadRequest, "scope_type must be global or realm")
		return
	}
	if in.ScopeType == "global" && in.ScopeID != "" {
		writeError(w, http.StatusBadRequest, "global schedules do not accept a scope_id")
		return
	}
	if in.ScopeType == "realm" {
		var exists int
		if in.ScopeID == "" || a.db.QueryRow(`SELECT count(*) FROM realms WHERE id=?`, in.ScopeID).Scan(&exists) != nil || exists != 1 {
			writeError(w, http.StatusBadRequest, "select an existing realm for this schedule")
			return
		}
	}
	if in.Action == "" {
		in.Action = "backup"
	}
	if _, supported := scheduleActionPermission(in.Action); !supported {
		writeError(w, http.StatusBadRequest, "unsupported schedule action")
		return
	}
	destination := strings.TrimSpace(in.Destination)
	if destination == "" {
		destination = "local"
	}
	if destination != "local" && destination != "s3" && destination != "sftp" && destination != "smb" && destination != "azure" && destination != "gcs" {
		writeError(w, http.StatusBadRequest, "backup destination must be local, s3, sftp, smb, azure, or gcs")
		return
	}
	if in.Action != "backup" && destination != "local" {
		writeError(w, http.StatusBadRequest, "destination is accepted only for backup schedules")
		return
	}
	if isRemoteBackupStorage(destination) {
		_, target, targetErr := a.backupStoreForRemote()
		if targetErr != nil || !target.Enabled || target.protocol() != destination {
			writeError(w, http.StatusBadRequest, "enable and configure the selected remote backup destination before scheduling it")
			return
		}
	}
	if in.SkipIfPlayersOnline && in.Action != "restart" && in.Action != "update" {
		writeError(w, http.StatusBadRequest, "skip_if_players_online is supported only for restart and update schedules")
		return
	}
	if in.WarnPlayers && in.Action != "restart" {
		writeError(w, http.StatusBadRequest, "warn_players is supported only for restart schedules")
		return
	}
	if err := a.validateScopedActionTargets(in.ScopeType, in.ScopeID, in.Action, in.SkipIfPlayersOnline); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	command := ""
	if in.Action == "command" {
		validated, err := validateScheduledCommand(in.Command)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		command = validated
	} else if strings.TrimSpace(in.Command) != "" {
		writeError(w, http.StatusBadRequest, "command is accepted only for command schedules")
		return
	}
	messagePayload := scheduledMessagePayload{}
	if in.Action == "message" {
		_, body, lookupErr := a.messageTemplateByID(in.MessageTemplateID)
		if errors.Is(lookupErr, sql.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "select an available message template")
			return
		}
		if lookupErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read the selected message template")
			return
		}
		payload, err := prepareScheduledMessage(body, in.MessageValues)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		messagePayload = payload
	} else if in.MessageTemplateID != "" || in.MessageValues != nil {
		writeError(w, http.StatusBadRequest, "message_template_id and values are accepted only for message schedules")
		return
	}
	warningSeconds := 60
	if in.WarnPlayers {
		if in.WarningSeconds < 1 || in.WarningSeconds > 24*60*60 {
			writeError(w, http.StatusBadRequest, "warning_seconds must be from 1 to 86400")
			return
		}
		warningSeconds = in.WarningSeconds
		if err := a.validateScopedRestart(in.ScopeType, in.ScopeID, warningSeconds); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		names := map[string]string{"backup": "Backup", "start": "Start", "stop": "Stop", "restart": "Restart", "update": "Update", "command": "Command", "message": "Message"}
		in.Name = "Scheduled " + names[in.Action]
	}
	if len(in.Name) > 80 {
		writeError(w, http.StatusBadRequest, "schedule name must be 80 characters or fewer")
		return
	}
	cronText := strings.TrimSpace(in.Cron)
	parsed, err := schedule.Parse(cronText)
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
	if _, err = a.db.Exec(`INSERT INTO backup_schedules(id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,command_enc,message_payload_enc,next_run) VALUES(?,'',?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, in.ScopeType, in.ScopeID, in.Name, in.Action, destination, cronText, boolInt(enabled), boolInt(in.WarnPlayers), warningSeconds, boolInt(in.SkipIfPlayersOnline), commandEnc, messagePayloadEnc, nextRun); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save scoped schedule")
		return
	}
	a.audit(principal(r), "schedule.create", "backup_schedule", id, fmt.Sprintf("scope=%s:%s action=%s cron=%s", in.ScopeType, in.ScopeID, in.Action, cronText))
	item, err := a.getScopedSchedule(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "schedule was saved but its metadata could not be read")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (a *App) validateScopedRestart(scopeType, scopeID string, warningSeconds int) error {
	servers, err := a.scopedServerIDs(scopeType, scopeID)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		return errors.New("restart warnings require at least one server in the selected scope")
	}
	seconds := warningSeconds
	warn := true
	for _, id := range servers {
		server, getErr := a.getServer(id)
		if getErr != nil {
			return errors.New("a server in the selected scope could not be read")
		}
		if _, _, validateErr := a.validateScheduleAction(server, "restart", &warn, &seconds); validateErr != nil {
			return fmt.Errorf("restart warnings must be supported by every server in scope: %w", validateErr)
		}
	}
	return nil
}

func (a *App) validateScopedActionTargets(scopeType, scopeID, action string, skipIfPlayersOnline bool) error {
	if action != "update" && action != "message" && !skipIfPlayersOnline {
		return nil
	}
	serverIDs, err := a.scopedServerIDs(scopeType, scopeID)
	if err != nil {
		return errors.New("could not read servers in the selected schedule scope")
	}
	if action == "message" && len(serverIDs) == 0 {
		return errors.New("message schedules require at least one Minecraft Java or Bedrock server in scope")
	}
	if skipIfPlayersOnline && len(serverIDs) == 0 {
		return errors.New("player-online skipping requires at least one query-capable server in scope")
	}
	for _, serverID := range serverIDs {
		server, getErr := a.getServer(serverID)
		if getErr != nil {
			return errors.New("a server in the selected scope could not be read")
		}
		switch action {
		case "update":
			if !server.Installed || server.Status == "installing" || server.Status == "updating" || server.Status == "starting" {
				return fmt.Errorf("scheduled updates require every server in scope to be installed and idle; %s is not eligible", server.Name)
			}
		case "message":
			if server.GameskillID != "minecraft-java" && server.GameskillID != "minecraft-bedrock" {
				return fmt.Errorf("scheduled player messages require Minecraft Java or Bedrock servers; %s uses %s", server.Name, server.GameskillID)
			}
		}
		if skipIfPlayersOnline {
			template, loadErr := a.loadRune(server.GameskillID)
			if loadErr != nil {
				return fmt.Errorf("could not read %s's template to validate its player query", server.Name)
			}
			if template.Query == nil {
				return fmt.Errorf("player-online skipping requires a query protocol for every server in scope; %s does not have one", server.Name)
			}
		}
	}
	return nil
}

func (a *App) scopedServerIDs(scopeType, scopeID string) ([]string, error) {
	query := `SELECT id FROM servers ORDER BY id`
	args := []any{}
	if scopeType == "realm" {
		query = `SELECT id FROM servers WHERE realm_id=? ORDER BY id`
		args = append(args, scopeID)
	} else if scopeType != "global" {
		return nil, errors.New("invalid schedule scope")
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (a *App) getScopedSchedule(id string) (backupSchedule, error) {
	var item backupSchedule
	var enabled, warnPlayers, skipPlayers int
	err := a.db.QueryRow(`SELECT id,server_id,scope_type,scope_id,name,action,destination,cron,enabled,warn_players,warning_seconds,skip_if_players_online,next_run,last_run,last_status,last_error,created_at FROM backup_schedules WHERE id=? AND scope_type IN ('realm','global')`, id).Scan(&item.ID, &item.ServerID, &item.ScopeType, &item.ScopeID, &item.Name, &item.Action, &item.Destination, &item.Cron, &enabled, &warnPlayers, &item.WarningSeconds, &skipPlayers, &item.NextRun, &item.LastRun, &item.LastStatus, &item.LastError, &item.CreatedAt)
	item.Enabled = enabled != 0
	item.WarnPlayers = warnPlayers != 0
	item.SkipIfPlayersOnline = skipPlayers != 0
	return item, err
}

func (a *App) updateScopedSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	item, err := a.getScopedSchedule(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read schedule")
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
	result, err := a.db.Exec(`UPDATE backup_schedules SET name=?,cron=?,enabled=?,next_run=?,run_now=0 WHERE id=? AND scope_type IN ('realm','global') AND last_status<>'running'`, item.Name, item.Cron, boolInt(item.Enabled), item.NextRun, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update schedule")
		return
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		writeError(w, http.StatusConflict, "schedule started while it was being edited")
		return
	}
	a.audit(principal(r), "schedule.update", "backup_schedule", id, fmt.Sprintf("enabled=%t", item.Enabled))
	item, err = a.getScopedSchedule(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "schedule was updated but its metadata could not be read")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *App) deleteScopedSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	tx, err := a.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start schedule deletion")
		return
	}
	result, err := tx.Exec(`DELETE FROM backup_schedules WHERE id=? AND scope_type IN ('realm','global') AND last_status<>'running'`, id)
	if err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not delete schedule")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var status string
		lookupErr := tx.QueryRow(`SELECT last_status FROM backup_schedules WHERE id=? AND scope_type IN ('realm','global')`, id).Scan(&status)
		_ = tx.Rollback()
		if errors.Is(lookupErr, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
		} else if lookupErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read schedule status")
		} else {
			writeError(w, http.StatusConflict, "a running schedule cannot be deleted")
		}
		return
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=?`, id); err != nil {
		_ = tx.Rollback()
		writeError(w, http.StatusInternalServerError, "could not remove schedule history")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish schedule deletion")
		return
	}
	a.audit(principal(r), "schedule.delete", "backup_schedule", id, "scope=realm-or-global")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) listScopedScheduleRuns(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	if _, err := a.getScopedSchedule(id); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read schedule")
		return
	}
	rows, err := a.db.Query(`SELECT r.id,r.schedule_id,r.server_id,COALESCE(s.name,''),r.started_at,r.finished_at,r.status,r.detail FROM backup_schedule_runs r LEFT JOIN servers s ON s.id=r.server_id WHERE r.schedule_id=? ORDER BY r.started_at DESC,r.id DESC LIMIT 50`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list schedule runs")
		return
	}
	defer rows.Close()
	items := []backupScheduleRun{}
	for rows.Next() {
		var item backupScheduleRun
		if err = rows.Scan(&item.ID, &item.ScheduleID, &item.ServerID, &item.ServerName, &item.StartedAt, &item.FinishedAt, &item.Status, &item.Detail); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read schedule run history")
			return
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read schedule run history")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *App) runScheduleNow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scheduleID")
	now := scheduleTimestamp(time.Now())
	result, err := a.db.Exec(`UPDATE backup_schedules SET run_now=1,next_run=? WHERE id=? AND run_now=0 AND last_status<>'running'`, now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not queue schedule run")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var found int
		if a.db.QueryRow(`SELECT count(*) FROM backup_schedules WHERE id=?`, id).Scan(&found) != nil || found == 0 {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusConflict, "schedule is already running")
		return
	}
	a.audit(principal(r), "schedule.run_now", "backup_schedule", id, "queued=true")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (a *App) runDueScopedSchedule(ctx context.Context, id string, now time.Time) error {
	var scheduleItem backupSchedule
	var enabled, runNow, warnPlayers, skipPlayers int
	var commandEnc, messagePayloadEnc string
	if err := a.db.QueryRow(`SELECT server_id,scope_type,scope_id,name,action,destination,cron,enabled,run_now,warn_players,warning_seconds,skip_if_players_online,command_enc,message_payload_enc,next_run FROM backup_schedules WHERE id=?`, id).Scan(&scheduleItem.ServerID, &scheduleItem.ScopeType, &scheduleItem.ScopeID, &scheduleItem.Name, &scheduleItem.Action, &scheduleItem.Destination, &scheduleItem.Cron, &enabled, &runNow, &warnPlayers, &scheduleItem.WarningSeconds, &skipPlayers, &commandEnc, &messagePayloadEnc, &scheduleItem.NextRun); err != nil {
		return err
	}
	scheduleItem.ID = id
	scheduleItem.WarnPlayers = warnPlayers != 0
	scheduleItem.SkipIfPlayersOnline = skipPlayers != 0
	if enabled == 0 && runNow == 0 || scheduleItem.NextRun == "" || scheduleItem.NextRun > scheduleTimestamp(now) {
		return nil
	}
	cron, err := schedule.Parse(scheduleItem.Cron)
	if err != nil {
		message := "invalid stored cron expression: " + err.Error()
		_, _ = a.db.Exec(`UPDATE backup_schedules SET enabled=0,run_now=0,next_run='',last_status='error',last_error=? WHERE id=?`, message, id)
		return errors.New(message)
	}
	nextStamp := ""
	if enabled != 0 {
		next, nextErr := cron.Next(now)
		if nextErr != nil {
			_, _ = a.db.Exec(`UPDATE backup_schedules SET enabled=0,run_now=0,next_run='',last_status='error',last_error=? WHERE id=?`, nextErr.Error(), id)
			return nextErr
		}
		nextStamp = scheduleTimestamp(next)
	}
	started := scheduleTimestamp(now)
	tx, err := a.db.Begin()
	if err != nil {
		return err
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
	if err = tx.Commit(); err != nil {
		return err
	}
	serverIDs, err := a.scopedServerIDs(scheduleItem.ScopeType, scheduleItem.ScopeID)
	if err != nil {
		runID, idErr := newID()
		if idErr == nil {
			_, _ = a.db.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,finished_at,status,detail) VALUES(?,?, '', ?,?,'error','could not resolve servers in schedule scope')`, runID, id, started, scheduleTimestamp(time.Now()))
		}
		a.finishScopedSchedule(id, scheduleItem, 0, 0, 1, "could not resolve servers in schedule scope")
		return err
	}
	if len(serverIDs) == 0 {
		runID, idErr := newID()
		if idErr != nil {
			return idErr
		}
		if _, err = a.db.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,finished_at,status,detail) VALUES(?,?, '', ?,?,'skipped','no servers in scope')`, runID, id, started, scheduleTimestamp(time.Now())); err != nil {
			return err
		}
		a.finishScopedSchedule(id, scheduleItem, 0, 0, 0, "no servers in scope")
		return nil
	}
	runs := make([]scopedScheduleTargetRun, 0, len(serverIDs))
	tx, err = a.db.Begin()
	if err != nil {
		return err
	}
	for _, serverID := range serverIDs {
		runID, idErr := newID()
		if idErr != nil {
			_ = tx.Rollback()
			return idErr
		}
		if _, err = tx.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,status,detail) VALUES(?,?,?,?, 'running',?)`, runID, id, serverID, started, "queued in scoped schedule"); err != nil {
			_ = tx.Rollback()
			return err
		}
		runs = append(runs, scopedScheduleTargetRun{serverID: serverID, runID: runID})
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if scheduleItem.Action == "restart" && scheduleItem.WarnPlayers {
		go func() {
			if runErr := a.executeScopedScheduleTargets(ctx, id, scheduleItem, runs, commandEnc, messagePayloadEnc); runErr != nil {
				log.Printf("scoped schedule %s: %v", id, runErr)
			}
		}()
		return nil
	}
	return a.executeScopedScheduleTargets(ctx, id, scheduleItem, runs, commandEnc, messagePayloadEnc)
}

func (a *App) executeScopedScheduleTargets(ctx context.Context, id string, scheduleItem backupSchedule, runs []scopedScheduleTargetRun, commandEnc, messagePayloadEnc string) error {
	var successes, skipped, failures int
	var err error
	consecutiveUpdateFailures := 0
	for _, target := range runs {
		if err = ctx.Err(); err != nil {
			return err
		}
		status, detail := "success", ""
		if scheduleItem.Action == "update" && consecutiveUpdateFailures >= 3 {
			status, detail = "skipped", "skipped after three consecutive update failures"
		} else {
			status, detail, err = a.executeScopedScheduleTarget(ctx, scheduleItem, target.serverID, commandEnc, messagePayloadEnc)
			if err != nil {
				status, detail = "error", err.Error()
			}
		}
		if finishErr := a.finishScopedTargetRun(scheduleItem, target.serverID, target.runID, status, detail); finishErr != nil {
			return finishErr
		}
		switch status {
		case "success":
			successes++
			if scheduleItem.Action == "update" {
				consecutiveUpdateFailures = 0
			}
		case "skipped":
			skipped++
		case "error":
			failures++
			if scheduleItem.Action == "update" {
				consecutiveUpdateFailures++
			}
		}
	}
	summary := fmt.Sprintf("targets=%d succeeded=%d skipped=%d failed=%d", len(runs), successes, skipped, failures)
	a.finishScopedSchedule(id, scheduleItem, successes, skipped, failures, summary)
	return nil
}

func (a *App) executeScopedScheduleTarget(ctx context.Context, item backupSchedule, serverID, commandEnc, messagePayloadEnc string) (string, string, error) {
	server, err := a.getServer(serverID)
	if err != nil {
		return "error", "", errors.New("server no longer exists")
	}
	playerCheckDetail := ""
	if item.SkipIfPlayersOnline && (item.Action == "restart" || item.Action == "update") {
		players, queryErr := a.scheduledPlayerCount(ctx, serverID)
		if ctx.Err() != nil {
			return "error", "", ctx.Err()
		}
		if queryErr == nil && players > 0 {
			return "skipped", fmt.Sprintf("skipped because players are online (%d online)", players), nil
		}
		if queryErr != nil {
			playerCheckDetail = "player count unavailable; proceeding with scheduled " + item.Action
		}
	}
	status, detail := "success", ""
	switch item.Action {
	case "backup":
		detail, err = a.executeScheduledBackup(serverID, item.ID, item.Name, item.Destination)
	case "start", "stop":
		if a.scheduleControl != nil {
			status, detail, err = a.scheduleControl(ctx, serverID, item.Action)
		} else {
			status, detail, err = a.executeScheduledControl(ctx, serverID, item.Action)
		}
	case "restart":
		if item.WarnPlayers {
			warn := true
			seconds := item.WarningSeconds
			if _, _, err = a.validateScheduleAction(server, "restart", &warn, &seconds); err == nil {
				if a.scheduleRestart != nil {
					detail, err = a.scheduleRestart(ctx, serverID, true, seconds)
				} else {
					detail, err = a.executeScheduledRestart(ctx, serverID, true, seconds)
				}
			}
		} else {
			detail, err = a.executeScheduledRestart(ctx, serverID, false, item.WarningSeconds)
		}
	case "update":
		if a.scheduleUpdate != nil {
			detail, err = a.scheduleUpdate(ctx, serverID)
		} else {
			detail, err = a.executeScheduledUpdate(ctx, serverID)
		}
		if errors.Is(err, errScheduledAppUpdateSkipped) {
			return "skipped", err.Error(), nil
		}
		if err == nil {
			if a.scheduleReady != nil {
				err = a.scheduleReady(ctx, serverID, 90*time.Second)
			} else {
				err = a.waitScheduledServerReady(ctx, serverID, 90*time.Second)
			}
			if err == nil {
				detail += "; server returned to ready state"
			}
		}
	case "command":
		command, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), commandEnc)
		if decryptErr != nil {
			err = errors.New("stored console command could not be decrypted; check auth.secret_key")
		} else {
			detail, err = a.executeScheduledCommand(ctx, serverID, command)
		}
	case "message":
		payloadJSON, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), messagePayloadEnc)
		if decryptErr != nil {
			err = errors.New("stored scheduled message could not be decrypted; check auth.secret_key")
		} else {
			var payload scheduledMessagePayload
			if json.Unmarshal([]byte(payloadJSON), &payload) != nil {
				err = errors.New("stored scheduled message could not be read")
			} else {
				detail, err = a.executeScheduledMessage(ctx, serverID, payload)
			}
		}
	default:
		err = errors.New("unsupported stored schedule action")
	}
	if err != nil {
		return "error", detail, err
	}
	if playerCheckDetail != "" {
		if detail != "" {
			detail = playerCheckDetail + "; " + detail
		} else {
			detail = playerCheckDetail
		}
	}
	return status, detail, nil
}

func (a *App) waitScheduledServerReady(parent context.Context, serverID string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		server, err := a.getServer(serverID)
		if err != nil {
			return errors.New("server disappeared before it returned to ready state")
		}
		switch server.Status {
		case "running":
			return nil
		case "error":
			if server.ErrorMessage != "" {
				return fmt.Errorf("server failed before returning to ready state: %s", server.ErrorMessage)
			}
			return errors.New("server failed before returning to ready state")
		case "stopped":
			return errors.New("server stopped before returning to ready state")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("server did not return to ready state within %s: %w", timeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (a *App) finishScopedTargetRun(item backupSchedule, serverID, runID, status, detail string) error {
	if _, err := a.db.Exec(`UPDATE backup_schedule_runs SET finished_at=?,status=?,detail=? WHERE id=?`, scheduleTimestamp(time.Now()), status, detail, runID); err != nil {
		return fmt.Errorf("could not record scoped %s result: %w", item.Action, err)
	}
	a.audit(User{Username: "scheduler"}, "server.schedule."+item.Action, "backup_schedule", item.ID, fmt.Sprintf("server=%s status=%s detail=%s", serverID, status, detail))
	if item.Action == "backup" {
		server, _ := a.getServer(serverID)
		if status == "success" {
			a.dispatchBackupNotification(notificationBackupSuccess, serverID, server.Name, "A scheduled backup completed and passed integrity verification.")
		} else {
			a.dispatchBackupNotification(notificationBackupFailure, serverID, server.Name, "A scheduled backup failed. Review the schedule run history for details.")
		}
	}
	a.dispatchScheduledRunNotification(item.ID, serverID, item.Action, status)
	return nil
}

func (a *App) finishScopedSchedule(id string, item backupSchedule, successes, skipped, failures int, summary string) {
	status := "success"
	if failures > 0 {
		status = "error"
	} else if successes == 0 {
		status = "skipped"
	}
	_, _ = a.db.Exec(`UPDATE backup_schedules SET last_status=?,last_error=? WHERE id=?`, status, scheduleError(status, summary), id)
	a.audit(User{Username: "scheduler"}, "schedule.run", "backup_schedule", id, fmt.Sprintf("scope=%s:%s %s", item.ScopeType, item.ScopeID, summary))
	if _, err := a.db.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id=? AND id NOT IN (SELECT id FROM backup_schedule_runs WHERE schedule_id=? ORDER BY started_at DESC,id DESC LIMIT 100)`, id, id); err != nil {
		logScopedPruneFailure(id)
	}
}

func logScopedPruneFailure(id string) {
	log.Printf("could not prune scoped schedule history for %s", id)
}
