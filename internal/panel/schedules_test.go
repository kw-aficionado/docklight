package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gameskill "example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

func TestRestartScheduleRequiresControlAndPersistsWarningSettings(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "restart-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('restart-schedule-server','Restart test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('restart-schedule-user','restart-schedule-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "restart-schedule-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('restart-schedule-user','server','restart-schedule-server','server.schedule')`); err != nil {
		t.Fatal(err)
	}
	options := testRequest(h, http.MethodGet, "/api/servers/restart-schedule-server/schedule-options", "", token)
	if options.Code != http.StatusOK || !strings.Contains(options.Body.String(), `"restart_warnings":[]`) {
		t.Fatalf("restart warnings leaked without server.control: %d %s", options.Code, options.Body.String())
	}
	denied := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","cron":"0 3 * * *","warning_seconds":60}`, token)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("restart schedule was created without server.control: %d %s", denied.Code, denied.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule,server.control' WHERE user_id='restart-schedule-user' AND scope_type='server' AND scope_id='restart-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	options = testRequest(h, http.MethodGet, "/api/servers/restart-schedule-server/schedule-options", "", token)
	if options.Code != http.StatusOK || !strings.Contains(options.Body.String(), `"at":"1m"`) || !strings.Contains(options.Body.String(), `"can_skip_if_players_online":true`) {
		t.Fatalf("authorized user did not receive template restart warnings: %d %s", options.Code, options.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","name":"Daily restart","cron":"0 3 * * *","warning_seconds":60,"skip_if_players_online":true}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create restart schedule: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Action != "restart" || !item.WarnPlayers || item.WarningSeconds != 60 || !item.SkipIfPlayersOnline || !item.Enabled || item.NextRun == "" {
		t.Fatalf("restart schedule was not persisted correctly: %#v", item)
	}
	invalid := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","cron":"0 4 * * *","warning_seconds":600}`, token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("countdown absent from template warnings was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	wrongAction := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"start","cron":"0 5 * * *","skip_if_players_online":true}`, token)
	if wrongAction.Code != http.StatusBadRequest {
		t.Fatalf("player guard was accepted for a start schedule: %d %s", wrongAction.Code, wrongAction.Body.String())
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/restart-schedule-server/schedules", "", token)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"action":"restart"`) || !strings.Contains(listed.Body.String(), `"warning_seconds":60`) || !strings.Contains(listed.Body.String(), `"skip_if_players_online":true`) {
		t.Fatalf("restart schedule settings missing from list response: %d %s", listed.Code, listed.Body.String())
	}
	if _, err = d.Exec(`UPDATE servers SET gameskill_id='uptime-kuma' WHERE id='restart-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	unsupportedQuery := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","cron":"0 6 * * *","warn_players":false,"skip_if_players_online":true}`, token)
	if unsupportedQuery.Code != http.StatusBadRequest || !strings.Contains(unsupportedQuery.Body.String(), "player query protocol") {
		t.Fatalf("player guard was accepted without a query-capable template: %d %s", unsupportedQuery.Code, unsupportedQuery.Body.String())
	}
}

func TestScheduledRestartSkipsWhenPlayersAreOnline(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "players-online-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('players-online-schedule-server','Online test','minecraft-java','running',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,skip_if_players_online,next_run) VALUES('players-online-restart','players-online-schedule-server','Do not interrupt players','restart','* * * * *',1,1,?)`, scheduleTimestamp(now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	a.schedulePlayers = func(context.Context, string) (int, error) { return 4, nil }
	restarted := make(chan struct{}, 1)
	a.scheduleRestart = func(context.Context, string, bool, int) (string, error) {
		restarted <- struct{}{}
		return "unexpected restart", nil
	}
	if err := a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var status, detail, lastError string
	deadline := time.Now().Add(time.Second)
	for {
		if err := d.QueryRow(`SELECT r.status,r.detail,s.last_error FROM backup_schedule_runs r JOIN backup_schedules s ON s.id=r.schedule_id WHERE s.id='players-online-restart'`).Scan(&status, &detail, &lastError); err != nil {
			t.Fatal(err)
		}
		if status != "running" || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-restarted:
		t.Fatal("scheduled restart ran while players were online")
	default:
	}
	if status != "skipped" || detail != "skipped because players are online (4 online)" || lastError != "" {
		t.Fatalf("online-player run status=%q detail=%q last_error=%q", status, detail, lastError)
	}
}

func TestScheduledRestartContinuesWhenPlayerCountIsUnavailable(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "unknown-player-count-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('unknown-player-count-schedule-server','Unknown count test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,skip_if_players_online,next_run) VALUES('unknown-player-count-restart','unknown-player-count-schedule-server','Proceed on query failure','restart','* * * * *',1,1,?)`, scheduleTimestamp(now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	a.schedulePlayers = func(context.Context, string) (int, error) { return 0, errors.New("query unavailable") }
	a.scheduleRestart = func(context.Context, string, bool, int) (string, error) { return "restart completed", nil }
	if err := a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	var status, detail string
	for time.Now().Before(deadline) {
		if err := d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='unknown-player-count-restart'`).Scan(&status, &detail); err != nil {
			t.Fatal(err)
		}
		if status == "success" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if status != "success" || !strings.Contains(detail, "player count unavailable; proceeding with scheduled restart") || !strings.Contains(detail, "restart completed") {
		t.Fatalf("restart did not proceed after the query failed: status=%q detail=%q", status, detail)
	}
}

func TestScheduledCommandRequiresConsoleAndStoresEncryptedCommand(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "command-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('command-schedule-server','Command test','minecraft-java','running',1,'command-container','{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('command-schedule-user','command-schedule-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "command-schedule-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('command-schedule-user','server','command-schedule-server','server.schedule')`); err != nil {
		t.Fatal(err)
	}
	denied := testRequest(h, http.MethodPost, "/api/servers/command-schedule-server/schedules", `{"action":"command","command":"say Maintenance starts soon","cron":"0 3 * * *"}`, token)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("command schedule was created without server.console: %d %s", denied.Code, denied.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule,server.console' WHERE user_id='command-schedule-user' AND scope_type='server' AND scope_id='command-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	plaintext := "say Maintenance starts soon"
	created := testRequest(h, http.MethodPost, "/api/servers/command-schedule-server/schedules", `{"action":"command","cron":"0 3 * * *","command":"`+plaintext+`"}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create command schedule: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Action != "command" || item.Name != "Scheduled command" || !item.Enabled || item.NextRun == "" || strings.Contains(created.Body.String(), plaintext) {
		t.Fatalf("command schedule response is invalid or exposed its command: %#v %s", item, created.Body.String())
	}
	var commandEnc string
	if err = d.QueryRow(`SELECT command_enc FROM backup_schedules WHERE id=?`, item.ID).Scan(&commandEnc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(commandEnc, "enc:") || strings.Contains(commandEnc, plaintext) {
		t.Fatalf("command was not encrypted at rest: %q", commandEnc)
	}
	decrypted, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), commandEnc)
	if err != nil || decrypted != plaintext {
		t.Fatalf("encrypted command did not round-trip: command=%q err=%v", decrypted, err)
	}
	invalid := testRequest(h, http.MethodPost, "/api/servers/command-schedule-server/schedules", `{"action":"command","cron":"0 4 * * *","command":"say one\nsay two"}`, token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("multi-line command was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestScheduledCommandDispatchesAndKeepsCommandOutOfRunHistory(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "command-run-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('command-run-server','Command run','minecraft-java','running',1,'command-run-container','{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	command := "say private maintenance note"
	commandEnc, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), command)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err = d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,command_enc,next_run) VALUES('command-run','command-run-server','Maintenance note','command','* * * * *',1,?,?)`, commandEnc, scheduleTimestamp(now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	var sent string
	a.scheduleCommand = func(_ context.Context, _ Server, value string) error { sent = value; return nil }
	if err = a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if sent != command {
		t.Fatalf("scheduled console command=%q, want %q", sent, command)
	}
	var status, detail string
	if err = d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='command-run'`).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	if status != "success" || detail != "console command sent" || strings.Contains(detail, command) {
		t.Fatalf("scheduled command history exposed command or has wrong result: status=%q detail=%q", status, detail)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('command-history-admin','command-history-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "command-history-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	listed := testRequest(h, http.MethodGet, "/api/servers/command-run-server/schedules", "", adminToken)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), command) || !strings.Contains(listed.Body.String(), `"action":"command"`) {
		t.Fatalf("command schedule response leaked its command or missed the action: %d %s", listed.Code, listed.Body.String())
	}
	runs := testRequest(h, http.MethodGet, "/api/servers/command-run-server/schedules/command-run/runs", "", adminToken)
	if runs.Code != http.StatusOK || strings.Contains(runs.Body.String(), command) {
		t.Fatalf("command run response leaked its command: %d %s", runs.Code, runs.Body.String())
	}
	a.scheduleCommand = func(_ context.Context, _ Server, value string) error { return errors.New("transport echoed " + value) }
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id='command-run'`, scheduleTimestamp(now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var failedDetail string
	if err = d.QueryRow(`SELECT detail FROM backup_schedule_runs WHERE schedule_id='command-run' AND status='error' ORDER BY started_at DESC LIMIT 1`).Scan(&failedDetail); err != nil {
		t.Fatal(err)
	}
	if failedDetail != "console command could not be sent" || strings.Contains(failedDetail, command) {
		t.Fatalf("failed command run exposed its command: %q", failedDetail)
	}
}

func TestScheduledMessageUsesEncryptedTemplateWithSchedulePermissionOnly(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "message-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('message-schedule-server','Visible MC','minecraft-java','running',1,'message-container','{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('message-schedule-user','message-schedule-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "message-schedule-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('message-schedule-user','server','message-schedule-server','server.schedule')`); err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	if _, err = d.Exec(`UPDATE servers SET gameskill_id='uptime-kuma' WHERE id='message-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	wrongTemplate := testRequest(h, http.MethodPost, "/api/servers/message-schedule-server/schedules", `{"action":"message","cron":"0 2 * * *","message_template_id":"builtin-maintenance-notice","values":{"minutes":5}}`, token)
	if wrongTemplate.Code != http.StatusBadRequest || !strings.Contains(wrongTemplate.Body.String(), "Minecraft Java and Bedrock") {
		t.Fatalf("player message schedule was offered for a non-Minecraft app: %d %s", wrongTemplate.Code, wrongTemplate.Body.String())
	}
	if _, err = d.Exec(`UPDATE servers SET gameskill_id='minecraft-java' WHERE id='message-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	missingValue := testRequest(h, http.MethodPost, "/api/servers/message-schedule-server/schedules", `{"action":"message","cron":"0 3 * * *","message_template_id":"builtin-maintenance-notice"}`, token)
	if missingValue.Code != http.StatusBadRequest || !strings.Contains(missingValue.Body.String(), "enter a value for {{minutes}}") {
		t.Fatalf("message schedule accepted a missing template value: %d %s", missingValue.Code, missingValue.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/servers/message-schedule-server/schedules", `{"action":"message","cron":"0 3 * * *","message_template_id":"builtin-maintenance-notice","values":{"minutes":5}}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create schedule with only server.schedule permission: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Action != "message" || item.Name != "Scheduled message" || strings.Contains(created.Body.String(), "maintenance starts") {
		t.Fatalf("message schedule response contains an unexpected value: %#v %s", item, created.Body.String())
	}
	var messagePayloadEnc, commandEnc string
	if err = d.QueryRow(`SELECT message_payload_enc,command_enc FROM backup_schedules WHERE id=?`, item.ID).Scan(&messagePayloadEnc, &commandEnc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(messagePayloadEnc, "enc:") || commandEnc != "" {
		t.Fatalf("message schedule payload is not encrypted in its dedicated field: payload=%q command=%q", messagePayloadEnc, commandEnc)
	}
	decrypted, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), messagePayloadEnc)
	if err != nil {
		t.Fatal(err)
	}
	var payload scheduledMessagePayload
	if err = json.Unmarshal([]byte(decrypted), &payload); err != nil || payload.Body != "say {{server_name}} maintenance starts in {{minutes}} minutes." || payload.Values["minutes"] != 5 {
		t.Fatalf("stored message template did not round-trip: payload=%#v err=%v", payload, err)
	}
	now := time.Now()
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(now.Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	var sent string
	a.scheduleCommand = func(_ context.Context, _ Server, value string) error { sent = value; return nil }
	if err = a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	want := "say Visible MC maintenance starts in 5 minutes."
	if sent != want {
		t.Fatalf("rendered scheduled message=%q, want %q", sent, want)
	}
	var status, detail string
	if err = d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id=?`, item.ID).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	if status != "success" || detail != "scheduled message sent" || strings.Contains(detail, want) {
		t.Fatalf("message run history leaked content or has wrong result: status=%q detail=%q", status, detail)
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/message-schedule-server/schedules", "", token)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), want) || !strings.Contains(listed.Body.String(), `"action":"message"`) {
		t.Fatalf("message schedule API response leaked rendered content: %d %s", listed.Code, listed.Body.String())
	}
	runs := testRequest(h, http.MethodGet, "/api/servers/message-schedule-server/schedules/"+item.ID+"/runs", "", token)
	if runs.Code != http.StatusOK || strings.Contains(runs.Body.String(), want) {
		t.Fatalf("message run API response leaked rendered content: %d %s", runs.Code, runs.Body.String())
	}
}

func TestLifecycleSchedulesRequireControlAndPersistAction(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "lifecycle-schedule-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('lifecycle-schedule-server','Lifecycle test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('lifecycle-schedule-user','lifecycle-schedule-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "lifecycle-schedule-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('lifecycle-schedule-user','server','lifecycle-schedule-server','server.schedule')`); err != nil {
		t.Fatal(err)
	}
	denied := testRequest(h, http.MethodPost, "/api/servers/lifecycle-schedule-server/schedules", `{"action":"start","cron":"0 3 * * *"}`, token)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("lifecycle schedule was created without server.control: %d %s", denied.Code, denied.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule,server.control' WHERE user_id='lifecycle-schedule-user' AND scope_type='server' AND scope_id='lifecycle-schedule-server'`); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop"} {
		created := testRequest(h, http.MethodPost, "/api/servers/lifecycle-schedule-server/schedules", `{"action":"`+action+`","cron":"0 3 * * *"}`, token)
		if created.Code != http.StatusCreated {
			t.Fatalf("create %s schedule: %d %s", action, created.Code, created.Body.String())
		}
		var item backupSchedule
		if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		if item.Action != action || item.Name != "Scheduled "+action || !item.Enabled || item.NextRun == "" {
			t.Fatalf("%s schedule was not persisted correctly: %#v", action, item)
		}
	}
}

func TestLifecycleScheduleRunsAndRecordsSkippedOutcomes(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "lifecycle-run-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('lifecycle-run-server','Lifecycle test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, action := range []string{"start", "stop"} {
		id := "lifecycle-" + action
		if _, err := d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,next_run) VALUES(?,?,?,?,'* * * * *',1,?)`, id, "lifecycle-run-server", "Test "+action, action, scheduleTimestamp(now.Add(-time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	var actions []string
	a.scheduleControl = func(_ context.Context, _ string, action string) (string, string, error) {
		actions = append(actions, action)
		if action == "stop" {
			return "skipped", "stop skipped because no container exists", nil
		}
		return "success", "start initiated", nil
	}
	if err := a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "start" || actions[1] != "stop" {
		t.Fatalf("scheduled lifecycle actions dispatched in wrong order: %v", actions)
	}
	for _, want := range []struct{ id, status, detail string }{
		{"lifecycle-start", "success", "start initiated"},
		{"lifecycle-stop", "skipped", "stop skipped because no container exists"},
	} {
		var status, detail string
		if err := d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id=?`, want.id).Scan(&status, &detail); err != nil {
			t.Fatal(err)
		}
		if status != want.status || detail != want.detail {
			t.Fatalf("schedule %s run status=%q detail=%q, want %q %q", want.id, status, detail, want.status, want.detail)
		}
		var lastError string
		if err := d.QueryRow(`SELECT last_error FROM backup_schedules WHERE id=?`, want.id).Scan(&lastError); err != nil {
			t.Fatal(err)
		}
		if want.status == "skipped" && lastError != "" {
			t.Fatalf("skipped schedule was stored as an error: %q", lastError)
		}
	}
}

func TestScheduledControlHandlesNoopAndUninstalledServers(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "control-noop-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('control-noop-server','Control test','minecraft-java','stopped',0,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	status, detail, err := a.executeScheduledControl(context.Background(), "control-noop-server", "stop")
	if err != nil || status != "skipped" || detail != "stop skipped because no container exists" {
		t.Fatalf("stop on a server with no container: status=%q detail=%q err=%v", status, detail, err)
	}
	status, _, err = a.executeScheduledControl(context.Background(), "control-noop-server", "start")
	if err == nil || status != "error" || !strings.Contains(err.Error(), "install this server") {
		t.Fatalf("start of an uninstalled server: status=%q err=%v", status, err)
	}
	if _, err = d.Exec(`UPDATE servers SET installed=1,status='running' WHERE id='control-noop-server'`); err != nil {
		t.Fatal(err)
	}
	status, detail, err = a.executeScheduledControl(context.Background(), "control-noop-server", "start")
	if err != nil || status != "skipped" || !strings.Contains(detail, "already running") {
		t.Fatalf("start on a running server: status=%q detail=%q err=%v", status, detail, err)
	}
}

func TestScheduledRestartCountdownSendsOnlySelectedWarningsInOrder(t *testing.T) {
	gs := gameskill.Rune{Restart: &gameskill.Restart{Warnings: []gameskill.RestartWarning{
		{At: "1m", Msg: "say {{server_name}} in {{seconds}} seconds"},
		{At: "15m", Msg: "say {{server_name}} in {{minutes}} minutes"},
		{At: "5m", Msg: "say {{server_name}} in {{minutes}} minutes"},
	}}}
	s := Server{Name: "Lobby"}
	var sent []string
	var waits []time.Duration
	restarted := false
	if err := runScheduledRestartCountdown(
		context.Background(), s, gs, 5*time.Minute,
		func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil },
		func(_ context.Context, _ Server, command string) error { sent = append(sent, command); return nil },
		func(context.Context) error { restarted = true; return nil },
	); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0] != "say Lobby in 5 minutes" || sent[1] != "say Lobby in 60 seconds" {
		t.Fatalf("warning commands=%q", sent)
	}
	if len(waits) != 2 || waits[0] != 4*time.Minute || waits[1] != time.Minute {
		t.Fatalf("countdown waits=%v", waits)
	}
	if !restarted {
		t.Fatal("restart was not called after the countdown")
	}
}

func TestScheduledRestartCountdownStopsWhenCanceled(t *testing.T) {
	gs := gameskill.Rune{Restart: &gameskill.Restart{Warnings: []gameskill.RestartWarning{{At: "1m", Msg: "say restarting"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restarted := false
	err := runScheduledRestartCountdown(
		ctx, Server{}, gs, time.Minute,
		func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() },
		func(context.Context, Server, string) error { return nil },
		func(context.Context) error { restarted = true; return nil },
	)
	if err == nil || err != context.Canceled || restarted {
		t.Fatalf("canceled countdown err=%v restarted=%t", err, restarted)
	}
}

func TestScheduledRestartCancelsIfServerChangesDuringCountdown(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "countdown-cancel-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('countdown-cancel-server','Lobby','minecraft-java','running',1,'old-container','{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	a.scheduleCommand = func(context.Context, Server, string) error { return nil }
	a.scheduleWait = func(context.Context, time.Duration) error {
		_, err := d.Exec(`UPDATE servers SET status='stopped' WHERE id='countdown-cancel-server'`)
		return err
	}
	_, err := a.executeScheduledRestart(context.Background(), "countdown-cancel-server", true, 60)
	if err == nil || !strings.Contains(err.Error(), "scheduled restart was canceled") {
		t.Fatalf("restart did not cancel after the server changed: %v", err)
	}
}

func TestRestartScheduleRunsInBackgroundAndPersistsResult(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "background-restart-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('background-restart-server','Background restart','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron,enabled,warn_players,warning_seconds,next_run) VALUES('background-restart','background-restart-server','Test restart','restart','* * * * *',1,1,60,?)`, scheduleTimestamp(now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	finish := make(chan struct{})
	a.scheduleRestart = func(ctx context.Context, _ string, _ bool, _ int) (string, error) {
		close(started)
		select {
		case <-finish:
			return "warned restart completed", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err := a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled restart did not start")
	}
	var status, detail string
	if err := d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='background-restart'`).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	if status != "running" || detail != "warned restart initiated" {
		t.Fatalf("background run was not marked initiated: status=%q detail=%q", status, detail)
	}
	close(finish)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='background-restart'`).Scan(&status, &detail); err != nil {
			t.Fatal(err)
		}
		if status == "success" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if status != "success" || !strings.Contains(detail, "warned restart completed") {
		t.Fatalf("background restart result was not persisted: status=%q detail=%q", status, detail)
	}
}
