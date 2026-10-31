package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gameskill "example.com/yggdrasil-panel/internal/rune"
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
	if options.Code != http.StatusOK || !strings.Contains(options.Body.String(), `"at":"1m"`) {
		t.Fatalf("authorized user did not receive template restart warnings: %d %s", options.Code, options.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","name":"Daily restart","cron":"0 3 * * *","warning_seconds":60}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create restart schedule: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Action != "restart" || !item.WarnPlayers || item.WarningSeconds != 60 || !item.Enabled || item.NextRun == "" {
		t.Fatalf("restart schedule was not persisted correctly: %#v", item)
	}
	invalid := testRequest(h, http.MethodPost, "/api/servers/restart-schedule-server/schedules", `{"action":"restart","cron":"0 4 * * *","warning_seconds":600}`, token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("countdown absent from template warnings was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/restart-schedule-server/schedules", "", token)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"action":"restart"`) || !strings.Contains(listed.Body.String(), `"warning_seconds":60`) {
		t.Fatalf("restart schedule settings missing from list response: %d %s", listed.Code, listed.Body.String())
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
