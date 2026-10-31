package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRealmScheduleUsesMembershipAtExecutionAndIsAdminOnly(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO realms(id,name) VALUES('operations','Operations')`); err != nil {
		t.Fatal(err)
	}
	for _, server := range []struct{ id, realm string }{{"realm-server-a", "operations"}, {"unassigned-server", ""}} {
		dataDir := filepath.Join(a.dataRoot, server.id)
		if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,realm_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?,'minecraft-java',?,'stopped',1,'{}','{}',?)`, server.id, server.id, server.realm, dataDir); err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []struct{ id, role string }{{"scope-admin", "admin"}, {"scope-user", "user"}} {
		if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)`, user.id, user.id, "unused-hash", user.role); err != nil {
			t.Fatal(err)
		}
	}
	adminToken, err := a.issue(User{ID: "scope-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "scope-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	if response := testRequest(h, http.MethodGet, "/api/schedules", "", userToken); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin viewed scoped schedules: %d %s", response.Code, response.Body.String())
	}
	if response := testRequest(h, http.MethodPost, "/api/schedules", `{"scope_type":"global","action":"start","cron":"* * * * *"}`, userToken); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin created a scoped schedule: %d %s", response.Code, response.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/schedules", `{"scope_type":"realm","scope_id":"operations","action":"start","cron":"* * * * *"}`, adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create realm schedule: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.ScopeType != "realm" || item.ScopeID != "operations" || item.ServerID != "" || item.Action != "start" {
		t.Fatalf("unexpected realm schedule metadata: %#v", item)
	}
	// Membership is intentionally changed after creation. The next firing must
	// use the current realm membership instead of a saved target list.
	lateData := filepath.Join(a.dataRoot, "realm-server-added-later")
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,realm_id,status,installed,env_json,ports_json,data_dir) VALUES('realm-server-added-later','Later','minecraft-java','operations','stopped',1,'{}','{}',?)`, lateData); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(time.Now().Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	var dispatched []string
	a.scheduleControl = func(_ context.Context, serverID, action string) (string, string, error) {
		if action != "start" {
			t.Fatalf("unexpected scoped action %q", action)
		}
		dispatched = append(dispatched, serverID)
		return "success", "start initiated", nil
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dispatched, []string{"realm-server-a", "realm-server-added-later"}) {
		t.Fatalf("scope did not use current realm membership in stable order: %v", dispatched)
	}
	var runs int
	if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=? AND server_id IN ('realm-server-a','realm-server-added-later') AND status='success'`, item.ID).Scan(&runs); err != nil || runs != 2 {
		t.Fatalf("realm firing should log one successful row per current target: rows=%d err=%v", runs, err)
	}
	listed := testRequest(h, http.MethodGet, "/api/schedules", "", adminToken)
	if listed.Code != http.StatusOK || len(decodeScheduleList(t, listed.Body.Bytes())) != 1 {
		t.Fatalf("admin scoped schedule listing: %d %s", listed.Code, listed.Body.String())
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET last_status='running' WHERE id=?`, item.ID); err != nil {
		t.Fatal(err)
	}
	if response := testRequest(h, http.MethodPut, "/api/schedules/"+item.ID, `{"enabled":false}`, adminToken); response.Code != http.StatusConflict {
		t.Fatalf("edited a running scoped schedule: %d %s", response.Code, response.Body.String())
	}
	if response := testRequest(h, http.MethodDelete, "/api/schedules/"+item.ID, `{}`, adminToken); response.Code != http.StatusConflict {
		t.Fatalf("deleted a running scoped schedule: %d %s", response.Code, response.Body.String())
	}
	if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=?`, item.ID).Scan(&runs); err != nil || runs != 2 {
		t.Fatalf("failed delete removed live scoped run history: rows=%d err=%v", runs, err)
	}
}

func TestGlobalScheduleRunNowRunsOnceAndEmptyRealmWritesHistory(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO realms(id,name) VALUES('empty-realm','Empty')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('global-schedule-server','Global target','minecraft-java','stopped',1,'{}','{}',?)`, filepath.Join(a.dataRoot, "global-schedule-server")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('scope-run-admin','scope-run-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "scope-run-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	created := testRequest(h, http.MethodPost, "/api/schedules", `{"scope_type":"global","action":"stop","cron":"0 3 * * *","enabled":false}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create disabled global schedule: %d %s", created.Code, created.Body.String())
	}
	var global backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &global); err != nil {
		t.Fatal(err)
	}
	queued := testRequest(h, http.MethodPost, "/api/schedules/"+global.ID+"/run-now", `{}`, token)
	if queued.Code != http.StatusAccepted {
		t.Fatalf("admin run-now: %d %s", queued.Code, queued.Body.String())
	}
	queuedAgain := testRequest(h, http.MethodPost, "/api/schedules/"+global.ID+"/run-now", `{}`, token)
	if queuedAgain.Code != http.StatusConflict {
		t.Fatalf("running schedule accepted duplicate run-now: %d %s", queuedAgain.Code, queuedAgain.Body.String())
	}
	var dispatched int
	a.scheduleControl = func(_ context.Context, serverID, action string) (string, string, error) {
		dispatched++
		if serverID != "global-schedule-server" || action != "stop" {
			t.Fatalf("unexpected global target/action: %s %s", serverID, action)
		}
		return "skipped", "stop skipped because no container exists", nil
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if dispatched != 1 {
		t.Fatalf("global run-now dispatched %d targets, want one", dispatched)
	}
	var serverID, status, detail string
	if err = d.QueryRow(`SELECT server_id,status,detail FROM backup_schedule_runs WHERE schedule_id=?`, global.ID).Scan(&serverID, &status, &detail); err != nil {
		t.Fatal(err)
	}
	if serverID != "global-schedule-server" || status != "skipped" || detail != "stop skipped because no container exists" {
		t.Fatalf("global run history mismatch: server=%q status=%q detail=%q", serverID, status, detail)
	}
	empty := testRequest(h, http.MethodPost, "/api/schedules", `{"scope_type":"realm","scope_id":"empty-realm","action":"start","cron":"* * * * *"}`, token)
	if empty.Code != http.StatusCreated {
		t.Fatalf("create empty realm schedule: %d %s", empty.Code, empty.Body.String())
	}
	var emptySchedule backupSchedule
	if err = json.Unmarshal(empty.Body.Bytes(), &emptySchedule); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(time.Now().Add(-time.Second)), emptySchedule.ID); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT server_id,status,detail FROM backup_schedule_runs WHERE schedule_id=?`, emptySchedule.ID).Scan(&serverID, &status, &detail); err != nil {
		t.Fatal(err)
	}
	if serverID != "" || status != "skipped" || detail != "no servers in scope" {
		t.Fatalf("empty scope must have a visible run row: server=%q status=%q detail=%q", serverID, status, detail)
	}
	if response := testRequest(h, http.MethodPost, "/api/schedules", `{"scope_type":"realm","scope_id":"empty-realm","action":"message","message_template_id":"builtin-maintenance","values":{"minutes":5},"cron":"* * * * *"}`, token); response.Code != http.StatusBadRequest {
		t.Fatalf("created a message schedule for a scope with no compatible servers: %d %s", response.Code, response.Body.String())
	}
}

func TestScopedUpdateStopsAfterThreeConsecutiveFailuresAndOnlineSkipDoesNotCount(t *testing.T) {
	a, d, _ := testApp(t)
	for _, id := range []string{"fleet-1", "fleet-2", "fleet-3", "fleet-4", "fleet-5"} {
		if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?,'minecraft-java','stopped',1,'{}','{}',?)`, id, id, filepath.Join(a.dataRoot, id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('fleet-admin','fleet-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "fleet-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	created := testRequest(a.Router(), http.MethodPost, "/api/schedules", `{"scope_type":"global","action":"update","skip_if_players_online":true,"cron":"* * * * *"}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create global update: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(time.Now().Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	a.schedulePlayers = func(_ context.Context, serverID string) (int, error) {
		if serverID == "fleet-2" {
			return 1, nil
		}
		return 0, nil
	}
	var updated []string
	a.scheduleUpdate = func(_ context.Context, serverID string) (string, error) {
		updated = append(updated, serverID)
		return "", errors.New("update failed")
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updated, []string{"fleet-1", "fleet-3", "fleet-4"}) {
		t.Fatalf("fleet update did not stop after three consecutive failures: %v", updated)
	}
	want := map[string][2]string{
		"fleet-1": {"error", "update failed"},
		"fleet-2": {"skipped", "skipped because players are online (1 online)"},
		"fleet-3": {"error", "update failed"},
		"fleet-4": {"error", "update failed"},
		"fleet-5": {"skipped", "skipped after three consecutive update failures"},
	}
	for serverID, expected := range want {
		var status, detail string
		if err = d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id=? AND server_id=?`, item.ID, serverID).Scan(&status, &detail); err != nil {
			t.Fatalf("read scoped update result for %s: %v", serverID, err)
		}
		if status != expected[0] || detail != expected[1] {
			t.Errorf("scoped update result for %s = (%q,%q), want (%q,%q)", serverID, status, detail, expected[0], expected[1])
		}
	}
}

func TestScopedUpdateWaitsForEachTargetToReturnToRunning(t *testing.T) {
	a, d, _ := testApp(t)
	for _, id := range []string{"ready-1", "ready-2"} {
		if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?,'minecraft-java','stopped',1,'{}','{}',?)`, id, id, filepath.Join(a.dataRoot, id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('ready-admin','ready-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "ready-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	created := testRequest(a.Router(), http.MethodPost, "/api/schedules", `{"scope_type":"global","action":"update","cron":"* * * * *"}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create global update: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(time.Now().Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	var events []string
	a.scheduleUpdate = func(_ context.Context, serverID string) (string, error) {
		events = append(events, "update:"+serverID)
		return "image pulled", nil
	}
	a.scheduleReady = func(_ context.Context, serverID string, timeout time.Duration) error {
		if timeout != 90*time.Second {
			t.Errorf("readiness timeout=%s, want 90s", timeout)
		}
		events = append(events, "ready:"+serverID)
		return nil
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"update:ready-1", "ready:ready-1", "update:ready-2", "ready:ready-2"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("scoped updates did not wait for readiness sequentially: got %v want %v", events, want)
	}
	var succeeded int
	if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=? AND status='success' AND detail='image pulled; server returned to ready state'`, item.ID).Scan(&succeeded); err != nil || succeeded != 2 {
		t.Fatalf("scoped readiness outcomes=%d err=%v, want two successful results", succeeded, err)
	}
}

func TestScopedWarnedRestartRunsInBackgroundAndSkipsOverlappingOccurrence(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('restart-scope-server','Restart target','minecraft-java','running',1,'running-container','{}','{}',?)`, filepath.Join(a.dataRoot, "restart-scope-server")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('restart-scope-admin','restart-scope-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "restart-scope-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	created := testRequest(a.Router(), http.MethodPost, "/api/schedules", `{"scope_type":"global","action":"restart","warn_players":true,"warning_seconds":60,"cron":"* * * * *"}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create warned scoped restart: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(time.Now().Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	a.scheduleRestart = func(ctx context.Context, serverID string, warn bool, seconds int) (string, error) {
		if serverID != "restart-scope-server" || !warn || seconds != 60 {
			return "", errors.New("unexpected scoped restart arguments")
		}
		close(started)
		select {
		case <-release:
			return "restart completed", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	now := time.Now()
	if err = a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("warned restart did not enter its background countdown")
	}
	if err = a.processDueBackupSchedules(context.Background(), now.Add(48*time.Hour)); err != nil {
		t.Fatalf("a background countdown blocked the scheduler: %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var running int
		if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=? AND status='running'`, item.ID).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	var completed, skipped int
	if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=? AND status='success'`, item.ID).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM backup_schedule_runs WHERE schedule_id=? AND status='skipped' AND detail LIKE 'previous schedule run is still active%'`, item.ID).Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if completed != 1 || skipped != 1 {
		t.Fatalf("overlapping scoped firing history = success %d skipped %d, want one each", completed, skipped)
	}
}

func decodeScheduleList(t *testing.T, raw []byte) []backupSchedule {
	t.Helper()
	var schedules []backupSchedule
	if err := json.Unmarshal(raw, &schedules); err != nil {
		t.Fatal(err)
	}
	return schedules
}
