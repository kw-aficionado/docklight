package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/security"
)

func insertRuntimeServer(t *testing.T, a *App, id string) string {
	t.Helper()
	dataDir := filepath.Join(a.dataRoot, id)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "keep.dat"), []byte("server data stays on disk"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES(?,?,'minecraft-java','running',1,'{}','{}',?,?)`, id, "Runtime test", dataDir, "container-"+id); err != nil {
		t.Fatal(err)
	}
	return dataDir
}

func TestRuntimeMonitorRecordsConfirmedExitAndScopesHistory(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "runtime-exit")
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('runtime-viewer','runtime-viewer','unused-hash','user'),('runtime-denied','runtime-denied','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('runtime-viewer','server','runtime-exit','server.view')`); err != nil {
		t.Fatal(err)
	}
	viewerToken, err := a.issue(User{ID: "runtime-viewer", Username: "runtime-viewer", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	deniedToken, err := a.issue(User{ID: "runtime-denied", Username: "runtime-denied", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	var inspections int
	a.runtimeInspect = func(_ context.Context, id string) (docker.Inspect, error) {
		inspections++
		if id != "container-runtime-exit" {
			t.Fatalf("inspected container %q unexpectedly", id)
		}
		var state docker.Inspect
		state.State.Status = "exited"
		state.State.ExitCode = 137
		return state, nil
	}
	now := time.Now()
	if err = a.monitorServerRuntime(context.Background(), "runtime-exit", now); err != nil {
		t.Fatal(err)
	}
	if err = a.monitorServerRuntime(context.Background(), "runtime-exit", now.Add(runtimeMissingConfirmInterval-time.Second)); err != nil {
		t.Fatal(err)
	}
	var status, message string
	if err = d.QueryRow(`SELECT status,error_message FROM servers WHERE id='runtime-exit'`).Scan(&status, &message); err != nil || status != "running" {
		t.Fatalf("one unconfirmed stopped observation changed status: status=%q message=%q err=%v", status, message, err)
	}
	if err = a.monitorServerRuntime(context.Background(), "runtime-exit", now.Add(runtimeMissingConfirmInterval)); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT status,error_message FROM servers WHERE id='runtime-exit'`).Scan(&status, &message); err != nil || status != "error" || !strings.Contains(message, "code 137") {
		t.Fatalf("confirmed container exit state=%q message=%q err=%v", status, message, err)
	}
	var crashCount int
	if err = d.QueryRow(`SELECT count(*) FROM server_crashes WHERE server_id='runtime-exit'`).Scan(&crashCount); err != nil || crashCount != 1 {
		t.Fatalf("crash history rows=%d err=%v, want exactly one", crashCount, err)
	}
	if inspections != 3 {
		t.Fatalf("container inspections=%d, want 3", inspections)
	}
	if err = a.monitorServerRuntime(context.Background(), "runtime-exit", now.Add(2*runtimeMissingConfirmInterval)); err != nil {
		t.Fatal(err)
	}
	if inspections != 3 {
		t.Fatalf("monitor re-inspected errored server; inspections=%d", inspections)
	}
	h := a.Router()
	listed := testRequest(h, http.MethodGet, "/api/servers/runtime-exit/crashes", "", viewerToken)
	var crashes []serverCrash
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &crashes) != nil || len(crashes) != 1 || crashes[0].Reason != "container_exited" || crashes[0].ExitCode != 137 {
		t.Fatalf("server crash history response=%d %s", listed.Code, listed.Body.String())
	}
	denied := testRequest(h, http.MethodGet, "/api/servers/runtime-exit/crashes", "", deniedToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("server without server.view read crash history: %d %s", denied.Code, denied.Body.String())
	}
}

func TestRuntimeMonitorDebouncesMissingContainerAndKeepsServerData(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := insertRuntimeServer(t, a, "runtime-missing")
	a.runtimeInspect = func(context.Context, string) (docker.Inspect, error) {
		return docker.Inspect{}, errors.New("Docker Engine: Docker no longer has this server container")
	}
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(runtimeMissingConfirmInterval - time.Second)} {
		if err := a.monitorServerRuntime(context.Background(), "runtime-missing", at); err != nil {
			t.Fatal(err)
		}
		var status string
		if err := d.QueryRow(`SELECT status FROM servers WHERE id='runtime-missing'`).Scan(&status); err != nil || status != "running" {
			t.Fatalf("single missing-container observation changed status to %q: %v", status, err)
		}
	}
	if err := a.monitorServerRuntime(context.Background(), "runtime-missing", now.Add(runtimeMissingConfirmInterval)); err != nil {
		t.Fatal(err)
	}
	var reason string
	var exitCode int
	if err := d.QueryRow(`SELECT reason,exit_code FROM server_crashes WHERE server_id='runtime-missing'`).Scan(&reason, &exitCode); err != nil || reason != "container_missing" || exitCode != -1 {
		t.Fatalf("missing-container history reason=%q code=%d err=%v", reason, exitCode, err)
	}
	if content, err := os.ReadFile(filepath.Join(dataDir, "keep.dat")); err != nil || string(content) != "server data stays on disk" {
		t.Fatalf("runtime monitor removed or changed server data: %q err=%v", content, err)
	}
}

func TestConfirmedCrashSendsOptInWebhook(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "crash-webhook")
	endpoint, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "http://127.0.0.1:18765/crash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO notification_settings(id,enabled,endpoint_enc,events_json) VALUES(1,1,?,'["server.crash"]')`, endpoint); err != nil {
		t.Fatal(err)
	}
	requests := make(chan webhookPayload, 1)
	a.notificationClient = &http.Client{Transport: notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read webhook body: %v", readErr)
		}
		var payload webhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		requests <- payload
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	s, err := a.getServer("crash-webhook")
	if err != nil {
		t.Fatal(err)
	}
	message := "Container exited unexpectedly with code 137; review its logs before restarting."
	if err = a.recordServerCrash(s, "container_exited", 137, message); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-requests:
		if payload.Event != notificationServerCrash || payload.Server == nil || payload.Server.ID != s.ID || payload.Server.Name != s.Name || payload.Message != message {
			t.Fatalf("unexpected crash webhook: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("confirmed crash webhook was not delivered")
	}
}

func TestRuntimeMonitorLeavesUnknownDockerStateUnchangedAndWaitsAtBoot(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "runtime-unknown")
	var inspections, pings int
	a.runtimeInspect = func(context.Context, string) (docker.Inspect, error) {
		inspections++
		return docker.Inspect{}, errors.New("Docker socket is temporarily unavailable")
	}
	if err := a.monitorServerRuntime(context.Background(), "runtime-unknown", time.Now()); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := d.QueryRow(`SELECT status FROM servers WHERE id='runtime-unknown'`).Scan(&status); err != nil || status != "running" {
		t.Fatalf("unknown Docker state changed server status to %q: %v", status, err)
	}
	a.runtimePing = func(context.Context) error { pings++; return nil }
	booted := time.Now()
	a.booted = booted
	if err := a.scanRunningServers(context.Background(), booted.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if pings != 0 || inspections != 1 {
		t.Fatalf("boot grace performed pings=%d inspections=%d; want 0 new calls", pings, inspections)
	}
	a.booted = booted.Add(-2 * runtimeStartupGrace)
	a.runtimePing = func(context.Context) error { pings++; return errors.New("Docker Engine is still starting") }
	if err := a.scanRunningServers(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if pings != 1 || inspections != 1 {
		t.Fatalf("unreachable Docker performed pings=%d inspections=%d; want one ping only", pings, inspections)
	}
}

func TestStartupExitIsRecordedAndServerDeletionRemovesCrashHistory(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := insertRuntimeServer(t, a, "startup-crash")
	if _, err := d.Exec(`UPDATE servers SET status='starting' WHERE id='startup-crash'`); err != nil {
		t.Fatal(err)
	}
	s, err := a.getServer("startup-crash")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.recordServerCrash(s, "container_exited", 1, "Container exited before readiness."); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = d.QueryRow(`SELECT status FROM servers WHERE id='startup-crash'`).Scan(&status); err != nil || status != "error" {
		t.Fatalf("startup exit state=%q err=%v", status, err)
	}
	if _, err = d.Exec(`UPDATE servers SET status='stopped',container_id='' WHERE id='startup-crash'`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('runtime-admin','runtime-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "runtime-admin", Username: "runtime-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	deleted := testRequest(a.Router(), http.MethodDelete, "/api/servers/startup-crash", "", adminToken)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete server with crash history: %d %s", deleted.Code, deleted.Body.String())
	}
	var crashes, servers int
	if err = d.QueryRow(`SELECT count(*) FROM server_crashes WHERE server_id='startup-crash'`).Scan(&crashes); err != nil || crashes != 0 {
		t.Fatalf("deleted server crash rows=%d err=%v, want 0", crashes, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM servers WHERE id='startup-crash'`).Scan(&servers); err != nil || servers != 0 {
		t.Fatalf("deleted server rows=%d err=%v, want 0", servers, err)
	}
	if _, err = os.Stat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("server data directory still exists after deletion: %v", err)
	}
}
