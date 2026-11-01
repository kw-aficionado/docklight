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

	"example.com/yggdrasil-panel/internal/docker"
)

func TestManualAppUpdateIsAdminOnlyAndRestartsAfterScriptFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		exitCode  int
		wantError string
	}{
		{name: "success"},
		{name: "script failure still restarts", exitCode: 7, wantError: "app update script exited with status 7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, d, config := testApp(t)
			adminToken, userToken := assistantTestSessions(t, a, d)
			fake := newFakeStackDocker("app-update-server", "")
			fake.logsOutput = "App update output\n"
			fake.appUpdateExitCode = test.exitCode
			a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})

			raw, err := os.ReadFile(filepath.Join("..", "..", "builtin-runes", "uptime-kuma.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			template := strings.TrimSpace(string(raw)) + `
  update:
    image: busybox:1.36
    script: |
      echo update
    app_writable:
      - uploads`
			if _, err = d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='uptime-kuma'`, template); err != nil {
				t.Fatal(err)
			}
			dataDir := filepath.Join(filepath.Dir(config.Database.Path), "servers", "app-update-server")
			if err = os.MkdirAll(dataDir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id,host_mounts)
				VALUES('app-update-server','App update','uptime-kuma','running',1,'{}','{}',?,'old-container','[]')`, dataDir); err != nil {
				t.Fatal(err)
			}
			fake.containers["old-container"] = fakeStackContainer{name: "old-app", state: "running", config: docker.CreateConfig{Image: "old-image"}}
			fake.byName["old-app"] = "old-container"

			h := a.Router()
			serverList := testRequest(h, http.MethodGet, "/api/servers", "", adminToken)
			if serverList.Code != http.StatusOK || !strings.Contains(serverList.Body.String(), `"app_update_label":"Update app"`) {
				t.Fatalf("server list did not expose the update button label: %d %s", serverList.Code, serverList.Body.String())
			}
			denied := testRequest(h, http.MethodPost, "/api/servers/app-update-server/app-update", `{}`, userToken)
			if denied.Code != http.StatusForbidden {
				t.Fatalf("non-admin app update returned %d: %s", denied.Code, denied.Body.String())
			}
			started := testRequest(h, http.MethodPost, "/api/servers/app-update-server/app-update", `{}`, adminToken)
			if started.Code != http.StatusAccepted || !strings.Contains(started.Body.String(), `"status":"updating"`) {
				t.Fatalf("app update did not start: %d %s", started.Code, started.Body.String())
			}

			var result struct {
				Done  bool     `json:"done"`
				Error string   `json:"error"`
				Lines []string `json:"lines"`
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				status := testRequest(h, http.MethodGet, "/api/servers/app-update-server/install/status", "", adminToken)
				if status.Code != http.StatusOK {
					t.Fatalf("app update status returned %d: %s", status.Code, status.Body.String())
				}
				if err = json.Unmarshal(status.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Done {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !result.Done {
				t.Fatal("app update job did not finish")
			}
			if result.Error != test.wantError {
				t.Fatalf("job error = %q, want %q", result.Error, test.wantError)
			}
			if !strings.Contains(strings.Join(result.Lines, "\n"), "Starting a fresh app container") {
				t.Fatalf("update log did not record the restart: %v", result.Lines)
			}
			current, err := a.getServer("app-update-server")
			if err != nil {
				t.Fatal(err)
			}
			if current.ContainerID == "" || current.ContainerID == "old-container" || current.Status != "starting" && current.Status != "running" {
				t.Fatalf("app was not recreated after update: container=%q status=%q error=%q", current.ContainerID, current.Status, current.ErrorMessage)
			}
			var auditCount int
			if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE target_id='app-update-server' AND action IN ('server.app_update.start','server.app_update.finish')`).Scan(&auditCount); err != nil || auditCount != 2 {
				t.Fatalf("app update start and finish were not audited: count=%d err=%v", auditCount, err)
			}

			fake.mu.Lock()
			operations := append([]string(nil), fake.operations...)
			var updateConfig docker.CreateConfig
			foundOwnershipHelper := false
			for name, cfg := range fake.configs {
				if strings.HasPrefix(name, "docklight-update-") {
					updateConfig = cfg
				}
				if strings.HasPrefix(name, "docklight-owner-") && strings.Contains(strings.Join(cfg.Cmd, "\n"), "chmod -R g+w -- '/data/uploads'") {
					foundOwnershipHelper = true
				}
			}
			fake.mu.Unlock()
			joined := strings.Join(operations, "|")
			stopAt := strings.Index(joined, "container:stop:old-app")
			toolAt := strings.Index(joined, "container:create:docklight-update-")
			waitAt := strings.Index(joined, "container:wait:docklight-update-")
			mainAt := strings.LastIndex(joined, "container:create:")
			if stopAt < 0 || toolAt <= stopAt || waitAt <= toolAt || mainAt <= waitAt {
				t.Fatalf("expected stop, update script, then fresh app container: %v", operations)
			}
			if updateConfig.Image != "busybox:1.36" || strings.Join(updateConfig.Entrypoint, " ") != "/bin/sh -c" || strings.Join(updateConfig.Cmd, " ") != "echo update" || strings.Join(updateConfig.HostConfig.Binds, ",") != dataDir+":/data" {
				t.Fatalf("update container did not use the declared image, script, and data bind: %#v", updateConfig)
			}
			if !foundOwnershipHelper {
				t.Fatal("app_writable group permission was not applied by the ownership helper")
			}
		})
	}
}

func TestAppUpdateRejectsTemplateWithoutUpdateBlock(t *testing.T) {
	a, d, config := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	dataDir := filepath.Join(filepath.Dir(config.Database.Path), "servers", "no-update-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,host_mounts) VALUES('no-update-server','No update','uptime-kuma','stopped',1,'{}','{}',?,'[]')`, dataDir); err != nil {
		t.Fatal(err)
	}
	if denied := testRequest(a.Router(), http.MethodPost, "/api/servers/no-update-server/app-update", `{}`, userToken); denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin was not rejected: %d %s", denied.Code, denied.Body.String())
	}
	if _, err := d.Exec(`UPDATE servers SET status='installing' WHERE id='no-update-server'`); err != nil {
		t.Fatal(err)
	}
	busy := testRequest(a.Router(), http.MethodPost, "/api/servers/no-update-server/app-update", `{}`, adminToken)
	if busy.Code != http.StatusConflict || !strings.Contains(busy.Body.String(), "current server operation") {
		t.Fatalf("app update was not serialized against an install: %d %s", busy.Code, busy.Body.String())
	}
	if _, err := d.Exec(`UPDATE servers SET status='stopped' WHERE id='no-update-server'`); err != nil {
		t.Fatal(err)
	}
	result := testRequest(a.Router(), http.MethodPost, "/api/servers/no-update-server/app-update", `{}`, adminToken)
	if result.Code != http.StatusConflict || !strings.Contains(result.Body.String(), "does not define an app update") {
		t.Fatalf("template without update block returned %d: %s", result.Code, result.Body.String())
	}
}

func TestAppUpdateToolJoinsPrivateStackNetwork(t *testing.T) {
	a, d, config := testApp(t)
	adminToken, _ := assistantTestSessions(t, a, d)
	fake := newFakeStackDocker("stack-server", "")
	fake.logsOutput = "Upgrade finished\n"
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	var raw string
	if err := d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='wordpress-mariadb'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	raw = strings.TrimRight(raw, "\n") + `
  update:
    image: busybox:1.36
    script: echo upgrade`
	if _, err := d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='wordpress-mariadb'`, raw); err != nil {
		t.Fatal(err)
	}
	started := testRequest(a.Router(), http.MethodPost, "/api/servers/stack-server/app-update", `{}`, adminToken)
	if started.Code != http.StatusAccepted {
		t.Fatalf("stack app update did not start: %d %s", started.Code, started.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	done := false
	for time.Now().Before(deadline) {
		status := testRequest(a.Router(), http.MethodGet, "/api/servers/stack-server/install/status", "", adminToken)
		if strings.Contains(status.Body.String(), `"done":true`) {
			done = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !done {
		t.Fatal("stack app update job did not finish")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var updateConfig docker.CreateConfig
	for name, cfg := range fake.configs {
		if strings.HasPrefix(name, "docklight-update-") {
			updateConfig = cfg
		}
	}
	if updateConfig.NetworkingConfig == nil {
		t.Fatalf("update container was not attached to a private stack network: %#v", updateConfig.NetworkingConfig)
	}
	if _, ok := updateConfig.NetworkingConfig.EndpointsConfig[stackNetworkName(s.ID)]; !ok {
		t.Fatalf("update container was not attached to the server network: %#v", updateConfig.NetworkingConfig.EndpointsConfig)
	}
	for _, container := range fake.containers {
		if container.config.Labels[docklightServiceLabel] == "database" && container.state != "running" {
			t.Fatalf("database sidecar was not kept running through the app update: %#v", container)
		}
	}
	if updateConfig.Image == "" {
		t.Fatal("stack update tool container was not created")
	}
	if _, err := a.getServer(s.ID); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledAppUpdateSkipsStoppedServer(t *testing.T) {
	a, d, config := testApp(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "builtin-runes", "uptime-kuma.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	template := strings.TrimSpace(string(raw)) + `
  update:
    script: echo upgrade`
	if _, err = d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='uptime-kuma'`, template); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(filepath.Dir(config.Database.Path), "servers", "stopped-app-update")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,host_mounts)
		VALUES('stopped-app-update','Stopped app','uptime-kuma','stopped',1,'{}','{}',?,'[]')`, dataDir); err != nil {
		t.Fatal(err)
	}
	due := scheduleTimestamp(time.Now().Add(-time.Second))
	if _, err = d.Exec(`INSERT INTO backup_schedules(id,server_id,scope_type,scope_id,name,action,cron,enabled,skip_if_players_online,next_run)
		VALUES('stopped-app-update-schedule','stopped-app-update','server','stopped-app-update','Update app','update','* * * * *',1,0,?)`, due); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var status, detail string
	if err = d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='stopped-app-update-schedule'`).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	if status != "skipped" || !strings.Contains(detail, "server is stopped") {
		t.Fatalf("stopped app schedule should be skipped: status=%q detail=%q", status, detail)
	}
	server, err := a.getServer("stopped-app-update")
	if err != nil || server.Status != "stopped" {
		t.Fatalf("skipped app update changed server state: status=%q err=%v", server.Status, err)
	}
}

func TestScheduledAppUpdateRunsUpdateBlockForRunningServer(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("scheduled-app-update", "")
	fake.logsOutput = "Scheduled upgrade output\n"
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	raw, err := os.ReadFile(filepath.Join("..", "..", "builtin-runes", "uptime-kuma.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	template := strings.TrimSpace(string(raw)) + `
  update:
    image: busybox:1.36
    script: echo upgrade`
	if _, err = d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='uptime-kuma'`, template); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(filepath.Dir(config.Database.Path), "servers", "scheduled-app-update")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id,host_mounts)
		VALUES('scheduled-app-update','Scheduled app','uptime-kuma','running',1,'{}','{}',?,'scheduled-old','[]')`, dataDir); err != nil {
		t.Fatal(err)
	}
	fake.containers["scheduled-old"] = fakeStackContainer{name: "scheduled-old", state: "running", config: docker.CreateConfig{Image: "old-image"}}
	fake.byName["scheduled-old"] = "scheduled-old"
	due := scheduleTimestamp(time.Now().Add(-time.Second))
	if _, err = d.Exec(`INSERT INTO backup_schedules(id,server_id,scope_type,scope_id,name,action,cron,enabled,skip_if_players_online,next_run)
		VALUES('scheduled-app-update-run','scheduled-app-update','server','scheduled-app-update','Update app','update','* * * * *',1,0,?)`, due); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var status, detail string
	if err = d.QueryRow(`SELECT status,detail FROM backup_schedule_runs WHERE schedule_id='scheduled-app-update-run'`).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	if status != "success" || !strings.Contains(detail, "app update completed") {
		t.Fatalf("scheduled app update did not run its block: status=%q detail=%q", status, detail)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	foundTool := false
	for name, cfg := range fake.configs {
		if strings.HasPrefix(name, "docklight-update-") && cfg.Image == "busybox:1.36" {
			foundTool = true
		}
	}
	if !foundTool {
		t.Fatal("scheduled update did not start the declared app update tool")
	}
}
