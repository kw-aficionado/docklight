package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicStatusPageRequiresDoubleOptInAndOmitsPrivateFields(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('status-admin','status-admin','unused','admin'),('status-user','status-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "status-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "status-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	for _, path := range []string{"/status", "/status.js", "/api/status"} {
		response := testRequest(h, http.MethodGet, path, "", "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled public route %s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
	denied := testRequest(h, http.MethodGet, "/api/settings/status-page", "", userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin read public status settings: %d %s", denied.Code, denied.Body.String())
	}
	adminSettings := testRequest(h, http.MethodGet, "/api/settings/status-page", "", adminToken)
	if adminSettings.Code != http.StatusOK || !strings.Contains(adminSettings.Body.String(), `"enabled":false`) || !strings.Contains(adminSettings.Body.String(), `"title":"Server Status"`) {
		t.Fatalf("default status page settings: %d %s", adminSettings.Code, adminSettings.Body.String())
	}

	dataRoot := t.TempDir()
	for _, server := range []struct {
		id, name, status string
		installed        int
	}{
		{"status-live-id-private", "Public Minecraft", "running", 1},
		{"status-starting-id-private", "Starting app", "starting", 1},
		{"status-uninstalled-id-private", "Uninstalled service", "running", 0},
		{"status-hidden-id-private", "Private service", "running", 1},
	} {
		dir := filepath.Join(dataRoot, server.id)
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?, 'minecraft-java', ?, ?, ?, ?, ?)`, server.id, server.name, server.status, server.installed, `{"RCON_PASSWORD":"do-not-publish-this"}`, `{"game":25565}`, dir); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	if _, err = d.Exec(`INSERT INTO server_query_samples(server_id,online,max_players,sampled_at) VALUES(?,?,?,?),(?,?,?,?)`, "status-live-id-private", 4, 20, now-60, "status-starting-id-private", 8, 50, now-int64(publicStatusPlayerFreshness.Seconds())-60); err != nil {
		t.Fatal(err)
	}
	configure := `{"enabled":true,"title":"Docklight uptime","server_ids":["status-live-id-private","status-starting-id-private","status-uninstalled-id-private"]}`
	updated := testRequest(h, http.MethodPut, "/api/settings/status-page", configure, adminToken)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"enabled":true`) || !strings.Contains(updated.Body.String(), `"status_public":true`) {
		t.Fatalf("enable public status page: %d %s", updated.Code, updated.Body.String())
	}

	response := testRequest(h, http.MethodGet, "/api/status", "", "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "public, max-age=15" || response.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Fatalf("public status response headers/status: %d cache=%q robots=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Header().Get("X-Robots-Tag"), response.Body.String())
	}
	var payload struct {
		Title     string `json:"title"`
		UpdatedAt string `json:"updated_at"`
		Servers   []struct {
			Name    string `json:"name"`
			Game    string `json:"game"`
			Status  string `json:"status"`
			Players *struct {
				Online int `json:"online"`
				Max    int `json:"max"`
			} `json:"players"`
		} `json:"servers"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Title != "Docklight uptime" || len(payload.Servers) != 3 || payload.Servers[0].Name != "Public Minecraft" || payload.Servers[0].Game != "Minecraft Java" || payload.Servers[0].Status != "online" || payload.Servers[0].Players == nil || payload.Servers[0].Players.Online != 4 || payload.Servers[0].Players.Max != 20 {
		t.Fatalf("unexpected public server payload: %#v", payload)
	}
	if payload.Servers[1].Name != "Starting app" || payload.Servers[1].Status != "starting" || payload.Servers[1].Players != nil {
		t.Fatalf("starting service exposed a stale player sample: %#v", payload.Servers[1])
	}
	if payload.Servers[2].Name != "Uninstalled service" || payload.Servers[2].Status != "offline" {
		t.Fatalf("uninstalled server status=%#v", payload.Servers[2])
	}
	if payload.UpdatedAt == "" {
		t.Fatal("public status payload omitted its update time")
	}
	for _, private := range []string{"status-live-id-private", "status-starting-id-private", "status-uninstalled-id-private", "status-hidden-id-private", "25565", "RCON_PASSWORD", "do-not-publish-this", "gameskill_id", "ports"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("public status leaked private value %q: %s", private, response.Body.String())
		}
	}

	page := testRequest(h, http.MethodGet, "/status", "", "")
	if page.Code != http.StatusOK || page.Header().Get("X-Robots-Tag") != "noindex, nofollow" || !strings.Contains(page.Body.String(), `name="robots" content="noindex,nofollow"`) || !strings.Contains(page.Body.String(), "Docklight") {
		t.Fatalf("public HTML page status/robots/brand: %d %q %s", page.Code, page.Header().Get("X-Robots-Tag"), page.Body.String())
	}
	script := testRequest(h, http.MethodGet, "/status.js", "", "")
	if script.Code != http.StatusOK || script.Header().Get("X-Robots-Tag") != "noindex, nofollow" || !strings.Contains(script.Body.String(), "setInterval(refresh, 30000)") {
		t.Fatalf("public status script response: %d %s", script.Code, script.Body.String())
	}

	if err = a.recordPlayerSample("status-live-id-private", 2, 24); err != nil {
		t.Fatal(err)
	}
	refreshed := testRequest(h, http.MethodGet, "/api/status", "", "")
	if refreshed.Code != http.StatusOK || !strings.Contains(refreshed.Body.String(), `"online":2`) || !strings.Contains(refreshed.Body.String(), `"max":24`) {
		t.Fatalf("fresh player sample did not bust public cache: %d %s", refreshed.Code, refreshed.Body.String())
	}

	invalid := testRequest(h, http.MethodPut, "/api/settings/status-page", `{"enabled":true,"title":"Invalid selection","server_ids":["missing-server"]}`, adminToken)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unknown public server accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	invalidTitle := testRequest(h, http.MethodPut, "/api/settings/status-page", `{"enabled":true,"title":" ","server_ids":[]}`, adminToken)
	if invalidTitle.Code != http.StatusBadRequest {
		t.Fatalf("empty public page title accepted: %d %s", invalidTitle.Code, invalidTitle.Body.String())
	}
	unchanged := testRequest(h, http.MethodGet, "/api/status", "", "")
	if unchanged.Code != http.StatusOK || !strings.Contains(unchanged.Body.String(), `"title":"Docklight uptime"`) || !strings.Contains(unchanged.Body.String(), "Public Minecraft") {
		t.Fatalf("rejected settings update partially changed public status: %d %s", unchanged.Code, unchanged.Body.String())
	}
	changed := testRequest(h, http.MethodPut, "/api/settings/status-page", `{"enabled":true,"title":"Only the app","server_ids":["status-starting-id-private"]}`, adminToken)
	if changed.Code != http.StatusOK {
		t.Fatalf("change public server selection: %d %s", changed.Code, changed.Body.String())
	}
	changedPayload := testRequest(h, http.MethodGet, "/api/status", "", "")
	if changedPayload.Code != http.StatusOK || !strings.Contains(changedPayload.Body.String(), `"title":"Only the app"`) || !strings.Contains(changedPayload.Body.String(), "Starting app") || strings.Contains(changedPayload.Body.String(), "Public Minecraft") {
		t.Fatalf("valid settings update did not bust public status cache: %d %s", changedPayload.Code, changedPayload.Body.String())
	}

	disabled := testRequest(h, http.MethodPut, "/api/settings/status-page", `{"enabled":false,"title":"Docklight uptime","server_ids":["status-live-id-private"]}`, adminToken)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable public status page: %d %s", disabled.Code, disabled.Body.String())
	}
	for _, path := range []string{"/status", "/status.js", "/api/status"} {
		response := testRequest(h, http.MethodGet, path, "", "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled public route %s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestRecordPlayerSampleRejectsNegativeCounts(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "sampled-server")
	if err := a.recordPlayerSample("sampled-server", -1, 20); err == nil {
		t.Fatal("negative online count was saved")
	}
	if err := a.recordPlayerSample("sampled-server", 5, -1); err == nil {
		t.Fatal("negative maximum count was saved")
	}
	if err := a.recordPlayerSample("sampled-server", 3, 20); err != nil {
		t.Fatal(err)
	}
	var online, maxPlayers int
	if err := d.QueryRow(`SELECT online,max_players FROM server_query_samples WHERE server_id='sampled-server'`).Scan(&online, &maxPlayers); err != nil || online != 3 || maxPlayers != 20 {
		t.Fatalf("saved query sample online=%d max=%d err=%v", online, maxPlayers, err)
	}
}
