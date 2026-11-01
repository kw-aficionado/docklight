package panel

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMetricsSamplerStoresSevenDaysAndAPIsEnforceAccess(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('metrics-admin','metrics-admin','unused-hash','admin'),('metrics-viewer','metrics-viewer','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "metrics-admin", Username: "metrics-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	viewerToken, err := a.issue(User{ID: "metrics-viewer", Username: "metrics-viewer", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES('metrics-server','Metrics server','minecraft-java','running',1,'{}','{}',?,'container-metrics')`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('metrics-stopped','Stopped server','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('metrics-viewer','server','metrics-server','server.view')`); err != nil {
		t.Fatal(err)
	}
	a.metricsStats = func(context.Context, Server) (float64, uint64, error) { return 120, 2 * 1024 * 1024, nil }
	a.metricsPlayers = func(context.Context, Server) (int, error) { return 6, nil }
	a.metricsHostProbe = func(now time.Time) hostMetricPoint {
		return hostMetricPoint{SampledAt: now.Unix(), CPUPercent: 37.5, MemoryUsedMB: 1200, MemoryTotalMB: 4000, DiskUsedMB: 5000, DiskTotalMB: 10000}
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-8 * 24 * time.Hour).Unix()
	if _, err = d.Exec(`INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES('metrics-server',?,-1,-1,-1)`, old); err != nil {
		t.Fatal(err)
	}
	if err = a.sampleMetrics(context.Background(), now); err != nil {
		t.Fatalf("sample metrics: %v", err)
	}
	var cpu, memory float64
	var players int
	if err = d.QueryRow(`SELECT cpu_percent,memory_mb,players FROM server_metrics WHERE server_id='metrics-server' AND sampled_at=?`, now.Unix()).Scan(&cpu, &memory, &players); err != nil {
		t.Fatal(err)
	}
	if cpu != 100 || memory != 2 || players != 6 {
		t.Fatalf("stored server metric = cpu %.1f memory %.1f players %d", cpu, memory, players)
	}
	var stoppedSamples int
	if err = d.QueryRow(`SELECT count(*) FROM server_metrics WHERE server_id='metrics-stopped'`).Scan(&stoppedSamples); err != nil || stoppedSamples != 0 {
		t.Fatalf("stopped server should not be sampled: rows=%d err=%v", stoppedSamples, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM server_metrics WHERE server_id='metrics-server' AND sampled_at=?`, old).Scan(&players); err != nil || players != 0 {
		t.Fatalf("eight-day-old sample was not pruned: rows=%d err=%v", players, err)
	}
	var hostCPU, hostMemory, hostMemoryTotal, hostDisk, hostDiskTotal float64
	if err = d.QueryRow(`SELECT cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb FROM host_metrics WHERE sampled_at=?`, now.Unix()).Scan(&hostCPU, &hostMemory, &hostMemoryTotal, &hostDisk, &hostDiskTotal); err != nil {
		t.Fatalf("read host metric: %v", err)
	}
	if hostCPU != 37.5 || hostMemory != 1200 || hostMemoryTotal != 4000 || hostDisk != 5000 || hostDiskTotal != 10000 {
		t.Fatalf("stored host metric = cpu %.1f memory %.1f/%.1f disk %.1f/%.1f", hostCPU, hostMemory, hostMemoryTotal, hostDisk, hostDiskTotal)
	}

	h := a.Router()
	history := testRequest(h, http.MethodGet, "/api/servers/metrics-server/metrics?hours=72", "", viewerToken)
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), `"players":6`) {
		t.Fatalf("server.view grant could not read history: %d %s", history.Code, history.Body.String())
	}
	if forbidden := testRequest(h, http.MethodGet, "/api/servers/metrics-stopped/metrics", "", viewerToken); forbidden.Code != http.StatusForbidden {
		t.Fatalf("user without server.view read metrics: %d %s", forbidden.Code, forbidden.Body.String())
	}
	if invalid := testRequest(h, http.MethodGet, "/api/servers/metrics-server/metrics?hours=169", "", adminToken); invalid.Code != http.StatusBadRequest {
		t.Fatalf("metrics API accepted a window over seven days: %d %s", invalid.Code, invalid.Body.String())
	}
	if history := testRequest(h, http.MethodGet, "/api/system/metrics?hours=24", "", adminToken); history.Code != http.StatusOK || !strings.Contains(history.Body.String(), `"memory_total_mb":4000`) {
		t.Fatalf("read host metrics: %d %s", history.Code, history.Body.String())
	}
	if fleet := testRequest(h, http.MethodGet, "/api/fleet/metrics?hours=24", "", adminToken); fleet.Code != http.StatusOK || !strings.Contains(fleet.Body.String(), `"average_cpu_percent":100`) {
		t.Fatalf("read fleet metric summary: %d %s", fleet.Code, fleet.Body.String())
	}
	if userHost := testRequest(h, http.MethodGet, "/api/system/metrics", "", viewerToken); userHost.Code != http.StatusForbidden {
		t.Fatalf("non-admin read host metrics: %d %s", userHost.Code, userHost.Body.String())
	}
}

func TestMetricsUnknownValuesAndHourWindow(t *testing.T) {
	if hours, err := metricsHours(httptestMetricsRequest("/metrics")); err != nil || hours != 24 {
		t.Fatalf("default metric window=%d err=%v", hours, err)
	}
	for _, raw := range []string{"0", "169", "invalid"} {
		if _, err := metricsHours(httptestMetricsRequest("/metrics?hours=" + raw)); err == nil {
			t.Errorf("invalid metrics window %q accepted", raw)
		}
	}
	if hours, err := metricsHours(httptestMetricsRequest("/metrics?hours=168")); err != nil || hours != 168 {
		t.Fatalf("maximum metric window=%d err=%v", hours, err)
	}
	if got := clampMetricCPU(-10); got != 0 {
		t.Fatalf("negative CPU should clamp to zero, got %v", got)
	}
}

func httptestMetricsRequest(target string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://panel.local"+target, nil)
	return r
}
