package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
)

func TestAssistantProactiveSettingsAreAdminOnlyAndValidateTriggers(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/proactive-settings", "{\"level\":2,\"triggers\":[\"crash\",\"anomalies\"]}", userToken); result.Code != http.StatusForbidden {
		t.Fatalf("non-admin changed proactive settings: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/proactive-settings", "{\"level\":2,\"triggers\":[\"unknown\"]}", adminToken); result.Code != http.StatusBadRequest {
		t.Fatalf("unknown proactive trigger accepted: %d %s", result.Code, result.Body.String())
	}
	saved := testRequest(a.Router(), http.MethodPut, "/api/ai/proactive-settings", "{\"level\":2,\"triggers\":[\"host\",\"crash\",\"anomalies\",\"crash\"]}", adminToken)
	if saved.Code != http.StatusOK || saved.Body.String() != "{\"level\":2,\"triggers\":[\"crash\",\"host\",\"anomalies\"]}\n" {
		t.Fatalf("valid proactive settings response=%d %s", saved.Code, saved.Body.String())
	}
	config := testRequest(a.Router(), http.MethodGet, "/api/ai/config", "", adminToken)
	var response assistantConfig
	if config.Code != http.StatusOK || json.Unmarshal(config.Body.Bytes(), &response) != nil || response.ProactiveLevel != 2 || strings.Join(response.ProactiveTriggers, ",") != "crash,host,anomalies" {
		t.Fatalf("saved proactive settings not returned by admin config: %d %s", config.Code, config.Body.String())
	}
}

func TestAssistantProactiveScannersCreateBoundedIdempotentEvents(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,proactive_level=1,proactive_triggers='crash,slowstart,resource,host' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-crash")
	insertRuntimeServer(t, a, "proactive-slow")
	insertRuntimeServer(t, a, "proactive-resource")
	now := time.Now().UTC()
	if _, err := d.Exec("UPDATE servers SET status='error' WHERE id='proactive-crash'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO server_crashes(id,server_id,container_id,reason,exit_code,message,detected_at) VALUES('proactive-crash-event','proactive-crash','container-proactive-crash','container_exited',137,'Container exited unexpectedly',?)", now.Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE servers SET status='starting',updated_at=datetime('now','-20 minutes') WHERE id='proactive-slow'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE servers SET memory_limit_mb=1000 WHERE id='proactive-resource'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES('proactive-resource',?,94,950,-1)", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO host_metrics(sampled_at,cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb) VALUES(?,96,9700,10000,9200,10000)", now.Unix()); err != nil {
		t.Fatal(err)
	}
	a.scanAssistantProactiveCrashes(t.Context(), now)
	a.scanAssistantProactiveSlowStarts(t.Context(), now)
	a.scanAssistantProactiveResources(t.Context(), now)
	a.scanAssistantProactiveHost(t.Context(), now)
	a.scanAssistantProactiveCrashes(t.Context(), now)
	var count int
	if err := d.QueryRow("SELECT COUNT(*) FROM assistant_proactive_events").Scan(&count); err != nil || count != 4 {
		t.Fatalf("scanner created %d events, want 4 unique crash/slowstart/resource/host events: %v", count, err)
	}
	var triggers string
	if err := d.QueryRow("SELECT group_concat(event_type,',') FROM (SELECT event_type FROM assistant_proactive_events ORDER BY event_type)").Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != "crash,host,resource,slowstart" {
		t.Fatalf("unexpected proactive triggers: %q", triggers)
	}
}

func TestAssistantProactiveAnomaliesDetectDisconnectAndPlayerInflux(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,proactive_level=1,proactive_triggers='anomalies' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-drop")
	insertRuntimeServer(t, a, "proactive-influx")
	now := time.Now().UTC()
	for _, sample := range []struct {
		server string
		mins   int
		count  int
	}{
		{"proactive-drop", 8, 8}, {"proactive-drop", 2, 2},
		{"proactive-influx", 1440, 5}, {"proactive-influx", 8, 6}, {"proactive-influx", 1, 10},
	} {
		if _, err := d.Exec("INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES(?,?,1,1,?)", sample.server, now.Add(-time.Duration(sample.mins)*time.Minute).Unix(), sample.count); err != nil {
			t.Fatal(err)
		}
	}
	a.scanAssistantProactiveAnomalies(t.Context(), now)
	rows, err := d.Query("SELECT summary,details_json FROM assistant_proactive_events WHERE event_type='anomalies' ORDER BY source_key")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := make([]string, 0, 2)
	for rows.Next() {
		var summary, details string
		if err = rows.Scan(&summary, &details); err != nil {
			t.Fatal(err)
		}
		got = append(got, summary+" "+details)
	}
	joined := strings.Join(got, "\n")
	if len(got) != 2 || !strings.Contains(joined, "mass disconnect") || !strings.Contains(joined, "player influx") {
		t.Fatalf("anomaly scan returned %d unexpected events: %#v", len(got), got)
	}
}

func TestAssistantProactiveAnomaliesDetectLogVolumeBurstWithoutSavingLogText(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,proactive_level=1,proactive_triggers='anomalies' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-log-volume")
	var currentBytes int64 = 64 << 10
	a.assistantLogVolumeProbe = func(_ context.Context, containerID string, _ time.Time) (int64, int64, bool, error) {
		if containerID != "container-proactive-log-volume" {
			t.Fatalf("unexpected container ID %q", containerID)
		}
		return currentBytes, currentBytes / 100, false, nil
	}
	start := time.Now().UTC().Truncate(time.Minute)
	for i := 0; i < assistantLogVolumeWarmup; i++ {
		a.scanAssistantProactiveLogVolume(t.Context(), start.Add(time.Duration(i)*time.Minute+time.Second))
	}
	var count int
	if err := d.QueryRow("SELECT COUNT(*) FROM assistant_proactive_events WHERE event_type='anomalies'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("log volume triggered before baseline warm-up: count=%d err=%v", count, err)
	}
	a.scanAssistantProactiveLogVolume(t.Context(), start.Add(time.Duration(assistantLogVolumeWarmup)*time.Minute+time.Second))
	if err := d.QueryRow("SELECT COUNT(*) FROM assistant_proactive_events WHERE event_type='anomalies'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("ordinary log volume was misclassified after warm-up: count=%d err=%v", count, err)
	}
	currentBytes = 2 << 20
	a.scanAssistantProactiveLogVolume(t.Context(), start.Add(time.Duration(assistantLogVolumeWarmup+1)*time.Minute+time.Second))
	a.scanAssistantProactiveLogVolume(t.Context(), start.Add(time.Duration(assistantLogVolumeWarmup+2)*time.Minute+time.Second))
	if err := d.QueryRow("SELECT COUNT(*) FROM assistant_proactive_events WHERE event_type='anomalies'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("log-volume outlier should create one deduplicated Advisory event: count=%d err=%v", count, err)
	}
	var summary, details string
	if err := d.QueryRow("SELECT summary,details_json FROM assistant_proactive_events WHERE event_type='anomalies'").Scan(&summary, &details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "unusually large amount of log output") || !strings.Contains(details, `"kind":"log_volume"`) || !strings.Contains(details, `"bytes":2097152`) || strings.Contains(details, "private-player-chat") {
		t.Fatalf("log-volume observation should contain counts but no log text: summary=%q details=%s", summary, details)
	}
	var samples int
	if err := d.QueryRow("SELECT sample_count FROM assistant_log_volume_baselines WHERE server_id='proactive-log-volume'").Scan(&samples); err != nil || samples != assistantLogVolumeWarmup+1 {
		t.Fatalf("outlier polluted the baseline: samples=%d err=%v", samples, err)
	}
}

func TestAssistantLogVolumeCounterCapsAndCountsOnlyBytesAndLines(t *testing.T) {
	counter := &assistantLogVolumeCounter{}
	if n, err := counter.Write([]byte("line one\nline two\n")); err != nil || n != len("line one\nline two\n") || counter.bytes != int64(n) || counter.lines != 2 {
		t.Fatalf("counter bytes=%d lines=%d n=%d err=%v", counter.bytes, counter.lines, n, err)
	}
	large := make([]byte, assistantLogVolumeByteCap+10)
	for i := range large {
		large[i] = 'x'
	}
	n, err := counter.Write(large)
	if !errors.Is(err, errAssistantLogVolumeLimit) || counter.bytes != assistantLogVolumeByteCap || int64(n) != assistantLogVolumeByteCap-int64(len("line one\nline two\n")) {
		t.Fatalf("counter cap bytes=%d n=%d err=%v", counter.bytes, n, err)
	}
}

func TestAssistantProactiveLogVolumeRelearnsAfterStaleBaseline(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,proactive_level=1,proactive_triggers='anomalies' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-stale-logs")
	if _, err := d.Exec(`INSERT INTO assistant_log_volume_baselines(server_id,sample_count,mean_bytes,variance_bytes,last_sample_at)
		VALUES('proactive-stale-logs',20,100,0,?)`, time.Now().Add(-25*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	a.assistantLogVolumeProbe = func(context.Context, string, time.Time) (int64, int64, bool, error) {
		return 64 << 10, 12, false, nil
	}
	now := time.Now().UTC()
	a.scanAssistantProactiveLogVolume(t.Context(), now)
	var samples int
	if err := d.QueryRow("SELECT sample_count FROM assistant_log_volume_baselines WHERE server_id='proactive-stale-logs'").Scan(&samples); err != nil || samples != 1 {
		t.Fatalf("stale baseline was not reset before learning: samples=%d err=%v", samples, err)
	}
	var events int
	if err := d.QueryRow("SELECT COUNT(*) FROM assistant_proactive_events WHERE event_type='anomalies'").Scan(&events); err != nil || events != 0 {
		t.Fatalf("stale baseline caused a false log-volume anomaly: events=%d err=%v", events, err)
	}
}

func TestAssistantProactiveLogVolumeReadsCountsFromDockerAndStoresNoLines(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,proactive_level=1,proactive_triggers='anomalies' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-docker-logs")
	const secretLine = "private-player-chat-with-sensitive-data"
	fake := newFakeStackDocker("proactive-docker-logs", "")
	fake.logsOutput = strings.Repeat(secretLine+"\n", 60_000)
	fake.containers["container-proactive-docker-logs"] = fakeStackContainer{name: "log-source", state: "running"}
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	now := time.Now().UTC()
	baselineAt := now.Add(-2 * time.Minute).Unix()
	if _, err := d.Exec(`INSERT INTO assistant_log_volume_baselines(server_id,sample_count,mean_bytes,variance_bytes,last_sample_at)
		VALUES('proactive-docker-logs',5,65536,0,?)`, baselineAt); err != nil {
		t.Fatal(err)
	}
	logBytes, logLines, capped, probeErr := a.assistantContainerLogVolume(t.Context(), "container-proactive-docker-logs", now.Add(-time.Minute))
	if probeErr != nil || logBytes <= assistantLogVolumeMinBytes || logLines != 60_000 || capped {
		t.Fatalf("Docker log probe bytes=%d lines=%d capped=%t err=%v", logBytes, logLines, capped, probeErr)
	}
	a.scanAssistantProactiveLogVolume(t.Context(), now)
	var details string
	if err := d.QueryRow("SELECT details_json FROM assistant_proactive_events WHERE event_type='anomalies' AND server_id='proactive-docker-logs'").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, secretLine) || !strings.Contains(details, `"kind":"log_volume"`) || !strings.Contains(details, `"lines":60000`) {
		t.Fatalf("Docker log-volume event stored raw output or omitted counts: %s", details)
	}
}

func TestAssistantProactiveCycleExplainsNewCrashWithoutSavingPromptOrProposalAtLevelOne(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec("UPDATE assistant_config SET enabled=1,provider='ollama',model='local-model',base_url='http://127.0.0.1:11434/v1',proactive_level=1,proactive_triggers='crash' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "proactive-explained")
	now := time.Now().UTC()
	if _, err := d.Exec("UPDATE servers SET status='error' WHERE id='proactive-explained'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO server_crashes(id,server_id,container_id,reason,exit_code,message,detected_at) VALUES('proactive-explain-event','proactive-explained','container-proactive-explained','container_exited',137,'Container exited unexpectedly',?)", now.Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	var providerPrompt string
	decision := "{\"explanation\":\"Check the startup log and available memory.\",\"action\":\"restart\",\"reason\":\"A restart may recover the service.\"}"
	responseBody, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": decision}}}})
	if err != nil {
		t.Fatal(err)
	}
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			return nil, readErr
		}
		providerPrompt = string(body)
		return assistantTestHTTPResponse(r, http.StatusOK, nil, string(responseBody))
	})}
	a.runAssistantProactiveCycle(t.Context(), now)
	if !strings.Contains(providerPrompt, "Runtime test") || !strings.Contains(providerPrompt, "untrusted observation data") {
		t.Fatalf("provider prompt did not contain bounded event context: %s", providerPrompt)
	}
	var status, action, explanation, details string
	if err = d.QueryRow("SELECT status,suggested_action,explanation,details_json FROM assistant_proactive_events WHERE id=(SELECT id FROM assistant_proactive_events LIMIT 1)").Scan(&status, &action, &explanation, &details); err != nil {
		t.Fatal(err)
	}
	if status != "explained" || action != "none" || explanation != "Check the startup log and available memory." || !strings.Contains(details, "exit_code") {
		t.Fatalf("level 1 event result status=%q action=%q explanation=%q details=%s", status, action, explanation, details)
	}
	if strings.Contains(details, "assistant-proactive") || strings.Contains(details, "Current proactive level") {
		t.Fatalf("prompt content was stored as event data: %s", details)
	}
}

func TestAssistantProactiveMemoryRaiseIsClampedToHostHeadroom(t *testing.T) {
	a, d, _ := testApp(t)
	now := time.Now().UTC()
	if _, err := d.Exec("INSERT INTO host_metrics(sampled_at,cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb) VALUES(?,10,6000,8000,1,2)", now.Unix()); err != nil {
		t.Fatal(err)
	}
	increased, err := a.assistantProactiveMemoryIncrease(t.Context(), 2048, now)
	if err != nil || increased != 2560 {
		t.Fatalf("bounded memory raise=%d err=%v, want 2560 MB", increased, err)
	}
	if _, err = d.Exec("UPDATE host_metrics SET memory_used_mb=7800 WHERE sampled_at=?", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = a.assistantProactiveMemoryIncrease(t.Context(), 2048, now); err == nil {
		t.Fatal("memory raise ignored insufficient host headroom")
	}
}

func TestAssistantParseProactiveDecisionNeverLetsLevelOneProposeActions(t *testing.T) {
	answer := "{\"explanation\":\"Inspect the recent crash.\",\"action\":\"restart\",\"reason\":\"The container exited.\"}"
	decision := assistantParseProactiveDecision(answer, 1)
	if decision.Explanation != "Inspect the recent crash." || decision.Action != "none" || decision.Reason != "" {
		t.Fatalf("level 1 decision was not read-only: %#v", decision)
	}
	decision = assistantParseProactiveDecision(answer, 3)
	if decision.Action != "restart" || decision.Reason != "The container exited." {
		t.Fatalf("level 3 decision parsing failed: %#v", decision)
	}
	decision = assistantParseProactiveDecision("{\"explanation\":\"Inspect.\",\"action\":\"delete_server\"}", 3)
	if decision.Action != "none" {
		t.Fatalf("unsupported proactive action was accepted: %#v", decision)
	}
}
