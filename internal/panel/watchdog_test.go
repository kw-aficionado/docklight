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

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

func TestWatchdogSettingsRequireControlAndQueryProtocol(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "watchdog-settings")
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('watchdog-admin','watchdog-admin','unused-hash','admin'),('watchdog-user','watchdog-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "watchdog-admin", Username: "watchdog-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "watchdog-user", Username: "watchdog-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()

	denied := testRequest(h, http.MethodPut, "/api/servers/watchdog-settings/watchdog", `{"enabled":true}`, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("user without server.control changed watchdog: %d %s", denied.Code, denied.Body.String())
	}
	if _, err = d.Exec(`UPDATE servers SET gameskill_id='cloudflared' WHERE id='watchdog-settings'`); err != nil {
		t.Fatal(err)
	}
	noQuery := testRequest(h, http.MethodPut, "/api/servers/watchdog-settings/watchdog", `{"enabled":true}`, adminToken)
	if noQuery.Code != http.StatusConflict {
		t.Fatalf("watchdog enabled without query protocol: %d %s", noQuery.Code, noQuery.Body.String())
	}
	var enabled int
	if err = d.QueryRow(`SELECT watchdog_enabled FROM servers WHERE id='watchdog-settings'`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("rejected watchdog update changed setting: enabled=%d err=%v", enabled, err)
	}
	if _, err = d.Exec(`UPDATE servers SET gameskill_id='minecraft-java' WHERE id='watchdog-settings'`); err != nil {
		t.Fatal(err)
	}
	enabledResponse := testRequest(h, http.MethodPut, "/api/servers/watchdog-settings/watchdog", `{"enabled":true}`, adminToken)
	var server Server
	if enabledResponse.Code != http.StatusOK || json.Unmarshal(enabledResponse.Body.Bytes(), &server) != nil || !server.WatchdogEnabled || server.WatchdogQuarantined {
		t.Fatalf("enable watchdog response=%d body=%s server=%#v", enabledResponse.Code, enabledResponse.Body.String(), server)
	}
	if err = d.QueryRow(`SELECT watchdog_enabled FROM servers WHERE id='watchdog-settings'`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("watchdog setting not persisted: enabled=%d err=%v", enabled, err)
	}
	if _, err = d.Exec(`UPDATE servers SET watchdog_quarantined=1 WHERE id='watchdog-settings'`); err != nil {
		t.Fatal(err)
	}
	unchanged := testRequest(h, http.MethodPut, "/api/servers/watchdog-settings/watchdog", `{"enabled":true}`, adminToken)
	if unchanged.Code != http.StatusOK || json.Unmarshal(unchanged.Body.Bytes(), &server) != nil || !server.WatchdogQuarantined {
		t.Fatalf("saving unchanged enabled state cleared quarantine: %d %s server=%#v", unchanged.Code, unchanged.Body.String(), server)
	}
	disabled := testRequest(h, http.MethodPut, "/api/servers/watchdog-settings/watchdog", `{"enabled":false}`, adminToken)
	if disabled.Code != http.StatusOK || json.Unmarshal(disabled.Body.Bytes(), &server) != nil || server.WatchdogEnabled || server.WatchdogQuarantined {
		t.Fatalf("disable watchdog response=%d body=%s server=%#v", disabled.Code, disabled.Body.String(), server)
	}
}

func TestWatchdogFailureThresholdCooldownAndQuarantine(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "watchdog-runtime")
	if _, err := d.Exec(`UPDATE servers SET watchdog_enabled=1 WHERE id='watchdog-runtime'`); err != nil {
		t.Fatal(err)
	}
	var queries, heals int
	a.watchdogQuery = func(context.Context, Server, rune.Rune) error {
		queries++
		return errors.New("query timed out")
	}
	a.watchdogHeal = func(context.Context, Server) error {
		heals++
		if heals == watchdogQuarantineAtHeals {
			// A real start returns while readiness is still in progress.
			_, _ = d.Exec(`UPDATE servers SET status='starting' WHERE id='watchdog-runtime'`)
		}
		return nil
	}

	now := time.Unix(1_800_000_000, 0)
	restartMonitorState := func() {
		a.watchdogMu.Lock()
		delete(a.watchdogStates, "watchdog-runtime")
		a.watchdogMu.Unlock()
	}
	for i := 0; i < watchdogFailureLimit-1; i++ {
		a.monitorWatchdogServer(context.Background(), "watchdog-runtime", now.Add(time.Duration(i)*watchdogInterval))
	}
	if heals != 0 {
		t.Fatalf("watchdog healed after only %d failures", watchdogFailureLimit-1)
	}
	a.monitorWatchdogServer(context.Background(), "watchdog-runtime", now.Add(2*watchdogInterval))
	if heals != 1 {
		t.Fatalf("watchdog heals after threshold=%d, want 1", heals)
	}
	restartMonitorState()

	// Failures remain consecutive during the cooldown, but cannot trigger another heal early.
	cooldownStart := now.Add(3 * time.Minute)
	for i := 0; i < watchdogFailureLimit; i++ {
		a.monitorWatchdogServer(context.Background(), "watchdog-runtime", cooldownStart.Add(time.Duration(i)*watchdogInterval))
	}
	if heals != 1 {
		t.Fatalf("watchdog bypassed cooldown; heals=%d", heals)
	}

	lastHeal := now.Add(2 * watchdogInterval)
	for expected := 2; expected <= watchdogQuarantineAtHeals; expected++ {
		start := lastHeal.Add(watchdogCooldown + time.Second)
		for i := 0; i < watchdogFailureLimit; i++ {
			a.monitorWatchdogServer(context.Background(), "watchdog-runtime", start.Add(time.Duration(i)*watchdogInterval))
		}
		if heals != expected {
			t.Fatalf("heal count=%d, want %d", heals, expected)
		}
		lastHeal = start.Add(time.Duration(watchdogFailureLimit-1) * watchdogInterval)
		if expected < watchdogQuarantineAtHeals {
			restartMonitorState()
		}
	}

	var quarantined int
	if err := d.QueryRow(`SELECT watchdog_quarantined FROM servers WHERE id='watchdog-runtime'`).Scan(&quarantined); err != nil || quarantined != 1 {
		t.Fatalf("fifth heal did not quarantine starting server: quarantined=%d err=%v", quarantined, err)
	}
	queryCount := queries
	a.monitorWatchdogServer(context.Background(), "watchdog-runtime", lastHeal.Add(time.Minute))
	if queries != queryCount {
		t.Fatalf("quarantined server was queried again: before=%d after=%d", queryCount, queries)
	}
	var persistedHeals int
	if err := d.QueryRow(`SELECT count(*) FROM server_watchdog_heals WHERE server_id='watchdog-runtime'`).Scan(&persistedHeals); err != nil || persistedHeals != watchdogQuarantineAtHeals {
		t.Fatalf("persistent heal history count=%d err=%v", persistedHeals, err)
	}
	var state *watchdogRuntimeState
	a.watchdogMu.Lock()
	state = a.watchdogStates["watchdog-runtime"]
	a.watchdogMu.Unlock()
	if state == nil || len(recentWatchdogHeals(state.Heals, lastHeal)) != watchdogQuarantineAtHeals {
		t.Fatalf("recent heal history lost: %#v", state)
	}
	a.resetWatchdog("watchdog-runtime")
	var lastAttempt int64
	if err := d.QueryRow(`SELECT watchdog_quarantined,watchdog_last_attempt FROM servers WHERE id='watchdog-runtime'`).Scan(&quarantined, &lastAttempt); err != nil || quarantined != 0 || lastAttempt != 0 {
		t.Fatalf("manual reset left cooldown/quarantine: quarantined=%d lastAttempt=%d err=%v", quarantined, lastAttempt, err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM server_watchdog_heals WHERE server_id='watchdog-runtime'`).Scan(&persistedHeals); err != nil || persistedHeals != 0 {
		t.Fatalf("manual reset left heal history: count=%d err=%v", persistedHeals, err)
	}
}

func TestWatchdogHealthyProbeResetsConsecutiveFailures(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "watchdog-healthy")
	if _, err := d.Exec(`UPDATE servers SET watchdog_enabled=1 WHERE id='watchdog-healthy'`); err != nil {
		t.Fatal(err)
	}
	var healthy bool
	var heals int
	a.watchdogQuery = func(context.Context, Server, rune.Rune) error {
		if healthy {
			return nil
		}
		return errors.New("query failed")
	}
	a.watchdogHeal = func(context.Context, Server) error { heals++; return nil }
	now := time.Unix(1_800_000_100, 0)
	a.monitorWatchdogServer(context.Background(), "watchdog-healthy", now)
	a.monitorWatchdogServer(context.Background(), "watchdog-healthy", now.Add(watchdogInterval))
	healthy = true
	a.monitorWatchdogServer(context.Background(), "watchdog-healthy", now.Add(2*watchdogInterval))
	healthy = false
	a.monitorWatchdogServer(context.Background(), "watchdog-healthy", now.Add(3*watchdogInterval))
	if heals != 0 {
		t.Fatalf("watchdog healed across a successful query; heals=%d", heals)
	}
	a.watchdogMu.Lock()
	state := a.watchdogStates["watchdog-healthy"]
	failures := state.Failures
	a.watchdogMu.Unlock()
	if failures != 1 {
		t.Fatalf("failure count after healthy probe=%d, want 1", failures)
	}
}

func TestWatchdogScanWaitsForStartupAndReachableDocker(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "watchdog-scan")
	if _, err := d.Exec(`UPDATE servers SET watchdog_enabled=1 WHERE id='watchdog-scan'`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.booted = now
	var pings, queries int
	a.runtimePing = func(context.Context) error { pings++; return nil }
	a.watchdogQuery = func(context.Context, Server, rune.Rune) error { queries++; return nil }
	if err := a.scanWatchdogs(context.Background(), now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if pings != 0 || queries != 0 {
		t.Fatalf("startup grace performed pings=%d queries=%d, want zero", pings, queries)
	}
	a.booted = now.Add(-2 * runtimeStartupGrace)
	a.runtimePing = func(context.Context) error { pings++; return errors.New("Docker is unreachable") }
	if err := a.scanWatchdogs(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if pings != 1 || queries != 0 {
		t.Fatalf("unreachable Docker performed pings=%d queries=%d, want one ping and no query", pings, queries)
	}
	a.runtimePing = func(context.Context) error { pings++; return nil }
	if err := a.scanWatchdogs(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if pings != 2 || queries != 1 {
		t.Fatalf("reachable Docker scan performed pings=%d queries=%d, want one probe", pings, queries)
	}
}

func TestWatchdogHealRetriesAndManualResetCancelsNextAttempt(t *testing.T) {
	a, d, _ := testApp(t)
	insertRuntimeServer(t, a, "watchdog-retries")
	if _, err := d.Exec(`UPDATE servers SET watchdog_enabled=1 WHERE id='watchdog-retries'`); err != nil {
		t.Fatal(err)
	}
	reservedAt := time.Unix(1_800_000_200, 0)
	if _, err := d.Exec(`UPDATE servers SET watchdog_last_attempt=? WHERE id='watchdog-retries'`, reservedAt.Unix()); err != nil {
		t.Fatal(err)
	}
	s, err := a.getServer("watchdog-retries")
	if err != nil {
		t.Fatal(err)
	}
	var attempts int
	var delays []time.Duration
	a.watchdogStart = func(context.Context, Server) error {
		attempts++
		if attempts < 3 {
			return errors.New("injected start failure")
		}
		return nil
	}
	a.watchdogWait = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}
	if err = a.watchdogHealServer(context.Background(), s, reservedAt); err != nil {
		t.Fatalf("third start attempt should succeed: %v", err)
	}
	if attempts != 3 || len(delays) != 2 || delays[0] != 15*time.Second || delays[1] != 15*time.Second {
		t.Fatalf("restart attempts=%d delays=%v, want 3 attempts and two 15-second waits", attempts, delays)
	}

	a.resetWatchdog("watchdog-retries")
	reservedAt = reservedAt.Add(watchdogCooldown)
	if _, err = d.Exec(`UPDATE servers SET watchdog_last_attempt=? WHERE id='watchdog-retries'`, reservedAt.Unix()); err != nil {
		t.Fatal(err)
	}
	attempts = 0
	a.watchdogStart = func(context.Context, Server) error {
		attempts++
		return errors.New("injected start failure")
	}
	a.watchdogWait = func(context.Context, time.Duration) error {
		a.resetWatchdog("watchdog-retries")
		return nil
	}
	err = a.watchdogHealServer(context.Background(), s, reservedAt)
	if err == nil || !strings.Contains(err.Error(), "cancelled by a manual server action") || attempts != 1 {
		t.Fatalf("manual reset did not cancel retry: err=%v attempts=%d", err, attempts)
	}
}

func TestWatchdogNotificationUsesOptInWebhookEvent(t *testing.T) {
	a, d, _ := testApp(t)
	endpoint, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "http://127.0.0.1:18765/watchdog")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO notification_settings(id,enabled,endpoint_enc,events_json) VALUES(1,1,?,'["server.watchdog"]')`, endpoint); err != nil {
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
	a.dispatchWebhookNotification(notificationWatchdog, &webhookServer{ID: "watchdog-event", Name: "Watchdog Event"}, "Automatic recovery started.")
	select {
	case payload := <-requests:
		if payload.Event != notificationWatchdog || payload.Server == nil || payload.Server.ID != "watchdog-event" || payload.Message != "Automatic recovery started." {
			t.Fatalf("unexpected watchdog webhook: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("opted-in watchdog webhook was not delivered")
	}
}
