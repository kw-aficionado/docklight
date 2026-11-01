package panel

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
)

func TestAssistantWatcherThresholdWindowAndCooldown(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO log_watchers(id,name,pattern,threshold,window_secs,action) VALUES('window-rule','Repeated timeout','timeout',2,60,'notify')`); err != nil {
		t.Fatal(err)
	}
	watcher := assistantLogWatcher{ID: "window-rule", Threshold: 2, WindowSecs: 60}
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if a.recordAssistantWatcherMatch(watcher, "server-a", base) {
		t.Fatal("one hit met a two-hit threshold")
	}
	if !a.recordAssistantWatcherMatch(watcher, "server-a", base.Add(30*time.Second)) {
		t.Fatal("second hit inside the time window did not meet the threshold")
	}
	if a.recordAssistantWatcherMatch(watcher, "server-b", base.Add(31*time.Second)) {
		t.Fatal("matches from different servers were combined")
	}
	if !a.claimAssistantWatcherFire("window-rule", base) {
		t.Fatal("first watcher fire was not claimed")
	}
	if a.claimAssistantWatcherFire("window-rule", base.Add(9*time.Minute)) {
		t.Fatal("watcher fired again before its ten-minute cooldown")
	}
	if !a.claimAssistantWatcherFire("window-rule", base.Add(10*time.Minute)) {
		t.Fatal("watcher did not rearm at the end of its cooldown")
	}
	if a.recordAssistantWatcherMatch(watcher, "server-a", base.Add(91*time.Second)) {
		t.Fatal("old hits outside the window were retained")
	}
}

func TestAssistantLogRedactionCoversTemplateSecretsAndCredentialShapes(t *testing.T) {
	input := `password=known-template-secret api_key="sk-proj-0123456789abcdefghijklmnop" Authorization: Bearer abcdef0123456789 token=ordinary-log-token https://user:pass@example.test/path ghp_abcdefghijklmnopqrstuvwxyz123456`
	got := redactAssistantLogContent(input, []string{"known-template-secret"})
	for _, secret := range []string{"known-template-secret", "sk-proj-0123456789abcdefghijklmnop", "abcdef0123456789", "ordinary-log-token", "user:pass", "ghp_abcdefghijklmnopqrstuvwxyz123456"} {
		if strings.Contains(got, secret) {
			t.Errorf("assistant log redaction left %q in %q", secret, got)
		}
	}
	if strings.Count(got, "[redacted]") < 6 {
		t.Errorf("credential-shaped values were not replaced: %q", got)
	}
}

func TestRuneWatcherSeedsAreIdempotentEditableAndRestorable(t *testing.T) {
	a, d, _ := testApp(t)
	gs := rune.Rune{ID: "minecraft-java", Watchers: []rune.Watcher{{Name: "Startup error", Pattern: `(?i)failed to bind`, Action: "kvasir"}}}
	if err := a.seedRuneWatchers("server-seed", gs); err != nil {
		t.Fatal(err)
	}
	var id, action, source string
	var threshold, window int
	if err := d.QueryRow(`SELECT id,action,source,threshold,window_secs FROM log_watchers WHERE server_id='server-seed'`).Scan(&id, &action, &source, &threshold, &window); err != nil {
		t.Fatal(err)
	}
	if action != "advisory" || source != "rune" || threshold != 1 || window != 60 {
		t.Fatalf("legacy template defaults were not normalized: action=%q source=%q threshold=%d window=%d", action, source, threshold, window)
	}
	if _, err := d.Exec(`UPDATE log_watchers SET pattern='edited-pattern',threshold=3 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := a.seedRuneWatchers("server-seed", gs); err != nil {
		t.Fatal(err)
	}
	var count int
	var pattern string
	if err := d.QueryRow(`SELECT COUNT(*),MAX(pattern) FROM log_watchers WHERE server_id='server-seed'`).Scan(&count, &pattern); err != nil {
		t.Fatal(err)
	}
	if count != 1 || pattern != "edited-pattern" {
		t.Fatalf("resync overwrote or duplicated an operator edit: count=%d pattern=%q", count, pattern)
	}
	if _, err := d.Exec(`DELETE FROM log_watchers WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := a.seedRuneWatchers("server-seed", gs); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM log_watchers WHERE server_id='server-seed' AND source='rune'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("deleted template watcher was not restored on install: count=%d", count)
	}
}

func TestLogWatcherManagementValidatesRulesAndRequiresAdmin(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('watcher-server','Watcher Test','minecraft-java','stopped',1,'{}','{}',?)`, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if result := testRequest(a.Router(), http.MethodGet, "/api/watchers", "", userToken); result.Code != http.StatusForbidden {
		t.Fatalf("non-admin listed watchers: %d %s", result.Code, result.Body.String())
	}
	bad := testRequest(a.Router(), http.MethodPost, "/api/watchers", `{"name":"Bad pattern","server_id":"watcher-server","pattern":"(?=secret)","threshold":1,"window_secs":60,"action":"notify","enabled":true}`, adminToken)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "valid Go regular expression") {
		t.Fatalf("invalid RE2 rule accepted: %d %s", bad.Code, bad.Body.String())
	}
	created := testRequest(a.Router(), http.MethodPost, "/api/watchers", `{"name":"Repeated timeout","server_id":"watcher-server","pattern":"(?i)timeout","threshold":2,"window_secs":90,"action":"notify","enabled":true}`, adminToken)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"server_name":"Watcher Test"`) {
		t.Fatalf("valid log watcher was not created: %d %s", created.Code, created.Body.String())
	}
}

func TestHostedWatcherRequiresConsentBoundToProviderHost(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, _ := assistantTestSessions(t, a, d)
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('hosted-watcher-server','Hosted Watcher','minecraft-java','running',1,'{}','{}',?)`, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	configBody := `{"provider":"openai","model":"test-model","base_url":"https://api.openai.com/v1","api_key":"test-provider-key"}`
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", configBody, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save hosted provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable hosted Advisory: %d %s", result.Code, result.Body.String())
	}
	base := `{"name":"Provider warning","server_id":"hosted-watcher-server","pattern":"warning","threshold":1,"window_secs":60,"action":"advisory","enabled":true}`
	missingConsent := testRequest(a.Router(), http.MethodPost, "/api/watchers", base, adminToken)
	if missingConsent.Code != http.StatusBadRequest || !strings.Contains(missingConsent.Body.String(), "confirm sending a redacted") {
		t.Fatalf("hosted log sharing did not require explicit consent: %d %s", missingConsent.Code, missingConsent.Body.String())
	}
	withConsent := strings.TrimSuffix(base, "}") + `,"confirm_external_logs":true}`
	staleConsent := strings.TrimSuffix(withConsent, "}") + `,"confirm_external_host":"old-provider.example"}`
	stale := testRequest(a.Router(), http.MethodPost, "/api/watchers", staleConsent, adminToken)
	if stale.Code != http.StatusBadRequest {
		t.Fatalf("consent for a different provider host was accepted: %d %s", stale.Code, stale.Body.String())
	}
	withConsent = strings.TrimSuffix(withConsent, "}") + `,"confirm_external_host":"api.openai.com"}`
	created := testRequest(a.Router(), http.MethodPost, "/api/watchers", withConsent, adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("confirmed hosted watcher was not created: %d %s", created.Code, created.Body.String())
	}
	var watcherID, consentHost string
	if err := d.QueryRow(`SELECT id,advisory_host FROM log_watchers WHERE server_id='hosted-watcher-server'`).Scan(&watcherID, &consentHost); err != nil {
		t.Fatal(err)
	}
	if consentHost != "api.openai.com" {
		t.Fatalf("watcher consent was not bound to the provider host: %q", consentHost)
	}
	otherProvider, _ := url.Parse("https://provider.example/v1")
	if _, err := d.Exec(`UPDATE assistant_config SET base_url=? WHERE id=1`, otherProvider.String()); err != nil {
		t.Fatal(err)
	}
	watcher := assistantLogWatcher{ID: watcherID, Name: "Provider warning", Action: "advisory", AdvisoryHost: consentHost}
	message := a.assistantLogWatcherExplanation(watcher, Server{Name: "Hosted Watcher"}, "warning line", true, "fallback")
	if !strings.Contains(message, "External log sharing was not confirmed") {
		t.Fatalf("changed hosted provider received logs without renewed consent: %q", message)
	}
}
