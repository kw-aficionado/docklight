package panel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

type networkRoundTripper func(*http.Request) (*http.Response, error)

func (fn networkRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestNetworkSettingsAreVisibleToUsersAndAdminCanSetHostname(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	passwordHash, err := security.HashPassword("network-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('network-user','network-user',?,'user')`, passwordHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "network-user", Username: "network-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	app.networkHTTPClient = &http.Client{Transport: networkRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.String() != "https://api.ipify.org?format=json" {
			return nil, errors.New("unexpected public IP request URL")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ip":"203.0.113.18"}`)), Header: make(http.Header)}, nil
	})}
	initial := testRequest(app.Router(), http.MethodGet, "/api/settings/network", "", userToken)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), `"effective":"203.0.113.18"`) {
		t.Fatalf("non-admin network read returned %d: %s", initial.Code, initial.Body.String())
	}
	denied := testRequest(app.Router(), http.MethodPut, "/api/settings/network", `{"public_hostname":"play.example.com"}`, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin network update returned %d: %s", denied.Code, denied.Body.String())
	}
	saved := testRequest(app.Router(), http.MethodPut, "/api/settings/network", `{"public_hostname":"https://Play.Example.com/"}`, adminToken)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"public_hostname":"play.example.com"`) || !strings.Contains(saved.Body.String(), `"effective":"play.example.com"`) {
		t.Fatalf("admin network update returned %d: %s", saved.Code, saved.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("public IP detection was not cached: %d requests", calls.Load())
	}
	invalid := testRequest(app.Router(), http.MethodPut, "/api/settings/network", `{"public_hostname":"http://localhost/"}`, adminToken)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("loopback hostname returned %d: %s", invalid.Code, invalid.Body.String())
	}
}

func TestPublicIPDetectionUsesStaleValueWhenServiceFails(t *testing.T) {
	app, _, _ := testApp(t)
	app.networkDetected = "203.0.113.19"
	app.networkDetectedAt = time.Now().Add(-2 * time.Hour)
	app.networkHTTPClient = &http.Client{Transport: networkRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	detected, stale, message := app.detectedPublicIP(context.Background())
	if detected != "203.0.113.19" || !stale || !strings.Contains(message, "last detected address") {
		t.Fatalf("stale public IP fallback was lost: ip=%q stale=%t message=%q", detected, stale, message)
	}
}

func TestExternalReachabilityTargetsConfiguredHostAndCachesProbe(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	dataDir := t.TempDir()
	if _, err := d.Exec(`UPDATE network_settings SET public_hostname='203.0.113.20' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,container_id,env_json,ports_json,data_dir) VALUES('reachability-server','Reachability','minecraft-java','running',1,'container-reachability','{}','{"game":25565}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	app.reachabilityProbe = func(_ context.Context, host string, port int, gs rune.Rune) error {
		calls.Add(1)
		if host != "203.0.113.20" || port != 25565 || gs.Query == nil || gs.Query.Type != "minecraft" {
			t.Errorf("probe target does not match configured endpoint: host=%q port=%d query=%#v", host, port, gs.Query)
		}
		return nil
	}
	first := testRequest(app.Router(), http.MethodGet, "/api/servers/reachability-server/reachability", "", token)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"reachable":true`) || !strings.Contains(first.Body.String(), `"host":"203.0.113.20"`) {
		t.Fatalf("external reachability returned %d: %s", first.Code, first.Body.String())
	}
	second := testRequest(app.Router(), http.MethodGet, "/api/servers/reachability-server/reachability", "", token)
	if second.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("reachability result was not cached: status=%d calls=%d body=%s", second.Code, calls.Load(), second.Body.String())
	}
	if _, err := d.Exec(`UPDATE servers SET status='stopped' WHERE id='reachability-server'`); err != nil {
		t.Fatal(err)
	}
	stopped := testRequest(app.Router(), http.MethodGet, "/api/servers/reachability-server/reachability", "", token)
	if stopped.Code != http.StatusOK || !strings.Contains(stopped.Body.String(), `"checked":false`) || calls.Load() != 1 {
		t.Fatalf("stopped server was probed or showed stale state: status=%d calls=%d body=%s", stopped.Code, calls.Load(), stopped.Body.String())
	}
}

func TestReachabilityRejectsLoopbackTargets(t *testing.T) {
	if _, err := resolveProbeIPs(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("loopback IPv4 was accepted as a public probe target")
	}
	if _, err := resolveProbeIPs(context.Background(), "::1"); err == nil {
		t.Fatal("loopback IPv6 was accepted as a public probe target")
	}
	if host, err := normalizePublicHostname("https://Game.Example.net/"); err != nil || host != "game.example.net" {
		t.Fatalf("public hostname normalization: host=%q err=%v", host, err)
	}
}

func TestReachabilityUsesFirstNonRCONPortForTCPTemplates(t *testing.T) {
	template := rune.Rune{Ports: []rune.Port{{Name: "web", Default: 8080}, {Name: "rcon", Default: 25575}}}
	server := Server{Ports: map[string]int{"web": 31234, "rcon": 25576}}
	port, protocol, err := reachabilityPort(server, template)
	if err != nil || port != 31234 || protocol != "tcp" {
		t.Fatalf("TCP reachability port selection: port=%d protocol=%q err=%v", port, protocol, err)
	}
}
