package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

type fakeUniFiController struct {
	mu          sync.Mutex
	rules       []uniFiControllerRule
	next        int
	csrfSeen    bool
	sessionSeen bool
}

type uniFiRoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn uniFiRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestUniFiCombinesTCPAndUDPRunePortsIntoOneRule(t *testing.T) {
	server := Server{ID: "combined-game", Ports: map[string]int{"game": 27015, "rcon": 27016}}
	game := rune.Rune{Ports: []rune.Port{{Name: "game", Protocol: "tcp+udp"}, {Name: "rcon", Protocol: "tcp"}}}
	mappings := desiredUniFiMappings(server, game, "192.168.1.40")
	if len(mappings) != 1 || mappings[0].PortName != "game" || mappings[0].Protocol != "TCP+UDP" || uniFiControllerProtocol(mappings[0].Protocol) != "tcp_udp" {
		t.Fatalf("UniFi should use one combined rule and exclude RCON: %#v", mappings)
	}
}

func (f *fakeUniFiController) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/login":
		w.Header().Set("X-CSRF-Token", "csrf-test")
		w.Header().Add("Set-Cookie", "TOKEN=test-session; Path=/; HttpOnly")
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	case r.URL.Path == "/proxy/network/api/s/default/rest/portforward":
		f.csrfSeen = r.Header.Get("X-CSRF-Token") == "csrf-test"
		f.sessionSeen = strings.Contains(r.Header.Get("Cookie"), "TOKEN=test-session")
		f.listOrCreate(w, r)
	case r.URL.Path == "/api/s/default/rest/portforward":
		f.csrfSeen = r.Header.Get("X-CSRF-Token") == "csrf-test"
		f.sessionSeen = strings.Contains(r.Header.Get("Cookie"), "TOKEN=test-session")
		f.listOrCreate(w, r)
	case strings.HasPrefix(r.URL.Path, "/proxy/network/api/s/default/rest/portforward/"):
		f.delete(w, r, "/proxy/network/api/s/default/rest/portforward/")
	case strings.HasPrefix(r.URL.Path, "/api/s/default/rest/portforward/"):
		f.delete(w, r, "/api/s/default/rest/portforward/")
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeUniFiController) listOrCreate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"rc": "ok"}, "data": f.rules})
	case http.MethodPost:
		var in uniFiRuleCreate
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		f.next++
		f.rules = append(f.rules, uniFiControllerRule{ID: fmt.Sprintf("rule-%d", f.next), Name: in.Name, Enabled: in.Enabled, Proto: in.Proto, DstPort: json.RawMessage(`"` + in.DstPort + `"`), Fwd: in.ForwardTo, FwdPort: json.RawMessage(`"` + in.ForwardPort + `"`)})
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"rc": "ok"}, "data": []any{map[string]string{"_id": fmt.Sprintf("rule-%d", f.next)}}})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeUniFiController) delete(w http.ResponseWriter, r *http.Request, prefix string) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix)
	for index, rule := range f.rules {
		if rule.ID == id {
			f.rules = append(f.rules[:index], f.rules[index+1:]...)
			break
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"rc": "ok"}, "data": []any{}})
}

func TestUniFiSettingsAreAdminOnlyEncryptedAndMasked(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	hash, err := security.HashPassword("unifi-user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('unifi-user','unifi-user',?,'user')`, hash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "unifi-user", Username: "unifi-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Router()
	if got := testRequest(handler, http.MethodGet, "/api/settings/unifi", "", userToken); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin settings read returned %d", got.Code)
	}
	updated := testRequest(handler, http.MethodPut, "/api/settings/unifi", `{"enabled":false,"controller_url":"unifi.example.test","username":"local-admin","password":"top-secret-password","site":"default"}`, adminToken)
	if updated.Code != http.StatusOK || strings.Contains(updated.Body.String(), "top-secret-password") {
		t.Fatalf("saving controller credentials returned %d or leaked the password: %s", updated.Code, updated.Body.String())
	}
	var usernameEnc, passwordEnc, controllerURL string
	if err = d.QueryRow(`SELECT controller_url,username_enc,password_enc FROM unifi_settings WHERE id=1`).Scan(&controllerURL, &usernameEnc, &passwordEnc); err != nil {
		t.Fatal(err)
	}
	if controllerURL != "https://unifi.example.test" || !strings.HasPrefix(usernameEnc, "enc:") || !strings.HasPrefix(passwordEnc, "enc:") || strings.Contains(usernameEnc, "local-admin") || strings.Contains(passwordEnc, "top-secret-password") {
		t.Fatalf("UniFi settings were not normalized/encrypted: url=%q username=%q password=%q", controllerURL, usernameEnc, passwordEnc)
	}
	for cipher, want := range map[string]string{usernameEnc: "local-admin", passwordEnc: "top-secret-password"} {
		plain, decryptErr := security.Decrypt([]byte(app.cfg.Auth.SecretKey), cipher)
		if decryptErr != nil || plain != want {
			t.Fatalf("saved secret decrypt=%q err=%v", plain, decryptErr)
		}
	}
	read := testRequest(handler, http.MethodGet, "/api/settings/unifi", "", adminToken)
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), "top-secret-password") || !strings.Contains(read.Body.String(), `"password_configured":true`) {
		t.Fatalf("settings summary did not mask the password: %d %s", read.Code, read.Body.String())
	}
	if got := testRequest(handler, http.MethodPut, "/api/settings/unifi", `{"enabled":true,"controller_url":"unifi.example.test","username":"local-admin","site":"default","clear_login":true}`, adminToken); got.Code != http.StatusBadRequest {
		t.Fatalf("enabling without a password returned %d", got.Code)
	}
}

func TestUniFiClientUsesLocalLoginAndListsRules(t *testing.T) {
	fake := &fakeUniFiController{}
	fake.rules = []uniFiControllerRule{
		{ID: "stray-1", Name: "Docklight migration rule", Enabled: true, Proto: "tcp", DstPort: json.RawMessage(`25565`), Fwd: "192.168.1.40", FwdPort: json.RawMessage(`25565`)},
		{ID: "remote-stray", Name: "Docklight: [docklight:old-host] game tcp/27015", Enabled: true, Proto: "tcp", DstPort: json.RawMessage(`27015`), Fwd: "192.168.1.90", FwdPort: json.RawMessage(`27015`)},
	}
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	app.unifiHTTPClient = fakeUniFiHTTPClient(fake)
	app.hostLocalIP = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.168.1.40"), nil }
	response := testRequest(app.Router(), http.MethodPost, "/api/unifi/test", `{}`, token)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"port_forward_rules":2`) {
		t.Fatalf("test controller returned %d %s", response.Code, response.Body.String())
	}
	fake.mu.Lock()
	if !fake.csrfSeen || !fake.sessionSeen {
		fake.mu.Unlock()
		t.Fatalf("controller API call did not include the session cookie and CSRF token: csrf=%t session=%t", fake.csrfSeen, fake.sessionSeen)
	}
	fake.mu.Unlock()
	allRulesResponse := testRequest(app.Router(), http.MethodGet, "/api/unifi/rules", "", token)
	if allRulesResponse.Code != http.StatusOK {
		t.Fatalf("rule listing returned %d %s", allRulesResponse.Code, allRulesResponse.Body.String())
	}
	var listed []uniFiRuleResponse
	if err := json.Unmarshal(allRulesResponse.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	for _, rule := range listed {
		if rule.ID == "remote-stray" && rule.Stray {
			t.Fatalf("rule targeting another host was mislabeled as this host's stray: %#v", rule)
		}
	}
	strays := testRequest(app.Router(), http.MethodGet, "/api/unifi/strays", "", token)
	if strays.Code != http.StatusOK || !strings.Contains(strays.Body.String(), "stray-1") || strings.Contains(strays.Body.String(), "remote-stray") || !strings.Contains(strays.Body.String(), `"stray":true`) {
		t.Fatalf("stray listing returned %d %s", strays.Code, strays.Body.String())
	}
}

func TestUniFiClientDoesNotFollowControllerRedirects(t *testing.T) {
	app, _, _ := testApp(t)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	cfg, err := app.readUniFiConfig()
	if err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	app.unifiHTTPClient = &http.Client{Transport: uniFiRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.Path)
		recorder := httptest.NewRecorder()
		if request.URL.Path == "/api/auth/login" {
			recorder.Header().Add("Set-Cookie", "TOKEN=test-session; Path=/; HttpOnly")
			_, _ = recorder.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		} else {
			recorder.Header().Set("Location", "https://outside.example.test/capture")
			recorder.WriteHeader(http.StatusFound)
		}
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
	controller, err := app.newUniFiController(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.ListPortForwards(context.Background(), cfg.Site); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("controller redirect was not rejected: %v", err)
	}
	if len(calls) != 2 || calls[1] != "/proxy/network/api/s/default/rest/portforward" {
		t.Fatalf("controller client followed a redirect or tried unexpected endpoints: %#v", calls)
	}
}

func TestUniFiCleanupKeepsOwnershipWhenControllerOmitsRuleData(t *testing.T) {
	app, d, _ := testApp(t)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	app.unifiHTTPClient = &http.Client{Transport: uniFiRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		if request.URL.Path == "/api/auth/login" {
			recorder.Header().Add("Set-Cookie", "TOKEN=test-session; Path=/; HttpOnly")
			_, _ = recorder.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		} else {
			_, _ = recorder.Write([]byte(`{"meta":{"rc":"ok"}}`))
		}
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
	if _, err := d.Exec(`INSERT INTO server_unifi_mappings(server_id,rule_id,controller_url,rule_name,protocol,external_port,internal_port,internal_client)
		VALUES('missing-data-server','rule-1','https://unifi.example.test','Docklight: [docklight:missing-data-server] game tcp/25565','TCP',25565,25565,'192.168.1.40')`); err != nil {
		t.Fatal(err)
	}
	err := app.removeServerUniFiMappings(context.Background(), "missing-data-server")
	if err == nil || !strings.Contains(err.Error(), "no port-forward rule data") {
		t.Fatalf("malformed controller list was accepted: %v", err)
	}
	var rows int
	if err = d.QueryRow(`SELECT count(*) FROM server_unifi_mappings WHERE server_id='missing-data-server'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("cleanup forgot its ownership record: rows=%d err=%v", rows, err)
	}
}

func TestUniFiLifecycleCreatesOnlyDeclaredGameRulesAndCleansOwnedTag(t *testing.T) {
	fake := &fakeUniFiController{rules: []uniFiControllerRule{{ID: "foreign-1", Name: "NAS: existing rule", Enabled: true, Proto: "tcp", DstPort: json.RawMessage(`8443`), Fwd: "192.168.1.25", FwdPort: json.RawMessage(`8443`)}}}
	app, d, _ := testApp(t)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	app.unifiHTTPClient = fakeUniFiHTTPClient(fake)
	app.hostLocalIP = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.168.1.40"), nil }
	seedUPnPServer(t, d, "unifi-game-server", `{"game":25565,"rcon":25575}`)
	s, err := app.getServer("unifi-game-server")
	if err != nil {
		t.Fatal(err)
	}
	if err = app.openServerUniFiMappings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	if len(fake.rules) != 2 {
		fake.mu.Unlock()
		t.Fatalf("expected one owned game rule plus the untouched foreign rule, got %#v", fake.rules)
	}
	var owned uniFiControllerRule
	for _, rule := range fake.rules {
		if parseUniFiServerTag(rule.Name) == s.ID {
			owned = rule
		}
	}
	if owned.ID == "" || owned.Name != "Docklight: [docklight:unifi-game-server] game tcp/25565" || owned.Fwd != "192.168.1.40" || rawText(owned.FwdPort) != "25565" {
		fake.mu.Unlock()
		t.Fatalf("created forwarding rule is wrong: %#v", owned)
	}
	fake.mu.Unlock()
	var recorded int
	if err = d.QueryRow(`SELECT count(*) FROM server_unifi_mappings WHERE server_id=?`, s.ID).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("ownership record count=%d err=%v", recorded, err)
	}
	if err = app.removeServerUniFiMappings(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.rules) != 1 || fake.rules[0].ID != "foreign-1" {
		t.Fatalf("cleanup removed a foreign rule or kept the Docklight one: %#v", fake.rules)
	}
	if err = d.QueryRow(`SELECT count(*) FROM server_unifi_mappings WHERE server_id=?`, s.ID).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatalf("cleanup ownership records count=%d err=%v", recorded, err)
	}
}

func TestUniFiCleanupDeletesOnlyExactServerTagAndStrayDeleteIsExplicit(t *testing.T) {
	fake := &fakeUniFiController{rules: []uniFiControllerRule{
		{ID: "owned-1", Name: "Docklight: [docklight:server-a] game tcp/25565", Enabled: true},
		{ID: "near-match", Name: "Docklight: [docklight:server-ab] game tcp/25565", Enabled: true, Fwd: "192.168.1.40"},
		{ID: "foreign", Name: "Other manager rule", Enabled: true},
	}}
	app, d, _ := testApp(t)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	app.unifiHTTPClient = fakeUniFiHTTPClient(fake)
	app.hostLocalIP = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.168.1.40"), nil }
	if err := app.removeServerUniFiMappings(context.Background(), "server-a"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	if len(fake.rules) != 2 || fake.rules[0].ID != "near-match" || fake.rules[1].ID != "foreign" {
		fake.mu.Unlock()
		t.Fatalf("cleanup did not restrict itself to exact server tag: %#v", fake.rules)
	}
	fake.mu.Unlock()

	admin := runeCatalogAdminToken(t, app, d)
	response := catalogJSONRequest(t, app.Router(), http.MethodPost, "/api/unifi/strays/delete", map[string]any{"ids": []string{"near-match"}}, admin)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deleted":1`) {
		t.Fatalf("explicit stray cleanup returned %d %s", response.Code, response.Body.String())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.rules) != 1 || fake.rules[0].ID != "foreign" {
		t.Fatalf("stray deletion touched another provider's rule: %#v", fake.rules)
	}
}

func TestUniFiDisableClearsRulesBeforeSavingAndPreservesSettingsOnFailure(t *testing.T) {
	fake := &fakeUniFiController{rules: []uniFiControllerRule{
		{ID: "owned-1", Name: "Docklight: [docklight:disable-server] game tcp/25565", Enabled: true},
		{ID: "foreign-1", Name: "NAS: preserve me", Enabled: true},
	}}
	app, d, _ := testApp(t)
	seedUPnPServer(t, d, "disable-server", `{"game":25565}`)
	setUniFiTestConfig(t, app, "https://unifi.example.test", true)
	app.unifiHTTPClient = fakeUniFiHTTPClient(fake)
	adminToken := runeCatalogAdminToken(t, app, d)
	body := `{"enabled":false,"controller_url":"https://unifi.example.test","site":"default"}`
	response := testRequest(app.Router(), http.MethodPut, "/api/settings/unifi", body, adminToken)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatalf("disabling controller returned %d %s", response.Code, response.Body.String())
	}
	fake.mu.Lock()
	if len(fake.rules) != 1 || fake.rules[0].ID != "foreign-1" {
		fake.mu.Unlock()
		t.Fatalf("disable removed a foreign rule or kept an owned rule: %#v", fake.rules)
	}
	fake.mu.Unlock()

	app2, d2, _ := testApp(t)
	setUniFiTestConfig(t, app2, "https://unifi.example.test", true)
	app2.unifiHTTPClient = &http.Client{Transport: uniFiRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("controller unavailable")
	})}
	adminToken2 := runeCatalogAdminToken(t, app2, d2)
	failed := testRequest(app2.Router(), http.MethodPut, "/api/settings/unifi", body, adminToken2)
	var enabled int
	if failed.Code != http.StatusConflict {
		t.Fatalf("cleanup failure returned %d %s", failed.Code, failed.Body.String())
	}
	if err := d2.QueryRow(`SELECT enabled FROM unifi_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("failed cleanup changed the enabled setting: enabled=%d err=%v", enabled, err)
	}
}

func setUniFiTestConfig(t *testing.T, app *App, controllerURL string, enabled bool) {
	t.Helper()
	usernameEnc, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), "local-admin")
	if err != nil {
		t.Fatal(err)
	}
	passwordEnc, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), "unifi-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.db.Exec(`UPDATE unifi_settings SET enabled=?,controller_url=?,username_enc=?,password_enc=?,site='default' WHERE id=1`, boolInt(enabled), controllerURL, usernameEnc, passwordEnc); err != nil {
		t.Fatal(err)
	}
}

func fakeUniFiHTTPClient(fake *fakeUniFiController) *http.Client {
	return &http.Client{Transport: uniFiRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		fake.handler(recorder, request)
		return recorder.Result(), nil
	})}
}
