package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	npmapi "example.com/yggdrasil-panel/internal/npm"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

type npmRoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn npmRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type fakeNPMController struct {
	mu            sync.Mutex
	hosts         map[string]npmapi.ProxyHost
	creates       []npmapi.ProxyHostCreate
	updates       []npmapi.ProxyHostUpdate
	deleted       []string
	nextID        int
	failLE        bool
	partialLE     bool
	partialCreate bool
	failDelete    bool
	badToken      bool
}

func (f *fakeNPMController) roundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	respond := func(status int, body string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return respond(http.StatusBadRequest, `{}`)
		}
		if in["identity"] == "" || in["secret"] == "" {
			return respond(http.StatusUnauthorized, `{"error":"credentials required"}`)
		}
		if f.badToken {
			return respond(http.StatusUnauthorized, `{"error":"invalid credentials"}`)
		}
		return respond(http.StatusOK, `{"token":"npm-test-token"}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/nginx/proxy-hosts":
		if r.Header.Get("Authorization") != "Bearer npm-test-token" {
			return respond(http.StatusUnauthorized, `{}`)
		}
		hosts := make([]npmapi.ProxyHost, 0, len(f.hosts))
		for _, host := range f.hosts {
			hosts = append(hosts, host)
		}
		body, err := json.Marshal(hosts)
		if err != nil {
			return nil, err
		}
		return respond(http.StatusOK, string(body))
	case r.Method == http.MethodPost && r.URL.Path == "/api/nginx/proxy-hosts":
		if r.Header.Get("Authorization") != "Bearer npm-test-token" {
			return respond(http.StatusUnauthorized, `{}`)
		}
		var in npmapi.ProxyHostCreate
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return respond(http.StatusBadRequest, `{}`)
		}
		f.creates = append(f.creates, in)
		if f.partialCreate {
			f.hosts["90"] = npmapi.ProxyHost{ID: json.RawMessage(`90`), DomainNames: in.DomainNames, ForwardHost: in.ForwardHost, ForwardPort: in.ForwardPort, CertificateID: json.RawMessage(`0`), Meta: in.Meta}
			return respond(http.StatusBadGateway, `{"error":"proxy host creation failed"}`)
		}
		f.nextID++
		id := strconv.Itoa(f.nextID)
		f.hosts[id] = npmapi.ProxyHost{ID: json.RawMessage(id), DomainNames: in.DomainNames, ForwardHost: in.ForwardHost, ForwardPort: in.ForwardPort, CertificateID: json.RawMessage(`0`), Meta: in.Meta}
		return respond(http.StatusCreated, fmt.Sprintf(`{"id":%s}`, id))
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/nginx/proxy-hosts/"):
		if r.Header.Get("Authorization") != "Bearer npm-test-token" {
			return respond(http.StatusUnauthorized, `{}`)
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/nginx/proxy-hosts/")
		host, ok := f.hosts[id]
		if !ok {
			return respond(http.StatusNotFound, `{}`)
		}
		var in npmapi.ProxyHostUpdate
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return respond(http.StatusBadRequest, `{}`)
		}
		f.updates = append(f.updates, in)
		if in.CertificateID == "new" && f.failLE {
			if f.partialLE {
				host.CertificateID = json.RawMessage(`9`)
				if in.SSLForced != nil {
					host.SSLForced = *in.SSLForced
				}
				if in.Meta != nil {
					host.Meta = *in.Meta
				}
				f.hosts[id] = host
			}
			return respond(http.StatusBadGateway, `{"error":"certificate request failed"}`)
		}
		if in.CertificateID == "new" {
			host.CertificateID = json.RawMessage(`9`)
		}
		if in.SSLForced != nil {
			host.SSLForced = *in.SSLForced
		}
		if in.Meta != nil {
			host.Meta = *in.Meta
		}
		f.hosts[id] = host
		return respond(http.StatusOK, `{}`)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/nginx/proxy-hosts/"):
		if r.Header.Get("Authorization") != "Bearer npm-test-token" {
			return respond(http.StatusUnauthorized, `{}`)
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/nginx/proxy-hosts/")
		if f.failDelete {
			return respond(http.StatusBadGateway, `{"error":"delete failed"}`)
		}
		f.deleted = append(f.deleted, id)
		delete(f.hosts, id)
		return respond(http.StatusOK, `{}`)
	default:
		return respond(http.StatusNotFound, `{}`)
	}
}

func setNPMTestConfig(t *testing.T, app *App, d interface {
	Exec(string, ...any) (sql.Result, error)
}, enabled bool) {
	t.Helper()
	passwordEnc, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), "npm-secret-for-test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`UPDATE npm_settings SET enabled=?,url=?,email=?,password_enc=?,base_domain=?,internal_host=?,le_email=? WHERE id=1`, boolInt(enabled), "http://npm.example.test:81", "admin@example.test", passwordEnc, "example.test", "192.168.1.40", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
}

func insertNPMTestServer(t *testing.T, d interface {
	Exec(string, ...any) (sql.Result, error)
}, id, status string, autoForward int, subdomain string) {
	t.Helper()
	_, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,auto_forward,npm_subdomain) VALUES(?,?,? ,?,1,'{}',?,?,?,?)`, id, "NPM test server", "uptime-kuma", status, `{"web":31234}`, "/tmp/docklight-npm-test", autoForward, subdomain)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNPMHostnameAndTCPPortSelection(t *testing.T) {
	for _, tc := range []struct{ input, base, want string }{
		{"console", "example.com", "console.example.com"},
		{"Web.App.Example.net.", "example.com", "web.app.example.net"},
		{"", "example.com", ""},
	} {
		got, err := npmHostname(tc.input, tc.base)
		if err != nil || got != tc.want {
			t.Errorf("npmHostname(%q,%q) = %q, %v; want %q", tc.input, tc.base, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"https://app.example.com", "*.example.com", "bad label", "-invalid"} {
		if _, err := npmHostname(invalid, "example.com"); err == nil {
			t.Errorf("invalid hostname %q was accepted", invalid)
		}
	}
	server := Server{Ports: map[string]int{"udp": 2456, "game": 25565, "web": 31001}}
	gs := rune.Rune{Ports: []rune.Port{{Name: "udp", Protocol: "udp"}, {Name: "game", Protocol: "tcp"}, {Name: "web", Protocol: "tcp"}}}
	name, port := npmProxyPort(server, gs)
	if name != "web" || port != 31001 {
		t.Fatalf("web TCP port should be preferred, got %s/%d", name, port)
	}
	server.Ports = map[string]int{"udp": 2456, "game": 25565}
	name, port = npmProxyPort(server, gs)
	if name != "game" || port != 25565 {
		t.Fatalf("first TCP port should be fallback, got %s/%d", name, port)
	}
	name, port = npmProxyPort(Server{Ports: map[string]int{"udp": 2456}}, rune.Rune{Ports: []rune.Port{{Name: "udp", Protocol: "udp"}}})
	if name != "" || port != 0 {
		t.Fatalf("UDP-only server must not be proxied, got %s/%d", name, port)
	}
}

func TestNPMSettingsAreAdminOnlyEncryptedAndConnectionTestUsesBearer(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	passwordHash, err := security.HashPassword("npm-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('npm-user','npm-user',?,'user')`, passwordHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "npm-user", Username: "npm-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if got := testRequest(app.Router(), http.MethodGet, "/api/settings/npm", "", userToken); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin NPM settings read returned %d", got.Code)
	}
	mismatchedLEEmail := testRequest(app.Router(), http.MethodPut, "/api/settings/npm", `{"enabled":false,"url":"npm.example.test:81","email":"admin@example.test","password":"npm-secret","base_domain":"example.test","le_email":"certs@example.test"}`, adminToken)
	if mismatchedLEEmail.Code != http.StatusBadRequest || !strings.Contains(mismatchedLEEmail.Body.String(), "connected account's email") {
		t.Fatalf("mismatched Let's Encrypt email should explain NPM account behavior: %d %s", mismatchedLEEmail.Code, mismatchedLEEmail.Body.String())
	}
	updated := testRequest(app.Router(), http.MethodPut, "/api/settings/npm", `{"enabled":false,"url":"npm.example.test:81","email":"admin@example.test","password":"npm-secret","base_domain":"Example.Test","internal_host":"192.168.1.40","le_email":""}`, adminToken)
	if updated.Code != http.StatusOK || strings.Contains(updated.Body.String(), "npm-secret") {
		t.Fatalf("saving NPM credentials returned %d or leaked password: %s", updated.Code, updated.Body.String())
	}
	var urlValue, passwordEnc, baseDomain string
	if err = d.QueryRow(`SELECT url,password_enc,base_domain FROM npm_settings WHERE id=1`).Scan(&urlValue, &passwordEnc, &baseDomain); err != nil {
		t.Fatal(err)
	}
	if urlValue != "http://npm.example.test:81" || !strings.HasPrefix(passwordEnc, "enc:") || strings.Contains(passwordEnc, "npm-secret") || baseDomain != "example.test" {
		t.Fatalf("NPM settings were not normalized and encrypted: url=%q base=%q cipher=%q", urlValue, baseDomain, passwordEnc)
	}
	fake := &fakeNPMController{hosts: map[string]npmapi.ProxyHost{"3": {ID: json.RawMessage(`3`), DomainNames: []string{"existing.example.test"}}}}
	app.npmHTTPClient = &http.Client{Transport: npmRoundTripperFunc(fake.roundTrip)}
	tested := testRequest(app.Router(), http.MethodPost, "/api/npm/test", `{}`, adminToken)
	if tested.Code != http.StatusOK || !strings.Contains(tested.Body.String(), `"proxy_hosts":1`) {
		t.Fatalf("NPM connection test returned %d: %s", tested.Code, tested.Body.String())
	}
}

func TestNPMProxyLifecycleIsIndependentOfRouterForwardingAndRetriesWithoutSSL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failLE    bool
		partialLE bool
		autoHost  bool
	}{{name: "certificate succeeds", autoHost: true}, {name: "certificate failure keeps plain host", failLE: true}, {name: "late certificate response error is checked", failLE: true, partialLE: true}} {
		t.Run(tc.name, func(t *testing.T) {
			app, d, _ := testApp(t)
			setNPMTestConfig(t, app, d, true)
			if tc.autoHost {
				if _, err := d.Exec(`UPDATE npm_settings SET internal_host='' WHERE id=1`); err != nil {
					t.Fatal(err)
				}
				app.hostLocalIP = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.168.1.40"), nil }
			}
			insertNPMTestServer(t, d, "npm-server", "running", 0, "monitor")
			fake := &fakeNPMController{hosts: map[string]npmapi.ProxyHost{}, failLE: tc.failLE, partialLE: tc.partialLE}
			app.npmHTTPClient = &http.Client{Transport: npmRoundTripperFunc(fake.roundTrip)}
			server := Server{ID: "npm-server", GameskillID: "uptime-kuma", Status: "running", Ports: map[string]int{"web": 31234}, AutoForward: false}
			ctx := context.Background()
			if err := app.openServerNPMHost(ctx, server); err != nil {
				t.Fatalf("open NPM host: %v", err)
			}
			state, err := app.readServerNPMState(ctx, server.ID)
			if err != nil || state.HostID == "" || state.Hostname != "monitor.example.test" {
				t.Fatalf("proxy state = %#v, err=%v", state, err)
			}
			if len(fake.creates) != 1 || fake.creates[0].ForwardHost != "192.168.1.40" || fake.creates[0].ForwardPort != 31234 || fake.creates[0].SSLForced || fmt.Sprint(fake.creates[0].CertificateID) != "0" {
				t.Fatalf("unexpected base proxy payload: %#v", fake.creates)
			}
			if len(fake.updates) != 3 || fake.updates[0].Meta == nil || len(*fake.updates[0].Meta) != 0 || fake.updates[1].CertificateID != "new" || fake.updates[1].SSLForced == nil || !*fake.updates[1].SSLForced || fake.updates[1].Meta == nil || (*fake.updates[1].Meta)["dns_challenge"] != false {
				t.Fatalf("unexpected ownership/certificate update sequence: %#v", fake.updates)
			}
			host := fake.hosts[state.HostID]
			if fmt.Sprint(host.Meta["docklight_managed"]) != "true" || fmt.Sprint(host.Meta["docklight_server_id"]) != server.ID {
				t.Fatalf("saved NPM host is missing its ownership marker: %#v", host.Meta)
			}
			if !tc.failLE {
				if state.LastError != "" || len(fake.hosts) != 1 || !host.SSLForced || string(host.CertificateID) != "9" {
					t.Fatalf("successful certificate left warning or unexpected host state: state=%#v host=%#v", state, host)
				}
			} else if tc.partialLE {
				if !strings.Contains(state.LastError, "after applying") || len(fake.hosts) != 1 || !host.SSLForced || string(host.CertificateID) != "9" {
					t.Fatalf("late NPM error was not reconciled from saved host state: state=%#v host=%#v", state, host)
				}
			} else if !strings.Contains(state.LastError, "without SSL") || len(fake.hosts) != 1 || host.SSLForced || string(host.CertificateID) != "0" {
				t.Fatalf("certificate fallback did not keep the proxy available without SSL: state=%#v host=%#v", state, host)
			}
			if err = app.removeServerNPMHost(ctx, server.ID); err != nil {
				t.Fatalf("remove NPM host: %v", err)
			}
			state, err = app.readServerNPMState(ctx, server.ID)
			if err != nil || state.HostID != "" || len(fake.hosts) != 0 {
				t.Fatalf("NPM host cleanup failed: state=%#v err=%v hosts=%d", state, err, len(fake.hosts))
			}
			var autoForward int
			if err = d.QueryRow(`SELECT auto_forward FROM servers WHERE id=?`, server.ID).Scan(&autoForward); err != nil || autoForward != 0 {
				t.Fatalf("NPM changed router-forwarding preference: auto_forward=%d err=%v", autoForward, err)
			}
		})
	}
}

func TestNPMFailedPartialHostCleanupIsSavedForRetry(t *testing.T) {
	app, d, _ := testApp(t)
	setNPMTestConfig(t, app, d, true)
	insertNPMTestServer(t, d, "npm-retry", "running", 1, "retry")
	fake := &fakeNPMController{hosts: map[string]npmapi.ProxyHost{}, partialCreate: true, failDelete: true}
	app.npmHTTPClient = &http.Client{Transport: npmRoundTripperFunc(fake.roundTrip)}
	server := Server{ID: "npm-retry", GameskillID: "uptime-kuma", Status: "running", Ports: map[string]int{"web": 31234}}
	ctx := context.Background()
	if err := app.openServerNPMHost(ctx, server); err == nil {
		t.Fatal("proxy creation should report a failed partial-host cleanup")
	}
	state, err := app.readServerNPMState(ctx, server.ID)
	if err != nil || state.HostID != "90" || !state.CleanupPending || len(fake.hosts) != 1 {
		t.Fatalf("failed cleanup ownership was not saved: state=%#v err=%v hosts=%d", state, err, len(fake.hosts))
	}
	fake.failDelete = false
	if err = app.removeServerNPMHost(ctx, server.ID); err != nil {
		t.Fatalf("retry partial-host cleanup: %v", err)
	}
	state, err = app.readServerNPMState(ctx, server.ID)
	if err != nil || state.HostID != "" || state.CleanupPending || len(fake.hosts) != 0 {
		t.Fatalf("retry did not clear saved orphan: state=%#v err=%v hosts=%d", state, err, len(fake.hosts))
	}
}

func TestNPMServerHostnameChangeRemovesSavedProxyBeforeReplacing(t *testing.T) {
	app, d, _ := testApp(t)
	setNPMTestConfig(t, app, d, true)
	insertNPMTestServer(t, d, "npm-change", "stopped", 1, "old")
	fake := &fakeNPMController{hosts: map[string]npmapi.ProxyHost{}}
	app.npmHTTPClient = &http.Client{Transport: npmRoundTripperFunc(fake.roundTrip)}
	adminToken := runeCatalogAdminToken(t, app, d)
	ctx := context.Background()
	if err := app.recordNPMState(ctx, "npm-change", npmServerState{HostID: "7", Hostname: "old.example.test"}); err != nil {
		t.Fatal(err)
	}
	fake.hosts["7"] = npmapi.ProxyHost{ID: json.RawMessage(`7`), DomainNames: []string{"old.example.test"}}
	updated := testRequest(app.Router(), http.MethodPut, "/api/servers/npm-change/npm", `{"subdomain":"new.example.test"}`, adminToken)
	if updated.Code != http.StatusOK || len(fake.deleted) != 1 || fake.deleted[0] != "7" {
		t.Fatalf("hostname change did not remove prior owned host: code=%d body=%s deleted=%#v", updated.Code, updated.Body.String(), fake.deleted)
	}
	var subdomain string
	if err := d.QueryRow(`SELECT npm_subdomain FROM servers WHERE id='npm-change'`).Scan(&subdomain); err != nil || subdomain != "new.example.test" {
		t.Fatalf("new hostname was not saved: %q err=%v", subdomain, err)
	}
	if len(fake.hosts) != 0 {
		t.Fatalf("stale proxy host remains after subdomain update: %#v", fake.hosts)
	}
}
