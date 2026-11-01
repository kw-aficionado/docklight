package panel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	gameskill "example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

type steamRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn steamRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type steamDuplexStream struct {
	read    *bytes.Reader
	written bytes.Buffer
}

func (stream *steamDuplexStream) Read(data []byte) (int, error)  { return stream.read.Read(data) }
func (stream *steamDuplexStream) Write(data []byte) (int, error) { return stream.written.Write(data) }
func (stream *steamDuplexStream) Close() error                   { return nil }

func steamDockerFrame(text string) []byte {
	frame := make([]byte, 8+len(text))
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(text)))
	copy(frame[8:], text)
	return frame
}

func TestSteamGuardAuthorizationDoesNotPersistPasswordOrCode(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	var requestCount int
	var created []docker.CreateConfig
	var attached []*steamDuplexStream
	client := &http.Client{Transport: steamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := func(status int, body string) *http.Response {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/images/create":
			if request.URL.Query().Get("fromImage") != steamCMDImage {
				t.Fatalf("Steam auth pulled unexpected image %q", request.URL.Query().Get("fromImage"))
			}
			if request.URL.Query().Get("platform") != steamCMDPlatform {
				t.Fatalf("Steam auth requested unexpected image platform %q", request.URL.Query().Get("platform"))
			}
			return response(http.StatusOK, `{"status":"Pulled"}`+"\n"), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/create":
			if request.URL.Query().Get("platform") != steamCMDPlatform {
				t.Fatalf("Steam auth container requested unexpected platform %q", request.URL.Query().Get("platform"))
			}
			var config docker.CreateConfig
			if err := json.NewDecoder(request.Body).Decode(&config); err != nil {
				return nil, err
			}
			created = append(created, config)
			return response(http.StatusCreated, `{"Id":"steam-auth"}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/steam-auth/start":
			return response(http.StatusNoContent, ""), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/steam-auth/attach":
			requestCount++
			output := "Login Failure: Account Login Denied"
			if requestCount == 2 {
				output = "Waiting for user info...OK"
			}
			stream := &steamDuplexStream{read: bytes.NewReader(steamDockerFrame(output))}
			attached = append(attached, stream)
			return &http.Response{StatusCode: http.StatusSwitchingProtocols, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}}, Body: stream, Request: request}, nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/steam-auth/wait":
			exit := 1
			if requestCount == 2 {
				exit = 0
			}
			return response(http.StatusOK, `{"StatusCode":`+strconv.Itoa(exit)+`}`), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/v1.45/containers/steam-auth":
			return response(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected Steam Docker request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	app.engine = docker.NewWithHTTPClient("steam-test", "1.45", client)
	handler := app.Router()
	if unauthorized := testRequest(handler, http.MethodGet, "/api/steam/account", "", ""); unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Steam account read status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	userHash, err := security.HashPassword("steam-user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('steam-user','steam-user',?,'user')`, userHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "steam-user", Username: "steam-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if denied := testRequest(handler, http.MethodGet, "/api/steam/account", "", userToken); denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin read Steam account status=%d body=%s", denied.Code, denied.Body.String())
	}
	invalidPassword := testRequest(handler, http.MethodPost, "/api/steam/send-code", `{"username":"steam-user","password":"line\nbreak"}`, token)
	if invalidPassword.Code != http.StatusBadRequest || requestCount != 0 {
		t.Fatalf("Steam password line break status=%d attach requests=%d body=%s", invalidPassword.Code, requestCount, invalidPassword.Body.String())
	}

	password := "steam-password-that-must-not-persist"
	requestBody, err := json.Marshal(map[string]string{"username": "steam-user", "password": password})
	if err != nil {
		t.Fatal(err)
	}
	send := testRequest(handler, http.MethodPost, "/api/steam/send-code", string(requestBody), token)
	if send.Code != http.StatusOK || strings.Contains(send.Body.String(), password) || !strings.Contains(send.Body.String(), `"needs_code":true`) {
		t.Fatalf("Steam Guard send response status=%d body=%s", send.Code, send.Body.String())
	}
	var storedUsername, authorizedAt string
	var authorized int
	if err = d.QueryRow(`SELECT username,authorized,authorized_at FROM steam_account WHERE id=1`).Scan(&storedUsername, &authorized, &authorizedAt); err != nil || storedUsername != "steam-user" || authorized != 0 || authorizedAt != "" {
		t.Fatalf("pending Steam account state username=%q authorized=%d at=%q err=%v", storedUsername, authorized, authorizedAt, err)
	}
	status := testRequest(handler, http.MethodGet, "/api/steam/account", "", token)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"needs_code":true`) || strings.Contains(status.Body.String(), password) {
		t.Fatalf("pending Steam account API status=%d body=%s", status.Code, status.Body.String())
	}
	var persisted string
	if err = d.QueryRow(`SELECT username||'|'||authorized||'|'||authorized_at FROM steam_account WHERE id=1`).Scan(&persisted); err != nil || strings.Contains(persisted, password) {
		t.Fatalf("Steam password was persisted: %q err=%v", persisted, err)
	}

	code := "QWERT"
	authorizedResponse := testRequest(handler, http.MethodPost, "/api/steam/authorize", `{"code":"`+code+`"}`, token)
	if authorizedResponse.Code != http.StatusOK || strings.Contains(authorizedResponse.Body.String(), password) || strings.Contains(authorizedResponse.Body.String(), code) {
		t.Fatalf("Steam authorization response status=%d body=%s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	if err = d.QueryRow(`SELECT username,authorized,authorized_at FROM steam_account WHERE id=1`).Scan(&storedUsername, &authorized, &authorizedAt); err != nil || storedUsername != "steam-user" || authorized != 1 || authorizedAt == "" {
		t.Fatalf("authorized Steam account state username=%q authorized=%d at=%q err=%v", storedUsername, authorized, authorizedAt, err)
	}
	if len(created) != 2 || len(attached) != 2 {
		t.Fatalf("Steam Guard flow created %d auth containers and %d streams; want 2 each", len(created), len(attached))
	}
	for index, config := range created {
		encoded, _ := json.Marshal(config)
		if bytes.Contains(encoded, []byte(password)) || bytes.Contains(encoded, []byte(code)) {
			t.Fatalf("Steam auth container %d persisted a password or Guard code in Docker config: %s", index, encoded)
		}
		if config.Image != steamCMDImage || config.Env == nil || !steamHas(config.Env, "HOME=/steamcache") || !steamHas(config.Env, "STEAM_USER=steam-user") || !steamHas(config.HostConfig.Binds, app.steamCachePath()+":/steamcache") {
			t.Fatalf("Steam auth container %d missing expected image, environment or persistent cache mount: %#v", index, config)
		}
	}
	if got := attached[0].written.String(); got != password+"\n\n" {
		t.Fatalf("Steam send-code stdin=%q, want password and empty code", got)
	}
	if got := attached[1].written.String(); got != password+"\n"+code+"\n" {
		t.Fatalf("Steam authorize stdin=%q, want password and one-time code", got)
	}
	var auditCount int
	if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE action IN ('steam.account.code_requested','steam.account.authorize')`).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("Steam Guard audit records=%d err=%v, want 2", auditCount, err)
	}
	if err = os.MkdirAll(app.steamCachePath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(app.steamCachePath(), "sentry-marker"), []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	removed := testRequest(handler, http.MethodDelete, "/api/steam/account", "", token)
	if removed.Code != http.StatusOK || strings.Contains(removed.Body.String(), password) {
		t.Fatalf("Steam account removal status=%d body=%s", removed.Code, removed.Body.String())
	}
	if _, err = os.Lstat(app.steamCachePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Steam cache survived account removal: %v", err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM steam_account WHERE id=1 AND username='' AND authorized=0 AND authorized_at=''`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("Steam account row was not cleared: count=%d err=%v", auditCount, err)
	}
}

func TestSteamInstallEnvironmentAndOneToOnePorts(t *testing.T) {
	app, d, _ := testApp(t)
	steamRune := parseSteamTestRune()
	if _, err := app.steamInstallEnv(steamRune, map[string]string{"HOME": "/data"}); err == nil || !strings.Contains(err.Error(), "Settings → Steam") {
		t.Fatalf("Steam install without account authorization: %v", err)
	}
	serverDataDir := filepath.Join(app.dataRoot, "steam-no-account")
	_, installErr := app.runInstallData(context.Background(), Server{ID: "steam-no-account", Name: "Steam test", DataDir: serverDataDir}, steamRune, &installJob{})
	if installErr == nil || !strings.Contains(installErr.Error(), "This game requires an authorized Steam account.") {
		t.Fatalf("Steam install without authorization returned error %v", installErr)
	}
	serverInfo, err := os.Stat(serverDataDir)
	if err != nil || serverInfo == nil || serverInfo.Mode().Perm() != 0777 {
		t.Fatalf("Steam data directory after blocked install has info=%v err=%v, want mode 0777", serverInfo, err)
	}
	if _, err := d.Exec(`UPDATE steam_account SET username='authorized-user',authorized=1,authorized_at='2026-11-01T00:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	installedEnv, err := app.steamInstallEnv(steamRune, map[string]string{"HOME": "/data"})
	if err != nil || installedEnv["HOME"] != "/steamcache" || installedEnv["STEAM_USER"] != "authorized-user" {
		t.Fatalf("authorized Steam install env=%v err=%v", installedEnv, err)
	}
	steamRune.Steam.Anonymous = true
	anonymousEnv, err := app.steamInstallEnv(steamRune, map[string]string{"HOME": "/data"})
	if err != nil || anonymousEnv["HOME"] != "/steamcache" || anonymousEnv["STEAM_USER"] != "" {
		t.Fatalf("anonymous Steam install env=%v err=%v", anonymousEnv, err)
	}

	app.portAvailableCheck = func(int, string) (bool, error) { return true, nil }
	ports, err := app.allocatePorts("steam-fixed-port-a", []gameskill.Port{{Name: "game", Default: 7777, Protocol: "udp"}}, true)
	if err != nil || ports["game"] != 7777 {
		t.Fatalf("Steam one-to-one port allocation=%v err=%v, want 7777 outside the configured range", ports, err)
	}
	steamRune.Ports = []gameskill.Port{{Name: "game", Default: 7777, Protocol: "udp"}}
	config, err := app.containerConfig(Server{ID: "steam-fixed-port-a", DataDir: filepath.Join(app.dataRoot, "steam-fixed-port-a"), Ports: ports}, steamRune, map[string]string{"HOME": "/data"})
	if err != nil || len(config.HostConfig.PortBindings["7777/udp"]) != 1 || config.HostConfig.PortBindings["7777/udp"][0].HostPort != "7777" {
		t.Fatalf("Steam port binding config=%#v err=%v, want host and container port 7777", config.HostConfig.PortBindings, err)
	}
	if _, err = app.allocatePorts("steam-fixed-port-b", []gameskill.Port{{Name: "game", Default: 7777, Protocol: "udp"}}, true); err == nil || !strings.Contains(err.Error(), "already owns it") {
		t.Fatalf("second Steam server reused port 7777: %v", err)
	}
}

func TestSteamInstallerUsesPersistentCacheAndWritableData(t *testing.T) {
	app, d, _ := testApp(t)
	if _, err := d.Exec(`UPDATE steam_account SET username='installer-account',authorized=1,authorized_at='2026-11-01T00:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var config docker.CreateConfig
	client := &http.Client{Transport: steamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := func(status int, body string) *http.Response {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/images/create":
			return response(http.StatusOK, `{"status":"Pulled"}`+"\n"), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/create":
			var created docker.CreateConfig
			if err := json.NewDecoder(request.Body).Decode(&created); err != nil {
				return nil, err
			}
			if created.Image == "example/app:1" {
				config = created
			}
			return response(http.StatusCreated, `{"Id":"steam-installer"}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/steam-installer/start":
			return response(http.StatusNoContent, ""), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1.45/containers/steam-installer/logs":
			return response(http.StatusOK, string(steamDockerFrame("installer ready"))), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1.45/containers/steam-installer/wait":
			return response(http.StatusOK, `{"StatusCode":0}`), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/v1.45/containers/steam-installer":
			return response(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected installer Docker request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	app.engine = docker.NewWithHTTPClient("steam-install-test", "1.45", client)
	server := Server{ID: "steam-installer-test", Name: "Steam installer", GameskillID: "steam-test", DataDir: filepath.Join(app.dataRoot, "steam-installer-test"), Ports: map[string]int{"game": 27015}}
	installerRune := parseSteamTestRune()
	installerRune.Install.Script = `steamcmd +login "$STEAM_USER"`
	installerRune.Ports = []gameskill.Port{{Name: "game", Default: 27015, Protocol: "udp"}}
	if _, err := app.runInstallData(context.Background(), server, installerRune, &installJob{}); err != nil {
		t.Fatalf("Steam install returned error: %v", err)
	}
	if !reflect.DeepEqual(config.Entrypoint, []string{"/bin/sh", "-c"}) || len(config.Cmd) != 1 || !strings.Contains(config.Cmd[0], "trap 'chmod -R a+rwX /data 2>/dev/null || true' EXIT") || !strings.Contains(config.Cmd[0], "chmod -R a+rwX /data 2>/dev/null || true\nsteamcmd +login") {
		t.Fatalf("Steam installer shell or writable-data handling is missing: entrypoint=%#v command=%#v", config.Entrypoint, config.Cmd)
	}
	if !steamHas(config.Env, "HOME=/steamcache") || !steamHas(config.Env, "STEAM_USER=installer-account") {
		t.Fatalf("Steam install environment is missing cache home or account: %#v", config.Env)
	}
	if !steamHas(config.HostConfig.Binds, server.DataDir+":/data") || !steamHas(config.HostConfig.Binds, app.steamCachePath()+":/steamcache") {
		t.Fatalf("Steam installer mounts are incorrect: %#v", config.HostConfig.Binds)
	}
	dataInfo, err := os.Stat(server.DataDir)
	if err != nil {
		t.Fatalf("Steam host app data stat failed: %v", err)
	}
	if dataInfo.Mode().Perm() != 0777 {
		t.Fatalf("Steam host app data mode=%v, want 0777", dataInfo.Mode().Perm())
	}
	cacheInfo, err := os.Stat(app.steamCachePath())
	if err != nil {
		t.Fatalf("Steam cache stat failed: %v", err)
	}
	if cacheInfo.Mode().Perm() != 0777 {
		t.Fatalf("Steam cache mode=%v, want 0777", cacheInfo.Mode().Perm())
	}
}

func TestSteamOutputBufferKeepsTheNewestOutput(t *testing.T) {
	var buffer steamOutputBuffer
	_, _ = buffer.Write([]byte(strings.Repeat("x", steamOutputLimit)))
	_, _ = buffer.Write([]byte("Waiting for user info...OK"))
	if !buffer.truncated || !steamLoginSucceeded(string(buffer.data)) {
		t.Fatal("Steam output buffer discarded the final login result")
	}
}

func TestExpiredSteamLoginIsClearedOnRead(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	pending := &steamPendingLogin{username: "expired-user", password: []byte("secret"), expires: time.Now().Add(-time.Second)}
	app.steamPending = pending
	status := testRequest(app.Router(), http.MethodGet, "/api/steam/account", "", token)
	if status.Code != http.StatusOK || strings.Contains(status.Body.String(), `"needs_code":true`) {
		t.Fatalf("expired Steam login status=%d body=%s", status.Code, status.Body.String())
	}
	if app.steamPending != nil || !bytes.Equal(pending.password, []byte{0, 0, 0, 0, 0, 0}) {
		t.Fatalf("expired Steam login remained in memory: pending=%#v password=%v", app.steamPending, pending.password)
	}
}

func parseSteamTestRune() gameskill.Rune {
	return gameskill.Rune{ID: "steam-test", Name: "Steam test", Docker: gameskill.Docker{Image: "example/app:1", KeepEntrypoint: true}, Install: &gameskill.Install{Script: "steamcmd +login"}, Startup: gameskill.Startup{Exec: []string{"run"}}, Steam: &gameskill.Steam{AppID: 123, Anonymous: false}}
}

func steamHas(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
