package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/config"
	"example.com/yggdrasil-panel/internal/db"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

func testApp(t *testing.T) (*App, *sql.DB, config.Config) {
	t.Helper()
	root := t.TempDir()
	c := config.Defaults()
	c.Database.Path = filepath.Join(root, "panel.db")
	c.Auth.SecretKey = "test-session-secret-32-bytes-minimum-value"
	c.Docker.Socket = "unix:///not-a-docker-socket"
	d, err := db.Open(c.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err = UpsertBuiltins(d); err != nil {
		t.Fatal(err)
	}
	return New(c, filepath.Join(root, "config.yaml"), d), d, c
}
func testRequest(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSameOriginChecksSchemeAndHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://panel.example/api/logout", nil)
	for _, tc := range []struct {
		origin string
		ok     bool
	}{
		{"http://panel.example", true},
		{"https://panel.example", false},
		{"http://other.example", false},
		{"http://panel.example/path", false},
	} {
		if got := sameOrigin(r, tc.origin); got != tc.ok {
			t.Errorf("sameOrigin(%q) = %t, want %t", tc.origin, got, tc.ok)
		}
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if !sameOrigin(r, "https://panel.example") {
		t.Fatal("same-origin request behind HTTPS reverse proxy was rejected")
	}
}

func TestEmbeddedUIAndHealthRoutes(t *testing.T) {
	a, _, _ := testApp(t)
	h := a.Router()
	for _, tc := range []struct {
		path, contentType, bodyContains string
	}{
		{"/", "text/html; charset=utf-8", `<div id="app"`},
		{"/app.js", "text/javascript; charset=utf-8", `from './ui-utils.mjs'`},
		{"/ui-utils.mjs", "text/javascript; charset=utf-8", `export function escapeHTML`},
		{"/style.css", "text/css; charset=utf-8", `--bg`},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != tc.contentType || w.Header().Get("Cache-Control") != "no-cache" || !strings.Contains(w.Body.String(), tc.bodyContains) {
			t.Errorf("GET %s: status=%d content-type=%q cache-control=%q body contains %q: %t", tc.path, w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"), tc.bodyContains, strings.Contains(w.Body.String(), tc.bodyContains))
		}
	}
	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("health endpoint: %d %s", health.Code, health.Body.String())
	}
}

func TestRBACIsEnforcedOnListControlAndFiles(t *testing.T) {
	a, d, _ := testApp(t)
	adminHash, err := security.HashPassword("not-used-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	userHash, err := security.HashPassword("a test user password 2026")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('admin','admin',?,'admin')`, adminHash)
	_, _ = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('user','limited',?,'user')`, userHash)
	for _, id := range []string{"server-a", "server-b"} {
		dir := filepath.Join(a.dataRoot, id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "world.txt"), []byte("server data"), 0600); err != nil {
			t.Fatal(err)
		}
		env := `{}`
		if id == "server-a" {
			secret, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "a-very-private-cloudflare-token")
			if err != nil {
				t.Fatal(err)
			}
			env = fmt.Sprintf(`{"TUNNEL_TOKEN":%q}`, secret)
		}
		if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?,'cloudflared','stopped',1,?,'{}',?)`, id, id, env, dir); err != nil {
			t.Fatal(err)
		}
	}
	_, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('user','server','server-a','server.view,server.control,server.console,server.files')`)
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	login := testRequest(h, http.MethodPost, "/api/login", `{"username":"limited","password":"a test user password 2026"}`, "")
	if login.Code != 200 {
		t.Fatalf("sign-in status %d: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(login.Body.Bytes(), &session); err != nil || session.Token == "" {
		t.Fatalf("login did not return session token: %v", err)
	}
	if strings.Contains(login.Body.String(), "a test user password 2026") {
		t.Fatal("login response returned the password")
	}
	list := testRequest(h, http.MethodGet, "/api/servers", "", session.Token)
	if list.Code != 200 {
		t.Fatalf("list status %d: %s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), "server-b") {
		t.Fatalf("server without view grant leaked in list: %s", list.Body.String())
	}
	if !strings.Contains(list.Body.String(), "server-a") {
		t.Fatalf("server with view grant missing: %s", list.Body.String())
	}
	var visible []Server
	if err = json.Unmarshal(list.Body.Bytes(), &visible); err != nil || len(visible) != 1 {
		t.Fatalf("could not decode visible server permissions: %v", err)
	}
	if len(visible[0].Permissions) != 4 || !slices.Contains(visible[0].Permissions, "server.view") || !slices.Contains(visible[0].Permissions, "server.control") || slices.Contains(visible[0].Permissions, "server.delete") {
		t.Fatalf("server response did not contain effective permissions: %#v", visible[0].Permissions)
	}
	if strings.Contains(list.Body.String(), "a-very-private-cloudflare-token") {
		t.Fatal("secret value leaked in server list")
	}
	for _, tc := range []struct{ method, path, body string }{{http.MethodGet, "/api/servers/server-b", ""}, {http.MethodPost, "/api/servers/server-b/start", "{}"}, {http.MethodGet, "/api/servers/server-b/files?path=", ""}} {
		w := testRequest(h, tc.method, tc.path, tc.body, session.Token)
		if w.Code != 403 {
			t.Errorf("%s %s: expected 403, got %d body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	files := testRequest(h, http.MethodGet, "/api/servers/server-a/files?path=", "", session.Token)
	if files.Code != 200 {
		t.Fatalf("authorized files status %d: %s", files.Code, files.Body.String())
	}
	if !strings.Contains(files.Body.String(), "world.txt") {
		t.Fatalf("expected one file in authorized data directory, got %s", files.Body.String())
	}
}

func TestAPITokensAreShownOnceAndIntersectUserPermissions(t *testing.T) {
	a, d, _ := testApp(t)
	hash, err := security.HashPassword("a long test credential 2026")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('api-user','api-user',?,'user')`, hash); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"token-server-a", "token-server-b"} {
		dir := filepath.Join(a.dataRoot, id)
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES(?,?,'uptime-kuma','stopped',1,'{}','{}',?)`, id, id, dir); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('api-user','server','token-server-a','server.view')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "api-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	created := testRequest(h, http.MethodPost, "/api/tokens", `{"name":"automation","scopes":["server.view","server.control"]}`, session)
	if created.Code != http.StatusCreated {
		t.Fatalf("token create: %d %s", created.Code, created.Body.String())
	}
	var out struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &out); err != nil || out.ID == "" || !strings.HasPrefix(out.Token, "ygg_") {
		t.Fatalf("invalid create response: %v %s", err, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "a long test credential 2026") {
		t.Fatal("API response exposed the account password")
	}
	list := testRequest(h, http.MethodGet, "/api/servers", "", out.Token)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "token-server-a") || strings.Contains(list.Body.String(), "token-server-b") {
		t.Fatalf("token did not stay within server grants: %d %s", list.Code, list.Body.String())
	}
	var tokenServers []Server
	if err = json.Unmarshal(list.Body.Bytes(), &tokenServers); err != nil || len(tokenServers) != 1 || len(tokenServers[0].Permissions) != 1 || tokenServers[0].Permissions[0] != "server.view" {
		t.Fatalf("API token permissions were not intersected with account grants: %v %#v", err, tokenServers)
	}
	control := testRequest(h, http.MethodPost, "/api/servers/token-server-a/start", `{}`, out.Token)
	if control.Code != 403 {
		t.Fatalf("token escaped account grants for control: %d %s", control.Code, control.Body.String())
	}
	admin := testRequest(h, http.MethodGet, "/api/users", "", out.Token)
	if admin.Code != 403 {
		t.Fatalf("user API token reached admin API: %d %s", admin.Code, admin.Body.String())
	}
	queryToken := testRequest(h, http.MethodGet, "/api/me?token="+out.Token, "", "")
	if queryToken.Code != 401 {
		t.Fatalf("URL token authentication was accepted: %d", queryToken.Code)
	}
	manageWithToken := testRequest(h, http.MethodGet, "/api/tokens", "", out.Token)
	if manageWithToken.Code != 403 {
		t.Fatalf("API token managed itself: %d", manageWithToken.Code)
	}
	listedTokens := testRequest(h, http.MethodGet, "/api/tokens", "", session)
	if listedTokens.Code != 200 || strings.Contains(listedTokens.Body.String(), out.Token) {
		t.Fatalf("token listing returned plaintext: %d %s", listedTokens.Code, listedTokens.Body.String())
	}
	revoked := testRequest(h, http.MethodDelete, "/api/tokens/"+out.ID, "", session)
	if revoked.Code != 200 {
		t.Fatalf("token revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	afterRevoke := testRequest(h, http.MethodGet, "/api/me", "", out.Token)
	if afterRevoke.Code != 401 {
		t.Fatalf("revoked token remained valid: %d", afterRevoke.Code)
	}
}

func TestLocalBackupsRequirePermissionAndRestoreVerifiedData(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('backup-user','backup-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(a.dataRoot, "backup-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	const original = "world snapshot that must stay private"
	if err := os.WriteFile(filepath.Join(dataDir, "world.dat"), []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('backup-server','Backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	otherDir := filepath.Join(a.dataRoot, "backup-other")
	if err := os.MkdirAll(otherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('backup-other','Other server','minecraft-java','stopped',1,'{}','{}',?)`, otherDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('backup-user','server','backup-server','server.view')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "backup-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	denied := testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", session)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("server.view alone reached backup list: %d %s", denied.Code, denied.Body.String())
	}
	createdToken := testRequest(h, http.MethodPost, "/api/tokens", `{"name":"backup token","scopes":["server.backup"]}`, session)
	if createdToken.Code != http.StatusCreated {
		t.Fatalf("create scoped token: %d %s", createdToken.Code, createdToken.Body.String())
	}
	var token struct {
		Value string `json:"token"`
	}
	if err = json.Unmarshal(createdToken.Body.Bytes(), &token); err != nil || token.Value == "" {
		t.Fatalf("decode scoped token: %v %s", err, createdToken.Body.String())
	}
	tokenDenied := testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", token.Value)
	if tokenDenied.Code != http.StatusForbidden {
		t.Fatalf("API token scope bypassed the account grant: %d %s", tokenDenied.Code, tokenDenied.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.view,server.backup' WHERE user_id='backup-user' AND scope_type='server' AND scope_id='backup-server'`); err != nil {
		t.Fatal(err)
	}
	otherDenied := testRequest(h, http.MethodPost, "/api/servers/backup-other/backups", `{}`, session)
	if otherDenied.Code != http.StatusForbidden {
		t.Fatalf("user backed up a server outside its grant: %d %s", otherDenied.Code, otherDenied.Body.String())
	}

	create := func() backupRecord {
		t.Helper()
		response := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups", `{}`, session)
		if response.Code != http.StatusCreated {
			t.Fatalf("create local backup: %d %s", response.Code, response.Body.String())
		}
		var result struct {
			Backup backupRecord `json:"backup"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Backup.ID == "" {
			t.Fatalf("decode backup response: %v %s", err, response.Body.String())
		}
		return result.Backup
	}
	first := create()
	backupPath := filepath.Join(a.backupRoot, "backup-server", first.ID+backupExtension)
	archive, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive, []byte(original)) {
		t.Fatal("encrypted local backup contains the original plaintext")
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", session)
	var backups []backupRecord
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &backups) != nil || len(backups) != 1 || backups[0].ID != first.ID {
		t.Fatalf("backup list did not return the stored record: %d %s", listed.Code, listed.Body.String())
	}
	verified := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups/"+first.ID+"/verify", `{}`, session)
	if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"valid":true`) || !strings.Contains(verified.Body.String(), `"files":1`) {
		t.Fatalf("verify did not report the expected archived file: %d %s", verified.Code, verified.Body.String())
	}
	if err = os.WriteFile(filepath.Join(dataDir, "world.dat"), []byte("newer live data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dataDir, "after-backup.txt"), []byte("keep this file"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups/"+first.ID+"/restore", `{}`, session)
	if restored.Code != http.StatusOK {
		t.Fatalf("restore backup: %d %s", restored.Code, restored.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "world.dat"))
	if err != nil || string(data) != original {
		t.Fatalf("restored file=%q err=%v; want original contents", data, err)
	}
	if retained, readErr := os.ReadFile(filepath.Join(dataDir, "after-backup.txt")); readErr != nil || string(retained) != "keep this file" {
		t.Fatalf("restore removed a file absent from the archive: contents=%q err=%v", retained, readErr)
	}
	if !strings.Contains(restored.Body.String(), `"restored":true`) {
		t.Fatalf("restore response missing success status: %s", restored.Body.String())
	}

	a.cfg.Backups.Retention = 2
	second := create()
	third := create()
	if !(first.CreatedAt < second.CreatedAt && second.CreatedAt < third.CreatedAt) {
		t.Fatalf("backup timestamps do not sort chronologically: %q, %q, %q", first.CreatedAt, second.CreatedAt, third.CreatedAt)
	}
	listed = testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", session)
	backups = nil
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &backups) != nil || len(backups) != 2 {
		t.Fatalf("automatic retention did not keep two backups: %d %s", listed.Code, listed.Body.String())
	}
	if _, err = os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("automatic retention left the oldest backup file behind: %v", err)
	}
	pruned := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups/prune", `{"keep":1}`, session)
	if pruned.Code != http.StatusOK || !strings.Contains(pruned.Body.String(), `"removed":1`) || !strings.Contains(pruned.Body.String(), `"remaining":1`) {
		t.Fatalf("prune did not remove the older backup: %d %s", pruned.Code, pruned.Body.String())
	}
	listed = testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", session)
	backups = nil
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &backups) != nil || len(backups) != 1 || backups[0].ID != third.ID || second.ID == third.ID {
		t.Fatalf("retention kept the wrong backup: %d %s", listed.Code, listed.Body.String())
	}

	file, err := os.OpenFile(filepath.Join(a.backupRoot, "backup-server", third.ID+backupExtension), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var last [1]byte
	if _, err = file.ReadAt(last[:], third.SizeBytes-1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	last[0] ^= 0xff
	if _, err = file.WriteAt(last[:], third.SizeBytes-1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups/"+third.ID+"/verify", `{}`, session)
	if corrupt.Code != http.StatusUnprocessableEntity {
		t.Fatalf("verification accepted a modified archive: %d %s", corrupt.Code, corrupt.Body.String())
	}
	beforeCorruptRestore, err := os.ReadFile(filepath.Join(dataDir, "world.dat"))
	if err != nil {
		t.Fatal(err)
	}
	corruptRestore := testRequest(h, http.MethodPost, "/api/servers/backup-server/backups/"+third.ID+"/restore", `{}`, session)
	if corruptRestore.Code != http.StatusUnprocessableEntity {
		t.Fatalf("restore accepted a modified archive: %d %s", corruptRestore.Code, corruptRestore.Body.String())
	}
	afterCorruptRestore, err := os.ReadFile(filepath.Join(dataDir, "world.dat"))
	if err != nil || !bytes.Equal(afterCorruptRestore, beforeCorruptRestore) {
		t.Fatalf("corrupt restore changed current data: before=%q after=%q err=%v", beforeCorruptRestore, afterCorruptRestore, err)
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/backup-server/backups/"+third.ID, `{}`, session)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete backup: %d %s", deleted.Code, deleted.Body.String())
	}
	if _, err = os.Stat(filepath.Join(a.backupRoot, "backup-server", third.ID+backupExtension)); !os.IsNotExist(err) {
		t.Fatalf("delete left the backup file behind: %v", err)
	}
	listed = testRequest(h, http.MethodGet, "/api/servers/backup-server/backups", "", session)
	backups = nil
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &backups) != nil || len(backups) != 0 {
		t.Fatalf("delete left the backup record behind: %d %s", listed.Code, listed.Body.String())
	}
}

func TestServerBackupCleanupRejectsSymlinkedServerDirectory(t *testing.T) {
	a, _, _ := testApp(t)
	if err := os.MkdirAll(a.backupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	sentinel := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(a.backupRoot, "backup-server")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := a.removeServerBackups("backup-server"); err == nil {
		t.Fatal("server cleanup accepted a symlinked backup directory")
	}
	if content, err := os.ReadFile(sentinel); err != nil || string(content) != "preserve" {
		t.Fatalf("symlink target was changed: content=%q err=%v", content, err)
	}
}

func TestBackupSchedulesRequirePermissionsAndRunFromWorker(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := filepath.Join(a.dataRoot, "scheduled-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "world.dat"), []byte("scheduled world"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('scheduled-server','Scheduled test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('schedule-user','schedule-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "schedule-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	noSchedule := testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules", "", session)
	if noSchedule.Code != http.StatusForbidden {
		t.Fatalf("user without server.schedule listed schedules: %d %s", noSchedule.Code, noSchedule.Body.String())
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('schedule-user','server','scheduled-server','server.schedule')`); err != nil {
		t.Fatal(err)
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules", "", session)
	if listed.Code != http.StatusOK || listed.Body.String() != "[]\n" {
		t.Fatalf("schedule permission could not list schedules: %d %s", listed.Code, listed.Body.String())
	}
	createdToken := testRequest(h, http.MethodPost, "/api/tokens", `{"name":"schedule token","scopes":["server.schedule","server.backup"]}`, session)
	if createdToken.Code != http.StatusCreated {
		t.Fatalf("create schedule token: %d %s", createdToken.Code, createdToken.Body.String())
	}
	var token struct {
		Value string `json:"token"`
	}
	if err = json.Unmarshal(createdToken.Body.Bytes(), &token); err != nil || token.Value == "" {
		t.Fatalf("decode schedule token: %v %s", err, createdToken.Body.String())
	}
	tokenDenied := testRequest(h, http.MethodPost, "/api/servers/scheduled-server/schedules", `{"cron":"* * * * *"}`, token.Value)
	if tokenDenied.Code != http.StatusForbidden {
		t.Fatalf("API token scope bypassed the server.backup grant: %d %s", tokenDenied.Code, tokenDenied.Body.String())
	}
	denied := testRequest(h, http.MethodPost, "/api/servers/scheduled-server/schedules", `{"cron":"* * * * *"}`, session)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("schedule was created without server.backup: %d %s", denied.Code, denied.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule,server.backup' WHERE user_id='schedule-user' AND scope_type='server' AND scope_id='scheduled-server'`); err != nil {
		t.Fatal(err)
	}
	invalid := testRequest(h, http.MethodPost, "/api/servers/scheduled-server/schedules", `{"cron":"90 * * * *"}`, session)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid cron was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/servers/scheduled-server/schedules", `{"name":"Nightly","cron":"* * * * *"}`, session)
	if created.Code != http.StatusCreated {
		t.Fatalf("create backup schedule: %d %s", created.Code, created.Body.String())
	}
	var item backupSchedule
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil || item.ID == "" || !item.Enabled || item.NextRun == "" {
		t.Fatalf("invalid created schedule: %#v err=%v body=%s", item, err, created.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule' WHERE user_id='schedule-user' AND scope_type='server' AND scope_id='scheduled-server'`); err != nil {
		t.Fatal(err)
	}
	deniedEnable := testRequest(h, http.MethodPut, "/api/servers/scheduled-server/schedules/"+item.ID, `{"enabled":true}`, session)
	if deniedEnable.Code != http.StatusForbidden {
		t.Fatalf("schedule was enabled without server.backup: %d %s", deniedEnable.Code, deniedEnable.Body.String())
	}
	disabled := testRequest(h, http.MethodPut, "/api/servers/scheduled-server/schedules/"+item.ID, `{"enabled":false}`, session)
	if disabled.Code != http.StatusOK || !strings.Contains(disabled.Body.String(), `"enabled":false`) || !strings.Contains(disabled.Body.String(), `"next_run":""`) {
		t.Fatalf("disable schedule: %d %s", disabled.Code, disabled.Body.String())
	}
	if _, err = d.Exec(`UPDATE permissions SET perms='server.schedule,server.backup' WHERE user_id='schedule-user' AND scope_type='server' AND scope_id='scheduled-server'`); err != nil {
		t.Fatal(err)
	}
	enabled := testRequest(h, http.MethodPut, "/api/servers/scheduled-server/schedules/"+item.ID, `{"enabled":true}`, session)
	if enabled.Code != http.StatusOK || !strings.Contains(enabled.Body.String(), `"enabled":true`) {
		t.Fatalf("re-enable schedule: %d %s", enabled.Code, enabled.Body.String())
	}
	now := time.Now()
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(now.Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatalf("process due backup schedule: %v", err)
	}
	var backupCount int
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='scheduled-server'`).Scan(&backupCount); err != nil || backupCount != 1 {
		t.Fatalf("scheduled backup count=%d err=%v", backupCount, err)
	}
	runs := testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules/"+item.ID+"/runs", "", session)
	if runs.Code != http.StatusOK || !strings.Contains(runs.Body.String(), `"status":"success"`) || !strings.Contains(runs.Body.String(), `created backup`) {
		t.Fatalf("scheduled run was not recorded: %d %s", runs.Code, runs.Body.String())
	}
	if _, err = d.Exec(`UPDATE servers SET status='running' WHERE id='scheduled-server'`); err != nil {
		t.Fatal(err)
	}
	now = time.Now()
	if _, err = d.Exec(`UPDATE backup_schedules SET next_run=? WHERE id=?`, scheduleTimestamp(now.Add(-time.Second)), item.ID); err != nil {
		t.Fatal(err)
	}
	if err = a.processDueBackupSchedules(context.Background(), now); err != nil {
		t.Fatalf("process running-server schedule: %v", err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='scheduled-server'`).Scan(&backupCount); err != nil || backupCount != 1 {
		t.Fatalf("running server was backed up: backups=%d err=%v", backupCount, err)
	}
	runs = testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules/"+item.ID+"/runs", "", session)
	if runs.Code != http.StatusOK || !strings.Contains(runs.Body.String(), `"status":"error"`) || !strings.Contains(runs.Body.String(), `stop the server`) {
		t.Fatalf("failed scheduled backup outcome was not recorded: %d %s", runs.Code, runs.Body.String())
	}
	scheduleList := testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules", "", session)
	if scheduleList.Code != http.StatusOK || !strings.Contains(scheduleList.Body.String(), `"last_status":"error"`) {
		t.Fatalf("schedule status was not updated: %d %s", scheduleList.Code, scheduleList.Body.String())
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/scheduled-server/schedules/"+item.ID, `{}`, session)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete schedule: %d %s", deleted.Code, deleted.Body.String())
	}
	runs = testRequest(h, http.MethodGet, "/api/servers/scheduled-server/schedules/"+item.ID+"/runs", "", session)
	if runs.Code != http.StatusNotFound {
		t.Fatalf("deleted schedule retained accessible run history: %d %s", runs.Code, runs.Body.String())
	}
}

func TestNameLikeSecretIsEncryptedAndMaskedWithoutRuneFlag(t *testing.T) {
	a, d, _ := testApp(t)
	adminHash, err := security.HashPassword("test admin password 2026")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('secret-admin','secret-admin',?,'admin')`, adminHash); err != nil {
		t.Fatal(err)
	}
	raw := `gameskill:
  id: secret-test
  name: Secret Test
  docker:
    image: example/app:1
  variables:
    - key: DATABASE_PASSWORD
      type: string
      required: true
  startup:
    command: exec app
`
	if _, err = d.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES('secret-test','Secret Test','Apps',1,?,0)`, raw); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "secret-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	created := testRequest(h, http.MethodPost, "/api/servers", `{"name":"secret app","gameskill_id":"secret-test","env":{"DATABASE_PASSWORD":"super-secret-value"}}`, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create server: %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "super-secret-value") || !strings.Contains(created.Body.String(), "********") {
		t.Fatalf("server response did not mask the field-name secret: %s", created.Body.String())
	}
	var stored string
	if err = d.QueryRow(`SELECT env_json FROM servers WHERE name='secret app'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "super-secret-value") || !strings.Contains(stored, "enc:") {
		t.Fatalf("field-name secret was not encrypted in SQLite: %s", stored)
	}
}

func TestUserCanChangeOwnPasswordAndOldSessionIsRevoked(t *testing.T) {
	a, d, _ := testApp(t)
	oldPassword := "the old test password 2026"
	hash, err := security.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('password-user','password-user',?,'user')`, hash); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "password-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	changed := testRequest(h, http.MethodPost, "/api/password", `{"current_password":"the old test password 2026","new_password":"a new test password 2026"}`, session)
	if changed.Code != 200 {
		t.Fatalf("password change: %d %s", changed.Code, changed.Body.String())
	}
	if strings.Contains(changed.Body.String(), "a new test password 2026") {
		t.Fatal("password change response exposed the new password")
	}
	oldSession := testRequest(h, http.MethodGet, "/api/me", "", session)
	if oldSession.Code != 401 {
		t.Fatalf("old session still worked after password change: %d", oldSession.Code)
	}
	oldLogin := testRequest(h, http.MethodPost, "/api/login", `{"username":"password-user","password":"the old test password 2026"}`, "")
	if oldLogin.Code != 401 {
		t.Fatalf("old password still worked: %d", oldLogin.Code)
	}
	newLogin := testRequest(h, http.MethodPost, "/api/login", `{"username":"password-user","password":"a new test password 2026"}`, "")
	if newLogin.Code != 200 {
		t.Fatalf("new password did not work: %d %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestContainerConfigAppliesAllowedDeviceCapabilityAndSysctls(t *testing.T) {
	a, _, _ := testApp(t)
	gs := rune.Rune{ID: "device-app", Name: "Device App", Docker: rune.Docker{Image: "example/app:1", Capabilities: []string{"cap_net_admin"}, Devices: []string{"/dev/net/tun:/dev/net/tun:rwm"}, Sysctls: map[string]string{"net.ipv4.ip_forward": "1"}}, Startup: rune.Startup{Command: "exec app"}}
	config, err := a.containerConfig(Server{ID: "device-server", DataDir: a.dataRoot}, gs, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.HostConfig.CapAdd) != 1 || config.HostConfig.CapAdd[0] != "NET_ADMIN" {
		t.Fatalf("capability was not passed to Docker: %#v", config.HostConfig.CapAdd)
	}
	if len(config.HostConfig.Devices) != 1 || config.HostConfig.Devices[0].PathInContainer != "/dev/net/tun" {
		t.Fatalf("device mapping was not passed to Docker: %#v", config.HostConfig.Devices)
	}
	if config.HostConfig.Sysctls["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("sysctl was not passed to Docker: %#v", config.HostConfig.Sysctls)
	}
}

func TestLoginRequiresEncryptedTOTPAndRejectsCodeReplay(t *testing.T) {
	a, d, _ := testApp(t)
	hash, err := security.HashPassword("totp test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), secret)
	if err != nil {
		t.Fatal(err)
	}
	counter := time.Now().Unix() / 30
	_, err = d.Exec(`INSERT INTO users(id,username,password_hash,role,totp_secret,totp_enabled,totp_last_counter) VALUES('totp-user','totp',?,'user',?,1,?)`, hash, encrypted, counter-1)
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	code, err := security.TOTP(secret, time.Unix(counter*30, 0))
	if err != nil {
		t.Fatal(err)
	}
	without := testRequest(h, http.MethodPost, "/api/login", `{"username":"totp","password":"totp test password 2026"}`, "")
	if without.Code != 401 {
		t.Fatalf("expected TOTP prompt, got %d %s", without.Code, without.Body.String())
	}
	with := testRequest(h, http.MethodPost, "/api/login", fmt.Sprintf(`{"username":"totp","password":"totp test password 2026","totp":%q}`, code), "")
	if with.Code != 200 {
		t.Fatalf("valid TOTP sign-in failed: %d %s", with.Code, with.Body.String())
	}
	replay := testRequest(h, http.MethodPost, "/api/login", fmt.Sprintf(`{"username":"totp","password":"totp test password 2026","totp":%q}`, code), "")
	if replay.Code != 401 {
		t.Fatalf("replayed code accepted: %d %s", replay.Code, replay.Body.String())
	}
}

func TestSafePathRejectsTraversalAndOutsideSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := safePath(root, "../secret", true); err == nil {
		t.Fatal("parent traversal was accepted")
	}
	if _, err := safePath(root, "escape", true); err == nil {
		t.Fatal("symlink outside data directory was accepted")
	}
	inside := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(inside, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := safePath(root, "ok.txt", true)
	expected, _ := filepath.EvalSymlinks(inside)
	if err != nil || got != expected {
		t.Fatalf("safe file rejected: %s %v", got, err)
	}
}

func TestConfigSecretMaskingDoesNotChangeStoredData(t *testing.T) {
	gs := rune.Rune{ID: "secret", Name: "secret", Docker: rune.Docker{Image: "secret:latest"}, Startup: rune.Startup{Command: "exec app"}, Variables: []rune.Variable{{Key: "API_TOKEN", Type: "string", Secret: true, Default: "should-never-be-shown"}}}
	public := publicRune(gs)
	if public.Variables[0].Default != nil {
		t.Fatal("secret rune default was returned")
	}
	if gs.Variables[0].Default != "should-never-be-shown" {
		t.Fatal("masking mutated the stored rune")
	}
	_ = bytes.MinRead
}
