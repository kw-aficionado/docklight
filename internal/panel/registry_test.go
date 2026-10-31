package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/security"
)

func TestNormalizeRegistryNamesAndDockerImageReferences(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		bad   bool
	}{
		{"Gitea.Example.com", "gitea.example.com", false},
		{"https://INDEX.DOCKER.IO/v1/", "docker.io", false},
		{"registry-1.docker.io", "docker.io", false},
		{"dockerhub", "docker.io", false},
		{"registry.example.com:05000", "registry.example.com:5000", false},
		{"[2001:db8::1]:5000", "[2001:db8::1]:5000", false},
		{"registry.example.com:0", "", true},
		{"https://registry.example.com/private", "", true},
	} {
		got, err := normalizeRegistryName(test.input)
		if test.bad {
			if err == nil {
				t.Errorf("normalizeRegistryName(%q) = %q, want error", test.input, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Errorf("normalizeRegistryName(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, test := range []struct{ image, want string }{
		{"nginx:latest", "docker.io"},
		{"team/nginx:latest", "docker.io"},
		{"ghcr.io/team/private:1", "ghcr.io"},
		{"localhost:5000/app", "localhost:5000"},
		{"Registry.Example.com/team/app", "registry.example.com"},
		{"registry/team/app", "docker.io"},
	} {
		got, err := imageRegistry(test.image)
		if err != nil || got != test.want {
			t.Errorf("imageRegistry(%q) = %q, %v; want %q", test.image, got, err, test.want)
		}
	}
}

func TestRegistryLoginIsEncryptedMaskedAndReplacedByNormalizedRegistry(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	handler := app.Router()
	requestBody := func(registry, username, secret string) string {
		data, err := json.Marshal(registryLoginInput{Registry: registry, Username: username, Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	created := testRequest(handler, http.MethodPost, "/api/registry-logins", requestBody("Gitea.Example.com", "docklight", "first-private-pat"), token)
	if created.Code != http.StatusOK || strings.Contains(created.Body.String(), "first-private-pat") {
		t.Fatalf("create login status=%d response=%s", created.Code, created.Body.String())
	}
	var summary registryLogin
	if err := json.Unmarshal(created.Body.Bytes(), &summary); err != nil || summary.ID == "" || summary.Registry != "gitea.example.com" || !summary.HasSecret {
		t.Fatalf("login summary=%s err=%v", created.Body.String(), err)
	}
	var encrypted string
	if err := d.QueryRow(`SELECT secret_enc FROM registry_logins WHERE id=?`, summary.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, "first-private-pat") {
		t.Fatalf("registry secret was not encrypted at rest: %q", encrypted)
	}
	plain, err := security.Decrypt([]byte(app.cfg.Auth.SecretKey), encrypted)
	if err != nil || plain != "first-private-pat" {
		t.Fatalf("decrypted registry secret=%q err=%v", plain, err)
	}
	replaced := testRequest(handler, http.MethodPost, "/api/registry-logins", requestBody("https://GITEA.EXAMPLE.COM", "new-user", "replacement-private-pat"), token)
	if replaced.Code != http.StatusOK || strings.Contains(replaced.Body.String(), "replacement-private-pat") {
		t.Fatalf("replace login status=%d response=%s", replaced.Code, replaced.Body.String())
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM registry_logins`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("normalized registry upsert created %d entries: %v", count, err)
	}
	var gotID, username string
	if err = d.QueryRow(`SELECT id,username FROM registry_logins WHERE registry='gitea.example.com'`).Scan(&gotID, &username); err != nil || gotID != summary.ID || username != "new-user" {
		t.Fatalf("registry record was not replaced in place: id=%q username=%q err=%v", gotID, username, err)
	}
	listed := testRequest(handler, http.MethodGet, "/api/registry-logins", "", token)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "replacement-private-pat") || !strings.Contains(listed.Body.String(), `"has_secret":true`) {
		t.Fatalf("list response leaked or omitted secret mask: %d %s", listed.Code, listed.Body.String())
	}
	var saves int
	if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE action='registry_login.save' AND target_id=?`, summary.ID).Scan(&saves); err != nil || saves != 2 {
		t.Fatalf("registry save audit count=%d err=%v", saves, err)
	}
	var auditDetail string
	if err = d.QueryRow(`SELECT detail FROM audit_log WHERE action='registry_login.save' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail); err != nil || strings.Contains(auditDetail, "replacement-private-pat") {
		t.Fatalf("registry audit included a secret: %q err=%v", auditDetail, err)
	}
	removed := testRequest(handler, http.MethodDelete, "/api/registry-logins/"+summary.ID, "", token)
	if removed.Code != http.StatusOK {
		t.Fatalf("delete registry login status=%d body=%s", removed.Code, removed.Body.String())
	}
	var deletes int
	if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE action='registry_login.delete' AND target_id=?`, summary.ID).Scan(&deletes); err != nil || deletes != 1 {
		t.Fatalf("registry delete audit count=%d err=%v", deletes, err)
	}
}

func TestRegistryPullUsesOnlyMatchingCredentials(t *testing.T) {
	app, d, _ := testApp(t)
	encrypted, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), "ghcr-private-pat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO registry_logins(id,registry,username,secret_enc) VALUES('ghcr-login','ghcr.io','registry-user',?)`, encrypted); err != nil {
		t.Fatal(err)
	}
	var seen int
	app.engine = docker.NewWithHTTPClient("test-socket", "1.45", &http.Client{Transport: runeCatalogRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen++
		if req.URL.Path != "/v1.45/images/create" {
			t.Fatalf("unexpected pull URL: %s", req.URL.String())
		}
		if req.URL.Query().Get("fromImage") == "ghcr.io/team/private:1" {
			authHeader := req.Header.Get("X-Registry-Auth")
			decoded, decodeErr := base64.URLEncoding.DecodeString(authHeader)
			if decodeErr != nil {
				t.Fatalf("matching pull lacks valid credentials: %v", decodeErr)
			}
			var auth docker.RegistryAuthConfig
			if decodeErr = json.Unmarshal(decoded, &auth); decodeErr != nil || auth.Username != "registry-user" || auth.Password != "ghcr-private-pat" || auth.ServerAddress != "ghcr.io" {
				t.Fatalf("wrong matched credentials: %#v err=%v", auth, decodeErr)
			}
		} else if req.Header.Get("X-Registry-Auth") != "" {
			t.Fatalf("credentials were sent to a different registry: %s", req.URL.Query().Get("fromImage"))
		}
		return runeCatalogResponse(req, http.StatusOK, `{"status":"Pulled"}`), nil
	})})
	if err = app.pullImage(context.Background(), "ghcr.io/team/private:1"); err != nil {
		t.Fatal(err)
	}
	if err = app.pullImage(context.Background(), "public.example.com/team/app:1"); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("expected two image pulls, saw %d", seen)
	}
}

func TestRegistryLoginTestUsesDockerAuthEndpointWithoutReturningCredential(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	secret := "docker-hub-pat"
	encrypted, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO registry_logins(id,registry,username,secret_enc) VALUES('hub-login','docker.io','hub-user',?)`, encrypted); err != nil {
		t.Fatal(err)
	}
	var checked bool
	app.engine = docker.NewWithHTTPClient("test-socket", "1.45", &http.Client{Transport: runeCatalogRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1.45/auth" {
			t.Fatalf("unexpected auth test request: %s %s", req.Method, req.URL.Path)
		}
		var auth docker.RegistryAuthConfig
		if err := json.NewDecoder(req.Body).Decode(&auth); err != nil {
			t.Fatal(err)
		}
		checked = auth.Username == "hub-user" && auth.Password == secret && auth.ServerAddress == "https://index.docker.io/v1/"
		return runeCatalogResponse(req, http.StatusOK, `{"Status":"Login Succeeded","IdentityToken":"must-not-be-returned"}`), nil
	})})
	response := testRequest(app.Router(), http.MethodPost, "/api/registry-logins/hub-login/test", `{}`, token)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ok":true`) || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "must-not-be-returned") || !checked {
		t.Fatalf("registry login test response=%d %s checked=%t", response.Code, response.Body.String(), checked)
	}
}

func TestRegistryLoginEndpointsRequireAdmin(t *testing.T) {
	app, d, _ := testApp(t)
	hash, err := security.HashPassword("registry-user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('registry-user','registry-user',?,'user')`, hash); err != nil {
		t.Fatal(err)
	}
	token, err := app.issue(User{ID: "registry-user", Username: "registry-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	response := testRequest(app.Router(), http.MethodGet, "/api/registry-logins", "", token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-admin registry list status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRegistryImagePullRouteDoesNotPutCredentialsInURL(t *testing.T) {
	app, d, _ := testApp(t)
	encrypted, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), "url-private-pat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO registry_logins(id,registry,username,secret_enc) VALUES('route-login','example.com','user',?)`, encrypted); err != nil {
		t.Fatal(err)
	}
	app.engine = docker.NewWithHTTPClient("test-socket", "1.45", &http.Client{Transport: runeCatalogRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		parsed, parseErr := url.Parse(req.URL.String())
		if parseErr != nil || strings.Contains(parsed.String(), "url-private-pat") || strings.Contains(req.URL.RawQuery, "secret") {
			t.Fatalf("pull URL exposed credentials: %s", req.URL.String())
		}
		return runeCatalogResponse(req, http.StatusOK, `{"status":"Pulled"}`), nil
	})})
	if err = app.pullImage(context.Background(), "example.com/private:1"); err != nil {
		t.Fatal(err)
	}
}
