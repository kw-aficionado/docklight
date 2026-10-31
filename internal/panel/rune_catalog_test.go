package panel

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/security"
)

type runeCatalogRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn runeCatalogRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func runeCatalogResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func runeCatalogAdminToken(t *testing.T, app *App, d *sql.DB) string {
	t.Helper()
	hash, err := security.HashPassword("catalog-admin-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('catalog-admin','catalog-admin',?,'admin')`, hash); err != nil {
		t.Fatal(err)
	}
	token, err := app.issue(User{ID: "catalog-admin", Username: "catalog-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func catalogJSONRequest(t *testing.T, handler http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return testRequest(handler, method, path, string(encoded), token)
}

func TestRuneRepoTokensAreEncryptedMaskedAndCleared(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	handler := app.Router()
	created := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos", runeRepoInput{
		Name: "Private templates", Host: "https://git.example.test/gitea", Repo: "ops/catalog", Path: "runes", Ref: "stable", Token: "private-repo-token",
	}, token)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "private-repo-token") {
		t.Fatalf("create repo status=%d response=%s", created.Code, created.Body.String())
	}
	var summary struct {
		ID       string `json:"id"`
		HasToken bool   `json:"has_token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &summary); err != nil || summary.ID == "" || !summary.HasToken {
		t.Fatalf("repo summary=%s err=%v", created.Body.String(), err)
	}
	var encrypted string
	if err := d.QueryRow(`SELECT token_enc FROM rune_repos WHERE id=?`, summary.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, "private-repo-token") {
		t.Fatalf("repository token was not encrypted at rest: %q", encrypted)
	}
	decrypted, err := security.Decrypt([]byte(app.cfg.Auth.SecretKey), encrypted)
	if err != nil || decrypted != "private-repo-token" {
		t.Fatalf("repository token decrypt=%q err=%v", decrypted, err)
	}
	listed := testRequest(handler, http.MethodGet, "/api/rune-repos", "", token)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "private-repo-token") || !strings.Contains(listed.Body.String(), `"has_token":true`) {
		t.Fatalf("repo listing leaked token or lost mask state: %d %s", listed.Code, listed.Body.String())
	}
	updated := catalogJSONRequest(t, handler, http.MethodPut, "/api/rune-repos/"+summary.ID, runeRepoInput{
		Name: "Private templates", Host: "https://git.example.test/gitea", Repo: "ops/catalog", Path: "runes", Ref: "stable/next", Token: runeRepoTokenMask,
	}, token)
	if updated.Code != http.StatusOK {
		t.Fatalf("masked token update: %d %s", updated.Code, updated.Body.String())
	}
	if err = d.QueryRow(`SELECT token_enc FROM rune_repos WHERE id=?`, summary.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	decrypted, err = security.Decrypt([]byte(app.cfg.Auth.SecretKey), encrypted)
	if err != nil || decrypted != "private-repo-token" {
		t.Fatalf("masked PUT did not retain saved token: %q err=%v", decrypted, err)
	}
	cleared := catalogJSONRequest(t, handler, http.MethodPut, "/api/rune-repos/"+summary.ID, runeRepoInput{
		Name: "Private templates", Host: "https://git.example.test/gitea", Repo: "ops/catalog", Path: "runes", Ref: "stable/next", Token: "",
	}, token)
	if cleared.Code != http.StatusOK || !strings.Contains(cleared.Body.String(), `"has_token":false`) {
		t.Fatalf("empty token did not clear saved token: %d %s", cleared.Code, cleared.Body.String())
	}
	if err = d.QueryRow(`SELECT token_enc FROM rune_repos WHERE id=?`, summary.ID).Scan(&encrypted); err != nil || encrypted != "" {
		t.Fatalf("token remained after explicit clear: %q err=%v", encrypted, err)
	}
	userHash, err := security.HashPassword("catalog-user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('catalog-user','catalog-user',?,'user')`, userHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "catalog-user", Username: "catalog-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	denied := testRequest(handler, http.MethodGet, "/api/rune-repos", "", userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin could read catalog repositories: %d %s", denied.Code, denied.Body.String())
	}
}

func TestRuneCatalogBrowseInstallUpdateAndFileLimit(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	var latestVersion = 2
	listingRequests := 0
	subfolderRequests := 0
	app.runeCatalogHTTPClient = &http.Client{Transport: runeCatalogRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "api.github.com" || request.Header.Get("Authorization") != "Bearer repo-only-token" {
			return nil, fmt.Errorf("unexpected host or credential: %s auth=%q", request.URL.Host, request.Header.Get("Authorization"))
		}
		if request.URL.Query().Get("ref") != "main" {
			return nil, fmt.Errorf("catalog ref was not sent: %s", request.URL.RawQuery)
		}
		switch request.URL.Path {
		case "/repos/owner/catalog/contents/community":
			listingRequests++
			return runeCatalogResponse(request, http.StatusOK, `[{"name":"sample.yaml","path":"community/sample.yaml","type":"file","size":120},{"name":"games","path":"community/games","type":"dir"},{"name":"too-large.yaml","path":"community/too-large.yaml","type":"file","size":600000},{"name":"nested","path":"community/games/nested","type":"dir"}]`), nil
		case "/repos/owner/catalog/contents/community/games":
			subfolderRequests++
			return runeCatalogResponse(request, http.StatusOK, `[{"name":"child.yaml","path":"community/games/child.yaml","type":"file","size":120},{"name":"nested","path":"community/games/nested","type":"dir"}]`), nil
		case "/repos/owner/catalog/contents/community/sample.yaml":
			yaml := catalogRuneYAML(latestVersion, "catalog-sample")
			return runeCatalogFileResponse(request, "community/sample.yaml", yaml), nil
		case "/repos/owner/catalog/contents/community/too-large.yaml":
			return runeCatalogFileResponse(request, "community/too-large.yaml", strings.Repeat("#", runeCatalogFileLimit+1)), nil
		case "/repos/owner/catalog/contents/community/builtin.yaml":
			return runeCatalogFileResponse(request, "community/builtin.yaml", catalogRuneYAML(latestVersion, "minecraft-java")), nil
		default:
			return runeCatalogResponse(request, http.StatusNotFound, `{"message":"not found"}`), nil
		}
	})}
	handler := app.Router()
	created := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos", runeRepoInput{
		Name: "Community", Repo: "owner/catalog", Path: "community", Ref: "main", Token: "repo-only-token",
	}, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create GitHub repo: %d %s", created.Code, created.Body.String())
	}
	var repo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &repo); err != nil || repo.ID == "" {
		t.Fatalf("repo response: %s err=%v", created.Body.String(), err)
	}
	for i := 0; i < 2; i++ {
		browse := testRequest(handler, http.MethodGet, "/api/rune-repos/"+repo.ID+"/browse", "", token)
		if browse.Code != http.StatusOK || !strings.Contains(browse.Body.String(), `"sample.yaml"`) || !strings.Contains(browse.Body.String(), `"games"`) || strings.Contains(browse.Body.String(), `"too-large.yaml"`) || strings.Contains(browse.Body.String(), `"nested"`) {
			t.Fatalf("catalog listing %d: %d %s", i, browse.Code, browse.Body.String())
		}
	}
	if listingRequests != 1 {
		t.Fatalf("catalog listing cache made %d requests, want 1", listingRequests)
	}
	childBrowse := testRequest(handler, http.MethodGet, "/api/rune-repos/"+repo.ID+"/browse?path=games", "", token)
	if childBrowse.Code != http.StatusOK || !strings.Contains(childBrowse.Body.String(), `"child.yaml"`) || strings.Contains(childBrowse.Body.String(), `"nested"`) || subfolderRequests != 1 {
		t.Fatalf("catalog child-folder listing exceeded one level: %d requests=%d %s", childBrowse.Code, subfolderRequests, childBrowse.Body.String())
	}
	installed := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos/"+repo.ID+"/install", map[string]string{"path": "community/sample.yaml"}, token)
	if installed.Code != http.StatusOK || !strings.Contains(installed.Body.String(), `"version":2`) {
		t.Fatalf("catalog install: %d %s", installed.Code, installed.Body.String())
	}
	var sourceHost, sourceRepo, sourcePath, sourceRef string
	var version int
	if err := d.QueryRow(`SELECT version,source_host,source_repo,source_path,source_ref FROM gameskills WHERE id='catalog-sample'`).Scan(&version, &sourceHost, &sourceRepo, &sourcePath, &sourceRef); err != nil {
		t.Fatal(err)
	}
	if version != 2 || sourceHost != "github.com" || sourceRepo != "owner/catalog" || sourcePath != "community/sample.yaml" || sourceRef != "main" {
		t.Fatalf("installed source provenance: version=%d host=%q repo=%q path=%q ref=%q", version, sourceHost, sourceRepo, sourcePath, sourceRef)
	}
	branchChange := catalogJSONRequest(t, handler, http.MethodPut, "/api/rune-repos/"+repo.ID, runeRepoInput{
		Name: "Community", Repo: "owner/catalog", Path: "community", Ref: "release/next", Token: runeRepoTokenMask,
	}, token)
	if branchChange.Code != http.StatusOK {
		t.Fatalf("change saved catalog branch: %d %s", branchChange.Code, branchChange.Body.String())
	}
	latestVersion = 3
	updates := testRequest(handler, http.MethodGet, "/api/gameskills/updates", "", token)
	if updates.Code != http.StatusOK || !strings.Contains(updates.Body.String(), `"installed_version":2`) || !strings.Contains(updates.Body.String(), `"available_version":3`) || !strings.Contains(updates.Body.String(), `"repository_id":"`+repo.ID+`"`) {
		t.Fatalf("catalog update check: %d %s", updates.Code, updates.Body.String())
	}
	updated := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos/"+repo.ID+"/install", map[string]string{"path": "community/sample.yaml", "ref": "main"}, token)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"version":3`) {
		t.Fatalf("apply catalog update: %d %s", updated.Code, updated.Body.String())
	}
	manual := testRequest(handler, http.MethodPost, "/api/gameskills", catalogRuneYAML(4, "catalog-sample"), token)
	if manual.Code != http.StatusCreated {
		t.Fatalf("manual import over catalog template: %d %s", manual.Code, manual.Body.String())
	}
	if err := d.QueryRow(`SELECT source_host,source_repo,source_path,source_ref FROM gameskills WHERE id='catalog-sample'`).Scan(&sourceHost, &sourceRepo, &sourcePath, &sourceRef); err != nil {
		t.Fatal(err)
	}
	if sourceHost != "" || sourceRepo != "" || sourcePath != "" || sourceRef != "" {
		t.Fatalf("manual import retained stale catalog provenance: host=%q repo=%q path=%q ref=%q", sourceHost, sourceRepo, sourcePath, sourceRef)
	}
	tooLarge := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos/"+repo.ID+"/install", map[string]string{"path": "community/too-large.yaml", "ref": "main"}, token)
	if tooLarge.Code != http.StatusBadGateway || !strings.Contains(tooLarge.Body.String(), "512 KiB") {
		t.Fatalf("oversized catalog YAML was accepted: %d %s", tooLarge.Code, tooLarge.Body.String())
	}
	builtin := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos/"+repo.ID+"/install", map[string]string{"path": "community/builtin.yaml", "ref": "main"}, token)
	if builtin.Code != http.StatusConflict || !strings.Contains(builtin.Body.String(), "built-in") {
		t.Fatalf("catalog overwrote a built-in: %d %s", builtin.Code, builtin.Body.String())
	}
	if _, err := d.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin,source_host,source_repo,source_path,source_ref) VALUES('orphaned-catalog','Orphaned','Apps',1,?,0,'https://gone.example','old/catalog','runes/app.yaml','main')`, catalogRuneYAML(1, "orphaned-catalog")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM rune_repos WHERE id=?`, repo.ID); err != nil {
		t.Fatal(err)
	}
	updates = testRequest(handler, http.MethodGet, "/api/gameskills/updates", "", token)
	if updates.Code != http.StatusOK || !strings.Contains(updates.Body.String(), "Source gone") {
		t.Fatalf("removed repository was not reported as a missing source: %d %s", updates.Code, updates.Body.String())
	}
}

func TestRuneCatalogCredentialsStayOnTheirSavedHostAndRedirectsStop(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	handler := app.Router()
	global := catalogJSONRequest(t, handler, http.MethodPut, "/api/settings/github", map[string]string{"token": "panel-github-token"}, token)
	if global.Code != http.StatusOK || strings.Contains(global.Body.String(), "panel-github-token") {
		t.Fatalf("save GitHub token: %d %s", global.Code, global.Body.String())
	}
	var encrypted string
	if err := d.QueryRow(`SELECT token_enc FROM github_catalog_settings WHERE id=1`).Scan(&encrypted); err != nil || encrypted == "" || strings.Contains(encrypted, "panel-github-token") {
		t.Fatalf("global GitHub token not encrypted: %q err=%v", encrypted, err)
	}
	forgeHostAuth := map[string]string{}
	var seenHosts []string
	app.runeCatalogHTTPClient = &http.Client{Transport: runeCatalogRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		seenHosts = append(seenHosts, request.URL.Host)
		if request.URL.Host == "forge.example" {
			forgeHostAuth[request.URL.Path] = request.Header.Get("Authorization")
			return runeCatalogResponse(request, http.StatusOK, `[]`), nil
		}
		if request.URL.Host == "api.github.com" {
			if request.Header.Get("Authorization") != "Bearer panel-github-token" {
				return nil, fmt.Errorf("GitHub request did not use the configured GitHub token: %q", request.Header.Get("Authorization"))
			}
			response := runeCatalogResponse(request, http.StatusFound, "")
			response.Header.Set("Location", "https://attacker.example/redirected")
			return response, nil
		}
		return nil, fmt.Errorf("unexpected remote host %q", request.URL.Host)
	})}
	created := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos", runeRepoInput{
		Name: "Forgejo private", Host: "https://forge.example", Repo: "team/private", Ref: "main", Token: "forge-repo-token",
	}, token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create Forgejo repo: %d %s", created.Code, created.Body.String())
	}
	var repo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &repo); err != nil || repo.ID == "" {
		t.Fatalf("Forgejo repo response: %s err=%v", created.Body.String(), err)
	}
	browsePrivate := testRequest(handler, http.MethodGet, "/api/rune-repos/"+repo.ID+"/browse", "", token)
	if browsePrivate.Code != http.StatusOK {
		t.Fatalf("browse private Forgejo repository: %d %s", browsePrivate.Code, browsePrivate.Body.String())
	}
	publicCreated := catalogJSONRequest(t, handler, http.MethodPost, "/api/rune-repos", runeRepoInput{
		Name: "Forgejo public", Host: "https://forge.example", Repo: "team/public", Ref: "main",
	}, token)
	if publicCreated.Code != http.StatusCreated {
		t.Fatalf("create public Forgejo repo: %d %s", publicCreated.Code, publicCreated.Body.String())
	}
	var publicRepo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(publicCreated.Body.Bytes(), &publicRepo); err != nil || publicRepo.ID == "" {
		t.Fatalf("public Forgejo repo response: %s err=%v", publicCreated.Body.String(), err)
	}
	browseExternal := testRequest(handler, http.MethodGet, "/api/rune-repos/"+publicRepo.ID+"/browse", "", token)
	if browseExternal.Code != http.StatusOK || forgeHostAuth["/api/v1/repos/team/private/contents"] != "token forge-repo-token" || forgeHostAuth["/api/v1/repos/team/public/contents"] != "" {
		t.Fatalf("repository credentials crossed to another repo or host: status=%d auth=%v body=%s", browseExternal.Code, forgeHostAuth, browseExternal.Body.String())
	}
	browseGitHub := testRequest(handler, http.MethodGet, "/api/gameskills/github?repo=owner/public&ref=main", "", token)
	if browseGitHub.Code != http.StatusBadGateway || len(seenHosts) != 3 || seenHosts[0] != "forge.example" || seenHosts[1] != "forge.example" || seenHosts[2] != "api.github.com" {
		t.Fatalf("redirect was followed or wrong host contacted: status=%d hosts=%v body=%s", browseGitHub.Code, seenHosts, browseGitHub.Body.String())
	}
	for _, test := range []string{"../escape", "a/../../escape", "/absolute", "nested/twice/deep"} {
		if _, err := safeCatalogBrowsePath("root", test); err == nil {
			t.Errorf("unsafe browse path %q accepted", test)
		}
	}
}

func runeCatalogFileResponse(request *http.Request, remotePath, content string) *http.Response {
	file := map[string]any{
		"name": path.Base(remotePath), "path": remotePath, "type": "file", "size": len(content),
		"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content)),
	}
	body, _ := json.Marshal(file)
	return runeCatalogResponse(request, http.StatusOK, string(body))
}

func catalogRuneYAML(version int, id string) string {
	return fmt.Sprintf("gameskill:\n  id: %s\n  name: Catalog Sample\n  category: Apps\n  version: %d\n  docker:\n    image: example/catalog:%d\n  startup:\n    command: exec app\n", id, version, version)
}

func TestRuneCatalogRejectsUnsafeHostsAndKeepsRepositoryIdentityExact(t *testing.T) {
	for _, host := range []string{"http://forge.example", "https://user:pass@forge.example", "https://forge.example/a/../b", "https://forge.example?token=x", "https://forge.example#fragment"} {
		if _, err := normalizeRuneRepo(runeRepoInput{Name: "Invalid", Host: host, Repo: "team/catalog"}); err == nil {
			t.Errorf("unsafe catalog host %q was accepted", host)
		}
	}
	app, _, _ := testApp(t)
	for _, repository := range []string{"owner/..", "../catalog", "owner/repo/extra", "owner/" + strings.Repeat("x", 201)} {
		if _, err := app.githubRepoConfig(repository, "main"); err == nil {
			t.Errorf("unsafe GitHub repository %q was accepted", repository)
		}
	}
	first := runeRepoSourceKey("https://forge.example/Group", "Team/Catalog")
	if first == runeRepoSourceKey("https://forge.example/group", "Team/Catalog") {
		t.Fatal("case-sensitive Gitea base paths were merged into one catalog source")
	}
	if first == runeRepoSourceKey("https://forge.example/Group", "Team/catalog") {
		t.Fatal("distinct repository names were merged into one catalog source")
	}
	if runeRepoSourceKey("github.com", "Community/Catalog") != runeRepoSourceKey("GITHUB.COM", "Community/Catalog") {
		t.Fatal("GitHub host identity was not normalized")
	}
}
