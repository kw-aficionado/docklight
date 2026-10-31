package panel

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/security"
)

func TestRealmInputLimitsCountInternationalCharacters(t *testing.T) {
	if _, _, ok := validRealmInput(strings.Repeat("界", 80), strings.Repeat("説明", 250)); !ok {
		t.Fatal("valid multibyte realm name and description were rejected by byte length")
	}
	if _, _, ok := validRealmInput(strings.Repeat("界", 81), ""); ok {
		t.Fatal("realm name over 80 Unicode characters was accepted")
	}
	if _, _, ok := validRealmInput("Valid", strings.Repeat("é", 501)); ok {
		t.Fatal("realm description over 500 Unicode characters was accepted")
	}
}

func addRealmTestUser(t *testing.T, a *App, id, role string) string {
	t.Helper()
	hash, err := security.HashPassword("a test realm account password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.db.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)`, id, id, hash, role); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: id, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func createTestRealm(t *testing.T, h http.Handler, token, name string) Realm {
	t.Helper()
	response := testRequest(h, http.MethodPost, "/api/realms", `{"name":"`+name+`","description":"test group"}`, token)
	if response.Code != http.StatusCreated {
		t.Fatalf("create realm %q: %d %s", name, response.Code, response.Body.String())
	}
	var realm Realm
	if err := json.Unmarshal(response.Body.Bytes(), &realm); err != nil || realm.ID == "" {
		t.Fatalf("invalid realm response %v: %s", err, response.Body.String())
	}
	return realm
}

func TestRealmPermissionsCollapseReorderAndDelete(t *testing.T) {
	a, d, _ := testApp(t)
	admin := addRealmTestUser(t, a, "realm-admin", "admin")
	viewer := addRealmTestUser(t, a, "realm-viewer", "user")
	secondViewer := addRealmTestUser(t, a, "realm-viewer-two", "user")
	h := a.Router()

	private := testRequest(h, http.MethodPost, "/api/realms", `{"name":"Hidden realm"}`, viewer)
	if private.Code != http.StatusForbidden {
		t.Fatalf("non-admin realm creation status=%d body=%s", private.Code, private.Body.String())
	}
	first := createTestRealm(t, h, admin, "Production")
	second := createTestRealm(t, h, admin, "Staging")
	duplicate := testRequest(h, http.MethodPost, "/api/realms", `{"name":"production"}`, admin)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("case-insensitive duplicate realm status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	for _, server := range []struct{ id, realmID string }{{"realm-server-a", first.ID}, {"realm-server-b", second.ID}} {
		if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,realm_id,status,data_dir) VALUES(?,?,'uptime-kuma',?,'stopped',?)`, server.id, server.id, server.realmID, filepath.Join(a.dataRoot, server.id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"realm-viewer", "realm-viewer-two"} {
		if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES(?,'realm',?,'server.view,server.create')`, userID, first.ID); err != nil {
			t.Fatal(err)
		}
	}
	visible := testRequest(h, http.MethodGet, "/api/servers", "", viewer)
	if visible.Code != http.StatusOK || !strings.Contains(visible.Body.String(), "realm-server-a") || strings.Contains(visible.Body.String(), "realm-server-b") {
		t.Fatalf("realm grant list leaked or hid a server: %d %s", visible.Code, visible.Body.String())
	}
	denied := testRequest(h, http.MethodGet, "/api/servers/realm-server-b", "", viewer)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("realm grant crossed into another realm: %d %s", denied.Code, denied.Body.String())
	}
	listedRealms := testRequest(h, http.MethodGet, "/api/realms", "", viewer)
	if listedRealms.Code != http.StatusOK || !strings.Contains(listedRealms.Body.String(), "Production") || strings.Contains(listedRealms.Body.String(), "Staging") {
		t.Fatalf("realm listing leaked hidden realm metadata: %d %s", listedRealms.Code, listedRealms.Body.String())
	}
	var realms []Realm
	if err := json.Unmarshal(listedRealms.Body.Bytes(), &realms); err != nil || len(realms) != 1 || realms[0].ServerCount != 1 || !realms[0].CanCreate {
		t.Fatalf("realm listing returned wrong visibility or counts: err=%v realms=%#v", err, realms)
	}
	collapsed := testRequest(h, http.MethodPut, "/api/realms/"+first.ID+"/collapsed", `{"collapsed":true}`, viewer)
	if collapsed.Code != http.StatusOK {
		t.Fatalf("save collapsed state: %d %s", collapsed.Code, collapsed.Body.String())
	}
	viewerRealms := testRequest(h, http.MethodGet, "/api/realms", "", viewer)
	otherRealms := testRequest(h, http.MethodGet, "/api/realms", "", secondViewer)
	if !strings.Contains(viewerRealms.Body.String(), `"collapsed":true`) || !strings.Contains(otherRealms.Body.String(), `"collapsed":false`) {
		t.Fatalf("collapse preference was not private per user: viewer=%s other=%s", viewerRealms.Body.String(), otherRealms.Body.String())
	}
	moveDenied := testRequest(h, http.MethodPut, "/api/servers/realm-server-b/realm", `{"realm_id":"`+first.ID+`"}`, viewer)
	if moveDenied.Code != http.StatusForbidden {
		t.Fatalf("non-admin server move status=%d body=%s", moveDenied.Code, moveDenied.Body.String())
	}
	moved := testRequest(h, http.MethodPut, "/api/servers/realm-server-b/realm", `{"realm_id":"`+first.ID+`"}`, admin)
	if moved.Code != http.StatusOK {
		t.Fatalf("admin server move status=%d body=%s", moved.Code, moved.Body.String())
	}
	visibleAfterMove := testRequest(h, http.MethodGet, "/api/servers/realm-server-b", "", viewer)
	if visibleAfterMove.Code != http.StatusOK {
		t.Fatalf("realm grant did not follow an admin move: %d %s", visibleAfterMove.Code, visibleAfterMove.Body.String())
	}
	reordered := testRequest(h, http.MethodPost, "/api/realms/reorder", `{"ids":["`+second.ID+`","`+first.ID+`"]}`, admin)
	if reordered.Code != http.StatusOK {
		t.Fatalf("reorder realms: %d %s", reordered.Code, reordered.Body.String())
	}
	var firstOrder, secondOrder int
	if err := d.QueryRow(`SELECT sort_order FROM realms WHERE id=?`, first.ID).Scan(&firstOrder); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT sort_order FROM realms WHERE id=?`, second.ID).Scan(&secondOrder); err != nil || firstOrder != 1 || secondOrder != 0 {
		t.Fatalf("realm order first=%d second=%d err=%v", firstOrder, secondOrder, err)
	}
	if _, err := d.Exec(`INSERT INTO realm_user_state(user_id,realm_id,collapsed) VALUES('realm-viewer-two',?,1)`, first.ID); err != nil {
		t.Fatal(err)
	}
	deleted := testRequest(h, http.MethodDelete, "/api/realms/"+first.ID, `{}`, admin)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete realm: %d %s", deleted.Code, deleted.Body.String())
	}
	var attached, grants, preferences int
	if err := d.QueryRow(`SELECT count(*) FROM servers WHERE realm_id=?`, first.ID).Scan(&attached); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM permissions WHERE scope_type='realm' AND scope_id=?`, first.ID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM realm_user_state WHERE realm_id=?`, first.ID).Scan(&preferences); err != nil {
		t.Fatal(err)
	}
	if attached != 0 || grants != 0 || preferences != 0 {
		t.Fatalf("realm delete cleanup attached=%d grants=%d preferences=%d", attached, grants, preferences)
	}
	var detached string
	if err := d.QueryRow(`SELECT realm_id FROM servers WHERE id='realm-server-a'`).Scan(&detached); err != nil || detached != "" {
		t.Fatalf("deleted realm did not detach its server: realm=%q err=%v", detached, err)
	}
}

func TestRealmScopedServerCreationRequiresExplicitRealm(t *testing.T) {
	a, d, _ := testApp(t)
	admin := addRealmTestUser(t, a, "realm-create-admin", "admin")
	creator := addRealmTestUser(t, a, "realm-creator", "user")
	h := a.Router()
	realm := createTestRealm(t, h, admin, "Builds")
	raw := `gameskill:
  id: realm-create-test
  name: Realm Create Test
  category: Testing
  docker:
    image: example/realm-test:latest
  startup:
    command: exec app
`
	if _, err := d.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES('realm-create-test','Realm Create Test','Testing',1,?,0)`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('realm-creator','realm',?,'server.create')`, realm.ID); err != nil {
		t.Fatal(err)
	}
	listed := testRequest(h, http.MethodGet, "/api/gameskills", "", creator)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "realm-create-test") || !strings.Contains(listed.Body.String(), `"can_create_default":false`) {
		t.Fatalf("realm creator could not select a template safely: %d %s", listed.Code, listed.Body.String())
	}
	implicit := testRequest(h, http.MethodPost, "/api/servers", `{"name":"Implicit realm","gameskill_id":"realm-create-test"}`, creator)
	if implicit.Code != http.StatusBadRequest {
		t.Fatalf("realm-only grant created in an implicit realm: %d %s", implicit.Code, implicit.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/servers", `{"name":"Realm build","gameskill_id":"realm-create-test","realm_id":"`+realm.ID+`"}`, creator)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"realm_id":"`+realm.ID+`"`) {
		t.Fatalf("realm-scoped server creation failed: %d %s", created.Code, created.Body.String())
	}
	defaulted := testRequest(h, http.MethodPost, "/api/servers", `{"name":"Category default","gameskill_id":"realm-create-test"}`, admin)
	if defaulted.Code != http.StatusCreated {
		t.Fatalf("category-default server creation failed: %d %s", defaulted.Code, defaulted.Body.String())
	}
	var defaultRealmName string
	if err := d.QueryRow(`SELECT r.name FROM servers s JOIN realms r ON r.id=s.realm_id WHERE s.name='Category default'`).Scan(&defaultRealmName); err != nil || defaultRealmName != "Testing" {
		t.Fatalf("category-default realm=%q err=%v, want Testing", defaultRealmName, err)
	}
}
