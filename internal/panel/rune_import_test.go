package panel

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
)

func TestEggImportIsAdminOnlyAndDropsSecretDefaults(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	passwordHash, err := security.HashPassword("egg-import-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('egg-import-user','egg-import-user',?,'user')`, passwordHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "egg-import-user", Username: "egg-import-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	egg := `{"name":"Example Egg","author":"Docklight test","docker_images":{"Java 21":"example.test/game:21"},"startup":"java -jar server.jar","config":{"startup":{"done":["Done (" ]},"files":{"server.properties":{}}},"scripts":{"installation":{"script":"echo install","container":"alpine:3"}},"variables":[{"name":"Memory","env_variable":"MEMORY","default_value":"2G","rules":"required|string"},{"name":"Server password","env_variable":"SERVER_PASSWORD","default_value":"plaintext-secret","rules":"string"}]}`
	denied := testRequest(app.Router(), http.MethodPost, "/api/gameskills/import-egg", egg, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin egg import returned %d: %s", denied.Code, denied.Body.String())
	}
	created := testRequest(app.Router(), http.MethodPost, "/api/gameskills/import-egg", egg, adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("egg import returned %d: %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "plaintext-secret") {
		t.Fatalf("egg import response leaked a secret default: %s", created.Body.String())
	}
	var response struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Warnings []string `json:"warnings"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != "example-egg" || response.Name != "Example Egg" || len(response.Warnings) != 1 {
		t.Fatalf("unexpected egg import response: %#v", response)
	}
	var stored string
	if err = d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id=?`, response.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "plaintext-secret") {
		t.Fatalf("stored egg contains secret default: %s", stored)
	}
	imported, err := rune.Parse(stored)
	if err != nil {
		t.Fatalf("stored egg did not pass parser: %v\n%s", err, stored)
	}
	if imported.Docker.Image != "example.test/game:21" || imported.Startup.DoneRegex != `Done \(` || imported.Install == nil || imported.Install.Image != "alpine:3" || len(imported.ConfigFiles) != 1 {
		t.Fatalf("egg fields were not translated: %#v", imported)
	}
	listed := testRequest(app.Router(), http.MethodGet, "/api/gameskills", "", adminToken)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"config_files":["server.properties"]`) {
		t.Fatalf("template list omitted config-file shortcuts: %d %s", listed.Code, listed.Body.String())
	}
	if len(imported.Variables) != 2 || imported.Variables[1].Default != nil || !imported.Variables[1].Secret {
		t.Fatalf("secret variable default was not removed: %#v", imported.Variables)
	}
	if _, err = d.Exec(`UPDATE gameskills SET source_host='github.com',source_repo='old/repo',source_path='egg.json',source_ref='main' WHERE id=?`, response.ID); err != nil {
		t.Fatal(err)
	}
	updated := testRequest(app.Router(), http.MethodPost, "/api/gameskills/import-egg", strings.Replace(egg, "game:21", "game:22", 1), adminToken)
	if updated.Code != http.StatusCreated {
		t.Fatalf("re-import egg returned %d: %s", updated.Code, updated.Body.String())
	}
	var sourceHost, storedAgain string
	if err = d.QueryRow(`SELECT yaml_blob,source_host FROM gameskills WHERE id=?`, response.ID).Scan(&storedAgain, &sourceHost); err != nil {
		t.Fatal(err)
	}
	updatedRune, err := rune.Parse(storedAgain)
	if err != nil {
		t.Fatal(err)
	}
	if updatedRune.Docker.Image != "example.test/game:22" || sourceHost != "" {
		t.Fatalf("egg re-import did not update template and clear catalog source: image=%q source=%q", updatedRune.Docker.Image, sourceHost)
	}
}

func TestXMLImportAcceptsMultipartAndNormalizesPortProtocol(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	xmlTemplate := `<gameskill><id>portable-xml</id><name>Portable XML</name><version>0</version><docker><image>example.test/xml:1</image></docker><startup><command>exec app</command></startup><variables><variable><key>API_TOKEN</key><name>API token</name><type>string</type><default>xml-secret</default></variable></variables><ports><port><name>Game</name><default>25565</default></port></ports></gameskill>`
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("file", "template.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte(xmlTemplate)); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/gameskills/import-xml", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	app.Router().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("multipart XML import returned %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "xml-secret") {
		t.Fatalf("XML import response leaked a secret default: %s", response.Body.String())
	}
	var stored string
	if err = d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='portable-xml'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	imported, err := rune.Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Version != 1 || len(imported.Ports) != 1 || imported.Ports[0].Protocol != "tcp" || imported.Variables[0].Default != nil || !imported.Variables[0].Secret {
		t.Fatalf("XML fields were not normalized safely: %#v", imported)
	}
}

func TestExternalRuneImportRejectsBuiltinsAndOversizeFiles(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	collision := testRequest(app.Router(), http.MethodPost, "/api/gameskills/import-egg", `{"name":"Minecraft Java","docker_image":"example/app:1","startup":"start"}`, token)
	if collision.Code != http.StatusConflict {
		t.Fatalf("built-in template collision returned %d: %s", collision.Code, collision.Body.String())
	}
	oversize := testRequest(app.Router(), http.MethodPost, "/api/gameskills/import-xml", strings.Repeat("x", 1<<20+1), token)
	if oversize.Code != http.StatusBadRequest || !strings.Contains(oversize.Body.String(), "1 MiB") {
		t.Fatalf("oversize XML returned %d: %s", oversize.Code, oversize.Body.String())
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM gameskills WHERE id='minecraft-java'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("built-in collision changed the built-in template row count: %d", rows)
	}
}
