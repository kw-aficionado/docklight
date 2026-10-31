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

func TestComposeImportIsAdminOnlyAndStoresValidatedTemplateWithoutSecrets(t *testing.T) {
	app, d, _ := testApp(t)
	handler := app.Router()
	adminToken := runeCatalogAdminToken(t, app, d)
	userHash, err := security.HashPassword("compose-user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('compose-user','compose-user',?,'user')`, userHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "compose-user", Username: "compose-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	composeYAML := `name: compose-import-test
services:
  app:
    image: example.test/app:1
    environment:
      APP_MODE: production
      APP_PASSWORD: plaintext-import-secret
    ports:
      - "9001:8080"
    volumes:
      - app-data:/var/lib/app
  database:
    image: mariadb:11
    environment:
      - MARIADB_ROOT_PASSWORD=second-plaintext-secret
    volumes:
      - db-data:/var/lib/mysql
    ports:
      - "3307:3306"
`
	denied := testRequest(handler, http.MethodPost, "/api/gameskills/import-compose", composeYAML, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin compose import returned %d: %s", denied.Code, denied.Body.String())
	}

	created := testRequest(handler, http.MethodPost, "/api/gameskills/import-compose", composeYAML, adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("compose import returned %d: %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "plaintext-import-secret") || strings.Contains(created.Body.String(), "second-plaintext-secret") {
		t.Fatalf("compose import response leaked secret: %s", created.Body.String())
	}
	var response struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Warnings []string `json:"warnings"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != "compose-import-test" || response.Name != "compose-import-test" || response.Warnings == nil {
		t.Fatalf("unexpected import response: %#v", response)
	}
	var stored string
	if err = d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id=?`, response.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "plaintext-import-secret") || strings.Contains(stored, "second-plaintext-secret") {
		t.Fatalf("stored template contains a Compose secret: %s", stored)
	}
	generated, err := rune.Parse(stored)
	if err != nil {
		t.Fatalf("stored template did not round trip: %v\n%s", err, stored)
	}
	if generated.Docker.Image != "example.test/app:1" || generated.Docker.DataPath != "/var/lib/app" || generated.Stack == nil || len(generated.Stack.Services) != 1 || generated.Stack.Services[0].DataPath != "/var/lib/mysql" {
		t.Fatalf("stored app stack does not match the Compose services: %#v", generated)
	}
	if _, err = d.Exec(`UPDATE gameskills SET source_host='github.com',source_repo='old/repo',source_path='old.yaml',source_ref='main' WHERE id='compose-import-test'`); err != nil {
		t.Fatalf("could not seed update metadata: %v", err)
	}
	updated := testRequest(handler, http.MethodPost, "/api/gameskills/import-compose", strings.ReplaceAll(composeYAML, "example.test/app:1", "example.test/app:2"), adminToken)
	if updated.Code != http.StatusCreated {
		t.Fatalf("re-import existing community ID returned %d: %s", updated.Code, updated.Body.String())
	}
	var image, sourceHost string
	var rows int
	if err = d.QueryRow(`SELECT yaml_blob,source_host FROM gameskills WHERE id='compose-import-test'`).Scan(&stored, &sourceHost); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM gameskills WHERE id='compose-import-test'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	updatedRune, err := rune.Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	image = updatedRune.Docker.Image
	if rows != 1 || image != "example.test/app:2" || sourceHost != "" {
		t.Fatalf("re-import did not upsert and clear source metadata: rows=%d image=%q source=%q", rows, image, sourceHost)
	}
}

func TestComposeImportAcceptsMultipartUploadAndMainOverride(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("file", "compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	composeYAML := `services:
  api:
    image: example.test/api:1
    ports: ["9000:9000"]
  web:
    image: example.test/web:1
    ports: ["8080:80"]
`
	if _, err = file.Write([]byte(composeYAML)); err != nil {
		t.Fatal(err)
	}
	if err = form.WriteField("main", "api"); err != nil {
		t.Fatal(err)
	}
	if err = form.WriteField("name", "Imported API"); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/gameskills/import-compose", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	app.Router().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"id":"imported-api"`) {
		t.Fatalf("multipart Compose import returned %d: %s", response.Code, response.Body.String())
	}
	var stored string
	if err = d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='imported-api'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	imported, err := rune.Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Docker.Image != "example.test/api:1" || imported.Name != "Imported API" {
		t.Fatalf("multipart main/name fields were not applied: %#v", imported)
	}
}

func TestComposeImportRejectsBuiltinCollisionAndOversize(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	handler := app.Router()
	collision := testRequest(handler, http.MethodPost, "/api/gameskills/import-compose", "name: minecraft-java\nservices:\n  app:\n    image: example/app:1\n", token)
	if collision.Code != http.StatusConflict {
		t.Fatalf("built-in template collision returned %d: %s", collision.Code, collision.Body.String())
	}
	oversize := testRequest(handler, http.MethodPost, "/api/gameskills/import-compose", strings.Repeat("x", 1<<20+1), token)
	if oversize.Code != http.StatusBadRequest || !strings.Contains(oversize.Body.String(), "1 MiB") {
		t.Fatalf("oversize Compose returned %d: %s", oversize.Code, oversize.Body.String())
	}
}
