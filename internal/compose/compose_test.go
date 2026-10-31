package compose

import (
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
)

func TestTranslateComposeAppStackAndDropsSecrets(t *testing.T) {
	input := `name: little-library
services:
  web:
    image: wordpress:6
    environment:
      WORDPRESS_DB_PASSWORD: imported-password-value
      TZ: UTC
    ports:
      - "0.0.0.0:8088:80/tcp"
      - "25565:25565/udp"
      - "3000-3002:3000-3002"
    volumes:
      - site-data:/var/www/html
      - uploads:/var/www/html/wp-content
      - ./config:/etc/app
  database:
    image: mariadb:11
    environment:
      - MARIADB_ROOT_PASSWORD=another-imported-secret
      - MARIADB_DATABASE=wordpress
    volumes:
      - db-data:/var/lib/mysql
      - db-extra:/var/lib/mysql-files
    ports:
      - "3307:3306"
    networks:
      - private
  worker:
    build: ./worker
`

	gs, warnings, err := Translate([]byte(input), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gs.ID != "little-library" || gs.Name != "little-library" || gs.Category != "Apps" || gs.Version != 1 {
		t.Fatalf("unexpected identity: %#v", gs)
	}
	if gs.Docker.Image != "wordpress:6" || !gs.Docker.KeepEntrypoint || gs.Docker.DataPath != "/var/www/html" {
		t.Fatalf("unexpected main container: %#v", gs.Docker)
	}
	if len(gs.Docker.ExtraVolumes) != 1 || gs.Docker.ExtraVolumes[0] != "/var/www/html/wp-content" {
		t.Fatalf("expected one additional persistent app path, got %#v", gs.Docker.ExtraVolumes)
	}
	if gs.Docker.Env["TZ"] != "UTC" || gs.Docker.Env["WORDPRESS_DB_PASSWORD"] == "imported-password-value" {
		t.Fatalf("main environment was not imported safely: %#v", gs.Docker.Env)
	}
	if got := gs.Docker.Env["WORDPRESS_DB_PASSWORD"]; !strings.HasPrefix(got, "{{IMPORT_WEB_WORDPRESS_DB_PASSWORD}}") {
		t.Fatalf("secret environment was not replaced with a variable: %q", got)
	}
	if len(gs.Ports) != 2 || gs.Ports[0].Name != "web" || gs.Ports[0].Default != 80 || gs.Ports[1].Default != 25565 || gs.Ports[1].Protocol != "udp" {
		t.Fatalf("expected 2 imported container ports, got %#v", gs.Ports)
	}
	if gs.Stack == nil || len(gs.Stack.Services) != 1 || gs.Stack.Services[0].Name != "database" {
		t.Fatalf("expected exactly one image sidecar, got %#v", gs.Stack)
	}
	if gs.Stack.Services[0].DataPath != "/var/lib/mysql" || len(gs.Stack.Services[0].ExtraVolumes) != 1 || gs.Stack.Services[0].ExtraVolumes[0] != "/var/lib/mysql-files" || gs.Stack.Services[0].Environment["MARIADB_DATABASE"] != "wordpress" {
		t.Fatalf("unexpected sidecar configuration: %#v", gs.Stack.Services[0])
	}
	if err = gs.Validate(); err != nil {
		t.Fatalf("generated template did not validate: %v", err)
	}

	for _, secret := range []string{"imported-password-value", "another-imported-secret"} {
		if strings.Contains(rune.ToJSON(gs), secret) {
			t.Fatalf("secret %q was retained in generated template", secret)
		}
	}
	if len(gs.Variables) != 2 || !gs.Variables[0].Secret || !gs.Variables[1].Secret {
		t.Fatalf("expected both secret inputs to be declared without defaults: %#v", gs.Variables)
	}
	joined := strings.Join(warnings, "\n")
	for _, expected := range []string{"Published host ports", "port range", "bind mounts", "published ports were dropped", "build instructions", "volume contents"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("missing warning %q in %q", expected, joined)
		}
	}
	if strings.Contains(joined, "imported-password-value") || strings.Contains(joined, "another-imported-secret") {
		t.Fatalf("warning exposed Compose secret values: %q", joined)
	}
}

func TestTranslateMainServiceSelectionAndOverrides(t *testing.T) {
	input := []byte(`services:
  api:
    image: example/api:1
    ports: ["9000:9000"]
  web:
    image: example/web:1
    ports: ["8080:80"]
`)
	gs, warnings, err := Translate(input, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gs.Docker.Image != "example/web:1" || len(warnings) != 2 || !strings.Contains(strings.Join(warnings, "\n"), "allocated by Docklight") {
		t.Fatalf("web heuristic failed: image=%q warnings=%v", gs.Docker.Image, warnings)
	}
	gs, _, err = Translate(input, "api", "My API")
	if err != nil {
		t.Fatal(err)
	}
	if gs.Docker.Image != "example/api:1" || gs.ID != "my-api" || gs.Name != "My API" {
		t.Fatalf("explicit service or name was ignored: %#v", gs)
	}
	if _, _, err = Translate(input, "missing", ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown main service should fail clearly, got %v", err)
	}
	loopback := []byte(`services:
  app:
    image: example/app:1
    ports: ["127.0.0.1:8080:8080"]
`)
	gs, warnings, err = Translate(loopback, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs.Ports) != 0 || !strings.Contains(strings.Join(warnings, "\n"), "localhost-only port") {
		t.Fatalf("localhost-only Compose port was exposed by the imported template: ports=%#v warnings=%v", gs.Ports, warnings)
	}
}

func TestTranslateComposeInputValidation(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":              nil,
		"no services":        []byte("name: sample\n"),
		"missing image":      []byte("services:\n  app:\n    build: .\n"),
		"multiple documents": []byte("services: {app: {image: example/app}}\n---\nservices: {app: {image: example/app}}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Translate(input, "", ""); err == nil {
				t.Fatal("invalid Compose input was accepted")
			}
		})
	}
	if _, _, err := Translate([]byte(strings.Repeat("x", MaxSize+1)), "", ""); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized Compose file should be rejected with a limit, got %v", err)
	}
}

func TestTranslateEnvListAndReservedValues(t *testing.T) {
	input := []byte(`services:
  app:
    image: example/app:1
    environment:
      - APP_MODE=production
      - API_TOKEN=do-not-store
      - JWT_SECRET_KEY=signing-material
      - DATABASE_URL=postgres://user:db-password@example.test/app
      - PUID=1000
    ports:
      - "8080"
`)
	gs, warnings, err := Translate(input, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gs.Docker.Env["APP_MODE"] != "production" || gs.Docker.Env["PUID"] != "" {
		t.Fatalf("environment list translation or reserved filtering failed: %#v", gs.Docker.Env)
	}
	for _, secret := range []string{"do-not-store", "signing-material", "db-password"} {
		if strings.Contains(rune.ToJSON(gs), secret) {
			t.Fatalf("sensitive environment value %q was not removed", secret)
		}
	}
	if len(gs.Variables) != 3 {
		t.Fatalf("secret list value was not removed: rune=%s vars=%#v", rune.ToJSON(gs), gs.Variables)
	}
	for _, variable := range gs.Variables {
		if !variable.Secret || variable.Default != nil || !variable.Required {
			t.Fatalf("imported secret variable must be marked secret with no default: %#v", variable)
		}
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning for Docklight-owned environment value")
	}
}
