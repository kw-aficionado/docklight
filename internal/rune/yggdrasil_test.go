package rune

import (
	"strings"
	"testing"
)

func TestImportYggdrasilConvertsServicesAndReportsDroppedFeatures(t *testing.T) {
	source := `gameskill:
  id: imported-app
  name: Imported App
  category: Apps
  version: 3
  docker:
    image: example.test/app:1
  variables:
    - key: DB_PASSWORD
      name: Database password
      type: string
      default: plaintext-variable-secret
  startup:
    command: exec app
  query:
    type: source
    port: query
  rcon:
    enabled: true
    type: rust-websocket
    port_var: RCON_PORT
  services:
    - name: database
      image: mariadb:11
      env: { MARIADB_PASSWORD: "{{DB_PASSWORD}}", MARIADB_DATABASE: app, MAX_CONNECTIONS: 100, API_TOKEN: plaintext-service-secret }
      ports:
        - { name: web, default: 3306, protocol: tcp }
  players:
    list_command: players
  events:
    - { key: login, label: Login, match: "failed" }
  admin_log:
    path: "logs/admin.log"
    events: [{ type: join, regex: "joined" }]
  wipe:
    paths: [world]
  import:
    inputs: [{ key: data, label: Data, accept: .zip }]
  backup:
    include: [world]
`

	got, warnings, err := ImportYggdrasil(source)
	if err != nil {
		t.Fatalf("ImportYggdrasil() error = %v", err)
	}
	if err = got.Validate(); err != nil {
		t.Fatalf("converted Rune failed validation: %v", err)
	}
	if got.ID != "imported-app" || got.Version != 3 || got.Stack == nil || len(got.Stack.Services) != 1 {
		t.Fatalf("identity or stack was not converted: %#v", got)
	}
	service := got.Stack.Services[0]
	if service.Name != "database" || service.Image != "mariadb:11" || service.Environment["MARIADB_PASSWORD"] != "{{DB_PASSWORD}}" || service.Environment["MARIADB_DATABASE"] != "app" || service.Environment["MAX_CONNECTIONS"] != "100" {
		t.Fatalf("service environment was not converted: %#v", service)
	}
	if _, ok := service.Environment["API_TOKEN"]; ok {
		t.Fatalf("static service secret was retained: %#v", service.Environment)
	}
	if got.Variables[0].Default != nil || !got.Variables[0].Secret {
		t.Fatalf("secret variable default was not removed and marked secret: %#v", got.Variables[0])
	}
	if len(got.Ports) != 0 || got.RCON != nil || got.Query == nil || got.Query.Type != "source" {
		t.Fatalf("unsupported RCON or query conversion is wrong: ports=%#v rcon=%#v query=%#v", got.Ports, got.RCON, got.Query)
	}
	for _, want := range []string{
		"publishes ports",
		"live player roster",
		"persistent aggregated event tracking",
		"parsed admin activity log",
		"template-specific world wipe action",
		"template-specific app-data import workflow",
		"backup.include was not applied",
		"Legacy Yggdrasil query.port",
		"Legacy Yggdrasil rcon.port_var",
		"RCON protocol \"rust-websocket\"",
		"sensitive variable default",
		"static sensitive environment value",
	} {
		if !containsWarning(warnings, want) {
			t.Errorf("warnings %#v do not contain %q", warnings, want)
		}
	}
	if strings.Contains(strings.Join(warnings, " "), "plaintext-variable-secret") || strings.Contains(strings.Join(warnings, " "), "plaintext-service-secret") {
		t.Fatalf("import warnings leaked secret values: %#v", warnings)
	}
}

func TestImportYggdrasilRecognizesFullBackupAndRejectsInvalidInput(t *testing.T) {
	fullBackup := `gameskill:
  id: backup-app
  name: Backup App
  docker:
    image: example.test/backup:1
  startup:
    command: exec app
  backup:
    include: ["."]
`
	if _, warnings, err := ImportYggdrasil(fullBackup); err != nil || len(warnings) != 0 {
		t.Fatalf("full-directory backup should convert without a warning: warnings=%#v err=%v", warnings, err)
	}
	for name, source := range map[string]string{
		"unknown top-level field": strings.Replace(fullBackup, "  backup:\n    include: [\".\"]\n", "  unknown: true\n", 1),
		"invalid backup include":  strings.Replace(fullBackup, "include: [\".\"]", "include: not-a-list", 1),
		"both stack formats":      strings.Replace(fullBackup, "  backup:\n    include: [\".\"]\n", "  services:\n    - name: db\n      image: mariadb:11\n  stack:\n    services:\n      - name: other\n        image: redis:7\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ImportYggdrasil(source); err == nil {
				t.Fatal("invalid Yggdrasil Rune was accepted")
			}
		})
	}
}

func containsWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return true
		}
	}
	return false
}
