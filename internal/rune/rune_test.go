package rune

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinRunesParse(t *testing.T) {
	dir := filepath.Join("..", "..", "builtin-runes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("expected 7 shipped runes, got %d", len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		gs, err := Parse(string(b))
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		seen[gs.ID] = true
	}
	for _, id := range []string{"minecraft-java", "minecraft-bedrock", "uptime-kuma", "vaultwarden", "cloudflared", "wordpress-mariadb", "dayz"} {
		if !seen[id] {
			t.Errorf("built-in rune %q was not parsed", id)
		}
	}
}

func TestBuiltinDayZTemplateConfiguration(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "builtin-runes", "dayz.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	gs, err := Parse(string(content))
	if err != nil {
		t.Fatalf("parse DayZ template: %v", err)
	}
	if gs.ID != "dayz" || gs.Steam == nil || gs.Steam.AppID != 223350 || gs.Steam.Anonymous {
		t.Fatalf("unexpected DayZ identity or Steam configuration: %#v", gs)
	}
	if gs.Query == nil || gs.Query.Type != "a2s" || gs.Bans == nil || gs.Bans.Adapter != "dayz-ban-file" {
		t.Fatalf("DayZ query or ban integration is missing: query=%#v bans=%#v", gs.Query, gs.Bans)
	}
	wantPorts := map[string]int{"game": 2302, "client": 2304, "query": 2305}
	for _, port := range gs.Ports {
		if port.Protocol != "udp" || wantPorts[port.Name] != port.Default {
			t.Errorf("unexpected DayZ port declaration: %#v", port)
		}
		delete(wantPorts, port.Name)
	}
	if len(wantPorts) != 0 {
		t.Errorf("DayZ ports are missing: %v", wantPorts)
	}
	variables := make(map[string]Variable, len(gs.Variables))
	for _, variable := range gs.Variables {
		variables[variable.Key] = variable
	}
	adminPassword := variables["ADMIN_PASSWORD"]
	if !adminPassword.Required || !adminPassword.Secret || adminPassword.Default != nil {
		t.Errorf("DayZ admin password must be required, secret, and have no public default: %#v", adminPassword)
	}
	joinPassword := variables["SERVER_PASSWORD"]
	if !joinPassword.Secret {
		t.Errorf("DayZ join password must be stored as a secret: %#v", joinPassword)
	}
	env := gs.DefaultEnv()
	env["ADMIN_PASSWORD"] = "a-long-admin-password"
	env["MODS"] = "@123456;@234567"
	if err := gs.ValidateEnv(env); err != nil {
		t.Fatalf("valid DayZ settings were rejected: %v", err)
	}
	env["MODS"] = "$(touch-pwned)"
	if err := gs.ValidateEnv(env); err == nil {
		t.Fatal("shell syntax was accepted in the DayZ MODS field")
	}
	if gs.Install == nil || !strings.Contains(gs.Install.Script, "+app_update 223350 validate") || strings.Contains(gs.Install.Script, "+workshop_download_item") {
		t.Fatalf("DayZ install script has unexpected Steam commands: %q", gs.Install)
	}
	if !strings.Contains(gs.Startup.Command, "steamQueryPort = %s") || !strings.Contains(gs.Startup.Command, "MODS folder %s is missing") || !strings.Contains(gs.Startup.Command, "-mod=$mods_argument") {
		t.Fatalf("DayZ startup script is missing generated config, folder validation, or load-order behavior")
	}
}

func TestParseRejectsUnknownAndDuplicateFields(t *testing.T) {
	valid := `gameskill:
  id: sample
  name: Sample
  docker:
    image: example/app:1
    keep_entrypoint: true
  startup:
    exec: [run]
`
	tests := []struct {
		name    string
		source  string
		wantErr string
	}{
		{
			name:    "unknown rune field",
			source:  strings.Replace(valid, "  name: Sample", "  nam: Sample", 1),
			wantErr: `unknown field "nam"`,
		},
		{
			name:    "unknown nested field",
			source:  strings.Replace(valid, "    image: example/app:1", "    imag: example/app:1", 1),
			wantErr: `unknown field "imag"`,
		},
		{
			name:    "duplicate top-level field",
			source:  valid + "  name: Another name\n",
			wantErr: `duplicate key "name"`,
		},
		{
			name:    "duplicate field in sequence item",
			source:  strings.Replace(valid, "  startup:", "  ports:\n    - name: game\n      name: other\n      default: 25565\n      protocol: tcp\n  startup:", 1),
			wantErr: `duplicate key "name"`,
		},
		{
			name:    "shell command with retained image entrypoint",
			source:  strings.Replace(valid, "    exec: [run]", "    command: run", 1),
			wantErr: "startup.command cannot be combined with docker.keep_entrypoint",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.source); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Parse() error = %v, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

func TestAppStackTemplateValidationAndSecrets(t *testing.T) {
	path := filepath.Join("..", "..", "builtin-runes", "wordpress-mariadb.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gs, err := Parse(string(content))
	if err != nil {
		t.Fatal(err)
	}
	if gs.Stack == nil || len(gs.Stack.Services) != 1 || gs.Stack.Services[0].Name != "database" {
		t.Fatalf("unexpected app stack metadata: %#v", gs.Stack)
	}
	if gs.Stack.Services[0].DataPath != "/var/lib/mysql" || gs.Stack.Services[0].Environment["MARIADB_PASSWORD"] != "{{DB_PASSWORD}}" {
		t.Fatalf("sidecar persistence or secret interpolation was not parsed: %#v", gs.Stack.Services[0])
	}
	values := gs.DefaultEnv()
	values["DB_PASSWORD"] = "unique-database-password-123"
	values["DB_ROOT_PASSWORD"] = "unique-root-password-456789"
	if err := gs.ValidateEnv(values); err != nil {
		t.Fatalf("valid stack secrets were rejected: %v", err)
	}
	values["DB_PASSWORD"] = "too-short"
	if err := gs.ValidateEnv(values); err == nil {
		t.Fatal("short database password was accepted")
	}
}

func TestStackRejectsUnsafeNamesPathsAndUndeclaredVariables(t *testing.T) {
	base := Rune{
		ID: "stack", Name: "Stack", Docker: Docker{Image: "example/app:1", KeepEntrypoint: true},
		Startup: Startup{}, Stack: &Stack{Services: []Service{{Name: "database", Image: "mariadb:11", DataPath: "/var/lib/mysql"}}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid stack was rejected: %v", err)
	}
	base.Stack.Services[0].ExtraVolumes = []string{"/var/lib/mysql-files"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid extra sidecar volume was rejected: %v", err)
	}
	base.Stack.Services[0].ExtraVolumes = []string{"/var/lib/mysql"}
	if err := base.Validate(); err == nil {
		t.Fatal("duplicate sidecar volume target was accepted")
	}
	base.Stack.Services[0].ExtraVolumes = []string{"/etc"}
	if err := base.Validate(); err == nil {
		t.Fatal("sidecar extra volume shadowing system files was accepted")
	}
	base.Stack.Services[0].ExtraVolumes = nil
	base.Stack.Services[0].DataPath = ""
	if err := base.Validate(); err != nil {
		t.Fatalf("stateless sidecar without a data path was rejected: %v", err)
	}
	base.Stack.Services[0].DataPath = "/var/lib/mysql"
	base.Stack.Services[0].Name = "bad_name"
	if err := base.Validate(); err == nil {
		t.Fatal("service name with underscore was accepted as a DNS alias")
	}
	base.Stack.Services[0].Name = "database"
	base.Stack.Services[0].DataPath = "/etc"
	if err := base.Validate(); err == nil {
		t.Fatal("sidecar data path shadowing system files was accepted")
	}
	base.Stack.Services[0].DataPath = "/var/lib/mysql"
	base.Stack.Services[0].Environment = map[string]string{"PASSWORD": "{{UNDECLARED}}"}
	if err := base.Validate(); err == nil {
		t.Fatal("undeclared sidecar template variable was accepted")
	}
	base.Stack.Services[0].Environment = nil
	base.Variables = []Variable{{Key: "DB_PASSWORD", Type: "string", Secret: true}}
	base.Stack.Services[0].Image = "mariadb:{{DB_PASSWORD}}"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "must not embed secret") {
		t.Fatalf("secret embedded in sidecar image was not rejected: %v", err)
	}
	base.Stack.Services[0].Image = "mariadb:11"
	base.Stack.Services[0].Command = []string{"--password={{DB_PASSWORD}}"}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "must not embed secret") {
		t.Fatalf("secret embedded in sidecar command was not rejected: %v", err)
	}
}

func TestAppUpdateValidation(t *testing.T) {
	base := Rune{
		ID: "updatable", Name: "Updatable", Docker: Docker{Image: "example/app:1", KeepEntrypoint: true},
		Update: &Update{Script: "./upgrade", Label: "Update app", AppWritable: []string{"uploads", "cache/data"}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid update block was rejected: %v", err)
	}
	base.Update.AppWritable = []string{"../outside"}
	if err := base.Validate(); err == nil {
		t.Fatal("app_writable path escaping the data root was accepted")
	}
	base.Update.AppWritable = []string{"cache/data", "cache/data"}
	if err := base.Validate(); err == nil {
		t.Fatal("duplicate app_writable path was accepted")
	}
	base.Update.AppWritable = nil
	base.Update.Script = "  "
	if err := base.Validate(); err == nil {
		t.Fatal("empty app update script was accepted")
	}
	base.Update.Script = "./upgrade"
	base.Variables = []Variable{{Key: "UPDATE_TAG", Type: "string"}}
	base.Update.Image = "example/app:{{UPDATE_TAG}}"
	if err := base.Validate(); err != nil {
		t.Fatalf("declared image placeholder was rejected: %v", err)
	}
	base.Variables = []Variable{{Key: "UPDATE_TOKEN", Type: "string", Secret: true}}
	base.Update.Image = "example/app:{{UPDATE_TOKEN}}"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "must not embed secret") {
		t.Fatalf("secret update image placeholder was accepted: %v", err)
	}
	base.Update.Image = ""
	base.Update.Script = "./upgrade --token {{UPDATE_TOKEN}}"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "must not embed secret") {
		t.Fatalf("secret update script placeholder was accepted: %v", err)
	}
}

func TestWatcherTemplateValidationAcceptsLegacyActionAndRejectsInvalidPatterns(t *testing.T) {
	base := Rune{
		ID: "watcher-template", Name: "Watcher template",
		Docker:   Docker{Image: "example/app:1", KeepEntrypoint: true},
		Watchers: []Watcher{{Name: "Startup warning", Pattern: `(?i)failed to bind`, Action: "kvasir"}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("legacy template Advisory action was rejected: %v", err)
	}
	base.Watchers[0].Pattern = `(?=failed)`
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "watchers[0].pattern") {
		t.Fatalf("unsupported lookahead pattern was accepted: %v", err)
	}
}

func TestServiceEnabledValues(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
		env        map[string]string
		want       bool
		wantErr    bool
	}{
		{name: "empty is enabled", want: true},
		{name: "static truthy", expression: "yes", want: true},
		{name: "templated truthy", expression: "{{FEATURE}}", env: map[string]string{"FEATURE": "on"}, want: true},
		{name: "static false", expression: "0", want: false},
		{name: "unset upgrade placeholder", expression: "{{NEW_FEATURE}}", want: false},
		{name: "invalid value", expression: "sometimes", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ServiceEnabled(test.expression, test.env)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("ServiceEnabled(%q) = (%t,%v), want (%t,error=%t)", test.expression, got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestParseBlockScriptAndRejectProtectedMount(t *testing.T) {
	src := `gameskill:
  id: sample
  name: Sample
  docker:
    image: example/sample:1
  startup:
    command: |
      exec /bin/sample --serve
      echo ready
`
	gs, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if gs.Startup.Command != "exec /bin/sample --serve\necho ready" {
		t.Fatalf("unexpected block script %q", gs.Startup.Command)
	}
	bad := `gameskill:
  id: bad
  name: Bad
  docker:
    image: example/bad:1
    extra_volumes: [/etc/shadow]
  startup:
    command: exec app
`
	if _, err := Parse(bad); err == nil {
		t.Fatal("expected a protected system mount to fail validation")
	}
}

func TestRestartWarningConfigurationAndValidation(t *testing.T) {
	src := `gameskill:
  id: restart-test
  name: Restart Test
  docker:
    image: example/restart-test:1
  startup:
    command: exec test
  restart:
    warnings:
      - at: 5m
        msg: say {{server_name}} restarts in {{minutes}} minutes
      - at: 1m
        msg: say restart in {{seconds}} seconds
`
	gs, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if gs.Restart == nil || len(gs.Restart.Warnings) != 2 || gs.Restart.Warnings[0].At != "5m" || gs.Restart.Warnings[1].Msg != "say restart in {{seconds}} seconds" {
		t.Fatalf("restart warning metadata was not parsed: %#v", gs.Restart)
	}
	duplicate := strings.Replace(src, "at: 1m", "at: 300s", 1)
	if _, err = Parse(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate duration") {
		t.Fatalf("duplicate restart durations were not rejected: %v", err)
	}
	invalidDuration := strings.Replace(src, "at: 5m", "at: soon", 1)
	if _, err = Parse(invalidDuration); err == nil || !strings.Contains(err.Error(), "restart.warnings[0].at") {
		t.Fatalf("invalid restart warning duration was not rejected: %v", err)
	}
	invalidMessage := strings.Replace(src, "msg: say restart in {{seconds}} seconds", "msg: ''", 1)
	if _, err = Parse(invalidMessage); err == nil || !strings.Contains(err.Error(), "restart.warnings[1].msg") {
		t.Fatalf("empty restart warning command was not rejected: %v", err)
	}
	unknownPlaceholder := strings.Replace(src, "{{seconds}}", "{{player}}", 1)
	if _, err = Parse(unknownPlaceholder); err == nil || !strings.Contains(err.Error(), "unsupported placeholder") {
		t.Fatalf("unknown restart warning placeholder was not rejected: %v", err)
	}
}

func TestValueValidation(t *testing.T) {
	min, max := 2, 10
	gs := Rune{ID: "test", Name: "Test", Docker: Docker{Image: "test:latest"}, Startup: Startup{Command: "exec test"}, Variables: []Variable{{Key: "COUNT", Type: "int", Min: &min, Max: &max, Required: true}}}
	if err := gs.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := gs.ValidateEnv(map[string]string{"COUNT": "11"}); err == nil {
		t.Fatal("expected max bound error")
	}
	if err := gs.ValidateEnv(map[string]string{}); err == nil {
		t.Fatal("expected required variable error")
	}
}

func TestTemplateReplacesOnlyDeclaredPlaceholders(t *testing.T) {
	got := ApplyTemplate("{{A}}/{{MISSING}}", map[string]string{"A": "ok"})
	if got != "ok/{{MISSING}}" {
		t.Fatalf("unexpected template result %q", got)
	}
}

func TestValidatedOptionalDockerFeaturesAndSteamMetadata(t *testing.T) {
	base := Rune{ID: "device-app", Name: "Device App", Docker: Docker{Image: "example/app:1", Capabilities: []string{"net_admin"}, Devices: []string{"/dev/net/tun:/dev/net/tun:rwm"}, Sysctls: map[string]string{"net.ipv4.ip_forward": "1"}}, Startup: Startup{Command: "exec app"}}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid constrained Docker features were rejected: %v", err)
	}
	base.Docker.Devices = []string{"/dev/mem"}
	if err := base.Validate(); err == nil {
		t.Fatal("unsafe host device was accepted")
	}
	base.Docker.Devices = nil
	base.Steam = &Steam{AppID: 1}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "requires an install.script") {
		t.Fatalf("Steam metadata without an installer was accepted: %v", err)
	}
	base.Install = &Install{Script: "steamcmd +login anonymous"}
	base.Steam = &Steam{AppID: 1}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid Steam installation metadata was rejected: %v", err)
	}
	base.Steam = &Steam{AppID: -1}
	if err := base.Validate(); err == nil {
		t.Fatal("negative Steam app ID was accepted")
	}
	base.Steam = nil
	base.Variables = []Variable{{Key: "STEAM_USER", Type: "string"}}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "injected by the panel") {
		t.Fatalf("panel-injected Steam username was accepted as a template variable: %v", err)
	}
	base.Variables = nil
	base.ConfigFiles = []string{"app.conf"}
	if err := base.Validate(); err != nil {
		t.Fatalf("safe config-file shortcut was rejected: %v", err)
	}
	base.ConfigFiles = []string{"../outside.conf"}
	if err := base.Validate(); err == nil {
		t.Fatal("config-file path escaped the server data directory")
	}
}
