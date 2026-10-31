package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateCreatesSecretAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	c, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Admin.Password) < 12 || len(c.Auth.SecretKey) < 32 {
		t.Fatal("generated credentials are too short")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Admin.Password != c.Admin.Password || loaded.Auth.SecretKey != c.Auth.SecretKey {
		t.Fatal("generated configuration did not round-trip")
	}
	if loaded.Backups.Retention != 10 {
		t.Fatalf("default backup retention = %d, want 10", loaded.Backups.Retention)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Generate(path); err == nil {
		t.Fatal("Generate overwrote an existing config")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing config changed after refused overwrite")
	}
}

func TestLoadBackupPathAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "server:\n  host: 127.0.0.1\n  port: 8080\ndatabase:\n  path: /tmp/panel.db\nbackups:\n  path: /srv/ygg/backups\n  retention: 4\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Backups.Path != "/srv/ygg/backups" || c.Backups.Retention != 4 {
		t.Fatalf("backup config = %#v, want path and retention from file", c.Backups)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(content, "retention: 4", "retention: 101", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("backup retention above 100 was accepted")
	}
}

func TestLoadAcceptsOldDemoKeyAndRejectsInvalidPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	legacy := "server:\n  host: 127.0.0.1\n  port: 8080\n  demo_mode: false\ndatabase:\n  path: /tmp/yggdrasil.db\nauth:\n  session_ttl_hours: 24\nports:\n  range_min: 25000\n  range_max: 30000\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("legacy demo key was not accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(legacy, "port: 8080", "port: 70000", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid listener port was accepted")
	}
}
