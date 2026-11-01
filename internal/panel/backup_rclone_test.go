package panel

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRcloneCustomConfigIsBoundToOneRemote(t *testing.T) {
	got, err := normalizeRcloneCustomConfig("# exported by rclone\n[backup]\ntype = s3\nprovider = Other\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "[docklight]\ntype = s3\nprovider = Other\n" {
		t.Fatalf("normalized config = %q", got)
	}
	if err = validateStoredRcloneConfig("custom", got); err != nil {
		t.Fatalf("normalized config was not accepted: %v", err)
	}

	for _, input := range []string{
		"type = s3",
		"[remote]\ntype = s3\n[other]\ntype = sftp\n",
		"[remote]\ntype = s3\ntype = local\n",
		"[remote]\ninvalid key = value\n",
		"[remote]\ntype = s3\npassword = unsafe\n\x00",
	} {
		if _, err = normalizeRcloneCustomConfig(input); err == nil {
			t.Errorf("accepted invalid custom config %q", input)
		}
	}
}

func TestRcloneOAuthTokenParsing(t *testing.T) {
	plain := `{"access_token":"access","token_type":"Bearer","expiry":"2030-01-01T00:00:00Z"}`
	for name, input := range map[string]string{
		"plain JSON":  plain,
		"base64 JSON": base64.StdEncoding.EncodeToString([]byte(plain)),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := compactRcloneOAuthToken(input)
			if err != nil || !strings.Contains(got, `"access_token":"access"`) {
				t.Fatalf("compactRcloneOAuthToken() = %q, %v", got, err)
			}
		})
	}
	for _, input := range []string{"not-json", `{"token_type":"Bearer"}`, `[]`} {
		if _, err := compactRcloneOAuthToken(input); err == nil {
			t.Errorf("accepted invalid token %q", input)
		}
	}
}

func TestRcloneProviderConfigValidationAndUpdates(t *testing.T) {
	if err := validateStoredRcloneConfig("drive", "[docklight]\ntype = drive\ntoken = {\"access_token\":\"x\"}\n"); err != nil {
		t.Fatalf("valid Drive config rejected: %v", err)
	}
	for provider, config := range map[string]string{
		"drive":      "[docklight]\ntype = box\ntoken = {\"access_token\":\"x\"}\n",
		"webdav":     "[docklight]\ntype = webdav\nurl = http://files.example\nvendor = nextcloud\nuser = user\npass = secret\n",
		"jottacloud": "[docklight]\ntype = jottacloud\nusername = user\n",
	} {
		if err := validateStoredRcloneConfig(provider, config); err == nil {
			t.Errorf("accepted invalid %s config", provider)
		}
	}

	updated, err := updateRcloneConfigOptions("[docklight]\ntype = webdav\nurl = https://old.example/remote.php/dav\nvendor = nextcloud\nuser = old\npass = obfuscated\n", map[string]string{"url": "https://new.example/dav", "user": "new"})
	if err != nil || !strings.Contains(updated, "url = https://new.example/dav") || !strings.Contains(updated, "user = new") || !strings.Contains(updated, "pass = obfuscated") {
		t.Fatalf("updateRcloneConfigOptions() = %q, %v", updated, err)
	}
	if _, err = updateRcloneConfigOptions(updated, map[string]string{"user": "bad\npass = injected"}); err == nil {
		t.Fatal("accepted a config update containing a line break")
	}
}

func TestRcloneHelperOutputRedactsSecrets(t *testing.T) {
	got := redactRcloneOutput("request failed\ntoken={\"access_token\":\"abc\"}\npassword=secret\naccount secret", []string{"abc", "secret"})
	for _, secret := range []string{"abc", "secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output still contains %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "token=[redacted]") || !strings.Contains(got, "password=[redacted]") {
		t.Fatalf("credential fields were not redacted: %s", got)
	}
}

func TestRcloneCustomTargetIsEncryptedAndIdentityLocked(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('rclone-admin','rclone-admin','unused','admin')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "rclone-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	config := "[backup]\ntype = alias\nremote = archive:/docklight\n"
	body, err := json.Marshal(map[string]any{"type": "rclone", "provider": "custom", "rclone_config": config, "enabled": true})
	if err != nil {
		t.Fatal(err)
	}
	saved := testRequest(h, http.MethodPut, "/api/backups/target", string(body), session)
	if saved.Code != http.StatusOK || strings.Contains(saved.Body.String(), "archive:/docklight") {
		t.Fatalf("save custom rclone target: %d %s", saved.Code, saved.Body.String())
	}
	target, err := a.readBackupTarget()
	if err != nil || target.protocol() != "rclone" || target.AuthMode != "custom" || target.SecretKey != "[docklight]\ntype = alias\nremote = archive:/docklight\n" {
		t.Fatalf("read saved rclone target: %#v, %v", target, err)
	}
	var ciphertext string
	if err = d.QueryRow(`SELECT secret_key_enc FROM backup_target_settings WHERE id=1`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, "archive:/docklight") {
		t.Fatal("rclone configuration was stored in plaintext")
	}
	if _, err = d.Exec(`INSERT INTO server_backups(id,server_id,storage,storage_key,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES('rclone-record','rclone-server','rclone','docklight/rclone-server/backup.dlbak',1,'abc',0,0,0,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	changed := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"rclone","provider":"drive","rclone_secret":"{\"access_token\":\"test\"}"}`, session)
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed rclone provider with existing backups: %d %s", changed.Code, changed.Body.String())
	}
}
