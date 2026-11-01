package panel

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPBSRepositoryAndTargetValidation(t *testing.T) {
	target := backupTargetConfig{
		Endpoint:  "pbs.example.net",
		Bucket:    "docklight-backups",
		AccessKey: "docklight@pbs!backup",
		SecretKey: "api-token-secret",
		Port:      8007,
	}
	repository, err := pbsRepository(target)
	if err != nil || repository != "docklight@pbs!backup@pbs.example.net:8007:docklight-backups" {
		t.Fatalf("pbsRepository() = %q, %v", repository, err)
	}
	target.Endpoint = "2001:db8::10"
	repository, err = pbsRepository(target)
	if err != nil || repository != "docklight@pbs!backup@[2001:db8::10]:8007:docklight-backups" {
		t.Fatalf("IPv6 pbsRepository() = %q, %v", repository, err)
	}
	target.Port = 0
	repository, err = pbsRepository(target)
	if err != nil || repository != "docklight@pbs!backup@[2001:db8::10]:8007:docklight-backups" {
		t.Fatalf("PBS repository default port = %q, %v", repository, err)
	}

	target.HostKeySHA256 = strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	err = validatePBSTarget(target)
	if runtime.GOARCH == "amd64" && err != nil {
		t.Fatalf("valid PBS target rejected on amd64: %v", err)
	}
	if runtime.GOARCH != "amd64" && (err == nil || !strings.Contains(err.Error(), "amd64")) {
		t.Fatalf("non-amd64 PBS target error = %v", err)
	}

	for _, host := range []string{"https://pbs.example.net", "bad..host", "bad host", "-invalid.example"} {
		invalid := target
		invalid.Endpoint = host
		if _, err := pbsRepository(invalid); err == nil {
			t.Errorf("accepted invalid PBS host %q", host)
		}
	}
	for _, id := range []string{"docklight@pbs", "docklight@pbs!token!extra", "docklight@pbs!token\n"} {
		if pbsAuthIDPattern.MatchString(id) {
			t.Errorf("accepted invalid PBS auth ID %q", id)
		}
	}
}

func TestPBSGroupAndStorageKeyRoundTrip(t *testing.T) {
	serverID := "3dca7f9b-2b1a-4f0d-a1c8-8cb8624f1e90"
	group := pbsGroupID("My Survival Server!", serverID)
	if !validPBSGroupID(group) || !strings.HasSuffix(group, "-"+shortID(serverID)) {
		t.Fatalf("unexpected PBS group: %q", group)
	}
	key := pbsStorageKey(group, 1_800_000_000)
	gotGroup, gotTime, err := parsePBSStorageKey(key)
	if err != nil || gotGroup != group || gotTime != 1_800_000_000 {
		t.Fatalf("parsePBSStorageKey(%q) = %q, %d, %v", key, gotGroup, gotTime, err)
	}
	for _, invalid := range []string{
		"vm/" + group + "/" + time.Unix(1_800_000_000, 0).UTC().Format(time.RFC3339),
		"host/../" + time.Unix(1_800_000_000, 0).UTC().Format(time.RFC3339),
		"host/" + group + "/not-a-time",
		"host/" + group + "/" + time.Unix(1_800_000_000, 0).UTC().Format(time.RFC3339) + "/extra",
	} {
		if _, _, err := parsePBSStorageKey(invalid); err == nil {
			t.Errorf("accepted invalid PBS storage key %q", invalid)
		}
	}
}

func TestPBSTargetIsEncryptedRedactedAndIdentityLocked(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the PBS helper supports amd64 hosts only")
	}
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('pbs-admin','pbs-admin','unused','admin')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "pbs-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	secret := "pbs-secret-that-must-not-leak"
	fingerprint := strings.TrimSuffix(strings.Repeat("C1:", 32), ":")
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"pbs","host":"pbs.example.net","datastore":"docklight-backups","auth_id":"docklight@pbs!backup","secret_key":"`+secret+`","namespace":"team/production","certificate_fingerprint":"`+fingerprint+`","enabled":true}`, session)
	if configured.Code != http.StatusOK || !strings.Contains(configured.Body.String(), `"port":8007`) || strings.Contains(configured.Body.String(), secret) {
		t.Fatalf("configure PBS target: %d %s", configured.Code, configured.Body.String())
	}
	target, err := a.readBackupTarget()
	if err != nil || target.protocol() != "pbs" || target.Port != 8007 || target.Endpoint != "pbs.example.net" || target.Bucket != "docklight-backups" || target.AccessKey != "docklight@pbs!backup" || target.SecretKey != secret || target.Prefix != "team/production" || target.HostKeySHA256 != fingerprint {
		t.Fatalf("read saved PBS settings: %#v, %v", target, err)
	}
	var endpointCipher, authCipher, secretCipher string
	if err = d.QueryRow(`SELECT endpoint_enc,access_key_enc,secret_key_enc FROM backup_target_settings WHERE id=1`).Scan(&endpointCipher, &authCipher, &secretCipher); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{endpointCipher, target.Endpoint}, {authCipher, target.AccessKey}, {secretCipher, secret}} {
		if pair[0] == "" || strings.Contains(pair[0], pair[1]) {
			t.Fatalf("PBS credential field was not encrypted: %q", pair[0])
		}
	}
	read := testRequest(h, http.MethodGet, "/api/backups/target", "", session)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"namespace":"team/production"`) || !strings.Contains(read.Body.String(), fingerprint) || strings.Contains(read.Body.String(), secret) || strings.Contains(read.Body.String(), "docklight@pbs!backup") {
		t.Fatalf("PBS target response exposed a credential or omitted public settings: %d %s", read.Code, read.Body.String())
	}
	if _, err = d.Exec(`INSERT INTO server_backups(id,server_id,storage,storage_key,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES('pbs-record','pbs-server','pbs','host/world-3dca7f9b/2026-01-01T00:00:00Z',1,'',1,0,1,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	changedHost := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"pbs","host":"other.example.net"}`, session)
	if changedHost.Code != http.StatusConflict {
		t.Fatalf("changed PBS host while snapshots were recorded: %d %s", changedHost.Code, changedHost.Body.String())
	}
	rotatedSecret := "rotated-pbs-token-secret"
	rotatedFingerprint := strings.TrimSuffix(strings.Repeat("D2:", 32), ":")
	rotated := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"pbs","secret_key":"`+rotatedSecret+`","certificate_fingerprint":"`+rotatedFingerprint+`"}`, session)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), rotatedSecret) {
		t.Fatalf("rotate PBS credentials without changing the destination: %d %s", rotated.Code, rotated.Body.String())
	}
}
