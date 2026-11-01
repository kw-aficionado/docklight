package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSFTPBackupTargetIsEncryptedAndUsesRemoteBackupLifecycle(t *testing.T) {
	a, d, _ := testApp(t)
	h := a.Router()
	adminSession, err := a.issue(User{ID: "remote-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('remote-admin','remote-admin','unused','admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('remote-user','remote-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	userSession, err := a.issue(User{ID: "remote-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	hostFingerprint := "SHA256:" + strings.Repeat("A", 43)
	withoutPin := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"sftp","host":"backup.internal","port":2222,"username":"docklight-backups","secret_key":"secret-that-must-not-be-stored-in-plaintext","prefix":"nightly","enabled":true}`, adminSession)
	if withoutPin.Code != http.StatusBadRequest || !strings.Contains(withoutPin.Body.String(), "host-key fingerprint") {
		t.Fatalf("enabled SFTP target without a host-key pin was accepted: %d %s", withoutPin.Code, withoutPin.Body.String())
	}
	invalidPin := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"sftp","host":"backup.internal","port":2222,"username":"docklight-backups","secret_key":"secret-that-must-not-be-stored-in-plaintext","host_key_sha256":"SHA256:invalid","enabled":true}`, adminSession)
	if invalidPin.Code != http.StatusBadRequest {
		t.Fatalf("invalid SFTP host-key fingerprint was accepted: %d %s", invalidPin.Code, invalidPin.Body.String())
	}
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"sftp","host":"backup.internal","port":2222,"username":"docklight-backups","secret_key":"secret-that-must-not-be-stored-in-plaintext","host_key_sha256":"`+hostFingerprint+`","prefix":"nightly","enabled":true}`, adminSession)
	if configured.Code != http.StatusOK || !strings.Contains(configured.Body.String(), `"type":"sftp"`) || !strings.Contains(configured.Body.String(), `"configured":true`) || strings.Contains(configured.Body.String(), "secret-that-must-not-be-stored") {
		t.Fatalf("configure SFTP target: %d %s", configured.Code, configured.Body.String())
	}
	var protocol string
	var port int
	var endpointEnc, usernameEnc, passwordEnc, storedFingerprint string
	if err = d.QueryRow(`SELECT protocol,port,endpoint_enc,access_key_enc,secret_key_enc,host_key_sha256 FROM backup_target_settings WHERE id=1`).Scan(&protocol, &port, &endpointEnc, &usernameEnc, &passwordEnc, &storedFingerprint); err != nil {
		t.Fatal(err)
	}
	if protocol != "sftp" || port != 2222 || storedFingerprint != hostFingerprint || strings.Contains(endpointEnc, "backup.internal") || strings.Contains(usernameEnc, "docklight-backups") || strings.Contains(passwordEnc, "secret-that-must") {
		t.Fatalf("SFTP target fields were not saved safely: protocol=%q port=%d fingerprint=%q endpoint=%q username=%q password=%q", protocol, port, storedFingerprint, endpointEnc, usernameEnc, passwordEnc)
	}
	target, err := a.readBackupTarget()
	if err != nil || target.Endpoint != "backup.internal" || target.AccessKey != "docklight-backups" || target.SecretKey != "secret-that-must-not-be-stored-in-plaintext" || target.HostKeySHA256 != hostFingerprint {
		t.Fatalf("decrypt saved SFTP settings: %#v err=%v", target, err)
	}
	read := testRequest(h, http.MethodGet, "/api/backups/target", "", adminSession)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"username_configured":true`) || !strings.Contains(read.Body.String(), hostFingerprint) || strings.Contains(read.Body.String(), "docklight-backups") || strings.Contains(read.Body.String(), "secret-that-must") {
		t.Fatalf("SFTP summary leaked a credential: %d %s", read.Code, read.Body.String())
	}
	status := testRequest(h, http.MethodGet, "/api/backups/target/status", "", userSession)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"type":"sftp"`) || !strings.Contains(status.Body.String(), `"enabled":true`) {
		t.Fatalf("SFTP target status: %d %s", status.Code, status.Body.String())
	}

	store := newMemoryBackupStore()
	a.backupStoreFactory = func(target backupTargetConfig) (backupObjectStore, error) {
		if target.protocol() != "sftp" || target.Endpoint != "backup.internal" || target.Port != 2222 {
			t.Fatalf("remote store received the wrong target: %#v", target)
		}
		return store, nil
	}
	dataDir := filepath.Join(a.dataRoot, "remote-backup-server")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dataDir, "world.dat")
	if err = os.WriteFile(dataPath, []byte("before restore"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('remote-backup-server','Remote backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('remote-user','server','remote-backup-server','server.view,server.backup,server.schedule')`); err != nil {
		t.Fatal(err)
	}

	created := testRequest(h, http.MethodPost, "/api/servers/remote-backup-server/backups", `{"destination":"sftp"}`, userSession)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"storage":"sftp"`) || store.count() != 1 {
		t.Fatalf("create remote backup: %d %s objects=%d", created.Code, created.Body.String(), store.count())
	}
	var response struct {
		Backup backupRecord `json:"backup"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Backup.ID == "" {
		t.Fatalf("decode remote backup response: %#v err=%v", response, err)
	}
	rotatedFingerprint := "SHA256:" + strings.Repeat("E", 43)
	rotated := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"sftp","host_key_sha256":"`+rotatedFingerprint+`"}`, adminSession)
	if rotated.Code != http.StatusOK || !strings.Contains(rotated.Body.String(), rotatedFingerprint) {
		t.Fatalf("could not rotate a verified SFTP host-key pin while preserving backup records: %d %s", rotated.Code, rotated.Body.String())
	}
	verify := testRequest(h, http.MethodPost, "/api/servers/remote-backup-server/backups/"+response.Backup.ID+"/verify", `{}`, userSession)
	if verify.Code != http.StatusOK || !strings.Contains(verify.Body.String(), `"valid":true`) {
		t.Fatalf("verify remote backup: %d %s", verify.Code, verify.Body.String())
	}
	if err = os.WriteFile(dataPath, []byte("changed after backup"), 0600); err != nil {
		t.Fatal(err)
	}
	restore := testRequest(h, http.MethodPost, "/api/servers/remote-backup-server/backups/"+response.Backup.ID+"/restore", `{}`, userSession)
	if restore.Code != http.StatusOK {
		t.Fatalf("restore remote backup: %d %s", restore.Code, restore.Body.String())
	}
	restored, err := os.ReadFile(dataPath)
	if err != nil || string(restored) != "before restore" {
		t.Fatalf("restored server data=%q err=%v", restored, err)
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/remote-backup-server/backups/"+response.Backup.ID, `{}`, userSession)
	if deleted.Code != http.StatusOK || store.count() != 0 {
		t.Fatalf("delete remote backup: %d %s objects=%d", deleted.Code, deleted.Body.String(), store.count())
	}

	scheduled := testRequest(h, http.MethodPost, "/api/servers/remote-backup-server/schedules", `{"action":"backup","destination":"sftp","cron":"0 3 * * *"}`, userSession)
	if scheduled.Code != http.StatusCreated || !strings.Contains(scheduled.Body.String(), `"destination":"sftp"`) {
		t.Fatalf("create SFTP backup schedule: %d %s", scheduled.Code, scheduled.Body.String())
	}
	changed := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"smb","host":"nas.internal","share":"backups","username":"docklight","secret_key":"new-secret","enabled":true}`, adminSession)
	if changed.Code != http.StatusOK {
		t.Fatalf("switch remote protocol after removing backup records: %d %s", changed.Code, changed.Body.String())
	}
}

func TestRemoteTargetIdentityCannotChangeWhileRemoteBackupExists(t *testing.T) {
	a, d, _ := testApp(t)
	h := a.Router()
	adminSession, err := a.issue(User{ID: "remote-lock-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('remote-lock-admin','remote-lock-admin','unused','admin')`); err != nil {
		t.Fatal(err)
	}
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"smb","host":"nas.internal","port":445,"share":"backup","username":"old-user","secret_key":"old-secret","prefix":"backup","enabled":true}`, adminSession)
	if configured.Code != http.StatusOK {
		t.Fatalf("configure SMB target: %d %s", configured.Code, configured.Body.String())
	}
	if _, err = d.Exec(`INSERT INTO server_backups(id,server_id,storage,storage_key,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES('remote-lock-backup','remote-lock-server','smb','backup/docklight/remote-lock-server/remote-lock-backup.dlbak',1,'abc',0,0,0,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	changed := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"smb","host":"nas.other.internal","port":445,"share":"backup","username":"new-user","secret_key":"new-secret","enabled":true}`, adminSession)
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed remote target identity with recorded remote backup: %d %s", changed.Code, changed.Body.String())
	}
	rotated := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"smb","host":"nas.internal","port":445,"share":"backup","username":"new-user","secret_key":"new-secret","enabled":true}`, adminSession)
	if rotated.Code != http.StatusOK {
		t.Fatalf("could not rotate SMB credentials without changing destination identity: %d %s", rotated.Code, rotated.Body.String())
	}
}

func TestRemoteBackupPrefixRejectsTraversal(t *testing.T) {
	for _, prefix := range []string{"../escape", "safe//nested", "safe/./nested", "safe/../nested", "bad\\path"} {
		if _, err := normalizeBackupPrefix(prefix); err == nil {
			t.Errorf("accepted remote backup prefix %q", prefix)
		}
	}
}

func TestSMBBackupUsesGenericRemoteSnapshotAndRetentionFlow(t *testing.T) {
	a, d, _ := testApp(t)
	h := a.Router()
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('smb-admin','smb-admin','unused','admin'),('smb-user','smb-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	adminSession, err := a.issue(User{ID: "smb-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userSession, err := a.issue(User{ID: "smb-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"smb","host":"fileserver.internal","port":445,"share":"docklight-backups","username":"panel-backups","secret_key":"smb-password","prefix":"nightly","enabled":true}`, adminSession)
	if configured.Code != http.StatusOK || !strings.Contains(configured.Body.String(), `"type":"smb"`) {
		t.Fatalf("configure SMB target: %d %s", configured.Code, configured.Body.String())
	}
	store := newMemoryBackupStore()
	a.backupStoreFactory = func(target backupTargetConfig) (backupObjectStore, error) {
		if target.protocol() != "smb" || target.Endpoint != "fileserver.internal" || target.Bucket != "docklight-backups" {
			t.Fatalf("SMB store received the wrong settings: %#v", target)
		}
		return store, nil
	}
	dataDir := filepath.Join(a.dataRoot, "smb-backup-server")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dataDir, "database.dump"), []byte("application database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('smb-backup-server','SMB backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('smb-user','server','smb-backup-server','server.view,server.backup')`); err != nil {
		t.Fatal(err)
	}
	created := testRequest(h, http.MethodPost, "/api/servers/smb-backup-server/backups", `{"destination":"smb"}`, userSession)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"storage":"smb"`) || store.count() != 1 {
		t.Fatalf("create SMB backup: %d %s objects=%d", created.Code, created.Body.String(), store.count())
	}
	var response struct {
		Backup backupRecord `json:"backup"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Backup.ID == "" {
		t.Fatalf("decode SMB backup response: %#v err=%v", response, err)
	}
	verified := testRequest(h, http.MethodPost, "/api/servers/smb-backup-server/backups/"+response.Backup.ID+"/verify", `{}`, userSession)
	if verified.Code != http.StatusOK {
		t.Fatalf("verify SMB backup: %d %s", verified.Code, verified.Body.String())
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/smb-backup-server/backups/"+response.Backup.ID, `{}`, userSession)
	if deleted.Code != http.StatusOK || store.count() != 0 {
		t.Fatalf("delete SMB backup: %d %s objects=%d", deleted.Code, deleted.Body.String(), store.count())
	}
}
