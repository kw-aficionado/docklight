package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAzureBackupTargetEncryptionAndLifecycle(t *testing.T) {
	a, d, _ := testApp(t)
	store := newMemoryBackupStore()
	a.backupStoreFactory = func(target backupTargetConfig) (backupObjectStore, error) {
		if target.protocol() != "azure" || target.AccessKey != "docklightstorage" || target.Bucket != "docklight-backups" || target.AuthMode != "key" {
			t.Fatalf("Azure target was not decrypted correctly: %#v", target)
		}
		return store, nil
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('azure-admin','azure-admin','unused','admin'),('azure-user','azure-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	adminSession, err := a.issue(User{ID: "azure-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userSession, err := a.issue(User{ID: "azure-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	const accountKey = "ZmFrZS1hY2NvdW50LWtleQ=="
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"type":"azure","endpoint":"","account_name":"docklightstorage","bucket":"docklight-backups","auth_mode":"key","secret_key":"`+accountKey+`","prefix":"nightly","enabled":true}`, adminSession)
	if configured.Code != http.StatusOK || !strings.Contains(configured.Body.String(), `"type":"azure"`) || !strings.Contains(configured.Body.String(), `"configured":true`) || !strings.Contains(configured.Body.String(), `"auth_mode":"key"`) || strings.Contains(configured.Body.String(), "docklightstorage") || strings.Contains(configured.Body.String(), accountKey) {
		t.Fatalf("configure Azure target: %d %s", configured.Code, configured.Body.String())
	}
	var protocol, endpoint, accountName, savedKey, authMode string
	if err = d.QueryRow(`SELECT protocol,endpoint_enc,access_key_enc,secret_key_enc,auth_mode FROM backup_target_settings WHERE id=1`).Scan(&protocol, &endpoint, &accountName, &savedKey, &authMode); err != nil {
		t.Fatal(err)
	}
	if protocol != "azure" || endpoint != "" || authMode != "key" || strings.Contains(accountName, "docklightstorage") || strings.Contains(savedKey, accountKey) {
		t.Fatalf("Azure target credentials were not stored safely: protocol=%q endpoint=%q account=%q key=%q mode=%q", protocol, endpoint, accountName, savedKey, authMode)
	}
	read := testRequest(h, http.MethodGet, "/api/backups/target", "", adminSession)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"account_name_configured":true`) || !strings.Contains(read.Body.String(), `"bucket":"docklight-backups"`) || strings.Contains(read.Body.String(), "docklightstorage") || strings.Contains(read.Body.String(), accountKey) {
		t.Fatalf("Azure summary leaked its account or key: %d %s", read.Code, read.Body.String())
	}
	status := testRequest(h, http.MethodGet, "/api/backups/target/status", "", userSession)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":true`) || !strings.Contains(status.Body.String(), `"type":"azure"`) {
		t.Fatalf("Azure status summary: %d %s", status.Code, status.Body.String())
	}

	dataDir := filepath.Join(a.dataRoot, "azure-backup-server")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dataDir, "world.dat")
	if err = os.WriteFile(dataPath, []byte("before restore"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('azure-backup-server','Azure backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('azure-user','server','azure-backup-server','server.view,server.backup,server.schedule')`); err != nil {
		t.Fatal(err)
	}
	created := testRequest(h, http.MethodPost, "/api/servers/azure-backup-server/backups", `{"destination":"azure"}`, userSession)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"storage":"azure"`) || store.count() != 1 {
		t.Fatalf("create Azure backup: %d %s objects=%d", created.Code, created.Body.String(), store.count())
	}
	var response struct {
		Backup backupRecord `json:"backup"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Backup.ID == "" {
		t.Fatalf("decode Azure backup response: %#v err=%v", response, err)
	}
	scheduled := testRequest(h, http.MethodPost, "/api/servers/azure-backup-server/schedules", `{"action":"backup","destination":"azure","cron":"0 3 * * *"}`, userSession)
	if scheduled.Code != http.StatusCreated || !strings.Contains(scheduled.Body.String(), `"destination":"azure"`) {
		t.Fatalf("create Azure backup schedule: %d %s", scheduled.Code, scheduled.Body.String())
	}
	changedAccount := testRequest(h, http.MethodPut, "/api/backups/target", `{"account_name":"anotherstorageaccount"}`, adminSession)
	if changedAccount.Code != http.StatusConflict {
		t.Fatalf("changed Azure account while backup records exist: %d %s", changedAccount.Code, changedAccount.Body.String())
	}
	rotatedKey := "YW5vdGhlci1hY2NvdW50LWtleQ=="
	rotated := testRequest(h, http.MethodPut, "/api/backups/target", `{"secret_key":"`+rotatedKey+`"}`, adminSession)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), rotatedKey) {
		t.Fatalf("could not rotate Azure account key safely: %d %s", rotated.Code, rotated.Body.String())
	}
	verified := testRequest(h, http.MethodPost, "/api/servers/azure-backup-server/backups/"+response.Backup.ID+"/verify", `{}`, userSession)
	if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"valid":true`) {
		t.Fatalf("verify Azure backup: %d %s", verified.Code, verified.Body.String())
	}
	if err = os.WriteFile(dataPath, []byte("changed after backup"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := testRequest(h, http.MethodPost, "/api/servers/azure-backup-server/backups/"+response.Backup.ID+"/restore", `{}`, userSession)
	if restored.Code != http.StatusOK {
		t.Fatalf("restore Azure backup: %d %s", restored.Code, restored.Body.String())
	}
	data, err := os.ReadFile(dataPath)
	if err != nil || string(data) != "before restore" {
		t.Fatalf("restored Azure server data=%q err=%v", data, err)
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/azure-backup-server/backups/"+response.Backup.ID, "", userSession)
	if deleted.Code != http.StatusOK || store.count() != 0 {
		t.Fatalf("delete Azure backup: %d %s objects=%d", deleted.Code, deleted.Body.String(), store.count())
	}
	cleared := testRequest(h, http.MethodPut, "/api/backups/target", `{"clear_target":true}`, adminSession)
	if cleared.Code != http.StatusOK {
		t.Fatalf("clear empty Azure target: %d %s", cleared.Code, cleared.Body.String())
	}
}
