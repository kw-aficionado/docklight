package panel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func panelGCSTestCredential(t *testing.T) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.MarshalIndent(map[string]string{
		"type":           "service_account",
		"private_key_id": "docklight-test-key",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})),
		"client_email":   "docklight@example-project.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(credential)
}

func TestGCSBackupTargetEncryptionAndLifecycle(t *testing.T) {
	a, d, _ := testApp(t)
	store := newMemoryBackupStore()
	credential := panelGCSTestCredential(t)
	expectedCredential := credential
	a.backupStoreFactory = func(target backupTargetConfig) (backupObjectStore, error) {
		if target.protocol() != "gcs" || target.Bucket != "docklight-backups" || target.SecretKey != expectedCredential {
			t.Fatalf("GCS target was not decrypted correctly: type=%s bucket=%q credential_matches=%t", target.protocol(), target.Bucket, target.SecretKey == expectedCredential)
		}
		return store, nil
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('gcs-admin','gcs-admin','unused','admin'),('gcs-user','gcs-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	adminSession, err := a.issue(User{ID: "gcs-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userSession, err := a.issue(User{ID: "gcs-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	configureBody, err := json.Marshal(map[string]any{"type": "gcs", "bucket": "docklight-backups", "secret_key": credential, "prefix": "nightly", "enabled": true})
	if err != nil {
		t.Fatal(err)
	}
	configured := testRequest(a.Router(), http.MethodPut, "/api/backups/target", string(configureBody), adminSession)
	responseText := configured.Body.String()
	if configured.Code != http.StatusOK || !strings.Contains(responseText, `"type":"gcs"`) || !strings.Contains(responseText, `"configured":true`) || !strings.Contains(responseText, `"secret_key_configured":true`) || strings.Contains(responseText, "docklight@example-project.iam.gserviceaccount.com") || strings.Contains(responseText, credential) {
		t.Fatalf("configure GCS target or redact credential: %d %s", configured.Code, responseText)
	}
	var protocol, endpoint, accessKey, savedCredential string
	if err = d.QueryRow(`SELECT protocol,endpoint_enc,access_key_enc,secret_key_enc FROM backup_target_settings WHERE id=1`).Scan(&protocol, &endpoint, &accessKey, &savedCredential); err != nil {
		t.Fatal(err)
	}
	if protocol != "gcs" || endpoint != "" || accessKey != "" || strings.Contains(savedCredential, "docklight@example-project.iam.gserviceaccount.com") || strings.Contains(savedCredential, credential) {
		t.Fatalf("GCS credentials were not encrypted at rest: protocol=%q endpoint=%q access=%q credential=%q", protocol, endpoint, accessKey, savedCredential)
	}
	read := testRequest(a.Router(), http.MethodGet, "/api/backups/target", "", adminSession)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"bucket":"docklight-backups"`) || strings.Contains(read.Body.String(), "docklight@example-project.iam.gserviceaccount.com") || strings.Contains(read.Body.String(), credential) {
		t.Fatalf("GCS target summary exposed its service-account key: %d %s", read.Code, read.Body.String())
	}
	status := testRequest(a.Router(), http.MethodGet, "/api/backups/target/status", "", userSession)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":true`) || !strings.Contains(status.Body.String(), `"type":"gcs"`) {
		t.Fatalf("GCS status summary: %d %s", status.Code, status.Body.String())
	}

	dataDir := filepath.Join(a.dataRoot, "gcs-backup-server")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dataDir, "world.dat")
	if err = os.WriteFile(dataPath, []byte("before restore"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('gcs-backup-server','GCS backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('gcs-user','server','gcs-backup-server','server.view,server.backup,server.schedule')`); err != nil {
		t.Fatal(err)
	}
	created := testRequest(a.Router(), http.MethodPost, "/api/servers/gcs-backup-server/backups", `{"destination":"gcs"}`, userSession)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"storage":"gcs"`) || store.count() != 1 {
		t.Fatalf("create GCS backup: %d %s objects=%d", created.Code, created.Body.String(), store.count())
	}
	var backupResponse struct {
		Backup backupRecord `json:"backup"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &backupResponse); err != nil || backupResponse.Backup.ID == "" {
		t.Fatalf("decode GCS backup response: %#v err=%v", backupResponse, err)
	}
	scheduled := testRequest(a.Router(), http.MethodPost, "/api/servers/gcs-backup-server/schedules", `{"action":"backup","destination":"gcs","cron":"0 3 * * *"}`, userSession)
	if scheduled.Code != http.StatusCreated || !strings.Contains(scheduled.Body.String(), `"destination":"gcs"`) {
		t.Fatalf("create GCS backup schedule: %d %s", scheduled.Code, scheduled.Body.String())
	}
	newBucket := testRequest(a.Router(), http.MethodPut, "/api/backups/target", `{"bucket":"another-bucket"}`, adminSession)
	if newBucket.Code != http.StatusConflict {
		t.Fatalf("changed GCS bucket while backup records exist: %d %s", newBucket.Code, newBucket.Body.String())
	}
	rotatedCredential := panelGCSTestCredential(t)
	expectedCredential = rotatedCredential
	rotationBody, err := json.Marshal(map[string]string{"secret_key": rotatedCredential})
	if err != nil {
		t.Fatal(err)
	}
	rotated := testRequest(a.Router(), http.MethodPut, "/api/backups/target", string(rotationBody), adminSession)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), rotatedCredential) {
		t.Fatalf("could not rotate GCS service-account key safely: %d %s", rotated.Code, rotated.Body.String())
	}
	verified := testRequest(a.Router(), http.MethodPost, "/api/servers/gcs-backup-server/backups/"+backupResponse.Backup.ID+"/verify", `{}`, userSession)
	if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"valid":true`) {
		t.Fatalf("verify GCS backup: %d %s", verified.Code, verified.Body.String())
	}
	if err = os.WriteFile(dataPath, []byte("changed after backup"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := testRequest(a.Router(), http.MethodPost, "/api/servers/gcs-backup-server/backups/"+backupResponse.Backup.ID+"/restore", `{}`, userSession)
	if restored.Code != http.StatusOK {
		t.Fatalf("restore GCS backup: %d %s", restored.Code, restored.Body.String())
	}
	data, err := os.ReadFile(dataPath)
	if err != nil || string(data) != "before restore" {
		t.Fatalf("restored GCS server data=%q err=%v", data, err)
	}
	deleted := testRequest(a.Router(), http.MethodDelete, "/api/servers/gcs-backup-server/backups/"+backupResponse.Backup.ID, "", userSession)
	if deleted.Code != http.StatusOK || store.count() != 0 {
		t.Fatalf("delete GCS backup: %d %s objects=%d", deleted.Code, deleted.Body.String(), store.count())
	}
	cleared := testRequest(a.Router(), http.MethodPut, "/api/backups/target", `{"clear_target":true}`, adminSession)
	if cleared.Code != http.StatusOK || !strings.Contains(cleared.Body.String(), `"type":"s3"`) {
		t.Fatalf("clear GCS target: %d %s", cleared.Code, cleared.Body.String())
	}
}
