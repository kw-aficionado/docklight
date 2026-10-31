package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"example.com/yggdrasil-panel/internal/security"
)

type memoryBackupStore struct {
	mu            sync.Mutex
	objects       map[string][]byte
	corruptReads  bool
	failUpload    bool
	deleteFailure bool
}

func newMemoryBackupStore() *memoryBackupStore {
	return &memoryBackupStore{objects: map[string][]byte{}}
}

func (s *memoryBackupStore) Put(_ context.Context, key string, source io.Reader) error {
	data, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failUpload {
		return errors.New("injected upload interruption")
	}
	s.objects[key] = data
	return nil
}

func (s *memoryBackupStore) PutFile(_ context.Context, key string, file *os.File) error {
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.objects[key] = data
	s.mu.Unlock()
	return nil
}

func (s *memoryBackupStore) GetObject(_ context.Context, key string, destination io.Writer) error {
	s.mu.Lock()
	data, ok := s.objects[key]
	if ok {
		data = bytes.Clone(data)
	}
	corrupt := s.corruptReads
	s.mu.Unlock()
	if !ok {
		return errors.New("NoSuchKey")
	}
	if corrupt && len(data) != 0 {
		data[len(data)/2] ^= 0xff
	}
	_, err := destination.Write(data)
	return err
}

func (s *memoryBackupStore) DeleteObject(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteFailure {
		return errors.New("injected delete failure")
	}
	delete(s.objects, key)
	return nil
}

func (s *memoryBackupStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

func setBackupTargetForTest(t *testing.T, a *App, d *sql.DB) {
	t.Helper()
	endpoint, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "http://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	accessKey, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "test-access-key")
	if err != nil {
		t.Fatal(err)
	}
	secretKey, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "test-secret-key-that-must-not-be-returned")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO backup_target_settings(id,enabled,endpoint_enc,bucket,region,access_key_enc,secret_key_enc,prefix) VALUES(1,1,?,'docklight-test','test-region',?,?,'integration')`, endpoint, accessKey, secretKey); err != nil {
		t.Fatal(err)
	}
}

func TestS3BackupLifecycleUsesEncryptedTargetAndDatabaseRetention(t *testing.T) {
	a, d, _ := testApp(t)
	store := newMemoryBackupStore()
	a.backupStoreFactory = func(target backupTargetConfig) (backupObjectStore, error) {
		if target.Bucket != "docklight-test" || target.Region != "test-region" || target.Endpoint != "http://127.0.0.1:9000" {
			t.Fatalf("unexpected decrypted S3 target: %#v", target)
		}
		return store, nil
	}
	setBackupTargetForTest(t, a, d)
	dataDir := filepath.Join(a.dataRoot, "s3-backup-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	worldPath := filepath.Join(dataDir, "world.dat")
	if err := os.WriteFile(worldPath, []byte("original world"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('s3-backup-server','S3 backup test','minecraft-java','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('s3-backup-user','s3-backup-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('s3-backup-user','server','s3-backup-server','server.view,server.backup')`); err != nil {
		t.Fatal(err)
	}
	session, err := a.issue(User{ID: "s3-backup-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	first := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups", `{"destination":"s3"}`, session)
	if first.Code != http.StatusCreated {
		t.Fatalf("create S3 backup: %d %s", first.Code, first.Body.String())
	}
	var created struct {
		Backup backupRecord `json:"backup"`
	}
	if err = json.Unmarshal(first.Body.Bytes(), &created); err != nil || created.Backup.ID == "" || created.Backup.Storage != "s3" || created.Backup.SizeBytes <= 0 {
		t.Fatalf("unexpected S3 backup response: %#v err=%v body=%s", created, err, first.Body.String())
	}
	if store.count() != 1 {
		t.Fatalf("expected one uploaded S3 object, got %d", store.count())
	}
	var storedObjectKey string
	if err = d.QueryRow(`SELECT storage_key FROM server_backups WHERE id=?`, created.Backup.ID).Scan(&storedObjectKey); err != nil || storedObjectKey == "" {
		t.Fatalf("S3 backup object key was not stored: key=%q err=%v", storedObjectKey, err)
	}
	if strings.Contains(first.Body.String(), storedObjectKey) || strings.Contains(first.Body.String(), "test-secret-key-that-must-not-be-returned") {
		t.Fatal("backup response exposed the object key or an S3 credential")
	}
	var storedEndpoint, storedAccess, storedSecret string
	if err = d.QueryRow(`SELECT endpoint_enc,access_key_enc,secret_key_enc FROM backup_target_settings WHERE id=1`).Scan(&storedEndpoint, &storedAccess, &storedSecret); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedEndpoint, "127.0.0.1") || strings.Contains(storedAccess, "test-access-key") || strings.Contains(storedSecret, "test-secret-key") {
		t.Fatal("S3 endpoint or credentials were stored without encryption")
	}
	listed := testRequest(h, http.MethodGet, "/api/servers/s3-backup-server/backups", "", session)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"storage":"s3"`) || strings.Contains(listed.Body.String(), "storage_key") {
		t.Fatalf("S3 backup listing was not safely redacted: %d %s", listed.Code, listed.Body.String())
	}
	verified := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups/"+created.Backup.ID+"/verify", `{}`, session)
	if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"valid":true`) {
		t.Fatalf("verify remote backup: %d %s", verified.Code, verified.Body.String())
	}
	if err = os.WriteFile(worldPath, []byte("changed world"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups/"+created.Backup.ID+"/restore", `{}`, session)
	if restored.Code != http.StatusOK {
		t.Fatalf("restore remote backup: %d %s", restored.Code, restored.Body.String())
	}
	if data, readErr := os.ReadFile(worldPath); readErr != nil || string(data) != "original world" {
		t.Fatalf("remote restore data = %q, err=%v", data, readErr)
	}
	store.mu.Lock()
	store.failUpload = true
	store.mu.Unlock()
	failedUpload := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups", `{"destination":"s3"}`, session)
	store.mu.Lock()
	store.failUpload = false
	store.mu.Unlock()
	if failedUpload.Code != http.StatusBadGateway {
		t.Fatalf("interrupted upload returned %d: %s", failedUpload.Code, failedUpload.Body.String())
	}
	var records int
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='s3-backup-server'`).Scan(&records); err != nil || records != 1 || store.count() != 1 {
		t.Fatalf("interrupted upload left incorrect state: records=%d objects=%d err=%v", records, store.count(), err)
	}

	store.mu.Lock()
	store.corruptReads = true
	store.mu.Unlock()
	corruptAttempt := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups", `{"destination":"s3"}`, session)
	if corruptAttempt.Code != http.StatusBadGateway {
		t.Fatalf("corrupt remote upload was accepted: %d %s", corruptAttempt.Code, corruptAttempt.Body.String())
	}
	store.mu.Lock()
	store.corruptReads = false
	store.mu.Unlock()
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='s3-backup-server'`).Scan(&records); err != nil || records != 1 || store.count() != 1 {
		t.Fatalf("failed verification left incorrect state: records=%d objects=%d err=%v", records, store.count(), err)
	}

	second := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups", `{"destination":"s3"}`, session)
	if second.Code != http.StatusCreated {
		t.Fatalf("create second S3 backup: %d %s", second.Code, second.Body.String())
	}
	pruned := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups/prune", `{"keep":1}`, session)
	if pruned.Code != http.StatusOK || !strings.Contains(pruned.Body.String(), `"removed":1`) || store.count() != 1 {
		t.Fatalf("prune remote backup retention: %d %s objects=%d", pruned.Code, pruned.Body.String(), store.count())
	}
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='s3-backup-server'`).Scan(&records); err != nil || records != 1 {
		t.Fatalf("retention left %d backup records, want 1 (err=%v)", records, err)
	}
	listedAfterPrune := testRequest(h, http.MethodGet, "/api/servers/s3-backup-server/backups", "", session)
	var retained []backupRecord
	if listedAfterPrune.Code != http.StatusOK || json.Unmarshal(listedAfterPrune.Body.Bytes(), &retained) != nil || len(retained) != 1 {
		t.Fatalf("list retained S3 backup: %d %s", listedAfterPrune.Code, listedAfterPrune.Body.String())
	}
	deleted := testRequest(h, http.MethodDelete, "/api/servers/s3-backup-server/backups/"+retained[0].ID, `{}`, session)
	if deleted.Code != http.StatusOK || store.count() != 0 {
		t.Fatalf("delete remote backup: %d %s objects=%d", deleted.Code, deleted.Body.String(), store.count())
	}
	if err = d.QueryRow(`SELECT count(*) FROM server_backups WHERE server_id='s3-backup-server'`).Scan(&records); err != nil || records != 0 {
		t.Fatalf("remote delete left %d backup records (err=%v)", records, err)
	}
	serverDeleteBackup := testRequest(h, http.MethodPost, "/api/servers/s3-backup-server/backups", `{"destination":"s3"}`, session)
	if serverDeleteBackup.Code != http.StatusCreated {
		t.Fatalf("create S3 server-cleanup fixture: %d %s", serverDeleteBackup.Code, serverDeleteBackup.Body.String())
	}
	if err = a.removeServerBackups("s3-backup-server"); err != nil {
		t.Fatalf("remove recorded S3 backups with server: %v", err)
	}
	if store.count() != 0 {
		t.Fatalf("server backup cleanup left %d S3 objects", store.count())
	}
}

func TestS3BackupTargetAdminRedactionAndIdentityLock(t *testing.T) {
	a, d, _ := testApp(t)
	store := newMemoryBackupStore()
	a.backupStoreFactory = func(backupTargetConfig) (backupObjectStore, error) { return store, nil }
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('target-admin','target-admin','unused','admin'),('target-user','target-user','unused','user')`); err != nil {
		t.Fatal(err)
	}
	adminSession, err := a.issue(User{ID: "target-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userSession, err := a.issue(User{ID: "target-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	unauthorized := testRequest(h, http.MethodGet, "/api/backups/target", "", userSession)
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("non-admin read target settings: %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	configured := testRequest(h, http.MethodPut, "/api/backups/target", `{"enabled":true,"endpoint":"http://127.0.0.1:9000","bucket":"docklight-test","region":"test-region","prefix":"safe-prefix","access_key":"never-return-this-access","secret_key":"never-return-this-secret"}`, adminSession)
	if configured.Code != http.StatusOK {
		t.Fatalf("configure target: %d %s", configured.Code, configured.Body.String())
	}
	for _, secret := range []string{"never-return-this-access", "never-return-this-secret"} {
		if strings.Contains(configured.Body.String(), secret) {
			t.Fatalf("target update returned credential %q: %s", secret, configured.Body.String())
		}
	}
	read := testRequest(h, http.MethodGet, "/api/backups/target", "", adminSession)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"configured":true`) || strings.Contains(read.Body.String(), "never-return-this") {
		t.Fatalf("target summary did not redact credentials: %d %s", read.Code, read.Body.String())
	}
	status := testRequest(h, http.MethodGet, "/api/backups/target/status", "", userSession)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":true`) {
		t.Fatalf("authenticated target status: %d %s", status.Code, status.Body.String())
	}
	connection := testRequest(h, http.MethodPost, "/api/backups/target/test", `{}`, adminSession)
	if connection.Code != http.StatusOK || !strings.Contains(connection.Body.String(), `"ok":true`) || store.count() != 0 {
		t.Fatalf("test target upload/delete: %d %s objects=%d", connection.Code, connection.Body.String(), store.count())
	}
	var savedEndpoint, savedAccess, savedSecret string
	if err = d.QueryRow(`SELECT endpoint_enc,access_key_enc,secret_key_enc FROM backup_target_settings WHERE id=1`).Scan(&savedEndpoint, &savedAccess, &savedSecret); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(savedEndpoint, "127.0.0.1") || strings.Contains(savedAccess, "never-return-this-access") || strings.Contains(savedSecret, "never-return-this-secret") {
		t.Fatal("target API stored endpoint or credentials without encryption")
	}
	if _, err = d.Exec(`INSERT INTO server_backups(id,server_id,storage,storage_key,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES('locked-backup','target-server','s3','safe-prefix/docklight/target-server/locked-backup.dlbak',1,'abc',0,0,0,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	changedIdentity := testRequest(h, http.MethodPut, "/api/backups/target", `{"bucket":"another-bucket"}`, adminSession)
	if changedIdentity.Code != http.StatusConflict {
		t.Fatalf("target identity changed while S3 backup record exists: %d %s", changedIdentity.Code, changedIdentity.Body.String())
	}
	rotateCredentials := testRequest(h, http.MethodPut, "/api/backups/target", `{"access_key":"rotated-access","secret_key":"rotated-secret"}`, adminSession)
	if rotateCredentials.Code != http.StatusOK {
		t.Fatalf("could not rotate credentials with existing backups: %d %s", rotateCredentials.Code, rotateCredentials.Body.String())
	}
	clearBlocked := testRequest(h, http.MethodPut, "/api/backups/target", `{"clear_target":true}`, adminSession)
	if clearBlocked.Code != http.StatusConflict {
		t.Fatalf("cleared target with existing S3 record: %d %s", clearBlocked.Code, clearBlocked.Body.String())
	}
	if _, err = d.Exec(`DELETE FROM server_backups WHERE id='locked-backup'`); err != nil {
		t.Fatal(err)
	}
	cleared := testRequest(h, http.MethodPut, "/api/backups/target", `{"clear_target":true}`, adminSession)
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "rotated-secret") {
		t.Fatalf("clear target: %d %s", cleared.Code, cleared.Body.String())
	}
}
