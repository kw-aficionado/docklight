package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"example.com/yggdrasil-panel/internal/backup"
	"example.com/yggdrasil-panel/internal/security"
)

type backupObjectStore interface {
	Put(context.Context, string, io.Reader) error
	PutFile(context.Context, string, *os.File) error
	GetObject(context.Context, string, io.Writer) error
	DeleteObject(context.Context, string) error
}

type backupTargetConfig struct {
	Enabled   bool
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Prefix    string
}

type backupTargetSummary struct {
	Enabled             bool   `json:"enabled"`
	Configured          bool   `json:"configured"`
	Endpoint            string `json:"endpoint,omitempty"`
	Bucket              string `json:"bucket,omitempty"`
	Region              string `json:"region,omitempty"`
	Prefix              string `json:"prefix,omitempty"`
	AccessKeyConfigured bool   `json:"access_key_configured"`
	SecretConfigured    bool   `json:"secret_key_configured"`
}

func (t backupTargetConfig) configured() bool {
	return t.Endpoint != "" && t.Bucket != "" && t.Region != "" && t.AccessKey != "" && t.SecretKey != ""
}

func (a *App) readBackupTarget() (backupTargetConfig, error) {
	var enabled int
	var endpointEnc, accessKeyEnc, secretKeyEnc string
	var target backupTargetConfig
	err := a.db.QueryRow(`SELECT enabled,endpoint_enc,bucket,region,access_key_enc,secret_key_enc,prefix FROM backup_target_settings WHERE id=1`).Scan(&enabled, &endpointEnc, &target.Bucket, &target.Region, &accessKeyEnc, &secretKeyEnc, &target.Prefix)
	if errors.Is(err, sql.ErrNoRows) {
		return backupTargetConfig{}, nil
	}
	if err != nil {
		return backupTargetConfig{}, err
	}
	target.Enabled = enabled != 0
	for _, field := range []struct {
		name        string
		cipher      string
		destination *string
	}{
		{name: "endpoint", cipher: endpointEnc, destination: &target.Endpoint},
		{name: "access key", cipher: accessKeyEnc, destination: &target.AccessKey},
		{name: "secret key", cipher: secretKeyEnc, destination: &target.SecretKey},
	} {
		if field.cipher == "" {
			continue
		}
		plain, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), field.cipher)
		if decryptErr != nil {
			return backupTargetConfig{}, fmt.Errorf("stored S3 %s cannot be decrypted; check auth.secret_key", field.name)
		}
		*field.destination = plain
	}
	return target, nil
}

func (a *App) getBackupTarget(w http.ResponseWriter, _ *http.Request) {
	target, err := a.readBackupTarget()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup target settings")
		return
	}
	writeJSON(w, http.StatusOK, summarizeBackupTarget(target))
}

func (a *App) backupTargetStatus(w http.ResponseWriter, _ *http.Request) {
	target, err := a.readBackupTarget()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backup target status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": target.Enabled && target.configured()})
}

func summarizeBackupTarget(target backupTargetConfig) backupTargetSummary {
	return backupTargetSummary{
		Enabled:             target.Enabled,
		Configured:          target.configured(),
		Endpoint:            target.Endpoint,
		Bucket:              target.Bucket,
		Region:              target.Region,
		Prefix:              target.Prefix,
		AccessKeyConfigured: target.AccessKey != "",
		SecretConfigured:    target.SecretKey != "",
	}
}

func (a *App) updateBackupTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled     *bool   `json:"enabled"`
		Endpoint    string  `json:"endpoint"`
		Bucket      string  `json:"bucket"`
		Region      string  `json:"region"`
		AccessKey   string  `json:"access_key"`
		SecretKey   string  `json:"secret_key"`
		Prefix      *string `json:"prefix"`
		ClearTarget bool    `json:"clear_target"`
	}
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	current, err := a.readBackupTarget()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current backup target settings")
		return
	}
	if in.ClearTarget {
		if count, countErr := a.remoteBackupCount(); countErr != nil {
			writeError(w, http.StatusInternalServerError, "could not check existing S3 backups before clearing the target")
			return
		} else if count != 0 {
			writeError(w, http.StatusConflict, "delete the existing S3 backups before clearing this target")
			return
		}
		if _, err = a.db.Exec(`DELETE FROM backup_target_settings WHERE id=1`); err != nil {
			writeError(w, http.StatusInternalServerError, "could not clear backup target settings")
			return
		}
		a.audit(principal(r), "backup.target.clear", "backup_target", "s3", "")
		writeJSON(w, http.StatusOK, summarizeBackupTarget(backupTargetConfig{}))
		return
	}
	next := current
	if in.Endpoint != "" {
		next.Endpoint = strings.TrimSpace(in.Endpoint)
	}
	if in.Bucket != "" {
		next.Bucket = strings.TrimSpace(in.Bucket)
	}
	if in.Region != "" {
		next.Region = strings.TrimSpace(in.Region)
	}
	if in.AccessKey != "" {
		next.AccessKey = in.AccessKey
	}
	if in.SecretKey != "" {
		next.SecretKey = in.SecretKey
	}
	if in.Prefix != nil {
		next.Prefix = strings.TrimSpace(*in.Prefix)
	}
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if next.Prefix, err = normalizeBackupPrefix(next.Prefix); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if anyBackupTargetValue(next) && !next.configured() {
		writeError(w, http.StatusBadRequest, "enter the S3 endpoint, bucket, region, access key, and secret key before saving the target")
		return
	}
	if next.Enabled && !next.configured() {
		writeError(w, http.StatusBadRequest, "configure all S3 target fields before enabling S3 backups")
		return
	}
	if next.configured() {
		if _, err = backup.NewS3Client(next.Endpoint, next.Bucket, next.Region, next.AccessKey, next.SecretKey, nil); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if count, countErr := a.remoteBackupCount(); countErr != nil {
		writeError(w, http.StatusInternalServerError, "could not check existing S3 backups before updating the target")
		return
	} else if count != 0 && !sameBackupTargetIdentity(current, next) {
		writeError(w, http.StatusConflict, "delete the existing S3 backups before changing the endpoint, bucket, region, or prefix")
		return
	}
	endpointEnc, accessKeyEnc, secretKeyEnc := "", "", ""
	if next.Endpoint != "" {
		endpointEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.Endpoint)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the S3 endpoint")
			return
		}
	}
	if next.AccessKey != "" {
		accessKeyEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.AccessKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the S3 access key")
			return
		}
	}
	if next.SecretKey != "" {
		secretKeyEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.SecretKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the S3 secret key")
			return
		}
	}
	if _, err = a.db.Exec(`INSERT INTO backup_target_settings(id,enabled,endpoint_enc,bucket,region,access_key_enc,secret_key_enc,prefix,updated_at)
		VALUES(1,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,endpoint_enc=excluded.endpoint_enc,bucket=excluded.bucket,region=excluded.region,access_key_enc=excluded.access_key_enc,secret_key_enc=excluded.secret_key_enc,prefix=excluded.prefix,updated_at=CURRENT_TIMESTAMP`, boolInt(next.Enabled), endpointEnc, next.Bucket, next.Region, accessKeyEnc, secretKeyEnc, next.Prefix); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save S3 backup target settings")
		return
	}
	a.audit(principal(r), "backup.target.update", "backup_target", "s3", fmt.Sprintf("enabled=%t bucket=%s region=%s", next.Enabled, next.Bucket, next.Region))
	writeJSON(w, http.StatusOK, summarizeBackupTarget(next))
}

func normalizeBackupPrefix(value string) (string, error) {
	value = strings.Trim(value, "/")
	if len(value) > 256 || strings.ContainsAny(value, "\\\x00") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("S3 prefix must be 256 characters or fewer and cannot contain control characters")
	}
	if value == "" {
		return "", nil
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("S3 prefix cannot contain empty or dot path segments")
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.~", r)) {
				return "", errors.New("S3 prefix segments may contain only letters, numbers, hyphens, periods, underscores, and tildes")
			}
		}
	}
	return value, nil
}

func anyBackupTargetValue(target backupTargetConfig) bool {
	return target.Endpoint != "" || target.Bucket != "" || target.Region != "" || target.AccessKey != "" || target.SecretKey != "" || target.Prefix != ""
}

func sameBackupTargetIdentity(first, second backupTargetConfig) bool {
	return first.Endpoint == second.Endpoint && first.Bucket == second.Bucket && first.Region == second.Region && first.Prefix == second.Prefix
}

func (a *App) remoteBackupCount() (int, error) {
	var count int
	err := a.db.QueryRow(`SELECT count(*) FROM server_backups WHERE storage='s3'`).Scan(&count)
	return count, err
}

func (a *App) newS3BackupStore(target backupTargetConfig) (backupObjectStore, error) {
	if !target.configured() {
		return nil, errors.New("configure the S3 endpoint, bucket, region, access key, and secret key in Backup storage first")
	}
	if a.backupStoreFactory != nil {
		return a.backupStoreFactory(target)
	}
	return backup.NewS3Client(target.Endpoint, target.Bucket, target.Region, target.AccessKey, target.SecretKey, nil)
}

func (a *App) backupStoreForRemote() (backupObjectStore, backupTargetConfig, error) {
	target, err := a.readBackupTarget()
	if err != nil {
		return nil, backupTargetConfig{}, errors.New("could not read S3 backup target settings")
	}
	store, err := a.newS3BackupStore(target)
	if err != nil {
		return nil, backupTargetConfig{}, err
	}
	return store, target, nil
}

func (a *App) testBackupTarget(w http.ResponseWriter, r *http.Request) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	store, target, err := a.backupStoreForRemote()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate an S3 connectivity test ID")
		return
	}
	if err = os.MkdirAll(a.dataRoot, 0700); err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare panel data storage for the S3 connectivity test")
		return
	}
	if err = ensureBackupDirectory(a.dataRoot); err != nil {
		writeError(w, http.StatusConflict, "panel data storage is not a real directory; repair it before testing the S3 destination")
		return
	}
	path, err := os.CreateTemp(a.dataRoot, ".s3-check-*.tmp")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create an S3 test file under panel data storage")
		return
	}
	key := backupObjectKey(target.Prefix, "connectivity-checks", id)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	uploadErr := store.PutFile(ctx, key, path)
	cancel()
	_ = path.Close()
	_ = os.Remove(path.Name())
	if uploadErr != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		cleanupErr := store.DeleteObject(cleanupCtx, key)
		cleanupCancel()
		message := explainS3BackupError("upload", uploadErr)
		if cleanupErr != nil {
			message += "; a partial test object may remain at " + key + " and could not be removed"
		}
		writeError(w, http.StatusBadGateway, message)
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = store.DeleteObject(cleanupCtx, key)
	cleanupCancel()
	if err != nil {
		writeError(w, http.StatusBadGateway, "S3 accepted the connectivity test object, but Docklight could not remove "+key+"; check s3:DeleteObject permissions and remove that test key manually")
		return
	}
	a.audit(principal(r), "backup.target.test", "backup_target", "s3", "connectivity test succeeded")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func backupObjectKey(prefix, serverID, backupID string) string {
	parts := []string{}
	if prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, "docklight", serverID, backupID+backupExtension)
	return strings.Join(parts, "/")
}

func explainS3BackupError(action string, err error) string {
	message := err.Error()
	if strings.Contains(message, "NoSuchBucket") {
		return "S3 bucket does not exist; create the bucket first, then retry"
	}
	if strings.Contains(message, "AccessDenied") || strings.Contains(message, "HTTP 401") || strings.Contains(message, "HTTP 403") {
		return "S3 access was denied; check the access key and bucket policy for the required S3 permissions"
	}
	if strings.Contains(message, "PermanentRedirect") || strings.Contains(message, "HTTP 301") || strings.Contains(message, "HTTP 302") || strings.Contains(message, "HTTP 307") || strings.Contains(message, "HTTP 308") {
		return "S3 redirected the request; enter the bucket's canonical HTTPS endpoint and region"
	}
	if strings.Contains(message, "certificate") || strings.Contains(message, "x509:") {
		return "S3 TLS certificate validation failed; install a trusted certificate for the endpoint and retry"
	}
	if strings.Contains(message, "no such host") {
		return "S3 endpoint hostname could not be resolved; check the endpoint and panel-host DNS"
	}
	if strings.Contains(message, "connection refused") || strings.Contains(message, "network is unreachable") || strings.Contains(message, "i/o timeout") || strings.Contains(message, "context deadline exceeded") {
		return "S3 endpoint is unreachable; check its host, port, firewall, and network route"
	}
	return fmt.Sprintf("S3 %s failed: %s", action, message)
}
