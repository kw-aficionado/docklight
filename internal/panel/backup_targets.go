package panel

import (
	"bytes"
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
	Type          string
	Enabled       bool
	Endpoint      string
	Port          int
	Bucket        string
	Region        string
	AccessKey     string
	SecretKey     string
	HostKeySHA256 string
	AuthMode      string
	Prefix        string
}

type backupTargetSummary struct {
	Type                   string `json:"type"`
	Enabled                bool   `json:"enabled"`
	Configured             bool   `json:"configured"`
	Endpoint               string `json:"endpoint,omitempty"`
	Host                   string `json:"host,omitempty"`
	Port                   int    `json:"port,omitempty"`
	Bucket                 string `json:"bucket,omitempty"`
	Share                  string `json:"share,omitempty"`
	Region                 string `json:"region,omitempty"`
	Prefix                 string `json:"prefix,omitempty"`
	AccessKeyConfigured    bool   `json:"access_key_configured"`
	UsernameConfigured     bool   `json:"username_configured"`
	SecretConfigured       bool   `json:"secret_key_configured"`
	HostKeySHA256          string `json:"host_key_sha256,omitempty"`
	AccountNameConfigured  bool   `json:"account_name_configured"`
	AuthMode               string `json:"auth_mode,omitempty"`
	Vendor                 string `json:"vendor,omitempty"`
	Datastore              string `json:"datastore,omitempty"`
	Namespace              string `json:"namespace,omitempty"`
	CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`
}

func (t backupTargetConfig) configured() bool {
	switch t.protocol() {
	case "s3":
		return t.Endpoint != "" && t.Bucket != "" && t.Region != "" && t.AccessKey != "" && t.SecretKey != ""
	case "sftp":
		return t.Endpoint != "" && t.AccessKey != "" && t.SecretKey != "" && t.HostKeySHA256 != ""
	case "smb":
		return t.Endpoint != "" && t.Bucket != "" && t.AccessKey != "" && t.SecretKey != ""
	case "azure":
		return t.Bucket != "" && t.AccessKey != "" && t.SecretKey != "" && (t.AuthMode == "key" || t.AuthMode == "sas")
	case "gcs":
		return t.Bucket != "" && t.SecretKey != ""
	case "rclone":
		return rcloneProviderAllowed(t.AuthMode) && t.SecretKey != ""
	case "pbs":
		return t.Endpoint != "" && t.Bucket != "" && t.AccessKey != "" && t.SecretKey != ""
	default:
		return false
	}
}

func (t backupTargetConfig) protocol() string {
	if t.Type == "" {
		return "s3"
	}
	return t.Type
}

func (a *App) readBackupTarget() (backupTargetConfig, error) {
	var enabled int
	var endpointEnc, accessKeyEnc, secretKeyEnc string
	var target backupTargetConfig
	err := a.db.QueryRow(`SELECT enabled,protocol,port,endpoint_enc,bucket,region,access_key_enc,secret_key_enc,prefix,host_key_sha256,auth_mode FROM backup_target_settings WHERE id=1`).Scan(&enabled, &target.Type, &target.Port, &endpointEnc, &target.Bucket, &target.Region, &accessKeyEnc, &secretKeyEnc, &target.Prefix, &target.HostKeySHA256, &target.AuthMode)
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
			return backupTargetConfig{}, fmt.Errorf("stored backup %s cannot be decrypted; check auth.secret_key", field.name)
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
	writeJSON(w, http.StatusOK, map[string]any{"enabled": target.Enabled && target.configured(), "configured": target.configured(), "type": target.protocol()})
}

func summarizeBackupTarget(target backupTargetConfig) backupTargetSummary {
	protocol := target.protocol()
	summary := backupTargetSummary{
		Type:                  protocol,
		Enabled:               target.Enabled,
		Configured:            target.configured(),
		AccessKeyConfigured:   protocol == "s3" && target.AccessKey != "",
		UsernameConfigured:    protocol != "s3" && protocol != "azure" && protocol != "gcs" && target.AccessKey != "",
		SecretConfigured:      target.SecretKey != "",
		Port:                  target.Port,
		Prefix:                target.Prefix,
		AccountNameConfigured: protocol == "azure" && target.AccessKey != "",
		AuthMode:              target.AuthMode,
	}
	if protocol == "s3" || protocol == "azure" || protocol == "gcs" || protocol == "rclone" {
		summary.Endpoint = target.Endpoint
		summary.Bucket = target.Bucket
		if protocol == "s3" {
			summary.Region = target.Region
		}
	} else {
		summary.Host = target.Endpoint
		if protocol == "sftp" {
			summary.HostKeySHA256 = target.HostKeySHA256
		}
		if protocol == "smb" {
			summary.Share = target.Bucket
		}
	}
	if protocol == "pbs" {
		summary.Host = target.Endpoint
		summary.Datastore = target.Bucket
		summary.Namespace = target.Prefix
		summary.UsernameConfigured = target.AccessKey != ""
		summary.CertificateFingerprint = target.HostKeySHA256
	}
	if protocol == "rclone" && target.SecretKey != "" {
		if options, err := parseRcloneSection(target.SecretKey); err == nil {
			summary.Vendor = options["vendor"]
		}
	}
	return summary
}

func (a *App) updateBackupTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled                *bool   `json:"enabled"`
		Type                   string  `json:"type"`
		Protocol               string  `json:"protocol"`
		Endpoint               *string `json:"endpoint"`
		Host                   string  `json:"host"`
		Port                   *int    `json:"port"`
		Bucket                 string  `json:"bucket"`
		Share                  string  `json:"share"`
		Region                 string  `json:"region"`
		AccessKey              string  `json:"access_key"`
		Username               string  `json:"username"`
		SecretKey              string  `json:"secret_key"`
		HostKeySHA256          *string `json:"host_key_sha256"`
		CertificateFingerprint *string `json:"certificate_fingerprint"`
		AccountName            string  `json:"account_name"`
		AuthMode               string  `json:"auth_mode"`
		Provider               string  `json:"provider"`
		RcloneSecret           string  `json:"rclone_secret"`
		RcloneConfig           string  `json:"rclone_config"`
		Vendor                 string  `json:"vendor"`
		Datastore              string  `json:"datastore"`
		AuthID                 string  `json:"auth_id"`
		Namespace              *string `json:"namespace"`
		Prefix                 *string `json:"prefix"`
		ClearTarget            bool    `json:"clear_target"`
	}
	if decodeJSON(w, r, &in, 24*1024) != nil {
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
			writeError(w, http.StatusInternalServerError, "could not check existing remote backups before clearing the target")
			return
		} else if count != 0 {
			writeError(w, http.StatusConflict, "delete the existing remote backups before clearing this target")
			return
		}
		if _, err = a.db.Exec(`DELETE FROM backup_target_settings WHERE id=1`); err != nil {
			writeError(w, http.StatusInternalServerError, "could not clear backup target settings")
			return
		}
		a.audit(principal(r), "backup.target.clear", "backup_target", current.protocol(), "")
		writeJSON(w, http.StatusOK, summarizeBackupTarget(backupTargetConfig{}))
		return
	}
	requestedType := strings.TrimSpace(in.Type)
	if requestedType == "" {
		requestedType = strings.TrimSpace(in.Protocol)
	}
	if requestedType == "" {
		requestedType = current.protocol()
	}
	if requestedType != "s3" && requestedType != "sftp" && requestedType != "smb" && requestedType != "azure" && requestedType != "gcs" && requestedType != "rclone" && requestedType != "pbs" {
		writeError(w, http.StatusBadRequest, "backup target type must be s3, sftp, smb, azure, gcs, rclone, or pbs")
		return
	}
	next := current
	if requestedType != current.protocol() {
		next = backupTargetConfig{Type: requestedType}
		if requestedType == "azure" {
			next.AuthMode = "key"
		}
		if requestedType == "pbs" {
			next.Port = 8007
		}
	} else {
		next.Type = requestedType
	}
	provider := strings.TrimSpace(in.Provider)
	if requestedType == "rclone" && provider != "" {
		if provider != next.AuthMode {
			next.Endpoint, next.AccessKey, next.SecretKey = "", "", ""
		}
		next.AuthMode = provider
	}
	host := strings.TrimSpace(in.Host)
	if in.Endpoint != nil {
		next.Endpoint = strings.TrimSpace(*in.Endpoint)
	} else if host != "" {
		next.Endpoint = host
	}
	if in.Port != nil {
		next.Port = *in.Port
	}
	if requestedType == "pbs" && next.Port == 0 {
		next.Port = 8007
	}
	if in.Share != "" {
		next.Bucket = strings.TrimSpace(in.Share)
	} else if in.Bucket != "" {
		next.Bucket = strings.TrimSpace(in.Bucket)
	}
	if in.Region != "" {
		next.Region = strings.TrimSpace(in.Region)
	}
	if in.AccountName != "" {
		next.AccessKey = strings.TrimSpace(in.AccountName)
	} else if in.Username != "" {
		next.AccessKey = strings.TrimSpace(in.Username)
	} else if in.AuthID != "" {
		next.AccessKey = strings.TrimSpace(in.AuthID)
	} else if in.AccessKey != "" {
		next.AccessKey = strings.TrimSpace(in.AccessKey)
	}
	if in.AuthMode != "" && requestedType != "rclone" {
		next.AuthMode = strings.TrimSpace(in.AuthMode)
	}
	if in.SecretKey != "" {
		next.SecretKey = in.SecretKey
	}
	if requestedType == "rclone" {
		credential := in.RcloneSecret
		if credential == "" && in.SecretKey != "" {
			credential = in.SecretKey
		}
		if credential != "" || in.RcloneConfig != "" {
			prepareCtx, prepareCancel := context.WithTimeout(r.Context(), 2*time.Minute)
			prepared, account, prepareErr := a.prepareRcloneConfig(prepareCtx, next.AuthMode, next.Endpoint, next.AccessKey, credential, in.RcloneConfig, in.Vendor)
			prepareCancel()
			if prepareErr != nil {
				writeError(w, http.StatusBadRequest, prepareErr.Error())
				return
			}
			next.SecretKey = prepared
			if account != "" {
				next.AccessKey = account
			}
		} else if current.protocol() == "rclone" && current.AuthMode == next.AuthMode && (next.AuthMode == "mega" || next.AuthMode == "webdav") {
			stored, parseErr := parseRcloneSection(current.SecretKey)
			if parseErr == nil {
				updates := map[string]string{}
				if next.AccessKey != stored["user"] {
					updates["user"] = next.AccessKey
				}
				if next.AuthMode == "webdav" {
					if next.Endpoint != stored["url"] {
						updates["url"] = next.Endpoint
					}
					vendor := strings.TrimSpace(in.Vendor)
					if vendor == "" {
						vendor = stored["vendor"]
					}
					if vendor != stored["vendor"] {
						updates["vendor"] = vendor
					}
				}
				if len(updates) != 0 {
					updated, updateErr := updateRcloneConfigOptions(current.SecretKey, updates)
					if updateErr != nil {
						writeError(w, http.StatusBadRequest, updateErr.Error())
						return
					}
					next.SecretKey = updated
				}
			}
		}
	}
	if requestedType == "pbs" && in.CertificateFingerprint != nil {
		next.HostKeySHA256 = strings.TrimSpace(*in.CertificateFingerprint)
	} else if in.HostKeySHA256 != nil {
		next.HostKeySHA256 = strings.TrimSpace(*in.HostKeySHA256)
	}
	if requestedType == "pbs" && in.Namespace != nil {
		next.Prefix = strings.TrimSpace(*in.Namespace)
	} else if in.Prefix != nil {
		next.Prefix = strings.TrimSpace(*in.Prefix)
	}
	if requestedType == "pbs" && in.Datastore != "" {
		next.Bucket = strings.TrimSpace(in.Datastore)
	}
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if next.Prefix, err = normalizeBackupPrefix(next.Prefix); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if anyBackupTargetValue(next) && !next.configured() {
		writeError(w, http.StatusBadRequest, incompleteTargetMessage(next.protocol()))
		return
	}
	if next.Enabled && !next.configured() {
		writeError(w, http.StatusBadRequest, "configure all required "+strings.ToUpper(next.protocol())+" target fields before enabling remote backups")
		return
	}
	if next.configured() {
		if err = validateBackupTarget(next); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if count, countErr := a.remoteBackupCount(); countErr != nil {
		writeError(w, http.StatusInternalServerError, "could not check existing remote backups before updating the target")
		return
	} else if count != 0 && !sameBackupTargetIdentity(current, next) {
		writeError(w, http.StatusConflict, "delete the existing remote backups before changing the protocol, account, host or endpoint, port, bucket or container, share, region, or prefix")
		return
	}
	endpointEnc, accessKeyEnc, secretKeyEnc := "", "", ""
	if next.Endpoint != "" {
		endpointEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.Endpoint)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the backup host or endpoint")
			return
		}
	}
	if next.AccessKey != "" {
		accessKeyEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.AccessKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the backup access key or username")
			return
		}
	}
	if next.SecretKey != "" {
		secretKeyEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.SecretKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the backup secret")
			return
		}
	}
	if _, err = a.db.Exec(`INSERT INTO backup_target_settings(id,enabled,endpoint_enc,bucket,region,access_key_enc,secret_key_enc,prefix,protocol,port,host_key_sha256,auth_mode,updated_at)
		VALUES(1,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,endpoint_enc=excluded.endpoint_enc,bucket=excluded.bucket,region=excluded.region,access_key_enc=excluded.access_key_enc,secret_key_enc=excluded.secret_key_enc,prefix=excluded.prefix,protocol=excluded.protocol,port=excluded.port,host_key_sha256=excluded.host_key_sha256,auth_mode=excluded.auth_mode,updated_at=CURRENT_TIMESTAMP`, boolInt(next.Enabled), endpointEnc, next.Bucket, next.Region, accessKeyEnc, secretKeyEnc, next.Prefix, next.protocol(), next.Port, next.HostKeySHA256, next.AuthMode); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save remote backup target settings")
		return
	}
	a.audit(principal(r), "backup.target.update", "backup_target", next.protocol(), fmt.Sprintf("enabled=%t host=%s", next.Enabled, next.Endpoint))
	writeJSON(w, http.StatusOK, summarizeBackupTarget(next))
}

func incompleteTargetMessage(protocol string) string {
	switch protocol {
	case "sftp":
		return "enter the SFTP host, username, password, and verified SHA-256 host-key fingerprint before enabling the target"
	case "smb":
		return "enter the SMB host, share, username, and password before saving the target"
	case "azure":
		return "enter the Azure account name, container, and account key or SAS token before saving the target"
	case "gcs":
		return "enter an existing Google Cloud Storage bucket and service-account JSON key before saving the target"
	case "rclone":
		return "choose an rclone provider and enter its authorization token, password, or custom config section"
	case "pbs":
		return "enter the Proxmox Backup Server host, datastore, auth ID, and API token secret before enabling the target"
	default:
		return "enter the S3 endpoint, bucket, region, access key, and secret key before saving the target"
	}
}

func validateBackupTarget(target backupTargetConfig) error {
	switch target.protocol() {
	case "s3":
		_, err := backup.NewS3Client(target.Endpoint, target.Bucket, target.Region, target.AccessKey, target.SecretKey, nil)
		return err
	case "sftp":
		_, err := backup.NewSFTPClient(target.Endpoint, target.Port, target.AccessKey, target.SecretKey, target.HostKeySHA256, "")
		return err
	case "smb":
		_, err := backup.NewSMBClient(target.Endpoint, target.Port, target.Bucket, target.AccessKey, target.SecretKey, "")
		return err
	case "azure":
		_, err := backup.NewAzureClient(target.Endpoint, target.AccessKey, target.Bucket, target.AuthMode, target.SecretKey, nil)
		return err
	case "gcs":
		_, err := backup.NewGCSClient(target.Bucket, target.SecretKey, nil)
		return err
	case "rclone":
		if !rcloneProviderAllowed(target.AuthMode) {
			return errors.New("choose a supported rclone provider")
		}
		return validateStoredRcloneConfig(target.AuthMode, target.SecretKey)
	case "pbs":
		return validatePBSTarget(target)
	default:
		return errors.New("backup target type must be s3, sftp, smb, azure, gcs, rclone, or pbs")
	}
}

func normalizeBackupPrefix(value string) (string, error) {
	value = strings.Trim(value, "/")
	if len(value) > 256 || strings.ContainsAny(value, "\\\x00") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("remote backup prefix must be 256 characters or fewer and cannot contain control characters")
	}
	if value == "" {
		return "", nil
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("remote backup prefix cannot contain empty or dot path segments")
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.~", r)) {
				return "", errors.New("remote backup prefix segments may contain only letters, numbers, hyphens, periods, underscores, and tildes")
			}
		}
	}
	return value, nil
}

func anyBackupTargetValue(target backupTargetConfig) bool {
	return target.Endpoint != "" || target.Port != 0 || target.Bucket != "" || target.Region != "" || target.AccessKey != "" || target.SecretKey != "" || target.HostKeySHA256 != "" || target.AuthMode != "" || target.Prefix != ""
}

func sameBackupTargetIdentity(first, second backupTargetConfig) bool {
	if first.protocol() != second.protocol() || first.Endpoint != second.Endpoint || first.Port != second.Port || first.Bucket != second.Bucket || first.Region != second.Region || first.Prefix != second.Prefix {
		return false
	}
	if first.protocol() == "rclone" && (first.AuthMode != second.AuthMode || first.AccessKey != second.AccessKey) {
		return false
	}
	return (first.protocol() != "azure" || first.AccessKey == second.AccessKey) && (first.protocol() != "gcs" || first.AccessKey == second.AccessKey) && (first.protocol() != "pbs" || first.AccessKey == second.AccessKey)
}

func (a *App) remoteBackupCount() (int, error) {
	var count int
	err := a.db.QueryRow(`SELECT count(*) FROM server_backups WHERE storage IN ('s3','sftp','smb','azure','gcs','rclone','pbs')`).Scan(&count)
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

func (a *App) newRemoteBackupStore(target backupTargetConfig) (backupObjectStore, error) {
	if !target.configured() {
		return nil, errors.New("configure the remote backup destination in Backup storage first")
	}
	if a.backupStoreFactory != nil {
		return a.backupStoreFactory(target)
	}
	switch target.protocol() {
	case "s3":
		return a.newS3BackupStore(target)
	case "sftp":
		return backup.NewSFTPClient(target.Endpoint, target.Port, target.AccessKey, target.SecretKey, target.HostKeySHA256, "")
	case "smb":
		return backup.NewSMBClient(target.Endpoint, target.Port, target.Bucket, target.AccessKey, target.SecretKey, "")
	case "azure":
		return backup.NewAzureClient(target.Endpoint, target.AccessKey, target.Bucket, target.AuthMode, target.SecretKey, nil)
	case "gcs":
		return backup.NewGCSClient(target.Bucket, target.SecretKey, nil)
	case "rclone":
		return a.newRcloneBackupStore(target)
	case "pbs":
		return a.newPBSBackupStore(target)
	default:
		return nil, errors.New("backup target type must be s3, sftp, smb, azure, gcs, rclone, or pbs")
	}
}

func (a *App) backupStoreForRemote() (backupObjectStore, backupTargetConfig, error) {
	target, err := a.readBackupTarget()
	if err != nil {
		return nil, backupTargetConfig{}, errors.New("could not read remote backup target settings")
	}
	store, err := a.newRemoteBackupStore(target)
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
	if lister, ok := store.(interface {
		List(context.Context, string) error
	}); ok {
		listCtx, listCancel := context.WithTimeout(r.Context(), 30*time.Second)
		listErr := lister.List(listCtx, target.Prefix)
		listCancel()
		if listErr != nil {
			writeError(w, http.StatusBadGateway, explainRemoteBackupError(target.protocol(), "list", listErr))
			return
		}
	}
	if target.protocol() == "pbs" {
		a.audit(principal(r), "backup.target.test", "backup_target", target.protocol(), "Proxmox snapshot listing succeeded")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a remote connectivity test ID")
		return
	}
	if err = os.MkdirAll(a.dataRoot, 0700); err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare panel data storage for the remote connectivity test")
		return
	}
	if err = ensureBackupDirectory(a.dataRoot); err != nil {
		writeError(w, http.StatusConflict, "panel data storage is not a real directory; repair it before testing the remote destination")
		return
	}
	path, err := os.CreateTemp(a.dataRoot, ".remote-check-*.tmp")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a remote test file under panel data storage")
		return
	}
	if _, err = io.WriteString(path, "Docklight remote backup connectivity check\n"); err == nil {
		err = path.Sync()
	}
	if err != nil {
		_ = path.Close()
		_ = os.Remove(path.Name())
		writeError(w, http.StatusInternalServerError, "could not prepare the remote connectivity test file")
		return
	}
	if _, err = path.Seek(0, io.SeekStart); err != nil {
		_ = path.Close()
		_ = os.Remove(path.Name())
		writeError(w, http.StatusInternalServerError, "could not rewind the remote connectivity test file")
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
		message := explainRemoteBackupError(target.protocol(), "upload", uploadErr)
		if cleanupErr != nil {
			message += "; a partial test object may remain at " + key + " and could not be removed"
		}
		writeError(w, http.StatusBadGateway, message)
		return
	}
	var readback bytes.Buffer
	readCtx, readCancel := context.WithTimeout(r.Context(), 30*time.Second)
	readErr := store.GetObject(readCtx, key, &readback)
	readCancel()
	if readErr != nil || readback.String() != "Docklight remote backup connectivity check\n" {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		cleanupErr := store.DeleteObject(cleanupCtx, key)
		cleanupCancel()
		message := "remote destination accepted a test upload but returned unexpected data when Docklight read it back"
		if readErr != nil {
			message = explainRemoteBackupError(target.protocol(), "download", readErr)
		}
		if cleanupErr != nil {
			message += "; a test object may remain at " + key + " and could not be removed"
		}
		writeError(w, http.StatusBadGateway, message)
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = store.DeleteObject(cleanupCtx, key)
	cleanupCancel()
	if err != nil {
		writeError(w, http.StatusBadGateway, strings.ToUpper(target.protocol())+" accepted the connectivity test object, but Docklight could not remove "+key+"; check delete permissions and remove that test object manually")
		return
	}
	a.audit(principal(r), "backup.target.test", "backup_target", target.protocol(), "connectivity test succeeded")
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

func explainRemoteBackupError(protocol, action string, err error) string {
	if protocol == "s3" {
		return explainS3BackupError(action, err)
	}
	message := err.Error()
	if protocol == "pbs" {
		lower := strings.ToLower(message)
		if strings.Contains(lower, "fingerprint") || strings.Contains(lower, "certificate") || strings.Contains(lower, "x509:") {
			return "Proxmox TLS certificate validation failed; verify the server certificate fingerprint and enter its SHA-256 value if it is self-signed"
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "access denied") || strings.Contains(lower, "401") || strings.Contains(lower, "403") {
			return "Proxmox access was denied; check the auth ID and API token secret, then grant DatastorePowerUser to both the user and API token"
		}
		if strings.Contains(lower, "no such host") {
			return "Proxmox host could not be resolved; check the hostname and panel-host DNS"
		}
		if strings.Contains(lower, "connection refused") || strings.Contains(lower, "network is unreachable") || strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "context deadline exceeded") {
			return "Proxmox host is unreachable; check its hostname, port (default 8007), firewall, and network route"
		}
		return fmt.Sprintf("Proxmox Backup Server %s failed: %s", action, message)
	}
	if protocol == "azure" {
		if strings.Contains(message, "ContainerNotFound") {
			return "Azure container does not exist; create it before retrying"
		}
		if strings.Contains(message, "HTTP 401") || strings.Contains(message, "HTTP 403") || strings.Contains(message, "AuthenticationFailed") || strings.Contains(message, "AuthorizationFailure") {
			return "Azure Blob access was denied; check the account key or SAS permissions for the container"
		}
		return fmt.Sprintf("Azure Blob %s failed: %s", action, message)
	}
	if protocol == "gcs" {
		if strings.Contains(message, "HTTP 401") || strings.Contains(message, "HTTP 403") {
			return "Google Cloud Storage denied access; check the service-account key and bucket IAM permissions"
		}
		if strings.Contains(message, "HTTP 404") {
			return "Google Cloud Storage bucket or object was not found; check the configured bucket name"
		}
		return fmt.Sprintf("Google Cloud Storage %s failed: %s", action, message)
	}
	if strings.Contains(message, "no such host") {
		return strings.ToUpper(protocol) + " host could not be resolved; check the host name and panel-host DNS"
	}
	if strings.Contains(message, "connection refused") || strings.Contains(message, "network is unreachable") || strings.Contains(message, "i/o timeout") || strings.Contains(message, "context deadline exceeded") {
		return strings.ToUpper(protocol) + " host is unreachable; check its port, firewall, and network route"
	}
	if strings.Contains(message, "permission denied") || strings.Contains(message, "authentication failed") || strings.Contains(message, "STATUS_LOGON_FAILURE") {
		return strings.ToUpper(protocol) + " authentication or file permissions were rejected; check the saved username, password, and destination access"
	}
	return fmt.Sprintf("%s %s failed: %s", strings.ToUpper(protocol), action, message)
}
