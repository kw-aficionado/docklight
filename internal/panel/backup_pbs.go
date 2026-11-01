package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/backup"
	"example.com/yggdrasil-panel/internal/docker"
)

const pbsArchiveName = "docklight.pxar"

var (
	pbsAuthIDPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+$`)
	pbsNamePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	pbsFingerprintPattern = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)
)

type pbsBackupStore struct {
	app    *App
	target backupTargetConfig
	image  string
}

func validatePBSTarget(target backupTargetConfig) error {
	if runtime.GOARCH != "amd64" {
		return errors.New("Proxmox Backup Server destinations require an amd64 Docklight host")
	}
	if _, err := pbsRepository(target); err != nil {
		return err
	}
	if target.Port < 1 || target.Port > 65535 {
		return errors.New("Proxmox Backup Server port must be from 1 to 65535; the default is 8007")
	}
	if !pbsNamePattern.MatchString(target.Bucket) {
		return errors.New("Proxmox datastore names may use letters, numbers, periods, underscores, and hyphens")
	}
	if !pbsAuthIDPattern.MatchString(target.AccessKey) {
		return errors.New("Proxmox auth ID must use user@realm!token format")
	}
	if !utf8.ValidString(target.SecretKey) || strings.IndexFunc(target.SecretKey, unicode.IsControl) >= 0 {
		return errors.New("Proxmox API token secret must be valid UTF-8 without control characters or newlines")
	}
	if target.HostKeySHA256 != "" && !pbsFingerprintPattern.MatchString(target.HostKeySHA256) {
		return errors.New("Proxmox certificate fingerprint must be a SHA-256 fingerprint such as AA:BB:… with 32 hexadecimal pairs")
	}
	if target.Prefix != "" {
		if normalized, err := normalizeBackupPrefix(target.Prefix); err != nil || normalized != target.Prefix {
			return errors.New("Proxmox namespace must be a safe slash-separated path")
		}
	}
	return nil
}

func pbsRepository(target backupTargetConfig) (string, error) {
	host := strings.TrimSpace(target.Endpoint)
	if strings.ContainsAny(host, "\r\n\t /@?#") || host == "" {
		return "", errors.New("enter the Proxmox Backup Server hostname or IP address without a URL scheme")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.To4() == nil {
			host = "[" + ip.String() + "]"
		} else {
			host = ip.String()
		}
	} else {
		if strings.ContainsAny(host, ":[]%") || len(host) > 253 {
			return "", errors.New("Proxmox host must be a DNS name or IP address, not a URL")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("Proxmox host is not a valid DNS name or IP address")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return "", errors.New("Proxmox host is not a valid DNS name or IP address")
				}
			}
		}
	}
	if target.Bucket == "" || target.AccessKey == "" {
		return "", errors.New("enter the Proxmox datastore and auth ID")
	}
	port := target.Port
	if port == 0 {
		port = 8007
	}
	return target.AccessKey + "@" + host + ":" + strconv.Itoa(port) + ":" + target.Bucket, nil
}

func (a *App) newPBSBackupStore(target backupTargetConfig) (backupObjectStore, error) {
	if !target.configured() {
		return nil, errors.New("configure a Proxmox Backup Server host, datastore, auth ID, and API token secret in Backup storage first")
	}
	if err := validatePBSTarget(target); err != nil {
		return nil, err
	}
	image := strings.TrimSpace(a.cfg.Docker.PBSClientImage)
	if image == "" {
		image = "ghcr.io/docklight/pbs-client:4.2.8"
	}
	return &pbsBackupStore{app: a, target: target, image: image}, nil
}

// PBS stores file archives in its chunked, content-addressed datastore rather
// than exposing individual remote objects through this interface.
func (s *pbsBackupStore) Put(context.Context, string, io.Reader) error {
	return errors.New("Proxmox backups must be created from a server data directory")
}

func (s *pbsBackupStore) PutFile(context.Context, string, *os.File) error {
	return errors.New("Proxmox backups must be created from a server data directory")
}

func (s *pbsBackupStore) GetObject(context.Context, string, io.Writer) error {
	return errors.New("Proxmox snapshots are restored in place and are not downloadable from Docklight")
}

func (s *pbsBackupStore) List(ctx context.Context, _ string) error {
	args := []string{"list", "--output-format=json"}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	_, err := s.run(ctx, args, nil, "")
	return err
}

func (s *pbsBackupStore) BackupDirectory(ctx context.Context, storageKey, sourceDir string) error {
	group, backupTime, err := parsePBSStorageKey(storageKey)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(sourceDir); statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("server data directory is missing or is not a real directory")
	}
	args := []string{
		"backup", pbsArchiveName + ":/run/docklight/source",
		"--backup-type=host", "--backup-id=" + group,
		"--backup-time=" + strconv.FormatInt(backupTime, 10),
		"--all-file-systems=true", "--crypt-mode=none",
	}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	_, err = s.run(ctx, args, []string{sourceDir + ":/run/docklight/source:rw"}, "0:0")
	return err
}

func (s *pbsBackupStore) RestoreDirectory(ctx context.Context, storageKey, targetDir string) error {
	if _, _, err := parsePBSStorageKey(storageKey); err != nil {
		return err
	}
	if info, err := os.Lstat(targetDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("restore staging path is missing or is not a real directory")
	}
	args := []string{"restore", storageKey, pbsArchiveName, "/run/docklight/restore"}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	user := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	_, err := s.run(ctx, args, []string{targetDir + ":/run/docklight/restore:rw"}, user)
	return err
}

func (s *pbsBackupStore) DeleteObject(ctx context.Context, storageKey string) error {
	if _, _, err := parsePBSStorageKey(storageKey); err != nil {
		return err
	}
	args := []string{"snapshot", "forget", storageKey}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	_, err := s.run(ctx, args, nil, "")
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "no such file or directory") || strings.Contains(strings.ToLower(err.Error()), "snapshot does not exist")) {
		return nil
	}
	return err
}

func (s *pbsBackupStore) PruneGroup(ctx context.Context, group string, keep int) error {
	if !validPBSGroupID(group) || keep < 1 || keep > 100 {
		return errors.New("Proxmox backup group or retention value is invalid")
	}
	args := []string{"prune", "host/" + group, "--keep-last=" + strconv.Itoa(keep), "--keep-daily=" + strconv.Itoa(keep)}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	_, err := s.run(ctx, args, nil, "")
	return err
}

func (s *pbsBackupStore) Snapshots(ctx context.Context, group string) (map[string]struct{}, error) {
	if !validPBSGroupID(group) {
		return nil, errors.New("Proxmox backup group is invalid")
	}
	args := []string{"snapshot", "list", "host/" + group, "--output-format=json"}
	if s.target.Prefix != "" {
		args = append(args, "--ns", s.target.Prefix)
	}
	output, err := s.run(ctx, args, nil, "")
	if err != nil {
		return nil, err
	}
	var entries []struct {
		BackupTime json.RawMessage `json:"backup-time"`
	}
	if err = json.Unmarshal([]byte(output), &entries); err != nil {
		return nil, errors.New("Proxmox returned an unreadable snapshot list; retention records were left in place")
	}
	keys := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		var epoch int64
		if err = json.Unmarshal(entry.BackupTime, &epoch); err != nil {
			var stamp string
			if err = json.Unmarshal(entry.BackupTime, &stamp); err != nil {
				return nil, errors.New("Proxmox returned a snapshot without a valid backup time")
			}
			parsed, parseErr := time.Parse(time.RFC3339, stamp)
			if parseErr != nil {
				return nil, errors.New("Proxmox returned a snapshot without a valid backup time")
			}
			epoch = parsed.Unix()
		}
		key := "host/" + group + "/" + time.Unix(epoch, 0).UTC().Format(time.RFC3339)
		keys[key] = struct{}{}
	}
	return keys, nil
}

func (s *pbsBackupStore) run(ctx context.Context, args, binds []string, user string) (string, error) {
	if err := validatePBSTarget(s.target); err != nil {
		return "", err
	}
	if err := s.app.engine.PullPlatform(ctx, s.image, "linux/amd64"); err != nil {
		return "", fmt.Errorf("could not prepare the Proxmox Backup Client image; check docker.pbs_client_image: %w", err)
	}
	repository, err := pbsRepository(s.target)
	if err != nil {
		return "", err
	}
	env := []string{"PBS_REPOSITORY=" + repository, "PBS_PASSWORD=" + s.target.SecretKey, "PBS_LOG=error"}
	if s.target.HostKeySHA256 != "" {
		env = append(env, "PBS_FINGERPRINT="+s.target.HostKeySHA256)
	}
	id, err := newID()
	if err != nil {
		return "", errors.New("could not create a Proxmox helper session")
	}
	config := docker.CreateConfig{
		Image:        s.image,
		Entrypoint:   []string{"proxmox-backup-client"},
		Cmd:          args,
		Env:          env,
		User:         user,
		AttachStdout: true, AttachStderr: true,
		Labels:     map[string]string{"docklight.helper": "pbs", "docklight.managed": "true"},
		HostConfig: docker.HostConfig{Binds: binds},
	}
	containerID, err := s.app.engine.CreateWithPlatform(ctx, "docklight-pbs-"+shortID(id), config, "linux/amd64")
	if err != nil {
		return "", fmt.Errorf("could not create the Proxmox helper container: %w", err)
	}
	defer func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.app.engine.Remove(removeCtx, containerID)
	}()
	if err = s.app.engine.Start(ctx, containerID); err != nil {
		return "", fmt.Errorf("could not start the Proxmox helper container: %w", err)
	}
	attachment, err := s.app.engine.AttachOutput(ctx, containerID)
	if err != nil {
		return "", fmt.Errorf("could not open the Proxmox helper output: %w", err)
	}
	var output limitedOutput
	output.limit = 128 * 1024
	streamDone := make(chan error, 1)
	go func() {
		defer attachment.Close()
		streamDone <- docker.CopyStream(&output, attachment, 1)
	}()
	exitCode, waitErr := s.app.engine.Wait(ctx, containerID)
	_ = attachment.Close()
	streamErr := <-streamDone
	if waitErr != nil {
		return output.String(), fmt.Errorf("Proxmox Backup Client did not finish: %w", waitErr)
	}
	if streamErr != nil && !errors.Is(streamErr, io.EOF) && !errors.Is(streamErr, io.ErrClosedPipe) {
		return output.String(), fmt.Errorf("could not read Proxmox Backup Client output: %w", streamErr)
	}
	if exitCode != 0 {
		logs := output.String()
		logsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if reader, logsErr := s.app.engine.Logs(logsCtx, containerID, "100", false); logsErr == nil {
			var all limitedOutput
			all.limit = 128 * 1024
			_ = docker.CopyLogs(&all, reader)
			_ = reader.Close()
			if value := strings.TrimSpace(all.String()); value != "" {
				logs = stripDockerLogTimestamps(value)
			}
		}
		cancel()
		detail := redactRcloneOutput(logs, []string{s.target.SecretKey, s.target.AccessKey})
		if detail == "" {
			detail = fmt.Sprintf("helper exited with status %d", exitCode)
		}
		return "", errors.New(detail)
	}
	return output.String(), nil
}

func stripDockerLogTimestamps(value string) string {
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if len(line) >= 31 && line[10] == 'T' {
			if index := strings.IndexByte(line, ' '); index > 0 && index < 36 {
				line = line[index+1:]
			}
		}
		lines[i] = line
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func pbsGroupID(serverName, serverID string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(serverName) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() != 0 {
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 48 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "server"
	}
	return slug + "-" + shortID(serverID)
}

func pbsStorageKey(group string, unixSeconds int64) string {
	return "host/" + group + "/" + time.Unix(unixSeconds, 0).UTC().Format(time.RFC3339)
}

func parsePBSStorageKey(key string) (string, int64, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 || parts[0] != "host" || !validPBSGroupID(parts[1]) {
		return "", 0, errors.New("Proxmox backup snapshot key is invalid")
	}
	stamp, err := time.Parse(time.RFC3339, parts[2])
	if err != nil || !safeRemoteBackupObjectKey(key) {
		return "", 0, errors.New("Proxmox backup snapshot key has an invalid timestamp")
	}
	return parts[1], stamp.Unix(), nil
}

func validPBSGroupID(group string) bool {
	return group != "" && len(group) <= 64 && !strings.Contains(group, "/") && pbsNamePattern.MatchString(group)
}

func pbsNowSeconds() int64 { return time.Now().UTC().Unix() }

func (a *App) createPBSBackupSnapshot(server Server, store backupObjectStore) (backupRecord, int, string, error) {
	fail := func(status int, message string) (backupRecord, int, string, error) {
		return backupRecord{}, 0, "", &backupOperationError{status: status, message: message}
	}
	pbsStore, ok := store.(*pbsBackupStore)
	if !ok {
		return fail(http.StatusBadGateway, "Proxmox Backup Server destination could not be prepared")
	}
	summary, err := backup.Summarize(server.DataDir)
	if err != nil {
		return fail(http.StatusConflict, "Proxmox backup stopped before upload: "+err.Error())
	}
	id, err := newID()
	if err != nil {
		return fail(http.StatusInternalServerError, "could not generate a backup ID")
	}
	group := pbsGroupID(server.Name, server.ID)
	backupTime := pbsNowSeconds()
	rows, err := a.db.Query(`SELECT storage_key FROM server_backups WHERE server_id=? AND storage='pbs'`, server.ID)
	if err != nil {
		return fail(http.StatusInternalServerError, "could not check existing Proxmox snapshots before creating a backup")
	}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			_ = rows.Close()
			return fail(http.StatusInternalServerError, "could not read existing Proxmox snapshot metadata")
		}
		if oldGroup, oldTime, parseErr := parsePBSStorageKey(key); parseErr == nil && oldGroup == group && oldTime >= backupTime {
			backupTime = oldTime + 1
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return fail(http.StatusInternalServerError, "could not read existing Proxmox snapshot metadata")
	}
	_ = rows.Close()
	storageKey := pbsStorageKey(group, backupTime)
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	if err = pbsStore.BackupDirectory(ctx, storageKey, server.DataDir); err != nil {
		return fail(http.StatusBadGateway, explainRemoteBackupError("pbs", "upload", err))
	}
	createdAt := time.Unix(backupTime, 0).UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	if _, err = a.db.Exec(`INSERT INTO server_backups(id,server_id,storage,storage_key,size_bytes,sha256,files,directories,data_bytes,created_at) VALUES(?,?,'pbs',?,?, '',?,?,?,?)`, id, server.ID, storageKey, summary.Bytes, summary.Files, summary.Directories, summary.Bytes, createdAt); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		cleanupErr := pbsStore.DeleteObject(cleanupCtx, storageKey)
		cleanupCancel()
		if cleanupErr != nil {
			return fail(http.StatusInternalServerError, "Proxmox snapshot was uploaded but its database record could not be saved; remove the orphaned snapshot after fixing panel storage")
		}
		return fail(http.StatusInternalServerError, "Proxmox snapshot was uploaded but its metadata could not be saved; check panel storage and retry")
	}
	item, err := a.getBackup(server.ID, id)
	if err != nil {
		return fail(http.StatusInternalServerError, "Proxmox snapshot was saved but its metadata could not be read")
	}
	pruned, _, pruneErr := a.pruneServerBackups(server.ID, a.backupRetention())
	warning := ""
	if pruneErr != nil {
		warning = "Backup kept, but retention could not run. Check Proxmox token permissions and review the PBS datastore before retrying."
	}
	return item, pruned, warning, nil
}

func pbsRestoreStage(parent string) (string, error) {
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, ".docklight-pbs-restore-")
	if err != nil {
		return "", err
	}
	if err = os.Chmod(stage, 0700); err != nil {
		_ = os.RemoveAll(stage)
		return "", err
	}
	return filepath.Clean(stage), nil
}
