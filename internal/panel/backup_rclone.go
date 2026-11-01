package panel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/security"
)

const (
	rcloneRemoteName  = "docklight"
	rcloneConfigPath  = "/run/docklight/rclone.conf"
	rcloneConfigLimit = 24 * 1024
	rcloneStagedPut   = "__docklight_staged_put__"
)

type rcloneBackupStore struct {
	app    *App
	target backupTargetConfig
	config string
	mu     sync.Mutex
}

func (a *App) newRcloneBackupStore(target backupTargetConfig) (backupObjectStore, error) {
	if !target.configured() {
		return nil, errors.New("configure a supported rclone provider in Backup storage first")
	}
	if a.backupStoreFactory != nil {
		return a.backupStoreFactory(target)
	}
	if err := validateStoredRcloneConfig(target.AuthMode, target.SecretKey); err != nil {
		return nil, err
	}
	return &rcloneBackupStore{app: a, target: target, config: target.SecretKey}, nil
}

func (s *rcloneBackupStore) Put(ctx context.Context, key string, src io.Reader) error {
	if !safeRemoteBackupObjectKey(key) {
		return errors.New("rclone backup object key is invalid")
	}
	remoteType := ""
	if section, err := parseRcloneSection(s.config); err == nil {
		remoteType = section["type"]
	}
	if remoteType == "dropbox" || remoteType == "box" {
		return s.run(ctx, []string{"rcat", rcloneRemoteName + ":" + key}, src, nil)
	}
	return s.run(ctx, []string{rcloneStagedPut, rcloneRemoteName + ":" + key}, src, nil)
}

func (s *rcloneBackupStore) PutFile(ctx context.Context, key string, file *os.File) error {
	if file == nil {
		return errors.New("rclone backup upload file is unavailable")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return s.Put(ctx, key, file)
}

func (s *rcloneBackupStore) GetObject(ctx context.Context, key string, dst io.Writer) error {
	if !safeRemoteBackupObjectKey(key) {
		return errors.New("rclone backup object key is invalid")
	}
	if dst == nil {
		return errors.New("rclone backup download destination is unavailable")
	}
	return s.run(ctx, []string{"cat", rcloneRemoteName + ":" + key}, nil, dst)
}

func (s *rcloneBackupStore) DeleteObject(ctx context.Context, key string) error {
	if !safeRemoteBackupObjectKey(key) {
		return errors.New("rclone backup object key is invalid")
	}
	return s.run(ctx, []string{"deletefile", rcloneRemoteName + ":" + key}, nil, io.Discard)
}

func (s *rcloneBackupStore) List(ctx context.Context, prefix string) error {
	if prefix != "" {
		if normalized, err := normalizeBackupPrefix(prefix); err != nil || normalized != prefix {
			return errors.New("rclone backup prefix is invalid")
		}
	}
	// List the remote root. A not-yet-created backup prefix must not prevent the
	// initial connection check; the test upload below creates that path.
	return s.run(ctx, []string{"lsf", rcloneRemoteName + ":"}, nil, io.Discard)
}

func (s *rcloneBackupStore) run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated, err := s.app.runRcloneHelper(ctx, s.config, args, input, output, input != nil, s.config, s.target.AccessKey, s.target.Endpoint)
	if updated != "" && updated != s.config {
		if saveErr := s.persistConfig(updated); saveErr != nil {
			return saveErr
		}
		s.config = updated
		s.target.SecretKey = updated
	}
	return err
}

func (s *rcloneBackupStore) persistConfig(configText string) error {
	if len(configText) == 0 || len(configText) > rcloneConfigLimit {
		return errors.New("rclone returned an invalid refreshed configuration")
	}
	if err := validateStoredRcloneConfig(s.target.AuthMode, configText); err != nil {
		return errors.New("rclone returned an invalid refreshed configuration")
	}
	cipher, err := security.Encrypt([]byte(s.app.cfg.Auth.SecretKey), configText)
	if err != nil {
		return errors.New("could not encrypt the refreshed rclone configuration")
	}
	result, err := s.app.db.Exec(`UPDATE backup_target_settings SET secret_key_enc=?,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND protocol='rclone'`, cipher)
	if err != nil {
		return errors.New("could not save refreshed rclone authorization")
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("rclone target changed before refreshed authorization could be saved")
	}
	return nil
}

// runRcloneHelper gives each invocation a private short-lived config directory.
// The mounted config is writable so rclone can rotate OAuth tokens; its updated
// contents are read back and encrypted in SQLite before the directory is removed.
func (a *App) runRcloneHelper(ctx context.Context, configText string, args []string, input io.Reader, output io.Writer, closeInput bool, secrets ...string) (string, error) {
	image := strings.TrimSpace(a.cfg.Docker.RcloneImage)
	if image == "" {
		image = "rclone/rclone:1.75.2"
	}
	if err := a.engine.Pull(ctx, image); err != nil {
		return "", fmt.Errorf("could not prepare the rclone helper image: %w", err)
	}
	if err := os.MkdirAll(a.updateDir, 0700); err != nil {
		return "", errors.New("could not prepare private rclone configuration storage")
	}
	dir, err := os.MkdirTemp(a.updateDir, ".docklight-rclone-")
	if err != nil {
		return "", errors.New("could not create a private rclone configuration directory")
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		return "", errors.New("could not secure temporary rclone configuration storage")
	}
	configFile := filepath.Join(dir, "rclone.conf")
	if len(configText) > rcloneConfigLimit {
		return "", errors.New("rclone configuration exceeds the 24 KiB limit")
	}
	if err = os.WriteFile(configFile, []byte(configText), 0600); err != nil {
		return "", errors.New("could not prepare the temporary rclone configuration")
	}
	id, err := newID()
	if err != nil {
		return "", errors.New("could not create an rclone helper session")
	}
	containerName := "docklight-rclone-" + shortID(id)
	containerConfig := docker.CreateConfig{
		Image:     image,
		Cmd:       append([]string{"--config=" + rcloneConfigPath, "--log-level=ERROR"}, args...),
		OpenStdin: input != nil, AttachStdin: input != nil, AttachStdout: true, AttachStderr: true,
		Labels:     map[string]string{"docklight.helper": "rclone", "docklight.managed": "true"},
		HostConfig: docker.HostConfig{Binds: []string{dir + ":/run/docklight:rw"}},
	}
	if len(args) == 2 && args[0] == rcloneStagedPut {
		containerConfig.Entrypoint = []string{"/bin/sh", "-c"}
		containerConfig.Cmd = []string{"umask 077; cat > /tmp/docklight-backup.archive || exit; rclone --config=" + rcloneConfigPath + " --log-level=ERROR copyto /tmp/docklight-backup.archive \"$DOCKLIGHT_REMOTE_PATH\"; status=$?; rm -f /tmp/docklight-backup.archive; exit $status"}
		containerConfig.Env = []string{"DOCKLIGHT_REMOTE_PATH=" + args[1]}
	}
	cid, err := a.engine.Create(ctx, containerName, containerConfig)
	if err != nil {
		return "", fmt.Errorf("could not create the rclone helper container: %w", err)
	}
	remove := func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.engine.Remove(removeCtx, cid)
	}
	defer remove()
	if err = a.engine.Start(ctx, cid); err != nil {
		return "", fmt.Errorf("could not start the rclone helper container: %w", err)
	}
	var captured limitedOutput
	captured.limit = 64 * 1024
	var streamErr error
	var streamDone chan error
	var attachment io.ReadWriteCloser
	if input != nil {
		attachment, err = a.engine.Attach(ctx, cid)
	} else {
		attachment, err = a.engine.AttachOutput(ctx, cid)
	}
	if err != nil {
		return "", fmt.Errorf("could not open the rclone helper stream: %w", err)
	}
	streamDone = make(chan error, 1)
	go func() {
		defer attachment.Close()
		if input != nil {
			destination := io.Writer(&captured)
			if output != nil {
				destination = io.MultiWriter(&captured, output)
			}
			streamDone <- docker.CopyLogs(destination, attachment)
			return
		}
		destination := io.Writer(io.Discard)
		if output != nil {
			destination = output
		}
		streamDone <- docker.CopyStream(destination, attachment, 1)
	}()
	if input != nil {
		if _, copyErr := io.Copy(attachment, input); copyErr != nil {
			streamErr = copyErr
		}
		if closeInput {
			_ = attachment.Close()
		}
	}
	exitCode, waitErr := a.engine.Wait(ctx, cid)
	_ = attachment.Close()
	copyErr := <-streamDone
	logs := captured.String()
	if waitErr != nil || exitCode != 0 {
		if containerLogs := a.rcloneContainerLogs(ctx, cid); containerLogs != "" {
			logs = containerLogs
		}
	}
	if waitErr != nil {
		return readUpdatedRcloneConfig(configFile), fmt.Errorf("rclone helper did not finish: %w", waitErr)
	}
	if streamErr != nil {
		return readUpdatedRcloneConfig(configFile), fmt.Errorf("rclone helper input failed: %w", streamErr)
	}
	if !(input != nil && closeInput) && copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, io.ErrClosedPipe) {
		return readUpdatedRcloneConfig(configFile), fmt.Errorf("could not read rclone helper output: %w", copyErr)
	}
	if exitCode != 0 {
		detail := redactRcloneOutput(logs, secrets)
		if detail == "" {
			detail = fmt.Sprintf("helper exited with status %d", exitCode)
		}
		return readUpdatedRcloneConfig(configFile), errors.New(detail)
	}
	return readUpdatedRcloneConfig(configFile), nil
}

func (a *App) rcloneContainerLogs(ctx context.Context, id string) string {
	reader, err := a.engine.Logs(ctx, id, "100", false)
	if err != nil {
		return ""
	}
	defer reader.Close()
	var output limitedOutput
	output.limit = 64 * 1024
	_ = docker.CopyLogs(&output, reader)
	return output.String()
}

type limitedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (o *limitedOutput) Write(p []byte) (int, error) {
	if o.limit <= 0 {
		return len(p), nil
	}
	remaining := o.limit - o.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = o.buffer.Write(p[:remaining])
		} else {
			_, _ = o.buffer.Write(p)
		}
	}
	return len(p), nil
}

func (o *limitedOutput) String() string { return strings.TrimSpace(o.buffer.String()) }

func readUpdatedRcloneConfig(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > rcloneConfigLimit {
		return ""
	}
	return string(data)
}

func redactRcloneOutput(message string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	var redacted []string
	for _, line := range strings.Split(message, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if ok {
			name := strings.ToLower(strings.TrimSpace(key))
			if strings.Contains(name, "token") || strings.Contains(name, "secret") || strings.Contains(name, "password") || name == "pass" || name == "bearer_token" {
				line = key + "=[redacted]"
			}
		}
		redacted = append(redacted, line)
	}
	message = strings.TrimSpace(strings.Join(redacted, "\n"))
	if len(message) > 4096 {
		message = message[:4096] + "…"
	}
	return message
}

func validateStoredRcloneConfig(provider, configText string) error {
	section, err := parseRcloneSection(configText)
	if err != nil {
		return err
	}
	typeName := section["type"]
	if typeName == "" {
		return errors.New("rclone configuration needs a type field")
	}
	if provider != "custom" && typeName != providerRcloneType(provider) {
		return errors.New("rclone configuration does not match the selected provider")
	}
	switch provider {
	case "jottacloud":
		if section["token"] == "" || section["username"] == "" {
			return errors.New("Jottacloud config needs its exchanged OAuth token and account identifier")
		}
	case "dropbox", "onedrive", "drive", "box", "pcloud":
		if section["token"] == "" {
			return errors.New("rclone OAuth config needs a token")
		}
		if _, err := compactRcloneOAuthToken(section["token"]); err != nil {
			return err
		}
	case "mega":
		if section["user"] == "" || section["pass"] == "" {
			return errors.New("MEGA config needs an account name and password")
		}
	case "webdav":
		endpoint, parseErr := url.Parse(section["url"])
		if parseErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || section["vendor"] == "" || section["user"] == "" || section["pass"] == "" {
			return errors.New("WebDAV config needs a trusted HTTPS URL, service type, account name, and password")
		}
	}
	return nil
}

func parseRcloneSection(input string) (map[string]string, error) {
	if len(input) == 0 || len(input) > rcloneConfigLimit || strings.ContainsRune(input, '\x00') {
		return nil, errors.New("rclone configuration must be from 1 to 24 KiB")
	}
	values := make(map[string]string)
	sectionCount := 0
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.ContainsAny(line[1:len(line)-1], "[]\r\n") {
				return nil, fmt.Errorf("rclone config line %d has an invalid section header", lineNumber+1)
			}
			sectionCount++
			if sectionCount > 1 {
				return nil, errors.New("rclone config must contain exactly one remote section")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("rclone config line %d must contain key = value", lineNumber+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || strings.ContainsAny(key, " \t\r\n[]") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("rclone config line %d contains an invalid key or value", lineNumber+1)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("rclone configuration repeats the %q option", key)
		}
		values[key] = value
	}
	if sectionCount != 1 {
		return nil, errors.New("rclone configuration needs one [remote] section")
	}
	return values, nil
}

func normalizeRcloneCustomConfig(input string) (string, error) {
	values, err := parseRcloneSection(input)
	if err != nil {
		return "", err
	}
	if values["type"] == "" {
		return "", errors.New("custom rclone section must include a type = ... option")
	}
	var out strings.Builder
	out.WriteString("[docklight]\n")
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func providerRcloneType(provider string) string {
	switch provider {
	case "drive":
		return "drive"
	case "onedrive":
		return "onedrive"
	case "mega":
		return "mega"
	case "webdav":
		return "webdav"
	default:
		return provider
	}
}

func updateRcloneConfigOptions(configText string, updates map[string]string) (string, error) {
	values, err := parseRcloneSection(configText)
	if err != nil {
		return "", err
	}
	for key, value := range updates {
		if value == "" {
			return "", fmt.Errorf("rclone %s cannot be empty", key)
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return "", fmt.Errorf("rclone %s cannot contain control characters", key)
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString("[docklight]\n")
	for _, key := range keys {
		out.WriteString(key)
		out.WriteString(" = ")
		out.WriteString(values[key])
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func rcloneProviderAllowed(provider string) bool {
	switch provider {
	case "jottacloud", "dropbox", "onedrive", "drive", "box", "pcloud", "mega", "webdav", "custom":
		return true
	default:
		return false
	}
}

func compactRcloneOAuthToken(input string) (string, error) {
	input = strings.TrimSpace(input)
	var token []byte
	if json.Valid([]byte(input)) {
		token = []byte(input)
	} else {
		for _, decoder := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			decoded, err := decoder.DecodeString(input)
			if err == nil && json.Valid(decoded) {
				token = decoded
				break
			}
		}
	}
	if len(token) == 0 {
		return "", errors.New("paste the JSON token returned by rclone authorize")
	}
	var parsed map[string]any
	if err := json.Unmarshal(token, &parsed); err != nil || parsed["access_token"] == nil {
		return "", errors.New("rclone authorize token must contain an access_token")
	}
	compact, err := json.Marshal(parsed)
	if err != nil {
		return "", errors.New("rclone authorize token could not be parsed")
	}
	return string(compact), nil
}

func configLine(key, value string) (string, error) {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("rclone %s cannot contain line breaks or control characters", key)
	}
	return key + " = " + value + "\n", nil
}

func (a *App) prepareRcloneConfig(ctx context.Context, provider, endpoint, username, credential, rawConfig, vendor string) (string, string, error) {
	if !rcloneProviderAllowed(provider) {
		return "", "", errors.New("choose Jottacloud, Dropbox, OneDrive, Google Drive, Box, pCloud, Mega, WebDAV, or custom rclone config")
	}
	if provider == "custom" {
		config, err := normalizeRcloneCustomConfig(rawConfig)
		if err != nil {
			return "", "", err
		}
		return config, "", nil
	}
	if provider == "jottacloud" {
		credential = strings.TrimSpace(credential)
		if credential == "" || strings.IndexFunc(credential, unicode.IsControl) >= 0 {
			return "", "", errors.New("enter a Jottacloud personal login token")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		config, err := a.exchangeJottacloudToken(ctx, credential)
		if err != nil {
			return "", "", errors.New("could not exchange the Jottacloud personal token; check that it is unused and still valid")
		}
		section, _ := parseRcloneSection(config)
		return config, section["username"], nil
	}
	if provider == "mega" || provider == "webdav" {
		if username == "" || credential == "" {
			return "", "", errors.New("enter the account username and password")
		}
		if strings.IndexFunc(username, unicode.IsControl) >= 0 {
			return "", "", errors.New("account username cannot contain line breaks or control characters")
		}
		if strings.IndexFunc(credential, unicode.IsControl) >= 0 {
			return "", "", errors.New("password cannot contain line breaks or control characters")
		}
		obscured, err := a.obscureRclonePassword(ctx, credential)
		if err != nil {
			return "", "", errors.New("rclone could not prepare the password securely")
		}
		var out strings.Builder
		out.WriteString("[docklight]\ntype = " + providerRcloneType(provider) + "\n")
		if provider == "mega" {
			userLine, err := configLine("user", username)
			if err != nil {
				return "", "", err
			}
			out.WriteString(userLine)
		} else {
			parsed, err := url.Parse(strings.TrimSpace(endpoint))
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return "", "", errors.New("WebDAV needs a trusted HTTPS URL without embedded credentials, query parameters, or a fragment")
			}
			vendor = strings.TrimSpace(vendor)
			if vendor == "" {
				vendor = "other"
			}
			if vendor != "nextcloud" && vendor != "owncloud" && vendor != "other" {
				return "", "", errors.New("WebDAV vendor must be Nextcloud, ownCloud, or Other")
			}
			urlLine, err := configLine("url", parsed.String())
			if err != nil {
				return "", "", err
			}
			vendorLine, err := configLine("vendor", vendor)
			if err != nil {
				return "", "", err
			}
			userLine, err := configLine("user", username)
			if err != nil {
				return "", "", err
			}
			out.WriteString(urlLine + vendorLine + userLine)
		}
		passLine, err := configLine("pass", obscured)
		if err != nil {
			return "", "", err
		}
		out.WriteString(passLine)
		return out.String(), username, nil
	}
	token, err := compactRcloneOAuthToken(credential)
	if err != nil {
		return "", "", err
	}
	var out strings.Builder
	out.WriteString("[docklight]\ntype = " + providerRcloneType(provider) + "\n")
	tokenLine, err := configLine("token", token)
	if err != nil {
		return "", "", err
	}
	out.WriteString(tokenLine)
	if provider == "onedrive" {
		out.WriteString("drive_type = personal\n")
	}
	return out.String(), "", nil
}

func (a *App) obscureRclonePassword(ctx context.Context, password string) (string, error) {
	var input bytes.Buffer
	input.WriteString(password)
	input.WriteByte('\n')
	var output bytes.Buffer
	_, err := a.runRcloneHelper(ctx, "", []string{"obscure", "-"}, &input, &output, false, password)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(output.String())
	if value == "" || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("rclone did not return an obscured password")
	}
	return value, nil
}

func (a *App) exchangeJottacloudToken(ctx context.Context, loginToken string) (string, error) {
	// rclone's config-create protocol exchanges this single-use token for its
	// normal rotating OAuth token and stores the result in rclone.conf. The
	// one-time token is held only in this short-lived helper command and the
	// container is removed immediately after the exchange.
	command := []string{"config", "create", rcloneRemoteName, "jottacloud", "client_id=jottacli", "client_secret=", "config_type=standard", "config_login_token=" + loginToken, "--no-output"}
	updated, err := a.runRcloneHelper(ctx, "", command, nil, io.Discard, false, loginToken)
	if err != nil {
		return "", err
	}
	if err = validateStoredRcloneConfig("jottacloud", updated); err != nil {
		return "", err
	}
	section, err := parseRcloneSection(updated)
	if err != nil || section["token"] == "" || section["config_login_token"] != "" {
		return "", errors.New("rclone did not finish the Jottacloud token exchange")
	}
	return updated, nil
}
