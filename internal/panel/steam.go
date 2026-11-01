package panel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"example.com/yggdrasil-panel/internal/docker"
	gameskill "example.com/yggdrasil-panel/internal/rune"
)

const (
	steamCMDImage       = "steamcmd/steamcmd:debian-12"
	steamCMDPlatform    = "linux/amd64"
	steamAuthTimeout    = 2 * time.Minute
	steamPendingTimeout = 5 * time.Minute
	steamOutputLimit    = 128 * 1024
)

type steamPendingLogin struct {
	username string
	password []byte
	expires  time.Time
}

type steamAccountResponse struct {
	Username     string `json:"username"`
	Authorized   bool   `json:"authorized"`
	AuthorizedAt string `json:"authorized_at,omitempty"`
	NeedsCode    bool   `json:"needs_code"`
}

type steamOutputBuffer struct {
	data      []byte
	truncated bool
}

func (b *steamOutputBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n >= steamOutputLimit {
		b.data = append(b.data[:0], p[n-steamOutputLimit:]...)
		b.truncated = true
		return n, nil
	}
	if len(b.data)+n > steamOutputLimit {
		remove := len(b.data) + n - steamOutputLimit
		copy(b.data, b.data[remove:])
		b.data = b.data[:len(b.data)-remove]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (a *App) steamCachePath() string {
	return filepath.Join(a.updateDir, "steam-cache")
}

func (a *App) prepareSteamCache() (string, error) {
	cache := a.steamCachePath()
	if err := os.MkdirAll(filepath.Dir(cache), 0700); err != nil {
		return "", fmt.Errorf("prepare Steam cache parent: %w", err)
	}
	info, err := os.Lstat(cache)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(cache, 0777); err != nil && !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create Steam cache: %w", err)
		}
		info, err = os.Lstat(cache)
	}
	if err != nil {
		return "", fmt.Errorf("inspect Steam cache: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("Steam cache must be a real directory, not a symlink or file")
	}
	if err = os.Chmod(cache, 0777); err != nil {
		return "", fmt.Errorf("make Steam cache writable: %w", err)
	}
	return cache, nil
}

func (a *App) steamInstallEnv(gs gameskill.Rune, env map[string]string) (map[string]string, error) {
	installed := make(map[string]string, len(env)+2)
	for key, value := range env {
		installed[key] = value
	}
	installed["HOME"] = "/steamcache"
	if gs.Steam == nil || gs.Steam.Anonymous {
		return installed, nil
	}
	var account steamAccountResponse
	var authorized int
	if err := a.db.QueryRow(`SELECT username,authorized,authorized_at FROM steam_account WHERE id=1`).Scan(&account.Username, &authorized, &account.AuthorizedAt); err != nil {
		return nil, errors.New("Steam account settings could not be read")
	}
	if authorized != 1 || account.Username == "" {
		return nil, errors.New("This game requires an authorized Steam account. Authorize one under Settings → Steam first.")
	}
	installed["STEAM_USER"] = account.Username
	return installed, nil
}

func (a *App) getSteamAccount(w http.ResponseWriter, _ *http.Request) {
	a.steamMu.Lock()
	defer a.steamMu.Unlock()
	var account steamAccountResponse
	var authorized int
	if err := a.db.QueryRow(`SELECT username,authorized,authorized_at FROM steam_account WHERE id=1`).Scan(&account.Username, &authorized, &account.AuthorizedAt); err != nil {
		writeError(w, http.StatusInternalServerError, "Steam account settings could not be read")
		return
	}
	account.Authorized = authorized == 1
	if a.steamPending != nil {
		if time.Now().Before(a.steamPending.expires) {
			account.NeedsCode = true
		} else {
			clear(a.steamPending.password)
			a.steamPending = nil
		}
	}
	writeJSON(w, http.StatusOK, account)
}

func (a *App) sendSteamCode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &input, 4096) != nil {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if input.Username == "" || len(input.Username) > 128 || strings.IndexFunc(input.Username, unicode.IsControl) >= 0 {
		writeError(w, http.StatusBadRequest, "Steam username must contain 1 to 128 printable characters")
		return
	}
	if input.Password == "" || len(input.Password) > 256 || strings.ContainsAny(input.Password, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "Steam password must contain 1 to 256 characters and cannot contain line breaks")
		return
	}

	a.steamMu.Lock()
	defer a.steamMu.Unlock()
	var savedUsername string
	var savedAuthorized int
	if err := a.db.QueryRow(`SELECT username,authorized FROM steam_account WHERE id=1`).Scan(&savedUsername, &savedAuthorized); err != nil {
		writeError(w, http.StatusInternalServerError, "Steam account settings could not be read")
		return
	}
	if savedAuthorized == 1 && savedUsername != input.Username {
		writeError(w, http.StatusConflict, "Remove the authorized Steam account before switching to a different account")
		return
	}
	if a.steamPending != nil {
		clear(a.steamPending.password)
		a.steamPending = nil
	}
	password := []byte(input.Password)
	input.Password = ""
	ctx, cancel := context.WithTimeout(r.Context(), steamAuthTimeout)
	defer cancel()
	output, _, err := a.runSteamCMD(ctx, input.Username, password, "")
	if err != nil {
		clear(password)
		writeError(w, http.StatusBadGateway, "Steam login could not be reached; check Docker access and outbound network access")
		return
	}
	if steamLoginSucceeded(output) {
		clear(password)
		if err = a.saveSteamAccount(input.Username, true); err != nil {
			writeError(w, http.StatusInternalServerError, "Steam account was verified but its status could not be saved")
			return
		}
		a.steamPending = nil
		a.audit(principal(r), "steam.account.authorize", "settings", "steam", "username="+input.Username)
		writeJSON(w, http.StatusOK, map[string]any{"username": input.Username, "authorized": true, "needs_code": false})
		return
	}
	if steamGuardRequired(output) {
		pending := &steamPendingLogin{username: input.Username, password: password, expires: time.Now().Add(steamPendingTimeout)}
		a.steamPending = pending
		time.AfterFunc(steamPendingTimeout, func() {
			a.steamMu.Lock()
			if a.steamPending == pending {
				clear(pending.password)
				a.steamPending = nil
			}
			a.steamMu.Unlock()
		})
		if _, err = a.db.ExecContext(r.Context(), `UPDATE steam_account SET username=?,authorized=0,authorized_at='' WHERE id=1`, input.Username); err != nil {
			clear(pending.password)
			a.steamPending = nil
			writeError(w, http.StatusInternalServerError, "Steam login is waiting for a code but its status could not be saved")
			return
		}
		a.audit(principal(r), "steam.account.code_requested", "settings", "steam", "username="+input.Username)
		writeJSON(w, http.StatusOK, map[string]any{"username": input.Username, "authorized": false, "needs_code": true, "message": "Enter the Steam Guard code from the account email or Steam Mobile app."})
		return
	}
	clear(password)
	writeError(w, http.StatusBadGateway, "Steam did not accept the login. Check the username and password, then request a new code.")
}

func (a *App) authorizeSteamAccount(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code string `json:"code"`
	}
	if decodeJSON(w, r, &input, 1024) != nil {
		return
	}
	input.Code = strings.TrimSpace(input.Code)
	if len(input.Code) < 4 || len(input.Code) > 10 || strings.IndexFunc(input.Code, func(ch rune) bool {
		return !(ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z')
	}) >= 0 {
		writeError(w, http.StatusBadRequest, "Steam Guard code must contain 4 to 10 letters or digits")
		return
	}
	a.steamMu.Lock()
	defer a.steamMu.Unlock()
	pending := a.steamPending
	if pending == nil || time.Now().After(pending.expires) {
		if pending != nil {
			clear(pending.password)
		}
		a.steamPending = nil
		writeError(w, http.StatusConflict, "Steam authorization expired; enter the username and password and request a new code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), steamAuthTimeout)
	defer cancel()
	output, _, err := a.runSteamCMD(ctx, pending.username, pending.password, input.Code)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Steam login could not be reached; request a new code after checking Docker and network access")
		return
	}
	if !steamLoginSucceeded(output) {
		writeError(w, http.StatusBadGateway, "Steam did not accept that code. Check the current email or mobile code and try again.")
		return
	}
	if err = a.saveSteamAccount(pending.username, true); err != nil {
		writeError(w, http.StatusInternalServerError, "Steam account was verified but its status could not be saved")
		return
	}
	clear(pending.password)
	a.steamPending = nil
	a.audit(principal(r), "steam.account.authorize", "settings", "steam", "username="+pending.username)
	writeJSON(w, http.StatusOK, map[string]any{"username": pending.username, "authorized": true})
}

func (a *App) deleteSteamAccount(w http.ResponseWriter, r *http.Request) {
	a.steamMu.Lock()
	defer a.steamMu.Unlock()
	if a.steamPending != nil {
		clear(a.steamPending.password)
	}
	a.steamPending = nil
	cache := a.steamCachePath()
	if info, err := os.Lstat(cache); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			writeError(w, http.StatusConflict, "Steam cache is not a directory; inspect the panel data path before removing the account")
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "Steam account cache could not be inspected")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE steam_account SET username='',authorized=0,authorized_at='' WHERE id=1`); err != nil {
		writeError(w, http.StatusInternalServerError, "Steam account could not be removed")
		return
	}
	a.audit(principal(r), "steam.account.delete", "settings", "steam", "")
	if err := os.RemoveAll(cache); err != nil {
		writeError(w, http.StatusInternalServerError, "Steam account was revoked but its local cache could not be removed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) saveSteamAccount(username string, authorized bool) error {
	value := 0
	authorizedAt := ""
	if authorized {
		value = 1
		authorizedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := a.db.Exec(`UPDATE steam_account SET username=?,authorized=?,authorized_at=? WHERE id=1`, username, value, authorizedAt)
	return err
}

func steamLoginSucceeded(output string) bool {
	output = strings.ToLower(strings.ReplaceAll(output, " ", ""))
	return strings.Contains(output, "waitingforuserinfo...ok") || strings.Contains(output, "loggedinok") || strings.Contains(output, "loggedinas")
}

func steamGuardRequired(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "steam guard") || strings.Contains(output, "steamguard") || strings.Contains(output, "account login denied") || strings.Contains(output, "auth code required")
}

func (a *App) runSteamCMD(ctx context.Context, username string, password []byte, code string) (string, int, error) {
	if err := a.engine.PullPlatform(ctx, steamCMDImage, steamCMDPlatform); err != nil {
		return "", -1, errors.New("could not prepare the SteamCMD authorization image")
	}
	cache, err := a.prepareSteamCache()
	if err != nil {
		return "", -1, err
	}
	containerID, err := newID()
	if err != nil {
		return "", -1, errors.New("could not create a SteamCMD authorization session")
	}
	steamCMD := `if [ -n "$steam_guard" ]; then exec steamcmd +set_steam_guard_code "$steam_guard" +login "$STEAM_USER" "$steam_password" +quit; else exec steamcmd +login "$STEAM_USER" "$steam_password" +quit; fi`
	cfg := docker.CreateConfig{
		Image: steamCMDImage, Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{"IFS= read -r steam_password || exit 2; IFS= read -r steam_guard || exit 2; " + steamCMD},
		Env: []string{"HOME=/steamcache", "STEAM_USER=" + username}, OpenStdin: true, AttachStdin: true, AttachStdout: true, AttachStderr: true, Tty: false,
		HostConfig: docker.HostConfig{Binds: []string{cache + ":/steamcache"}},
	}
	cid, err := a.engine.CreateWithPlatform(ctx, "docklight-steam-"+shortID(containerID), cfg, steamCMDPlatform)
	if err != nil {
		return "", -1, errors.New("could not create a SteamCMD authorization container")
	}
	if err = a.engine.Start(ctx, cid); err != nil {
		a.removeSteamAuthContainer(cid)
		return "", -1, errors.New("could not start SteamCMD authorization")
	}
	logCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	attachment, err := a.engine.Attach(logCtx, cid)
	if err != nil {
		a.removeSteamAuthContainer(cid)
		return "", -1, errors.New("could not open the SteamCMD authorization stream")
	}
	buffer := &steamOutputBuffer{}
	logsDone := make(chan error, 1)
	go func() {
		defer attachment.Close()
		logsDone <- docker.CopyLogs(buffer, attachment)
	}()
	secretInput := make([]byte, 0, len(password)+len(code)+2)
	secretInput = append(secretInput, password...)
	secretInput = append(secretInput, '\n')
	secretInput = append(secretInput, code...)
	secretInput = append(secretInput, '\n')
	_, err = io.Copy(attachment, bytes.NewReader(secretInput))
	clear(secretInput)
	if err != nil {
		cancel()
		_ = attachment.Close()
		a.removeSteamAuthContainer(cid)
		return "", -1, errors.New("SteamCMD could not receive the one-time login input")
	}
	exitCode, waitErr := a.engine.Wait(ctx, cid)
	if waitErr != nil {
		cancel()
	}
	logsErr := <-logsDone
	cancel()
	a.removeSteamAuthContainer(cid)
	if waitErr != nil || logsErr != nil {
		return "", exitCode, errors.New("SteamCMD authorization did not finish")
	}
	return string(buffer.data), exitCode, nil
}

func (a *App) removeSteamAuthContainer(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.engine.Remove(ctx, id)
}

var _ io.Writer = (*steamOutputBuffer)(nil)
