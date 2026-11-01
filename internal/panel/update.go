package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	releaseCheckTTL      = 6 * time.Hour
	updateCheckInterval  = 20 * time.Minute
	updateRequestName    = ".update-request"
	updateStatusName     = ".update-status"
	updateHelperPath     = "/usr/local/bin/yggdrasil-update"
	updateServiceUnit    = "/etc/systemd/system/yggdrasil-update.service"
	updatePathUnit       = "/etc/systemd/system/yggdrasil-update.path"
	installedUpdateState = "/var/lib/yggdrasil"
)

var (
	releaseTagPattern  = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	releaseRepoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	errUpdateQueued    = errors.New("a panel update request is already pending")
)

type releaseCacheEntry struct {
	Tag       string
	Error     string
	CheckedAt time.Time
}

type releasePayload struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

type panelVersionInfo struct {
	Version            string `json:"version"`
	Repo               string `json:"repo"`
	LatestRelease      string `json:"latest_release"`
	UpdateAvailable    bool   `json:"update_available"`
	SelfUpdatePossible bool   `json:"self_update_possible"`
	SelfUpdateReason   string `json:"self_update_reason,omitempty"`
	UpdateError        string `json:"update_error,omitempty"`
	PanelName          string `json:"panel_name"`
}

type panelUpdateStatus struct {
	State   string `json:"state"`
	Tag     string `json:"tag"`
	Message string `json:"message"`
	At      string `json:"at"`
}

type autoUpdateSettings struct {
	Enabled     bool   `json:"enabled"`
	Hour        int    `json:"hour"`
	LastAutoDay string `json:"last_auto_day"`
}

func (a *App) SetReleaseRepository(repository string) {
	repository = strings.TrimSpace(repository)
	if releaseRepoPattern.MatchString(repository) {
		a.releaseRepo = repository
	}
}

func (a *App) latestRelease(ctx context.Context, refresh bool) (string, error) {
	if !releaseRepoPattern.MatchString(a.releaseRepo) {
		return "", errors.New("the GitHub release repository is not configured")
	}
	a.releaseMu.Lock()
	defer a.releaseMu.Unlock()
	if !refresh && !a.releaseCache.CheckedAt.IsZero() && time.Since(a.releaseCache.CheckedAt) < releaseCheckTTL {
		if a.releaseCache.Error != "" {
			return "", errors.New(a.releaseCache.Error)
		}
		return a.releaseCache.Tag, nil
	}
	endpoint := "https://api.github.com/repos/" + a.releaseRepo + "/releases/latest"
	requestCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", errors.New("could not create GitHub release request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Docklight/"+a.version)
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return a.cacheReleaseError("could not reach GitHub to check the latest release")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		message := fmt.Sprintf("GitHub release lookup returned HTTP %d", resp.StatusCode)
		return a.cacheReleaseError(message)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return a.cacheReleaseError("GitHub release response was unavailable or too large")
	}
	var release releasePayload
	if err = json.Unmarshal(body, &release); err != nil || release.Draft || release.Prerelease || !validReleaseTag(release.TagName) {
		return a.cacheReleaseError("GitHub did not return a stable vX.Y.Z release")
	}
	a.releaseCache = releaseCacheEntry{Tag: release.TagName, CheckedAt: time.Now()}
	return release.TagName, nil
}

func (a *App) cacheReleaseError(message string) (string, error) {
	a.releaseCache = releaseCacheEntry{Error: message, CheckedAt: time.Now()}
	return "", errors.New(message)
}

func validReleaseTag(tag string) bool {
	return releaseTagPattern.MatchString(tag)
}

func compareReleaseTags(left, right string) int {
	leftParts, leftOK := releaseParts(left)
	rightParts, rightOK := releaseParts(right)
	if !leftOK || !rightOK {
		return 0
	}
	for i := range leftParts {
		if leftParts[i] < rightParts[i] {
			return -1
		}
		if leftParts[i] > rightParts[i] {
			return 1
		}
	}
	return 0
}

func releaseParts(tag string) ([3]uint64, bool) {
	var out [3]uint64
	matches := releaseTagPattern.FindStringSubmatch(tag)
	if len(matches) != 4 {
		return out, false
	}
	for i, part := range matches[1:] {
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return out, false
		}
		out[i] = value
	}
	return out, true
}

func (a *App) currentVersionInfo(ctx context.Context, refresh bool) panelVersionInfo {
	info := panelVersionInfo{Version: a.version, Repo: a.releaseRepo, PanelName: "Docklight"}
	canUpdate, reason := a.selfUpdateCapability()
	info.SelfUpdatePossible = canUpdate
	info.SelfUpdateReason = reason
	latest, err := a.latestRelease(ctx, refresh)
	if err != nil {
		info.UpdateError = err.Error()
		return info
	}
	info.LatestRelease = latest
	if validReleaseTag(a.version) && compareReleaseTags(latest, a.version) > 0 {
		info.UpdateAvailable = true
	}
	return info
}

func (a *App) getVersionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.currentVersionInfo(r.Context(), false))
}

func (a *App) selfUpdateCapability() (bool, string) {
	if !validReleaseTag(a.version) {
		return false, "Self-update is available only in a vX.Y.Z release build."
	}
	if !releaseRepoPattern.MatchString(a.releaseRepo) {
		return false, "This build has no GitHub release repository configured."
	}
	if a.updateDir != installedUpdateState {
		return false, "Self-update requires the standard /var/lib/yggdrasil installation path."
	}
	helper, err := os.Lstat(updateHelperPath)
	if err != nil || !trustedRootFile(helper) || helper.Mode()&0111 == 0 {
		return false, "The yggdrasil-update helper is missing or not securely root-owned; reinstall with install.sh to add it."
	}
	if !trustedRootPath(updatePathUnit) {
		return false, "The yggdrasil-update systemd path unit is missing or not securely root-owned; reinstall with install.sh to add it."
	}
	if !trustedRootPath(updateServiceUnit) {
		return false, "The yggdrasil-update systemd service is missing or not securely root-owned; reinstall with install.sh to add it."
	}
	return true, ""
}

func trustedRootPath(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && trustedRootFile(info)
}

func trustedRootFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func (a *App) getPanelUpdateStatus(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(a.updateDir, updateStatusName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, panelUpdateStatus{State: "idle", Message: "No panel update has run on this installation yet."})
		return
	}
	if err != nil || len(data) > 16*1024 {
		writeError(w, http.StatusInternalServerError, "could not read panel update status")
		return
	}
	var status panelUpdateStatus
	if err = json.Unmarshal(data, &status); err != nil || (status.State != "running" && status.State != "done" && status.State != "error") {
		writeError(w, http.StatusInternalServerError, "panel update status file is invalid")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *App) requestPanelUpdateHandler(w http.ResponseWriter, r *http.Request) {
	info := a.currentVersionInfo(r.Context(), true)
	if info.UpdateError != "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": info.UpdateError, "version": info})
		return
	}
	if !info.SelfUpdatePossible {
		writeError(w, http.StatusConflict, info.SelfUpdateReason)
		return
	}
	if !info.UpdateAvailable {
		writeError(w, http.StatusConflict, "there is no newer stable release to install")
		return
	}
	if err := a.queuePanelUpdate(info.LatestRelease); err != nil {
		if errors.Is(err, errUpdateQueued) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusServiceUnavailable, err.Error())
		}
		return
	}
	a.audit(principal(r), "panel.update.queue", "panel", "binary", info.LatestRelease)
	writeJSON(w, http.StatusAccepted, panelUpdateStatus{State: "running", Tag: info.LatestRelease, Message: "The signed-in panel queued the update; systemd is downloading and verifying the official release."})
}

func (a *App) queuePanelUpdate(tag string) error {
	if !validReleaseTag(tag) {
		return errors.New("update tag must match vX.Y.Z")
	}
	canUpdate, reason := a.selfUpdateCapability()
	if !canUpdate {
		return errors.New(reason)
	}
	a.updateRequestMu.Lock()
	defer a.updateRequestMu.Unlock()
	requestPath := filepath.Join(a.updateDir, updateRequestName)
	if _, err := os.Lstat(requestPath); err == nil {
		return errUpdateQueued
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not inspect the pending update request")
	}
	if a.panelUpdateRecentlyStarted() {
		return errUpdateQueued
	}
	tmp, err := os.CreateTemp(a.updateDir, ".update-request-*")
	if err != nil {
		return errors.New("could not create the update request file")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.WriteString(tag + "\n"); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("could not write the update request file")
	}
	if err = os.Rename(tmpName, requestPath); err != nil {
		return errors.New("could not arm the systemd update request")
	}
	return nil
}

func (a *App) panelUpdateRecentlyStarted() bool {
	data, err := os.ReadFile(filepath.Join(a.updateDir, updateStatusName))
	if err != nil || len(data) > 16*1024 {
		return false
	}
	var status panelUpdateStatus
	if json.Unmarshal(data, &status) != nil || status.State != "running" {
		return false
	}
	started, err := time.Parse(time.RFC3339, status.At)
	if err != nil {
		return true
	}
	age := time.Since(started)
	return age >= 0 && age < 20*time.Minute
}

func (a *App) checkPanelUpdateNow(w http.ResponseWriter, r *http.Request) {
	info := a.currentVersionInfo(r.Context(), true)
	if info.UpdateError != "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": info.UpdateError, "version": info})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *App) getAutoUpdateSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.readAutoUpdateSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read automatic update settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *App) readAutoUpdateSettings(ctx context.Context) (autoUpdateSettings, error) {
	var enabled, hour int
	var settings autoUpdateSettings
	err := a.db.QueryRowContext(ctx, `SELECT auto_enabled,auto_hour,last_auto_day FROM panel_update_settings WHERE id=1`).Scan(&enabled, &hour, &settings.LastAutoDay)
	settings.Enabled, settings.Hour = enabled != 0, hour
	return settings, err
}

func (a *App) updateAutoUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
		Hour    *int  `json:"hour"`
	}
	if decodeJSON(w, r, &in, 1024) != nil {
		return
	}
	if in.Enabled == nil || in.Hour == nil || *in.Hour < 0 || *in.Hour > 23 {
		writeError(w, http.StatusBadRequest, "choose an auto-update hour from 0 to 23")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE panel_update_settings SET auto_enabled=?,auto_hour=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(*in.Enabled), *in.Hour); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save automatic update settings")
		return
	}
	a.audit(principal(r), "panel.auto_update.settings", "panel", "binary", fmt.Sprintf("enabled=%t hour=%d", *in.Enabled, *in.Hour))
	settings, err := a.readAutoUpdateSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settings were saved but could not be read back")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *App) StartPanelUpdateWorker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(updateCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.checkAutoUpdate(ctx)
			}
		}
	}()
}

func (a *App) checkAutoUpdate(ctx context.Context) {
	settings, err := a.readAutoUpdateSettings(ctx)
	if err != nil || !settings.Enabled || time.Now().Hour() < settings.Hour {
		return
	}
	today := time.Now().Format("2006-01-02")
	if settings.LastAutoDay == today {
		return
	}
	info := a.currentVersionInfo(ctx, false)
	if info.UpdateError != "" || !info.UpdateAvailable || !info.SelfUpdatePossible {
		return
	}
	if err = a.queuePanelUpdate(info.LatestRelease); err != nil {
		return
	}
	if _, err = a.db.ExecContext(ctx, `UPDATE panel_update_settings SET last_auto_day=?,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND last_auto_day<>?`, today, today); err == nil {
		a.audit(User{Username: "system"}, "panel.update.auto_queue", "panel", "binary", info.LatestRelease)
	}
}
