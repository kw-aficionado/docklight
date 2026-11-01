package panel

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

type assistantLogWatcher struct {
	ID           string         `json:"id"`
	ServerID     string         `json:"server_id"`
	ServerName   string         `json:"server_name,omitempty"`
	Name         string         `json:"name"`
	Pattern      string         `json:"pattern"`
	Threshold    int            `json:"threshold"`
	WindowSecs   int            `json:"window_secs"`
	Action       string         `json:"action"`
	Enabled      bool           `json:"enabled"`
	LastFired    string         `json:"last_fired,omitempty"`
	Source       string         `json:"source"`
	CreatedAt    string         `json:"created_at,omitempty"`
	UpdatedAt    string         `json:"updated_at,omitempty"`
	AdvisoryHost string         `json:"-"`
	compiled     *regexp.Regexp `json:"-"`
}

type assistantLogWatcherInput struct {
	ServerID            string `json:"server_id"`
	Name                string `json:"name"`
	Pattern             string `json:"pattern"`
	Threshold           int    `json:"threshold"`
	WindowSecs          int    `json:"window_secs"`
	Action              string `json:"action"`
	Enabled             *bool  `json:"enabled"`
	ConfirmExternalLogs bool   `json:"confirm_external_logs"`
	ConfirmExternalHost string `json:"confirm_external_host"`
	advisoryHost        string
}

func (a *App) listAssistantLogWatchers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT w.id,w.server_id,COALESCE(s.name,''),w.name,w.pattern,w.threshold,w.window_secs,w.action,w.enabled,w.last_fired,w.source,w.created_at,w.updated_at FROM log_watchers w LEFT JOIN servers s ON s.id=w.server_id ORDER BY CASE WHEN w.server_id='' THEN 0 ELSE 1 END,COALESCE(s.name,''),w.name COLLATE NOCASE,w.id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read log watchers")
		return
	}
	defer rows.Close()
	watchers := make([]assistantLogWatcher, 0)
	for rows.Next() {
		var watcher assistantLogWatcher
		var enabled int
		if err = rows.Scan(&watcher.ID, &watcher.ServerID, &watcher.ServerName, &watcher.Name, &watcher.Pattern, &watcher.Threshold, &watcher.WindowSecs, &watcher.Action, &enabled, &watcher.LastFired, &watcher.Source, &watcher.CreatedAt, &watcher.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read log watchers")
			return
		}
		watcher.Enabled = enabled != 0
		watchers = append(watchers, watcher)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read log watchers")
		return
	}
	writeJSON(w, http.StatusOK, watchers)
}

func (a *App) createAssistantLogWatcher(w http.ResponseWriter, r *http.Request) {
	var input assistantLogWatcherInput
	if decodeJSON(w, r, &input, 8<<10) != nil {
		return
	}
	if input.Enabled == nil {
		input.Enabled = new(bool)
		*input.Enabled = true
	}
	serverID, name, pattern, compiled, err := a.validateAssistantLogWatcher(&input)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "server not found" {
			status = http.StatusNotFound
		} else if strings.HasPrefix(err.Error(), "enable and configure Advisory") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	advisoryHost := input.advisoryHost
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create watcher ID")
		return
	}
	_, err = a.db.Exec(`INSERT INTO log_watchers(id,server_id,name,pattern,threshold,window_secs,action,enabled,source,advisory_host) VALUES(?,?,?,?,?,?,?,?, 'user',?)`, id, serverID, name, pattern, input.Threshold, input.WindowSecs, input.Action, boolInt(*input.Enabled), advisoryHost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save log watcher")
		return
	}
	detail := assistantWatcherAuditDetail(serverID, input.Action)
	if advisoryHost != "" {
		detail += " external_host=" + advisoryHost
	}
	a.audit(principal(r), "watcher.create", "watcher", id, detail)
	watcher := assistantLogWatcher{ID: id, ServerID: serverID, Name: name, Pattern: pattern, Threshold: input.Threshold, WindowSecs: input.WindowSecs, Action: input.Action, Enabled: *input.Enabled, Source: "user", compiled: compiled}
	if serverID != "" {
		if server, getErr := a.getServer(serverID); getErr == nil {
			watcher.ServerName = server.Name
		}
	}
	writeJSON(w, http.StatusCreated, watcher)
}

func (a *App) updateAssistantLogWatcher(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var source, currentServerID string
	if err := a.db.QueryRow(`SELECT source,server_id FROM log_watchers WHERE id=?`, id).Scan(&source, &currentServerID); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "log watcher not found")
		} else {
			writeError(w, http.StatusInternalServerError, "could not read log watcher")
		}
		return
	}
	var input assistantLogWatcherInput
	if decodeJSON(w, r, &input, 8<<10) != nil {
		return
	}
	if input.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	serverID, name, pattern, compiled, err := a.validateAssistantLogWatcher(&input)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "server not found" {
			status = http.StatusNotFound
		} else if strings.HasPrefix(err.Error(), "enable and configure Advisory") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	advisoryHost := input.advisoryHost
	if source == "rune" && serverID != currentServerID {
		writeError(w, http.StatusConflict, "template-seeded watchers stay scoped to their server")
		return
	}
	_, err = a.db.Exec(`UPDATE log_watchers SET server_id=?,name=?,pattern=?,threshold=?,window_secs=?,action=?,enabled=?,advisory_host=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, serverID, name, pattern, input.Threshold, input.WindowSecs, input.Action, boolInt(*input.Enabled), advisoryHost, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update log watcher")
		return
	}
	detail := assistantWatcherAuditDetail(serverID, input.Action)
	if advisoryHost != "" {
		detail += " external_host=" + advisoryHost
	}
	a.audit(principal(r), "watcher.update", "watcher", id, detail)
	watcher := assistantLogWatcher{ID: id, ServerID: serverID, Name: name, Pattern: pattern, Threshold: input.Threshold, WindowSecs: input.WindowSecs, Action: input.Action, Enabled: *input.Enabled, Source: source, compiled: compiled}
	if serverID != "" {
		if server, getErr := a.getServer(serverID); getErr == nil {
			watcher.ServerName = server.Name
		}
	}
	writeJSON(w, http.StatusOK, watcher)
}

func (a *App) deleteAssistantLogWatcher(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, err := a.db.Exec(`DELETE FROM log_watchers WHERE id=?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not remove log watcher")
		return
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not remove log watcher")
		return
	}
	if deleted == 0 {
		writeError(w, http.StatusNotFound, "log watcher not found")
		return
	}
	a.audit(principal(r), "watcher.delete", "watcher", id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (a *App) validateAssistantLogWatcher(input *assistantLogWatcherInput) (string, string, string, *regexp.Regexp, error) {
	serverID := strings.TrimSpace(input.ServerID)
	if serverID != "" {
		if _, err := a.getServer(serverID); err != nil {
			return "", "", "", nil, fmt.Errorf("server not found")
		}
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", "", "", nil, fmt.Errorf("name must contain 1 to 80 printable characters")
	}
	pattern := strings.TrimSpace(input.Pattern)
	if pattern == "" || len(pattern) > 512 || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
		return "", "", "", nil, fmt.Errorf("pattern must contain 1 to 512 printable characters")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("pattern is not a valid Go regular expression: %w", err)
	}
	if input.Threshold < 1 || input.Threshold > 1000 {
		return "", "", "", nil, fmt.Errorf("threshold must be from 1 to 1000")
	}
	if input.WindowSecs < 1 || input.WindowSecs > 3600 {
		return "", "", "", nil, fmt.Errorf("window_secs must be from 1 to 3600")
	}
	if input.Action != "notify" && input.Action != "advisory" {
		return "", "", "", nil, fmt.Errorf("action must be notify or advisory")
	}
	if input.Enabled == nil {
		return "", "", "", nil, fmt.Errorf("enabled must be true or false")
	}
	if input.Action == "advisory" && *input.Enabled {
		runtime, runtimeErr := a.assistantRuntime()
		if runtimeErr != nil || !runtime.enabled {
			return "", "", "", nil, fmt.Errorf("enable and configure Advisory before saving an Advisory watcher")
		}
		host, local := assistantWatcherProviderHost(runtime.baseURL)
		if !assistantExternalLogConsent(runtime, input.ConfirmExternalLogs, input.ConfirmExternalHost) {
			return "", "", "", nil, fmt.Errorf("confirm sending a redacted matching log line to the configured provider host")
		}
		if !local {
			input.advisoryHost = host
		}
	}
	return serverID, name, pattern, compiled, nil
}

func assistantWatcherProviderHost(baseURL string) (string, bool) {
	providerURL, err := url.Parse(baseURL)
	if err != nil || providerURL.Hostname() == "" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(providerURL.Hostname(), "."))
	return host, assistantPrivateHTTPHost(host)
}

func assistantWatcherAuditDetail(serverID, action string) string {
	scope := "all"
	if serverID != "" {
		scope = serverID
	}
	return "scope=" + scope + " action=" + action
}

func (a *App) seedRuneWatchers(serverID string, gs rune.Rune) error {
	for _, watcher := range gs.Watchers {
		threshold := watcher.Threshold
		if threshold == 0 {
			threshold = 1
		}
		window := watcher.WindowSecs
		if window == 0 {
			window = 60
		}
		action := watcher.Action
		if action == "" {
			action = "notify"
		} else if action == "kvasir" {
			action = "advisory"
		}
		id, err := newID()
		if err != nil {
			return err
		}
		seedKey := gs.ID + ":" + strings.ToLower(strings.TrimSpace(watcher.Name))
		if _, err = a.db.Exec(`INSERT OR IGNORE INTO log_watchers(id,server_id,name,pattern,threshold,window_secs,action,source,source_key) VALUES(?,?,?,?,?,?,?,'rune',?)`, id, serverID, strings.TrimSpace(watcher.Name), strings.TrimSpace(watcher.Pattern), threshold, window, action, seedKey); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) claimAssistantWatcherFire(id string, now time.Time) bool {
	const cooldown = 10 * time.Minute
	result, err := a.db.Exec(`UPDATE log_watchers SET last_fired=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1 AND (last_fired='' OR last_fired<=?)`, assistantWatcherTimestamp(now), id, assistantWatcherTimestamp(now.Add(-cooldown)))
	if err != nil {
		return false
	}
	rows, err := result.RowsAffected()
	return err == nil && rows == 1
}

func assistantWatcherTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
