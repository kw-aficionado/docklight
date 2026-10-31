package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	yggdrasil "example.com/yggdrasil-panel"
)

const publicStatusCacheTTL = 15 * time.Second
const publicStatusPlayerFreshness = 15 * time.Minute

type statusPageServer struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Game         string `json:"game"`
	Status       string `json:"status"`
	StatusPublic bool   `json:"status_public"`
}

type statusPageSettings struct {
	Enabled bool               `json:"enabled"`
	Title   string             `json:"title"`
	Servers []statusPageServer `json:"servers"`
}

type publicStatusPlayers struct {
	Online int `json:"online"`
	Max    int `json:"max"`
}

type publicStatusServer struct {
	Name    string               `json:"name"`
	Game    string               `json:"game,omitempty"`
	Status  string               `json:"status"`
	Players *publicStatusPlayers `json:"players,omitempty"`
}

type publicStatusPayload struct {
	Title     string               `json:"title"`
	UpdatedAt string               `json:"updated_at"`
	Servers   []publicStatusServer `json:"servers"`
}

func (a *App) getStatusPageSettings(w http.ResponseWriter, r *http.Request) {
	var enabled int
	var title string
	if err := a.db.QueryRow(`SELECT enabled,title FROM status_page_settings WHERE id=1`).Scan(&enabled, &title); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read public status page settings")
		return
	}
	rows, err := a.db.Query(`SELECT s.id,s.name,COALESCE(g.name,''),s.status,s.status_public FROM servers s LEFT JOIN gameskills g ON g.id=s.gameskill_id ORDER BY s.name COLLATE NOCASE,s.id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list servers for the public status page")
		return
	}
	defer rows.Close()
	settings := statusPageSettings{Enabled: enabled != 0, Title: title, Servers: []statusPageServer{}}
	for rows.Next() {
		var item statusPageServer
		var statusPublic int
		if err = rows.Scan(&item.ID, &item.Name, &item.Game, &item.Status, &statusPublic); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server status-page settings")
			return
		}
		item.StatusPublic = statusPublic != 0
		settings.Servers = append(settings.Servers, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server status-page settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *App) updateStatusPageSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled   *bool     `json:"enabled"`
		Title     string    `json:"title"`
		ServerIDs *[]string `json:"server_ids"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "choose whether the public status page is enabled")
		return
	}
	if in.ServerIDs == nil {
		writeError(w, http.StatusBadRequest, "provide the complete server_ids selection; use an empty list to select none")
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" || len(in.Title) > 80 {
		writeError(w, http.StatusBadRequest, "status page title must contain 1 to 80 characters")
		return
	}
	if len(*in.ServerIDs) > 1000 {
		writeError(w, http.StatusBadRequest, "select no more than 1000 public servers")
		return
	}
	ids := make([]string, 0, len(*in.ServerIDs))
	seen := make(map[string]bool, len(*in.ServerIDs))
	for _, id := range *in.ServerIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			writeError(w, http.StatusBadRequest, "public server IDs cannot be empty")
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update public status page settings")
		return
	}
	rollback := func(status int, message string) {
		_ = tx.Rollback()
		writeError(w, status, message)
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE servers SET status_public=0`); err != nil {
		rollback(http.StatusInternalServerError, "could not update public server selection")
		return
	}
	for _, id := range ids {
		var exists int
		if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM servers WHERE id=?`, id).Scan(&exists); err != nil {
			rollback(http.StatusInternalServerError, "could not validate the selected servers")
			return
		}
		if exists != 1 {
			rollback(http.StatusBadRequest, "one or more selected servers no longer exist; refresh and try again")
			return
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE servers SET status_public=1 WHERE id=?`, id); err != nil {
			rollback(http.StatusInternalServerError, "could not update public server selection")
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO status_page_settings(id,enabled,title,updated_at) VALUES(1,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,title=excluded.title,updated_at=CURRENT_TIMESTAMP`, boolInt(*in.Enabled), in.Title); err != nil {
		rollback(http.StatusInternalServerError, "could not save public status page settings")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save public status page settings")
		return
	}
	a.invalidatePublicStatusCache()
	a.audit(principal(r), "status_page.update", "status_page", "1", fmt.Sprintf("enabled=%t public_servers=%d", *in.Enabled, len(ids)))
	a.getStatusPageSettings(w, r)
}

func (a *App) publicStatusPage(w http.ResponseWriter, r *http.Request) {
	if !a.publicStatusEnabled() {
		http.NotFound(w, r)
		return
	}
	a.servePublicStatusAsset(w, r, "web/status.html", "text/html; charset=utf-8")
}

func (a *App) publicStatusScript(w http.ResponseWriter, r *http.Request) {
	if !a.publicStatusEnabled() {
		http.NotFound(w, r)
		return
	}
	a.servePublicStatusAsset(w, r, "web/status.js", "text/javascript; charset=utf-8")
}

func (a *App) servePublicStatusAsset(w http.ResponseWriter, r *http.Request, path, contentType string) {
	content, err := yggdrasil.WebFS.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *App) publicStatusJSON(w http.ResponseWriter, r *http.Request) {
	content, err := a.cachedPublicStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build the public status page")
		return
	}
	if content == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=15")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *App) publicStatusEnabled() bool {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	var enabled int
	if err := a.db.QueryRow(`SELECT enabled FROM status_page_settings WHERE id=1`).Scan(&enabled); err != nil {
		return false
	}
	return enabled != 0
}

func (a *App) cachedPublicStatus() ([]byte, error) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	now := time.Now()
	var enabled int
	var title string
	if err := a.db.QueryRow(`SELECT enabled,title FROM status_page_settings WHERE id=1`).Scan(&enabled, &title); err != nil {
		return nil, err
	}
	if enabled == 0 {
		a.statusCache = nil
		a.statusCacheUntil = time.Time{}
		return nil, nil
	}
	if len(a.statusCache) != 0 && now.Before(a.statusCacheUntil) {
		return append([]byte(nil), a.statusCache...), nil
	}
	rows, err := a.db.Query(`SELECT s.name,COALESCE(g.name,''),s.status,s.installed,p.online,p.max_players FROM servers s LEFT JOIN gameskills g ON g.id=s.gameskill_id LEFT JOIN server_query_samples p ON p.server_id=s.id AND p.sampled_at>? AND p.sampled_at<=? WHERE s.status_public=1 ORDER BY s.name COLLATE NOCASE,s.id`, now.Add(-publicStatusPlayerFreshness).Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	payload := publicStatusPayload{Title: title, UpdatedAt: now.UTC().Format(time.RFC3339), Servers: []publicStatusServer{}}
	for rows.Next() {
		var item publicStatusServer
		var state string
		var installed int
		var online, maxPlayers sql.NullInt64
		if err = rows.Scan(&item.Name, &item.Game, &state, &installed, &online, &maxPlayers); err != nil {
			_ = rows.Close()
			return nil, err
		}
		item.Status = publicServerStatus(state, installed != 0)
		if online.Valid && maxPlayers.Valid && online.Int64 >= 0 && maxPlayers.Int64 >= 0 {
			item.Players = &publicStatusPlayers{Online: int(online.Int64), Max: int(maxPlayers.Int64)}
		}
		payload.Servers = append(payload.Servers, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	a.statusCache = append(a.statusCache[:0], content...)
	a.statusCacheUntil = now.Add(publicStatusCacheTTL)
	return append([]byte(nil), content...), nil
}

func publicServerStatus(status string, installed bool) string {
	if !installed {
		return "offline"
	}
	switch status {
	case "running":
		return "online"
	case "starting", "installing", "updating":
		return "starting"
	default:
		return "offline"
	}
}

func (a *App) recordPlayerSample(serverID string, online, maxPlayers int) error {
	if online < 0 || maxPlayers < 0 {
		return errors.New("player query returned a negative count")
	}
	if _, err := a.db.Exec(`INSERT INTO server_query_samples(server_id,online,max_players,sampled_at) VALUES(?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET online=excluded.online,max_players=excluded.max_players,sampled_at=excluded.sampled_at`, serverID, online, maxPlayers, time.Now().Unix()); err != nil {
		return err
	}
	a.invalidatePublicStatusCache()
	return nil
}

func (a *App) invalidatePublicStatusCache() {
	a.statusMu.Lock()
	a.statusCache = nil
	a.statusCacheUntil = time.Time{}
	a.statusMu.Unlock()
}
