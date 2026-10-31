package panel

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

type Realm struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
	Collapsed   bool   `json:"collapsed"`
	ServerCount int    `json:"server_count"`
	CanCreate   bool   `json:"can_create"`
}

func (a *App) listRealms(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	rows, err := a.db.Query(`SELECT r.id,r.name,r.description,r.sort_order,COALESCE(us.collapsed,0)
		FROM realms r LEFT JOIN realm_user_state us ON us.realm_id=r.id AND us.user_id=?
		ORDER BY r.sort_order,r.name COLLATE NOCASE,r.id`, u.ID)
	if err != nil {
		writeError(w, 500, "could not list realms")
		return
	}
	all := []Realm{}
	for rows.Next() {
		var realm Realm
		var collapsed int
		if rows.Scan(&realm.ID, &realm.Name, &realm.Description, &realm.SortOrder, &collapsed) == nil {
			realm.Collapsed = collapsed != 0
			all = append(all, realm)
		}
	}
	_ = rows.Close()

	serverRows, err := a.db.Query(`SELECT id,gameskill_id,realm_id FROM servers`)
	if err != nil {
		writeError(w, 500, "could not read realm servers")
		return
	}
	type serverScope struct{ id, runeID, realmID string }
	servers := []serverScope{}
	for serverRows.Next() {
		var server serverScope
		if serverRows.Scan(&server.id, &server.runeID, &server.realmID) == nil {
			servers = append(servers, server)
		}
	}
	_ = serverRows.Close()
	counts := map[string]int{}
	for _, server := range servers {
		if a.allowedServer(u, "server.view", server.id, server.runeID, server.realmID) {
			counts[server.realmID]++
		}
	}

	out := make([]Realm, 0, len(all))
	for _, realm := range all {
		realm.ServerCount = counts[realm.ID]
		realm.CanCreate = a.canCreateInAnyRealm(u, realm.ID)
		if realm.ServerCount == 0 && !realm.CanCreate {
			continue
		}
		out = append(out, realm)
	}
	writeJSON(w, 200, out)
}

func (a *App) canCreateInAnyRealm(u User, realmID string) bool {
	if u.IsAPIToken && !u.APIScopes["server.create"] {
		return false
	}
	if u.Role == "admin" || a.grant(u.ID, "server.create", "global", "") || a.grant(u.ID, "server.create", "realm", realmID) {
		return true
	}
	rows, err := a.db.Query(`SELECT id FROM gameskills`)
	if err != nil {
		return false
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if a.grant(u.ID, "server.create", "gameskill", id) {
			return true
		}
	}
	return false
}

func (a *App) updateRealmCollapsed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var in struct {
		Collapsed bool `json:"collapsed"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	u := principal(r)
	result, err := a.db.Exec(`INSERT INTO realm_user_state(user_id,realm_id,collapsed) SELECT ?,id,? FROM realms WHERE id=?
		ON CONFLICT(user_id,realm_id) DO UPDATE SET collapsed=excluded.collapsed`, u.ID, boolInt(in.Collapsed), id)
	if err != nil {
		writeError(w, 500, "could not save realm preference")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		writeError(w, 404, "realm not found")
		return
	}
	writeJSON(w, 200, map[string]bool{"collapsed": in.Collapsed})
}

func validRealmInput(name, description string) (string, string, bool) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	return name, description, name != "" && utf8.RuneCountInString(name) <= 80 && utf8.RuneCountInString(description) <= 500
}

func (a *App) createRealm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	name, description, ok := validRealmInput(in.Name, in.Description)
	if !ok {
		writeError(w, 400, "realm name must contain 1 to 80 characters and description at most 500")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, 500, "could not create realm ID")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO realms(id,name,description,sort_order) VALUES(?,?,?,(SELECT COALESCE(MAX(sort_order)+1,0) FROM realms))`, id, name, description); err != nil {
		writeError(w, 409, "a realm with that name already exists")
		return
	}
	a.audit(principal(r), "realm.create", "realm", id, "name="+name)
	writeJSON(w, 201, Realm{ID: id, Name: name, Description: description})
}

func (a *App) updateRealm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	name, description, ok := validRealmInput(in.Name, in.Description)
	if !ok {
		writeError(w, 400, "realm name must contain 1 to 80 characters and description at most 500")
		return
	}
	result, err := a.db.Exec(`UPDATE realms SET name=?,description=? WHERE id=?`, name, description, id)
	if err != nil {
		writeError(w, 409, "a realm with that name already exists")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		writeError(w, 404, "realm not found")
		return
	}
	a.audit(principal(r), "realm.update", "realm", id, "name="+name)
	writeJSON(w, 200, Realm{ID: id, Name: name, Description: description})
}

func (a *App) deleteRealm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tx, err := a.db.Begin()
	if err != nil {
		writeError(w, 500, "could not delete realm")
		return
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT count(*) FROM realms WHERE id=?`, id).Scan(&exists); err != nil || exists == 0 {
		writeError(w, 404, "realm not found")
		return
	}
	var scheduleCount int
	if err = tx.QueryRow(`SELECT count(*) FROM backup_schedules WHERE scope_type='realm' AND scope_id=?`, id).Scan(&scheduleCount); err != nil {
		writeError(w, 500, "could not read realm schedules")
		return
	}
	if _, err = tx.Exec(`DELETE FROM backup_schedule_runs WHERE schedule_id IN (SELECT id FROM backup_schedules WHERE scope_type='realm' AND scope_id=?)`, id); err != nil {
		writeError(w, 500, "could not remove realm schedule history")
		return
	}
	deletedSchedules, deleteErr := tx.Exec(`DELETE FROM backup_schedules WHERE scope_type='realm' AND scope_id=? AND last_status<>'running'`, id)
	if deleteErr != nil {
		writeError(w, 500, "could not remove realm schedules")
		return
	}
	deletedScheduleCount, _ := deletedSchedules.RowsAffected()
	if int(deletedScheduleCount) != scheduleCount {
		writeError(w, http.StatusConflict, "wait for running realm schedules to finish before deleting this realm")
		return
	}
	if _, err = tx.Exec(`UPDATE servers SET realm_id='' WHERE realm_id=?`, id); err != nil {
		writeError(w, 500, "could not detach realm servers")
		return
	}
	if _, err = tx.Exec(`DELETE FROM permissions WHERE scope_type='realm' AND scope_id=?`, id); err != nil {
		writeError(w, 500, "could not clear realm permissions")
		return
	}
	if _, err = tx.Exec(`DELETE FROM realms WHERE id=?`, id); err != nil {
		writeError(w, 500, "could not delete realm")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "could not delete realm")
		return
	}
	a.audit(principal(r), "realm.delete", "realm", id, fmt.Sprintf("servers detached; schedules removed=%d", scheduleCount))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) reorderRealms(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	rows, err := a.db.Query(`SELECT id FROM realms`)
	if err != nil {
		writeError(w, 500, "could not read realms")
		return
	}
	current := map[string]bool{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			current[id] = true
		}
	}
	_ = rows.Close()
	if len(in.IDs) != len(current) {
		writeError(w, 400, "reorder must include every realm exactly once")
		return
	}
	seen := map[string]bool{}
	for _, id := range in.IDs {
		if !current[id] || seen[id] {
			writeError(w, 400, "reorder must include every realm exactly once")
			return
		}
		seen[id] = true
	}
	tx, err := a.db.Begin()
	if err != nil {
		writeError(w, 500, "could not reorder realms")
		return
	}
	defer tx.Rollback()
	for i, id := range in.IDs {
		if _, err = tx.Exec(`UPDATE realms SET sort_order=? WHERE id=?`, i, id); err != nil {
			writeError(w, 500, "could not reorder realms")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "could not reorder realms")
		return
	}
	a.audit(principal(r), "realm.reorder", "realm", "", "count="+strconv.Itoa(len(in.IDs)))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) moveServerRealm(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var in struct {
		RealmID string `json:"realm_id"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	var name string
	if err := a.db.QueryRow(`SELECT name FROM servers WHERE id=?`, serverID).Scan(&name); err != nil {
		writeError(w, 404, "server not found")
		return
	}
	if in.RealmID != "" {
		var exists int
		if err := a.db.QueryRow(`SELECT count(*) FROM realms WHERE id=?`, in.RealmID).Scan(&exists); err != nil || exists == 0 {
			writeError(w, 404, "realm not found")
			return
		}
	}
	if _, err := a.db.Exec(`UPDATE servers SET realm_id=? WHERE id=?`, in.RealmID, serverID); err != nil {
		writeError(w, 500, "could not move server")
		return
	}
	a.audit(principal(r), "server.realm.move", "server", serverID, "realm="+in.RealmID)
	writeJSON(w, 200, map[string]any{"id": serverID, "name": name, "realm_id": in.RealmID})
}

func (a *App) ensureCategoryRealm(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		name = "Default"
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	if _, err = a.db.Exec(`INSERT INTO realms(id,name,sort_order) VALUES(?,?,(SELECT COALESCE(MAX(sort_order)+1,0) FROM realms)) ON CONFLICT(name) DO NOTHING`, id, name); err != nil {
		return "", err
	}
	err = a.db.QueryRow(`SELECT id FROM realms WHERE name=? COLLATE NOCASE`, name).Scan(&id)
	return id, err
}

func (a *App) realmExists(id string) bool {
	var n int
	return a.db.QueryRow(`SELECT count(*) FROM realms WHERE id=?`, id).Scan(&n) == nil && n == 1
}
