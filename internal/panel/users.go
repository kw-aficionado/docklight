package panel

import (
	"net/http"
	"strings"

	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query(`SELECT id,username,role,disabled,created_at,totp_enabled FROM users ORDER BY username`)
	if e != nil {
		writeError(w, 500, "could not list users")
		return
	}
	defer rows.Close()
	type item struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		Role        string `json:"role"`
		Disabled    bool   `json:"disabled"`
		CreatedAt   string `json:"created_at"`
		TOTPEnabled bool   `json:"totp_enabled"`
	}
	out := []item{}
	for rows.Next() {
		var x item
		var d, t int
		if rows.Scan(&x.ID, &x.Username, &x.Role, &d, &x.CreatedAt, &t) == nil {
			x.Disabled = d != 0
			x.TOTPEnabled = t != 0
			out = append(out, x)
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if !a.requireSession(w, r) {
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	var hash string
	if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, u.ID).Scan(&hash); err != nil || !security.VerifyPassword(hash, in.CurrentPassword) {
		writeError(w, 401, "current password is incorrect")
		return
	}
	newHash, err := security.HashPassword(in.NewPassword)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, err = a.db.Exec(`UPDATE users SET password_hash=?,token_version=token_version+1 WHERE id=?`, newHash, u.ID); err != nil {
		writeError(w, 500, "could not change the password")
		return
	}
	a.audit(u, "auth.password.change", "user", u.ID, "")
	http.SetCookie(w, &http.Cookie{Name: "ygg_token", Value: "", Path: "/", HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || len(in.Username) > 64 {
		writeError(w, 400, "username must contain 1 to 64 characters")
		return
	}
	if in.Role == "" {
		in.Role = "user"
	}
	if in.Role != "user" && in.Role != "admin" {
		writeError(w, 400, "role must be user or admin")
		return
	}
	hash, e := security.HashPassword(in.Password)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	id, e := newID()
	if e != nil {
		writeError(w, 500, "could not create user ID")
		return
	}
	if _, e = a.db.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)`, id, in.Username, hash, in.Role); e != nil {
		writeError(w, 409, "that username is already in use")
		return
	}
	a.audit(principal(r), "user.create", "user", id, "role="+in.Role)
	writeJSON(w, 201, map[string]string{"id": id, "username": in.Username, "role": in.Role})
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var old User
	var disabled int
	if e := a.db.QueryRow(`SELECT id,username,role,disabled,token_version,totp_enabled FROM users WHERE id=?`, id).Scan(&old.ID, &old.Username, &old.Role, &disabled, &old.TokenVersion, &old.TotpEnabled); e != nil {
		writeError(w, 404, "user not found")
		return
	}
	old.Disabled = disabled != 0
	var in struct {
		Username *string `json:"username"`
		Password string  `json:"password"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	role := old.Role
	if in.Role != nil {
		role = *in.Role
	}
	if role != "user" && role != "admin" {
		writeError(w, 400, "role must be user or admin")
		return
	}
	username := old.Username
	if in.Username != nil {
		username = strings.TrimSpace(*in.Username)
		if username == "" || len(username) > 64 {
			writeError(w, 400, "username must contain 1 to 64 characters")
			return
		}
	}
	dis := old.Disabled
	if in.Disabled != nil {
		dis = *in.Disabled
	}
	if old.ID == principal(r).ID && (dis || role != "admin") {
		writeError(w, 409, "you cannot disable or demote your own account")
		return
	}
	if (old.Role == "admin" && old.Disabled == false) && (role != "admin" || dis) {
		if a.enabledAdminCount() <= 1 {
			writeError(w, 409, "the last enabled administrator cannot be disabled or demoted")
			return
		}
	}
	query := `UPDATE users SET username=?,role=?,disabled=?,token_version=token_version+1`
	args := []any{username, role, boolInt(dis)}
	if in.Password != "" {
		hash, e := security.HashPassword(in.Password)
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		query += `,password_hash=?`
		args = append(args, hash)
	}
	query += ` WHERE id=?`
	args = append(args, id)
	if _, e := a.db.Exec(query, args...); e != nil {
		writeError(w, 409, "could not update the user; username may already be in use")
		return
	}
	a.audit(principal(r), "user.update", "user", id, "role="+role)
	writeJSON(w, 200, map[string]any{"id": id, "username": username, "role": role, "disabled": dis})
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == principal(r).ID {
		writeError(w, 409, "you cannot delete your own account")
		return
	}
	var role string
	var disabled int
	if e := a.db.QueryRow(`SELECT role,disabled FROM users WHERE id=?`, id).Scan(&role, &disabled); e != nil {
		writeError(w, 404, "user not found")
		return
	}
	if role == "admin" && disabled == 0 && a.enabledAdminCount() <= 1 {
		writeError(w, 409, "the last enabled administrator cannot be deleted")
		return
	}
	_, _ = a.db.Exec(`DELETE FROM permissions WHERE user_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM api_tokens WHERE user_id=?`, id)
	if _, e := a.db.Exec(`DELETE FROM users WHERE id=?`, id); e != nil {
		writeError(w, 500, "could not delete user")
		return
	}
	a.audit(principal(r), "user.delete", "user", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) setPermissions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists int
	if e := a.db.QueryRow(`SELECT count(*) FROM users WHERE id=?`, id).Scan(&exists); e != nil || exists == 0 {
		writeError(w, 404, "user not found")
		return
	}
	var in struct {
		Grants []struct {
			ScopeType   string   `json:"scope_type"`
			ScopeID     string   `json:"scope_id"`
			Permissions []string `json:"permissions"`
		} `json:"grants"`
	}
	if decodeJSON(w, r, &in, 1<<20) != nil {
		return
	}
	valid := map[string]bool{}
	for _, p := range permissionCatalog {
		valid[p] = true
	}
	tx, e := a.db.Begin()
	if e != nil {
		writeError(w, 500, "could not update permissions")
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`DELETE FROM permissions WHERE user_id=?`, id); e != nil {
		writeError(w, 500, "could not update permissions")
		return
	}
	seen := map[string]bool{}
	for _, g := range in.Grants {
		if g.ScopeType != "global" && g.ScopeType != "gameskill" && g.ScopeType != "server" {
			writeError(w, 400, "scope_type must be global, gameskill or server")
			return
		}
		if g.ScopeType == "global" && g.ScopeID != "" || g.ScopeType != "global" && g.ScopeID == "" {
			writeError(w, 400, "permission scope needs a matching scope_id")
			return
		}
		perms := []string{}
		for _, p := range g.Permissions {
			if !valid[p] {
				writeError(w, 400, "unknown permission: "+p)
				return
			}
			perms = append(perms, p)
		}
		if len(perms) == 0 {
			continue
		}
		key := g.ScopeType + ":" + g.ScopeID
		if seen[key] {
			writeError(w, 400, "duplicate permission scope: "+key)
			return
		}
		seen[key] = true
		if _, e = tx.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES(?,?,?,?)`, id, g.ScopeType, g.ScopeID, strings.Join(perms, ",")); e != nil {
			writeError(w, 500, "could not save permission grant")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		writeError(w, 500, "could not save permission grant")
		return
	}
	a.audit(principal(r), "user.permissions", "user", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) getPermissions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rows, err := a.db.Query(`SELECT scope_type,scope_id,perms FROM permissions WHERE user_id=? ORDER BY scope_type,scope_id`, id)
	if err != nil {
		writeError(w, 500, "could not read permissions")
		return
	}
	defer rows.Close()
	type grant struct {
		ScopeType   string   `json:"scope_type"`
		ScopeID     string   `json:"scope_id"`
		Permissions []string `json:"permissions"`
	}
	out := []grant{}
	for rows.Next() {
		var g grant
		var raw string
		if rows.Scan(&g.ScopeType, &g.ScopeID, &raw) == nil {
			g.Permissions = strings.Split(raw, ",")
			out = append(out, g)
		}
	}
	writeJSON(w, 200, map[string]any{"grants": out})
}
func (a *App) enabledAdminCount() int {
	var n int
	_ = a.db.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&n)
	return n
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
