package panel

import (
	"net/http"
	"sort"
	"strings"

	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) bool {
	if principal(r).IsAPIToken {
		writeError(w, 403, "sign in with your account to manage API tokens")
		return false
	}
	return true
}

func (a *App) listAPITokens(w http.ResponseWriter, r *http.Request) {
	if !a.requireSession(w, r) {
		return
	}
	u := principal(r)
	rows, err := a.db.Query(`SELECT id,name,scope,created_at,last_used_at FROM api_tokens WHERE user_id=? ORDER BY created_at DESC`, u.ID)
	if err != nil {
		writeError(w, 500, "could not list API tokens")
		return
	}
	defer rows.Close()
	type item struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		CreatedAt string   `json:"created_at"`
		LastUsed  string   `json:"last_used_at"`
	}
	out := []item{}
	for rows.Next() {
		var x item
		var scopes string
		if rows.Scan(&x.ID, &x.Name, &scopes, &x.CreatedAt, &x.LastUsed) == nil {
			x.Scopes = splitScopes(scopes)
			out = append(out, x)
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireSession(w, r) {
		return
	}
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 80 {
		writeError(w, 400, "token name must contain 1 to 80 characters")
		return
	}
	valid := map[string]bool{"admin": true}
	for _, scope := range permissionCatalog {
		valid[scope] = true
	}
	u := principal(r)
	seen := map[string]bool{}
	scopes := []string{}
	for _, scope := range in.Scopes {
		scope = strings.TrimSpace(scope)
		if !valid[scope] || scope == "admin" && u.Role != "admin" {
			writeError(w, 400, "one or more API token scopes are invalid for this account")
			return
		}
		if !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		writeError(w, 400, "select at least one API token scope")
		return
	}
	sort.Strings(scopes)
	token, err := security.NewAPIToken()
	if err != nil {
		writeError(w, 500, "could not generate an API token")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, 500, "could not create API token ID")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO api_tokens(id,user_id,name,token_hash,scope) VALUES(?,?,?,?,?)`, id, u.ID, in.Name, security.APIKeyHash(token), strings.Join(scopes, ",")); err != nil {
		writeError(w, 500, "could not save the API token")
		return
	}
	a.audit(u, "api_token.create", "api_token", id, "scopes="+strings.Join(scopes, ","))
	writeJSON(w, 201, map[string]any{"id": id, "name": in.Name, "scopes": scopes, "token": token})
}

func (a *App) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireSession(w, r) {
		return
	}
	u := principal(r)
	id := chi.URLParam(r, "id")
	result, err := a.db.Exec(`DELETE FROM api_tokens WHERE id=? AND user_id=?`, id, u.ID)
	if err != nil {
		writeError(w, 500, "could not revoke API token")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeError(w, 404, "API token not found")
		return
	}
	a.audit(u, "api_token.revoke", "api_token", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func splitScopes(raw string) []string {
	out := []string{}
	for _, scope := range strings.Split(raw, ",") {
		if scope = strings.TrimSpace(scope); scope != "" {
			out = append(out, scope)
		}
	}
	return out
}
