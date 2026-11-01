package panel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const (
	mcpScope             = "yggdrasil"
	mcpProtocolVersion   = "2025-03-26"
	mcpAccessTokenTTL    = 30 * 24 * time.Hour
	mcpRefreshTokenTTL   = 90 * 24 * time.Hour
	mcpAuthorizationTTL  = 5 * time.Minute
	mcpConsentNonceTTL   = 15 * time.Minute
	mcpRegistrationLimit = 10
)

var (
	mcpPKCEChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	mcpPKCEVerifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	mcpClientSchemePattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{0,31}$`)
)

func (a *App) mcpIssuer(r *http.Request) (string, error) {
	base := strings.TrimSpace(a.cfg.Server.PublicURL)
	if base == "" {
		if strings.ContainsAny(r.Host, "\r\n\t /\\@") || strings.TrimSpace(r.Host) == "" {
			return "", errors.New("invalid panel host")
		}
		base = requestScheme(r) + "://" + r.Host
	}
	u, err := url.Parse(base)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("configure server.public_url as a panel origin before using MCP OAuth")
	}
	if !strings.EqualFold(u.Scheme, "https") && !(strings.EqualFold(u.Scheme, "http") && mcpLoopbackHost(u.Hostname())) {
		return "", errors.New("MCP OAuth requires an HTTPS panel URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = ""
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func (a *App) mcpRequireSecureRequest(r *http.Request) error {
	issuer, err := a.mcpIssuer(r)
	if err != nil {
		return err
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return errors.New("invalid Docklight MCP issuer")
	}
	if !mcpLoopbackHost(u.Hostname()) && requestScheme(r) != "https" {
		return errors.New("MCP OAuth and connector tokens require HTTPS transport")
	}
	return nil
}

func (a *App) mcpResourceURL(r *http.Request) (string, error) {
	issuer, err := a.mcpIssuer(r)
	if err != nil {
		return "", err
	}
	return issuer + "/api/mcp", nil
}

func mcpLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func mcpPublicURL(issuer string) (bool, string) {
	u, err := url.Parse(issuer)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false, "Use a publicly reachable HTTPS URL for MCP connectors."
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if mcpLikelyPrivateHost(host) {
		return false, "This address appears to be local, private, or VPN-only and may not be reachable by hosted MCP clients."
	}
	return true, ""
}

func mcpLikelyPrivateHost(host string) bool {
	if assistantPrivateHTTPHost(host) || strings.HasSuffix(host, ".lab") || strings.HasSuffix(host, ".vpn") || strings.HasSuffix(host, ".ts.net") || strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".example") || strings.HasSuffix(host, ".invalid") || strings.HasSuffix(host, ".onion") || strings.Contains(host, ".vpn.") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, raw := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, subnet, _ := net.ParseCIDR(raw)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *App) mcpAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer, err := a.mcpIssuer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/oauth/authorize",
		"token_endpoint":                                 issuer + "/oauth/token",
		"registration_endpoint":                          issuer + "/oauth/register",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{mcpScope},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (a *App) mcpProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	issuer, err := a.mcpIssuer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 issuer + "/api/mcp",
		"authorization_servers":    []string{issuer},
		"scopes_supported":         []string{mcpScope},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   "https://docklight.app",
	})
}

type mcpRegisterInput struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ResponseTypes           []string `json:"response_types"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (a *App) mcpRegisterClient(w http.ResponseWriter, r *http.Request) {
	a.pruneMCPOAuth(r.Context())
	if err := a.mcpRequireSecureRequest(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !a.mcpRegistrationAllowed(clientIP(r), time.Now()) {
		writeError(w, http.StatusTooManyRequests, "client registration rate limit exceeded")
		return
	}
	var input mcpRegisterInput
	if decodeJSON(w, r, &input, 16<<10) != nil {
		return
	}
	input.ClientName = cleanModerationText(strings.TrimSpace(input.ClientName), 128)
	if input.ClientName == "" || !utf8.ValidString(input.ClientName) || len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 16 {
		writeError(w, http.StatusBadRequest, "client_name and between one and sixteen redirect_uris are required")
		return
	}
	if len(input.ResponseTypes) > 0 && !equalStringSet(input.ResponseTypes, []string{"code"}) {
		writeError(w, http.StatusBadRequest, "only the authorization code response type is supported")
		return
	}
	if len(input.GrantTypes) > 0 && !equalStringSet(input.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		writeError(w, http.StatusBadRequest, "only authorization_code and refresh_token grants are supported")
		return
	}
	if input.TokenEndpointAuthMethod != "" && input.TokenEndpointAuthMethod != "none" {
		writeError(w, http.StatusBadRequest, "Docklight supports public clients without a client secret")
		return
	}
	redirects := make([]string, 0, len(input.RedirectURIs))
	seen := make(map[string]bool, len(input.RedirectURIs))
	for _, redirect := range input.RedirectURIs {
		redirect = strings.TrimSpace(redirect)
		if len(redirect) > 2048 || !validMCPRedirectURI(redirect) || seen[redirect] {
			writeError(w, http.StatusBadRequest, "redirect_uris must be unique valid HTTPS, loopback HTTP, or app callback URLs")
			return
		}
		seen[redirect] = true
		redirects = append(redirects, redirect)
	}
	redirectJSON, err := json.Marshal(redirects)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode registered redirect URLs")
		return
	}
	var existing int
	if err = a.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM mcp_clients").Scan(&existing); err != nil || existing >= 5000 {
		writeError(w, http.StatusServiceUnavailable, "client registration is temporarily unavailable")
		return
	}
	clientID, err := mcpOpaqueToken("docklight_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a client identifier")
		return
	}
	if _, err = a.db.ExecContext(r.Context(), "INSERT INTO mcp_clients(client_id,name,redirect_uris_json) VALUES(?,?,?)", clientID, input.ClientName, string(redirectJSON)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not register MCP client")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": clientID, "client_name": input.ClientName, "redirect_uris": redirects,
		"response_types": []string{"code"}, "grant_types": []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_method": "none", "client_id_issued_at": time.Now().Unix(),
	})
}

func (a *App) mcpRegistrationAllowed(ip string, now time.Time) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	if len(a.oauthRegisterIPs) > 4096 {
		cutoff := now.Add(-time.Minute)
		for key, timestamps := range a.oauthRegisterIPs {
			if len(recent(timestamps, cutoff)) == 0 {
				delete(a.oauthRegisterIPs, key)
			}
		}
	}
	entries := recent(a.oauthRegisterIPs[ip], now.Add(-time.Minute))
	if len(entries) >= mcpRegistrationLimit {
		a.oauthRegisterIPs[ip] = entries
		return false
	}
	a.oauthRegisterIPs[ip] = append(entries, now)
	return true
}

func validMCPRedirectURI(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" {
		return u.Hostname() != "" && u.Opaque == ""
	}
	if scheme == "http" {
		return u.Hostname() != "" && mcpLoopbackHost(u.Hostname()) && u.Opaque == ""
	}
	if containsString([]string{"data", "file", "ftp", "javascript", "mailto", "vbscript"}, scheme) || u.Opaque != "" {
		return false
	}
	return mcpClientSchemePattern.MatchString(scheme) && (u.Hostname() != "" || u.Path != "")
}

func equalStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	a, b := append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type mcpConsentView struct {
	ClientName   string
	RedirectHost string
	ResourceHost string
	Nonce        string
}

var mcpConsentTemplate = template.Must(template.New("mcp-consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Connect {{.ClientName}} · Docklight</title><link rel="icon" href="/brand.svg"><link rel="stylesheet" href="/style.css"><style>.oauth-wrap{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at 25% 15%,#17322d 0,transparent 34%),var(--bg)}.oauth-card{width:min(100%,520px);padding:28px;background:var(--panel);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}.oauth-card .brand-lockup{margin-bottom:32px}.oauth-card h1{font-size:25px;letter-spacing:-.5px;margin:0 0 8px}.oauth-card p{color:var(--muted);font-size:12px;line-height:1.6}.oauth-client{margin:20px 0;padding:14px;border:1px solid var(--border-soft);border-radius:8px;background:var(--panel-2)}.oauth-client b{display:block;margin-bottom:4px}.oauth-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:22px}.oauth-note{font-size:10px!important}.oauth-host{font-family:ui-monospace,monospace;overflow-wrap:anywhere}</style></head><body><main class="oauth-wrap"><section class="oauth-card"><div class="brand-lockup"><img class="brand-logo" src="/brand.svg" alt=""><span>Docklight</span></div><div class="eyebrow">MCP CONNECTOR ACCESS</div><h1>Connect {{.ClientName}}?</h1><p>This client will act as your Docklight account and follow your current server permissions. You can revoke this connection later in Account → MCP connections.</p><div class="oauth-client"><b>Requested access</b><p>List and inspect servers you can view, read their recent logs, and start, stop, or restart servers you can control.</p><p>Docklight does not provide file, settings, create, or delete tools.</p><p class="oauth-host">Connector: {{.ResourceHost}}</p><p class="oauth-host">Callback: {{.RedirectHost}}</p></div><p class="oauth-note">Recent logs may contain player chat, IP addresses, and other private server text. Stop and restart can disconnect players. Sign in to Docklight in another tab if needed, then return here and choose Allow.</p><form method="post" action="/oauth/authorize"><input type="hidden" name="nonce" value="{{.Nonce}}"><div class="oauth-actions"><button class="button subtle" type="submit" name="decision" value="deny">Deny</button><button class="button primary" type="submit" name="decision" value="allow">Allow access</button></div></form></section></main></body></html>`))

func (a *App) mcpAuthorizationPage(w http.ResponseWriter, r *http.Request) {
	a.pruneMCPOAuth(r.Context())
	if err := a.mcpRequireSecureRequest(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !a.mcpRegistrationAllowed(clientIP(r), time.Now()) {
		writeError(w, http.StatusTooManyRequests, "authorization request rate limit exceeded")
		return
	}
	_, err := a.mcpIssuer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	redirectURI := r.URL.Query().Get("redirect_uri")
	if r.URL.Query().Get("response_type") != "code" || r.URL.Query().Get("code_challenge_method") != "S256" || !mcpPKCEChallengePattern.MatchString(r.URL.Query().Get("code_challenge")) {
		writeError(w, http.StatusBadRequest, "OAuth authorization requires response_type=code and PKCE S256")
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = mcpScope
	}
	if scope != mcpScope {
		writeError(w, http.StatusBadRequest, "only the yggdrasil scope is supported")
		return
	}
	resource, resourceErr := a.mcpResourceURL(r)
	if resourceErr != nil {
		writeError(w, http.StatusBadRequest, resourceErr.Error())
		return
	}
	requestedResource := strings.TrimSpace(r.URL.Query().Get("resource"))
	if requestedResource == "" || requestedResource != resource {
		writeError(w, http.StatusBadRequest, "the requested resource does not match this Docklight MCP endpoint")
		return
	}
	state := r.URL.Query().Get("state")
	if len(state) > 512 {
		writeError(w, http.StatusBadRequest, "state is too long")
		return
	}
	clientName, redirects, err := a.mcpClient(r.Context(), clientID)
	if err != nil || !slicesContainsString(redirects, redirectURI) {
		writeError(w, http.StatusBadRequest, "unknown MCP client or unregistered redirect URI")
		return
	}
	nonce, err := mcpOpaqueToken("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a consent nonce")
		return
	}
	_, _ = a.db.ExecContext(r.Context(), "DELETE FROM mcp_authorization_requests WHERE expires_at<? OR consumed=1", time.Now().Unix())
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO mcp_authorization_requests(nonce_hash,client_id,redirect_uri,code_challenge,state,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?)`,
		security.APIKeyHash(nonce), clientID, redirectURI, r.URL.Query().Get("code_challenge"), state, scope, resource, time.Now().Add(mcpConsentNonceTTL).Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create MCP consent request")
		return
	}
	redirectHost := redirectURI
	if parsed, parseErr := url.Parse(redirectURI); parseErr == nil {
		redirectHost = parsed.Host
		if redirectHost == "" {
			redirectHost = parsed.Scheme + ":" + parsed.Path
		}
	}
	resourceHost := resource
	if parsed, parseErr := url.Parse(resource); parseErr == nil {
		resourceHost = parsed.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err = mcpConsentTemplate.Execute(w, mcpConsentView{ClientName: clientName, RedirectHost: redirectHost, ResourceHost: resourceHost, Nonce: nonce}); err != nil {
		return
	}
}

func (a *App) mcpAuthorizationConsent(w http.ResponseWriter, r *http.Request) {
	if err := a.mcpRequireSecureRequest(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	origin := r.Header.Get("Origin")
	if origin == "" || !sameOrigin(r, origin) {
		writeError(w, http.StatusForbidden, "MCP approval must come from the Docklight origin")
		return
	}
	user := principal(r)
	if user.IsAPIToken {
		writeError(w, http.StatusForbidden, "sign in with your account to approve MCP connections")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid consent form")
		return
	}
	nonce := strings.TrimSpace(r.Form.Get("nonce"))
	decision := r.Form.Get("decision")
	if nonce == "" || (decision != "allow" && decision != "deny") {
		writeError(w, http.StatusBadRequest, "invalid or expired consent request")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not process MCP consent")
		return
	}
	defer tx.Rollback()
	var clientID, redirectURI, challenge, state, scope, resource string
	var expiresAt int64
	err = tx.QueryRowContext(r.Context(), `SELECT client_id,redirect_uri,code_challenge,state,scope,resource,expires_at FROM mcp_authorization_requests WHERE nonce_hash=? AND consumed=0`, security.APIKeyHash(nonce)).Scan(&clientID, &redirectURI, &challenge, &state, &scope, &resource, &expiresAt)
	if err != nil || expiresAt <= time.Now().Unix() {
		writeError(w, http.StatusBadRequest, "invalid or expired consent request")
		return
	}
	result, err := tx.ExecContext(r.Context(), "UPDATE mcp_authorization_requests SET consumed=1 WHERE nonce_hash=? AND consumed=0 AND expires_at>?", security.APIKeyHash(nonce), time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not consume the consent request")
		return
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		writeError(w, http.StatusBadRequest, "consent request has already been used")
		return
	}
	if decision == "deny" {
		if err = tx.Commit(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record the consent decision")
			return
		}
		a.mcpRedirectOAuthError(w, r, redirectURI, "access_denied", state, a.mcpIssuerString(r))
		return
	}
	var disabled, tokenVersion int
	var username, role string
	if err = tx.QueryRowContext(r.Context(), "SELECT username,role,disabled,token_version FROM users WHERE id=?", user.ID).Scan(&username, &role, &disabled, &tokenVersion); err != nil || disabled != 0 || tokenVersion != user.TokenVersion {
		writeError(w, http.StatusUnauthorized, "sign in again before approving this MCP connection")
		return
	}
	code, err := mcpOpaqueToken("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create an authorization code")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO mcp_authorization_codes(code_hash,client_id,user_id,user_token_version,redirect_uri,code_challenge,scope,resource,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		security.APIKeyHash(code), clientID, user.ID, tokenVersion, redirectURI, challenge, scope, resource, time.Now().Add(mcpAuthorizationTTL).Unix()); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store the authorization code")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue the authorization code")
		return
	}
	a.audit(User{ID: user.ID, Username: username, Role: role}, "mcp.authorize", "mcp_client", clientID, "scope="+scope)
	a.mcpRedirectOAuthCode(w, r, redirectURI, code, state, a.mcpIssuerString(r))
}

func (a *App) mcpIssuerString(r *http.Request) string {
	issuer, _ := a.mcpIssuer(r)
	return issuer
}

func (a *App) mcpRedirectOAuthCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state, issuer string) {
	a.mcpRedirectOAuth(w, r, redirectURI, map[string]string{"code": code, "state": state, "iss": issuer})
}

func (a *App) mcpRedirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, oauthError, state, issuer string) {
	a.mcpRedirectOAuth(w, r, redirectURI, map[string]string{"error": oauthError, "state": state, "iss": issuer})
}

func (a *App) mcpRedirectOAuth(w http.ResponseWriter, r *http.Request, redirectURI string, values map[string]string) {
	u, err := url.Parse(redirectURI)
	if err != nil || !validMCPRedirectURI(redirectURI) {
		writeError(w, http.StatusBadRequest, "invalid registered redirect URI")
		return
	}
	query := u.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	u.RawQuery = query.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (a *App) mcpClient(ctx context.Context, clientID string) (string, []string, error) {
	var name, rawRedirects string
	if err := a.db.QueryRowContext(ctx, "SELECT name,redirect_uris_json FROM mcp_clients WHERE client_id=?", clientID).Scan(&name, &rawRedirects); err != nil {
		return "", nil, err
	}
	var redirects []string
	if err := json.Unmarshal([]byte(rawRedirects), &redirects); err != nil {
		return "", nil, err
	}
	return name, redirects, nil
}

func (a *App) mcpToken(w http.ResponseWriter, r *http.Request) {
	a.pruneMCPOAuth(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := a.mcpRequireSecureRequest(r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form request")
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client_id is required")
		return
	}
	if _, _, err := a.mcpClient(r.Context(), clientID); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	resource, err := a.mcpResourceURL(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	if supplied := strings.TrimSpace(r.Form.Get("resource")); supplied != resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource must match this Docklight MCP endpoint")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		a.mcpExchangeAuthorizationCode(w, r, clientID, resource)
	case "refresh_token":
		a.mcpRotateRefreshToken(w, r, clientID, resource)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func (a *App) mcpExchangeAuthorizationCode(w http.ResponseWriter, r *http.Request, clientID, resource string) {
	code := strings.TrimSpace(r.Form.Get("code"))
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")
	if code == "" || len(code) > 256 || !mcpPKCEVerifierPattern.MatchString(verifier) || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code, redirect_uri, and PKCE verifier are required")
		return
	}
	var redirects []string
	_, redirects, err := a.mcpClient(r.Context(), clientID)
	if err != nil || !slicesContainsString(redirects, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match this client")
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	accessToken, err := mcpOpaqueToken("ygg_mcp_")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue an access token")
		return
	}
	refreshToken, err := mcpOpaqueToken("ygg_mcp_")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}
	connectionID, err := newID()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not create a connection")
		return
	}
	now := time.Now().Unix()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not exchange the authorization code")
		return
	}
	defer tx.Rollback()
	var storedClient, userID, storedRedirect, storedChallenge, scope, storedResource string
	var version, expiresAt, consumed, disabled, currentVersion int
	err = tx.QueryRowContext(r.Context(), `SELECT c.client_id,c.user_id,c.user_token_version,c.redirect_uri,c.code_challenge,c.scope,c.resource,c.expires_at,c.consumed,u.disabled,u.token_version
		FROM mcp_authorization_codes c JOIN users u ON u.id=c.user_id WHERE c.code_hash=?`, security.APIKeyHash(code)).Scan(&storedClient, &userID, &version, &storedRedirect, &storedChallenge, &scope, &storedResource, &expiresAt, &consumed, &disabled, &currentVersion)
	if err != nil || storedClient != clientID || storedRedirect != redirectURI || !hmac.Equal([]byte(storedChallenge), []byte(challenge)) || storedResource != resource || scope != mcpScope || expiresAt <= int(now) || consumed != 0 || disabled != 0 || version != currentVersion {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired, used, or bound to a different client")
		return
	}
	var activeConnections int
	err = tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM mcp_connections c
		WHERE c.user_id=? AND c.revoked_at=0 AND c.user_token_version=? AND
		(EXISTS(SELECT 1 FROM mcp_access_tokens t WHERE t.connection_id=c.id AND t.expires_at>?) OR
		 EXISTS(SELECT 1 FROM mcp_refresh_tokens t WHERE t.connection_id=c.id AND t.expires_at>? AND t.consumed_at=0))`, userID, version, now, now).Scan(&activeConnections)
	if err != nil || activeConnections >= 100 {
		writeOAuthError(w, http.StatusTooManyRequests, "access_denied", "this Docklight account already has the maximum number of active MCP connections")
		return
	}
	result, err := tx.ExecContext(r.Context(), "UPDATE mcp_authorization_codes SET consumed=1 WHERE code_hash=? AND consumed=0 AND expires_at>?", security.APIKeyHash(code), now)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not consume the authorization code")
		return
	}
	if updated, _ := result.RowsAffected(); updated != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code has already been used")
		return
	}
	if err = a.insertMCPConnectionTokens(r.Context(), tx, connectionID, clientID, userID, version, resource, accessToken, refreshToken, now); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not store MCP tokens")
		return
	}
	if err = tx.Commit(); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not save the MCP connection")
		return
	}
	writeMCPTokens(w, accessToken, refreshToken, resource)
}

func (a *App) insertMCPConnectionTokens(ctx context.Context, tx *sql.Tx, connectionID, clientID, userID string, tokenVersion int, resource, accessToken, refreshToken string, now int64) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO mcp_connections(id,client_id,user_id,user_token_version,scope,resource) VALUES(?,?,?,?,?,?)", connectionID, clientID, userID, tokenVersion, mcpScope, resource); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO mcp_access_tokens(token_hash,connection_id,user_id,expires_at) VALUES(?,?,?,?)", security.APIKeyHash(accessToken), connectionID, userID, now+int64(mcpAccessTokenTTL.Seconds())); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO mcp_refresh_tokens(token_hash,connection_id,user_id,expires_at) VALUES(?,?,?,?)", security.APIKeyHash(refreshToken), connectionID, userID, now+int64(mcpRefreshTokenTTL.Seconds()))
	return err
}

func (a *App) mcpRotateRefreshToken(w http.ResponseWriter, r *http.Request, clientID, resource string) {
	oldRefresh := strings.TrimSpace(r.Form.Get("refresh_token"))
	if oldRefresh == "" || len(oldRefresh) > 256 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is required")
		return
	}
	accessToken, err := mcpOpaqueToken("ygg_mcp_")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue an access token")
		return
	}
	newRefresh, err := mcpOpaqueToken("ygg_mcp_")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}
	now := time.Now().Unix()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not rotate refresh token")
		return
	}
	defer tx.Rollback()
	var connectionID, userID, storedClient, scope, storedResource string
	var expiresAt, consumedAt, revokedAt, storedVersion, currentVersion, disabled int64
	err = tx.QueryRowContext(r.Context(), `SELECT t.connection_id,t.user_id,t.expires_at,t.consumed_at,c.client_id,c.scope,c.resource,c.revoked_at,c.user_token_version,u.token_version,u.disabled
		FROM mcp_refresh_tokens t JOIN mcp_connections c ON c.id=t.connection_id AND c.user_id=t.user_id JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`, security.APIKeyHash(oldRefresh)).Scan(&connectionID, &userID, &expiresAt, &consumedAt, &storedClient, &scope, &storedResource, &revokedAt, &storedVersion, &currentVersion, &disabled)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	if storedClient != clientID || scope != mcpScope || storedResource != resource || expiresAt <= now || revokedAt != 0 || storedVersion != currentVersion || disabled != 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is expired or bound to another client or resource")
		return
	}
	if consumedAt != 0 {
		_, _ = tx.ExecContext(r.Context(), "UPDATE mcp_connections SET revoked_at=? WHERE id=? AND revoked_at=0", now, connectionID)
		_ = tx.Commit()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected; this MCP connection was revoked")
		return
	}
	result, err := tx.ExecContext(r.Context(), "UPDATE mcp_refresh_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at=0 AND expires_at>?", now, security.APIKeyHash(oldRefresh), now)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not consume the refresh token")
		return
	}
	if updated, _ := result.RowsAffected(); updated != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token has already been used")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO mcp_access_tokens(token_hash,connection_id,user_id,expires_at) VALUES(?,?,?,?)", security.APIKeyHash(accessToken), connectionID, userID, now+int64(mcpAccessTokenTTL.Seconds())); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not store the access token")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO mcp_refresh_tokens(token_hash,connection_id,user_id,expires_at) VALUES(?,?,?,?)", security.APIKeyHash(newRefresh), connectionID, userID, now+int64(mcpRefreshTokenTTL.Seconds())); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not store the rotated refresh token")
		return
	}
	if err = tx.Commit(); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not save the rotated tokens")
		return
	}
	writeMCPTokens(w, accessToken, newRefresh, resource)
}

func (a *App) pruneMCPOAuth(ctx context.Context) {
	now := time.Now().Unix()
	_, _ = a.db.ExecContext(ctx, "DELETE FROM mcp_authorization_requests WHERE expires_at<? OR consumed=1", now)
	_, _ = a.db.ExecContext(ctx, "DELETE FROM mcp_authorization_codes WHERE expires_at<?", now)
	_, _ = a.db.ExecContext(ctx, "DELETE FROM mcp_access_tokens WHERE expires_at<?", now)
	_, _ = a.db.ExecContext(ctx, "DELETE FROM mcp_refresh_tokens WHERE expires_at<?", now)
}

func writeMCPTokens(w http.ResponseWriter, accessToken, refreshToken, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": "Bearer", "expires_in": int(mcpAccessTokenTTL.Seconds()),
		"refresh_token": refreshToken, "scope": mcpScope, "resource": resource,
	})
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

func mcpOpaqueToken(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func slicesContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (a *App) mcpInfo(w http.ResponseWriter, r *http.Request) {
	issuer, err := a.mcpIssuer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	public, note := mcpPublicURL(issuer)
	writeJSON(w, http.StatusOK, map[string]any{
		"connector_url": issuer + "/api/mcp", "authorization_server": issuer,
		"tool_count": len(mcpToolDefinitions()), "public_reachable": public, "reachability_note": note,
	})
}

func (a *App) mcpListConnections(w http.ResponseWriter, r *http.Request) {
	user := principal(r)
	if user.IsAPIToken {
		writeError(w, http.StatusForbidden, "sign in with your account to manage MCP connections")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT c.id,coalesce(k.name,'Docklight MCP client'),c.scope,c.created_at,c.last_used_at
		FROM mcp_connections c JOIN users u ON u.id=c.user_id LEFT JOIN mcp_clients k ON k.client_id=c.client_id
		WHERE c.user_id=? AND c.revoked_at=0 AND c.user_token_version=u.token_version AND u.disabled=0
		AND (EXISTS(SELECT 1 FROM mcp_access_tokens t WHERE t.connection_id=c.id AND t.expires_at>?) OR EXISTS(SELECT 1 FROM mcp_refresh_tokens t WHERE t.connection_id=c.id AND t.expires_at>? AND t.consumed_at=0))
		ORDER BY c.created_at DESC LIMIT 100`, user.ID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read MCP connections")
		return
	}
	defer rows.Close()
	type connection struct {
		ID        string `json:"id"`
		Client    string `json:"client_name"`
		Scope     string `json:"scope"`
		CreatedAt string `json:"created_at"`
		LastUsed  string `json:"last_used_at"`
	}
	connections := make([]connection, 0)
	for rows.Next() {
		var item connection
		if err = rows.Scan(&item.ID, &item.Client, &item.Scope, &item.CreatedAt, &item.LastUsed); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read MCP connections")
			return
		}
		connections = append(connections, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish reading MCP connections")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": connections})
}

func (a *App) mcpRevokeConnection(w http.ResponseWriter, r *http.Request) {
	user := principal(r)
	if user.IsAPIToken {
		writeError(w, http.StatusForbidden, "sign in with your account to revoke MCP connections")
		return
	}
	connectionID := chi.URLParam(r, "id")
	result, err := a.db.ExecContext(r.Context(), "UPDATE mcp_connections SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at=0", time.Now().Unix(), connectionID, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke MCP connection")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		writeError(w, http.StatusNotFound, "MCP connection not found")
		return
	}
	a.audit(user, "mcp.revoke", "mcp_connection", connectionID, "")
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (a *App) mcpEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "MCP uses POST")
		return
	}
	if err := a.mcpRequireSecureRequest(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A browser session alone is not an MCP grant: external clients need
	// OAuth consent or an explicitly created, scoped API token.
	authorization := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
	if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") || !strings.HasPrefix(authorization[1], "ygg_") {
		a.writeAuthError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	a.auth(a.mcpHandle)(w, r)
}

func (a *App) mcpRejectSubpath(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "unknown MCP resource; connector tokens are accepted only at /api/mcp")
}

func (a *App) mcpHandle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	if contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "MCP requests must use application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	var request mcpRPCRequest
	if err := decoder.Decode(&request); err != nil {
		a.writeMCPRPCError(w, json.RawMessage("null"), -32700, "parse error")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		a.writeMCPRPCError(w, request.ID, -32600, "invalid request")
		return
	}
	if request.JSONRPC != "2.0" || request.Method == "" || len(request.ID) > 512 || !validMCPRPCID(request.ID) {
		a.writeMCPRPCError(w, request.ID, -32600, "invalid request")
		return
	}
	id := request.ID
	if len(id) == 0 {
		if strings.HasPrefix(request.Method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		a.writeMCPRPCError(w, json.RawMessage("null"), -32600, "request id is required")
		return
	}
	var result any
	switch request.Method {
	case "initialize":
		var input struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(request.Params) > 0 {
			_ = json.Unmarshal(request.Params, &input)
		}
		if input.ProtocolVersion != "" && input.ProtocolVersion != mcpProtocolVersion {
			a.writeMCPRPCError(w, id, -32602, "unsupported MCP protocol version")
			return
		}
		result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "docklight", "title": "Docklight", "version": a.version},
			"instructions":    "Docklight exposes only the user's permitted game server operations. Stop and restart may disconnect players.",
		}
	case "ping", "notifications/initialized":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": mcpToolDefinitions()}
	case "tools/call":
		var input struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(request.Params, &input); err != nil || strings.TrimSpace(input.Name) == "" || len(input.Name) > 80 {
			a.writeMCPRPCError(w, id, -32602, "tools/call requires a tool name and arguments object")
			return
		}
		value, targetID, toolErr := a.callMCPTool(r.Context(), principal(r), input.Name, input.Arguments)
		isControlTool := containsString([]string{"start_server", "stop_server", "restart_server"}, input.Name)
		if !isControlTool || toolErr != nil {
			detail := "outcome=success"
			if toolErr != nil {
				detail = "outcome=error"
			}
			if targetID != "" {
				detail += " target=" + targetID
			}
			a.audit(principal(r), "mcp.tool", "mcp_tool", input.Name, detail)
		}
		if toolErr != nil {
			result = map[string]any{"content": []map[string]string{{"type": "text", "text": toolErr.Error()}}, "isError": true}
		} else {
			encoded, err := json.Marshal(value)
			if err != nil {
				result = map[string]any{"content": []map[string]string{{"type": "text", "text": "Docklight could not format the tool result."}}, "isError": true}
			} else {
				result = map[string]any{"content": []map[string]string{{"type": "text", "text": string(encoded)}}, "structuredContent": value, "isError": false}
			}
		}
	default:
		a.writeMCPRPCError(w, id, -32601, "method not found")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func validMCPRPCID(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch value.(type) {
	case nil, string, float64:
		return true
	default:
		return false
	}
}

func (a *App) writeMCPRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": mcpRPCError{Code: code, Message: message}})
}

func mcpToolDefinitions() []map[string]any {
	serverSchema := map[string]any{
		"type": "object", "properties": map[string]any{"server": map[string]any{"type": "string", "description": "Visible server name or ID. Ambiguous names are rejected."}}, "required": []string{"server"}, "additionalProperties": false,
	}
	return []map[string]any{
		{"name": "list_servers", "description": "List only servers the current Docklight user can view.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
		{"name": "get_server", "description": "Get safe status and resource details for one visible server. Accepts its name or ID.", "inputSchema": serverSchema},
		{"name": "server_logs", "description": "Read recent logs with configured server secrets redacted. Defaults to 100 lines and accepts at most 500. Logs may include private player text or IP addresses.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"server": map[string]any{"type": "string", "description": "Visible server name or ID."}, "lines": map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}, "required": []string{"server"}, "additionalProperties": false}},
		{"name": "start_server", "description": "Start one installed server the current user can control.", "inputSchema": serverSchema},
		{"name": "stop_server", "description": "Stop one server the current user can control. This disconnects players.", "inputSchema": serverSchema},
		{"name": "restart_server", "description": "Restart one installed server the current user can control. This can disconnect players.", "inputSchema": serverSchema},
		{"name": "panel_status", "description": "Return Docklight version, uptime, and counts for servers visible to the current user.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
	}
}

type mcpVisibleServer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
	Status     string `json:"status"`
	Installed  bool   `json:"installed"`
}

func (a *App) mcpVisibleServers(ctx context.Context, user User) ([]mcpVisibleServer, error) {
	rows, err := a.db.QueryContext(ctx, "SELECT id,name,gameskill_id,realm_id,status,installed FROM servers ORDER BY name COLLATE NOCASE,id")
	if err != nil {
		return nil, err
	}
	type candidate struct {
		server  mcpVisibleServer
		realmID string
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		var installed int
		if err = rows.Scan(&item.server.ID, &item.server.Name, &item.server.TemplateID, &item.realmID, &item.server.Status, &installed); err != nil {
			_ = rows.Close()
			return nil, err
		}
		item.server.Installed = installed != 0
		candidates = append(candidates, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	visible := make([]mcpVisibleServer, 0, len(candidates))
	for _, item := range candidates {
		if a.allowedServer(user, "server.view", item.server.ID, item.server.TemplateID, item.realmID) {
			visible = append(visible, item.server)
		}
	}
	return visible, nil
}

func (a *App) callMCPTool(ctx context.Context, user User, name string, arguments map[string]any) (any, string, error) {
	switch name {
	case "list_servers":
		servers, err := a.mcpVisibleServers(ctx, user)
		if err != nil {
			return nil, "", errors.New("Docklight could not read visible servers")
		}
		return map[string]any{"servers": servers}, "", nil
	case "panel_status":
		servers, err := a.mcpVisibleServers(ctx, user)
		if err != nil {
			return nil, "", errors.New("Docklight could not read visible server status")
		}
		running := 0
		for _, server := range servers {
			if server.Status == "running" {
				running++
			}
		}
		return map[string]any{"version": a.version, "uptime_seconds": max(0, int(time.Since(a.booted).Seconds())), "visible_servers": len(servers), "running_servers": running}, "", nil
	case "get_server", "server_logs", "start_server", "stop_server", "restart_server":
		selector, _ := arguments["server"].(string)
		selector = strings.TrimSpace(selector)
		if selector == "" || len(selector) > 256 {
			return nil, "", errors.New("server must be a server name or ID you can access with this tool")
		}
		permission := "server.view"
		if containsString([]string{"start_server", "stop_server", "restart_server"}, name) {
			permission = "server.control"
		}
		server, err := a.resolveMCPServer(ctx, user, selector, permission)
		if err != nil {
			return nil, "", err
		}
		switch name {
		case "get_server":
			return a.mcpServerDetails(ctx, server), server.ID, nil
		case "server_logs":
			lines := 100
			if raw, ok := arguments["lines"]; ok {
				value, valid := raw.(float64)
				if !valid || value != float64(int(value)) || value < 1 || value > 500 {
					return nil, server.ID, errors.New("lines must be an integer from 1 to 500")
				}
				lines = int(value)
			}
			logs, logErr := a.mcpServerLogs(ctx, server, lines)
			return map[string]any{"server_id": server.ID, "server_name": server.Name, "lines": lines, "logs": logs}, server.ID, logErr
		case "start_server", "stop_server", "restart_server":
			value, actionErr := a.mcpControlServer(ctx, user, server.ID, name)
			return value, server.ID, actionErr
		}
	}
	return nil, "", fmt.Errorf("unknown Docklight tool %q", name)
}

func (a *App) resolveMCPServer(ctx context.Context, user User, selector, permission string) (Server, error) {
	if server, err := a.getServer(selector); err == nil {
		if a.allowedServer(user, permission, server.ID, server.GameskillID, server.RealmID) {
			return server, nil
		}
		return Server{}, fmt.Errorf("server not found or you do not have %s permission", permission)
	}
	rows, err := a.db.QueryContext(ctx, "SELECT id,name FROM servers")
	if err != nil {
		return Server{}, errors.New("Docklight could not resolve the server")
	}
	ids := make([]string, 0, 2)
	for rows.Next() {
		var id, name string
		if err = rows.Scan(&id, &name); err != nil {
			_ = rows.Close()
			return Server{}, errors.New("Docklight could not resolve the server")
		}
		if strings.EqualFold(name, selector) {
			ids = append(ids, id)
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return Server{}, errors.New("Docklight could not resolve the server")
	}
	_ = rows.Close()
	visible := make([]Server, 0, len(ids))
	for _, id := range ids {
		server, getErr := a.getServer(id)
		if getErr == nil && a.allowedServer(user, permission, server.ID, server.GameskillID, server.RealmID) {
			visible = append(visible, server)
		}
	}
	if len(visible) > 1 {
		return Server{}, errors.New("server name is ambiguous; use its server ID")
	}
	if len(visible) == 0 {
		return Server{}, fmt.Errorf("server not found or you do not have %s permission", permission)
	}
	return visible[0], nil
}

func (a *App) mcpServerDetails(ctx context.Context, server Server) map[string]any {
	result := map[string]any{
		"id": server.ID, "name": server.Name, "template_id": server.GameskillID, "realm_id": server.RealmID,
		"status": server.Status, "installed": server.Installed, "ports": server.Ports,
		"cpu_limit": server.CPULimit, "memory_limit_mb": server.MemoryLimitMB,
		"watchdog_enabled": server.WatchdogEnabled, "watchdog_quarantined": server.WatchdogQuarantined,
	}
	var sampledAt int64
	var cpu, memory float64
	var players int
	if err := a.db.QueryRowContext(ctx, "SELECT sampled_at,cpu_percent,memory_mb,players FROM server_metrics WHERE server_id=? ORDER BY sampled_at DESC LIMIT 1", server.ID).Scan(&sampledAt, &cpu, &memory, &players); err == nil {
		age := time.Since(time.Unix(sampledAt, 0))
		if age >= 0 && age <= 15*time.Minute {
			result["metrics"] = map[string]any{"sampled_at": sampledAt, "cpu_percent": cpu, "memory_mb": memory, "players": players}
		}
	}
	return result
}

func (a *App) mcpServerLogs(ctx context.Context, server Server, lines int) (string, error) {
	if a.engine == nil || server.ContainerID == "" {
		return "", errors.New("server container logs are not available")
	}
	gs, err := a.loadRune(server.GameskillID)
	if err != nil {
		return "", errors.New("could not safely prepare server log redaction")
	}
	env, err := a.runtimeEnv(server, gs)
	if err != nil {
		return "", errors.New("a configured secret could not be safely read; no logs were returned")
	}
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, err := a.engine.Logs(readCtx, server.ContainerID, strconv.Itoa(lines), false)
	if err != nil {
		return "", errors.New("could not read recent server logs")
	}
	defer body.Close()
	tail := &assistantTailBuffer{limit: 1 << 20}
	if err = docker.CopyLogs(tail, body); err != nil {
		return "", errors.New("could not decode recent server logs")
	}
	text := strings.ToValidUTF8(string(tail.data), "�")
	text = redactAssistantLogContent(text, assistantSecretValues(gs, env))
	return assistantLastRunes(strings.TrimSpace(text), 1<<18), nil
}

func (a *App) mcpControlServer(ctx context.Context, user User, serverID, action string) (map[string]any, error) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, err := a.getServer(serverID)
	if err != nil || !a.allowedServer(user, "server.control", server.ID, server.GameskillID, server.RealmID) {
		return nil, errors.New("server.control permission is required for this server")
	}
	if (action == "start_server" || action == "restart_server") && !server.Installed {
		return nil, errors.New("install this server before starting it")
	}
	operationCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	switch action {
	case "start_server":
		err = a.startWithContext(server, operationCtx)
	case "stop_server":
		err = a.stop(server)
	case "restart_server":
		err = a.recreateAndStart(operationCtx, server)
	default:
		return nil, errors.New("action not allowed")
	}
	if err != nil {
		a.audit(user, map[string]string{"start_server": "server.start_failed", "stop_server": "server.stop_failed", "restart_server": "server.restart_failed"}[action], "server", server.ID, "MCP action failed")
		return nil, errors.New("Docklight could not complete the requested server action")
	}
	a.resetWatchdog(server.ID)
	a.audit(user, map[string]string{"start_server": "server.start", "stop_server": "server.stop", "restart_server": "server.restart"}[action], "server", server.ID, "")
	status := "starting"
	if action == "stop_server" {
		status = "stopped"
	}
	return map[string]any{"server_id": server.ID, "server_name": server.Name, "status": status}, nil
}
