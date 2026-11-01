package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/npm"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const npmRequestTimeout = 20 * time.Second

const npmReconcileEvery = 10 * time.Minute

var npmDomainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)

type npmConfig struct {
	Enabled      bool
	URL          string
	Email        string
	Password     string
	BaseDomain   string
	InternalHost string
	LEEmail      string
}

type npmSettingsResponse struct {
	Enabled            bool   `json:"enabled"`
	Configured         bool   `json:"configured"`
	URL                string `json:"url"`
	Email              string `json:"email"`
	PasswordConfigured bool   `json:"password_configured"`
	BaseDomain         string `json:"base_domain"`
	InternalHost       string `json:"internal_host"`
	LEEmail            string `json:"le_email"`
}

type npmServerState struct {
	HostID         string
	Hostname       string
	LastError      string
	CleanupPending bool
}

func (a *App) readNPMConfig() (npmConfig, error) {
	var enabled int
	var passwordEnc string
	var cfg npmConfig
	err := a.db.QueryRow(`SELECT enabled,url,email,password_enc,base_domain,internal_host,le_email FROM npm_settings WHERE id=1`).Scan(&enabled, &cfg.URL, &cfg.Email, &passwordEnc, &cfg.BaseDomain, &cfg.InternalHost, &cfg.LEEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return npmConfig{}, nil
	}
	if err != nil {
		return npmConfig{}, err
	}
	cfg.Enabled = enabled != 0
	if passwordEnc != "" {
		plain, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), passwordEnc)
		if decryptErr != nil {
			return npmConfig{}, errors.New("stored Nginx Proxy Manager password cannot be decrypted; check auth.secret_key")
		}
		cfg.Password = plain
	}
	return cfg, nil
}

func (c npmConfig) configured() bool {
	return strings.TrimSpace(c.URL) != "" && strings.TrimSpace(c.Email) != "" && c.Password != ""
}

func summarizeNPMConfig(c npmConfig) npmSettingsResponse {
	return npmSettingsResponse{Enabled: c.Enabled, Configured: c.configured(), URL: c.URL, Email: c.Email, PasswordConfigured: c.Password != "", BaseDomain: c.BaseDomain, InternalHost: c.InternalHost, LEEmail: c.LEEmail}
}

func normalizeNPMURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter a valid Nginx Proxy Manager URL using http or https, without credentials or query parameters")
	}
	if u.Port() != "" {
		port, portErr := strconv.Atoi(u.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return "", errors.New("Nginx Proxy Manager URL has an invalid port")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func normalizeNPMDomain(raw string, allowEmpty bool) (string, error) {
	domain := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(raw), "."))
	if domain == "" && allowEmpty {
		return "", nil
	}
	if domain == "" || len(domain) > 253 || strings.Contains(domain, "://") || !npmDomainPattern.MatchString(domain) {
		return "", errors.New("enter a valid DNS name using letters, numbers, hyphens, and dots; use punycode for internationalized domains")
	}
	return domain, nil
}

func npmHostname(subdomain, baseDomain string) (string, error) {
	value := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(subdomain), "."))
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, ".") {
		return normalizeNPMDomain(value, false)
	}
	label, err := normalizeNPMDomain(value, false)
	if err != nil || strings.Contains(label, ".") {
		return "", errors.New("enter a subdomain label or a full hostname")
	}
	base, err := normalizeNPMDomain(baseDomain, false)
	if err != nil {
		return "", errors.New("set a valid Nginx Proxy Manager base domain before using a subdomain label")
	}
	return label + "." + base, nil
}

func normalizeNPMInternalHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", nil
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	if len(host) > 253 || !npmDomainPattern.MatchString(host) {
		return "", errors.New("internal host must be an IP address or DNS hostname without a scheme or port")
	}
	return strings.ToLower(host), nil
}

func (a *App) npmClient(cfg npmConfig) (*npm.Client, error) {
	return npm.NewClient(cfg.URL, cfg.Email, cfg.Password, a.npmHTTPClient)
}

func (a *App) getNPMSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager settings")
		return
	}
	writeJSON(w, http.StatusOK, summarizeNPMConfig(cfg))
}

func (a *App) updateNPMSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled      *bool  `json:"enabled"`
		URL          string `json:"url"`
		Email        string `json:"email"`
		Password     string `json:"password"`
		BaseDomain   string `json:"base_domain"`
		InternalHost string `json:"internal_host"`
		LEEmail      string `json:"le_email"`
		ClearLogin   bool   `json:"clear_login"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	next := npmConfig{Enabled: *in.Enabled}
	var err error
	next.URL, err = normalizeNPMURL(in.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next.Email = strings.TrimSpace(in.Email)
	if next.Email != "" {
		parsed, parseErr := mail.ParseAddress(next.Email)
		if parseErr != nil || parsed.Address != next.Email {
			writeError(w, http.StatusBadRequest, "enter the email address for the Nginx Proxy Manager account")
			return
		}
	}
	next.BaseDomain, err = normalizeNPMDomain(in.BaseDomain, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "base domain: "+err.Error())
		return
	}
	next.InternalHost, err = normalizeNPMInternalHost(in.InternalHost)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next.LEEmail = strings.TrimSpace(in.LEEmail)
	if next.LEEmail != "" {
		parsed, parseErr := mail.ParseAddress(next.LEEmail)
		if parseErr != nil || parsed.Address != next.LEEmail {
			writeError(w, http.StatusBadRequest, "enter a valid Let's Encrypt contact email")
			return
		}
	}
	a.npmMu.Lock()
	defer a.npmMu.Unlock()
	current, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current Nginx Proxy Manager settings")
		return
	}
	if !in.ClearLogin {
		if next.Email == "" {
			next.Email = current.Email
		}
		if in.Password == "" {
			next.Password = current.Password
		} else {
			next.Password = in.Password
		}
	}
	if next.LEEmail != "" && !strings.EqualFold(next.LEEmail, next.Email) {
		writeError(w, http.StatusBadRequest, "Nginx Proxy Manager uses the connected account's email for Let's Encrypt; enter the same address here or leave this field blank")
		return
	}
	if next.Enabled && (!next.configured() || next.BaseDomain == "") {
		writeError(w, http.StatusBadRequest, "Nginx Proxy Manager URL, account email, password, and base domain are required before enabling proxy automation")
		return
	}
	changed := current.URL != next.URL || current.Email != next.Email || current.Password != next.Password || current.BaseDomain != next.BaseDomain || current.InternalHost != next.InternalHost || current.LEEmail != next.LEEmail
	if current.configured() && (changed || current.Enabled && !next.Enabled) {
		ctx, cancel := context.WithTimeout(r.Context(), npmRequestTimeout)
		cleanupErr := a.cleanupAllNPMHostsLocked(ctx, current)
		cancel()
		if cleanupErr != nil {
			writeError(w, http.StatusConflict, "saved Nginx Proxy Manager hosts could not be cleared; settings were not changed: "+cleanupErr.Error())
			return
		}
	}
	passwordEnc := ""
	if next.Password != "" {
		passwordEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the Nginx Proxy Manager password")
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE npm_settings SET enabled=?,url=?,email=?,password_enc=?,base_domain=?,internal_host=?,le_email=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(next.Enabled), next.URL, next.Email, passwordEnc, next.BaseDomain, next.InternalHost, next.LEEmail); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save Nginx Proxy Manager settings")
		return
	}
	a.audit(principal(r), "npm.settings", "network", "npm", fmt.Sprintf("enabled=%t url=%s base_domain=%s", next.Enabled, next.URL, next.BaseDomain))
	var syncErr error
	if next.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		syncErr = a.syncRunningNPMHostsLocked(ctx)
		cancel()
	}
	response := summarizeNPMConfig(next)
	if syncErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"settings": response, "message": syncErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) testNPMConnection(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readNPMConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save an Nginx Proxy Manager URL, account email, and password first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), npmRequestTimeout)
	defer cancel()
	client, err := a.npmClient(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "proxy_hosts": len(hosts)})
}

func (a *App) getServerNPMSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.view", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	cfg, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager settings")
		return
	}
	var subdomain string
	if err = a.db.QueryRowContext(r.Context(), `SELECT npm_subdomain FROM servers WHERE id=?`, s.ID).Scan(&subdomain); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server hostname settings")
		return
	}
	state, err := a.readServerNPMState(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server proxy state")
		return
	}
	hostname, _ := npmHostname(subdomain, cfg.BaseDomain)
	if state.Hostname != "" {
		hostname = state.Hostname
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": cfg.Enabled, "configured": cfg.configured(), "subdomain": subdomain, "hostname": hostname, "active": state.HostID != "", "cleanup_pending": state.CleanupPending, "last_error": state.LastError})
}

func (a *App) updateServerNPMSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.control permission is required")
		return
	}
	var in struct {
		Subdomain string `json:"subdomain"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	a.npmMu.Lock()
	defer a.npmMu.Unlock()
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	cfg, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager settings")
		return
	}
	subdomain := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(in.Subdomain), "."))
	hostname, err := npmHostname(subdomain, cfg.BaseDomain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if hostname != "" {
		if other, inUse, useErr := a.serverRouteProviderHostnameInUse(r.Context(), hostname, "npm", "", s.ID, cfg, cloudflareConfig{}); useErr != nil {
			writeError(w, http.StatusInternalServerError, "could not check additional Nginx Proxy Manager hostnames")
			return
		} else if inUse {
			writeError(w, http.StatusConflict, fmt.Sprintf("hostname %s is already assigned through an additional route to server %s", hostname, other))
			return
		}
	}
	var previous string
	if err = a.db.QueryRowContext(r.Context(), `SELECT npm_subdomain FROM servers WHERE id=?`, s.ID).Scan(&previous); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current server hostname")
		return
	}
	previousName, _ := npmHostname(previous, cfg.BaseDomain)
	state, stateErr := a.readServerNPMState(r.Context(), s.ID)
	if stateErr != nil {
		writeError(w, http.StatusInternalServerError, "could not read existing proxy ownership")
		return
	}
	if previousName != hostname || state.CleanupPending || s.Status != "running" && s.Status != "starting" && state.HostID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), npmRequestTimeout)
		cleanupErr := a.removeServerNPMHostLocked(ctx, s.ID, cfg)
		cancel()
		if cleanupErr != nil {
			writeError(w, http.StatusConflict, "the existing proxy host could not be removed; hostname was not changed: "+cleanupErr.Error())
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE servers SET npm_subdomain=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, subdomain, s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save server hostname")
		return
	}
	if (s.Status == "running" || s.Status == "starting") && hostname != "" && cfg.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), npmRequestTimeout)
		openErr := a.openServerNPMHostLocked(ctx, s, cfg)
		cancel()
		if openErr != nil {
			writeJSON(w, http.StatusOK, map[string]any{"subdomain": subdomain, "hostname": hostname, "active": false, "last_error": openErr.Error(), "message": openErr.Error()})
			return
		}
	}
	state, err = a.readServerNPMState(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hostname was saved but proxy status could not be read")
		return
	}
	if state.Hostname == "" {
		state.Hostname = hostname
	}
	writeJSON(w, http.StatusOK, map[string]any{"subdomain": subdomain, "hostname": state.Hostname, "active": state.HostID != "", "cleanup_pending": state.CleanupPending, "last_error": state.LastError})
}

func (a *App) readServerNPMState(ctx context.Context, serverID string) (npmServerState, error) {
	var state npmServerState
	var pending int
	err := a.db.QueryRowContext(ctx, `SELECT host_id,hostname,last_error,cleanup_pending FROM server_npm_state WHERE server_id=?`, serverID).Scan(&state.HostID, &state.Hostname, &state.LastError, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return npmServerState{}, nil
	}
	state.CleanupPending = pending != 0
	return state, err
}

func (a *App) recordNPMState(ctx context.Context, serverID string, state npmServerState) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO server_npm_state(server_id,host_id,hostname,last_error,cleanup_pending,updated_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(server_id) DO UPDATE SET host_id=excluded.host_id,hostname=excluded.hostname,last_error=excluded.last_error,cleanup_pending=excluded.cleanup_pending,updated_at=CURRENT_TIMESTAMP`, serverID, state.HostID, state.Hostname, state.LastError, boolInt(state.CleanupPending))
	return err
}

func (a *App) setNPMError(ctx context.Context, serverID, message string) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO server_npm_state(server_id,last_error,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(server_id) DO UPDATE SET last_error=excluded.last_error,updated_at=CURRENT_TIMESTAMP`, serverID, message)
	return err
}

func (a *App) removeServerNPMHost(ctx context.Context, serverID string) error {
	a.npmMu.Lock()
	defer a.npmMu.Unlock()
	cfg, err := a.readNPMConfig()
	if err != nil {
		return err
	}
	primaryErr := a.removeServerNPMHostLocked(ctx, serverID, cfg)
	extraErr := a.reconcileServerExtraNPMRoutesLocked(ctx, serverID, nil, cfg)
	return errors.Join(primaryErr, extraErr)
}

func (a *App) removeServerNPMHostLocked(ctx context.Context, serverID string, cfg npmConfig) error {
	state, err := a.readServerNPMState(ctx, serverID)
	if err != nil || state.HostID == "" && !state.CleanupPending {
		return err
	}
	if !cfg.configured() {
		missing := errors.New("Nginx Proxy Manager host is recorded but credentials are not configured")
		return errors.Join(missing, a.setNPMError(ctx, serverID, missing.Error()))
	}
	client, err := a.npmClient(cfg)
	if err != nil {
		return err
	}
	if state.HostID != "" {
		if err = client.DeleteProxyHost(ctx, state.HostID); err != nil {
			state.CleanupPending = true
			state.LastError = err.Error()
			_ = a.recordNPMState(ctx, serverID, state)
			return err
		}
	}
	if state.CleanupPending {
		if err = a.removePartialNPMHosts(ctx, client, state.Hostname, serverID); err != nil {
			state.LastError = err.Error()
			_ = a.recordNPMState(ctx, serverID, state)
			return err
		}
	}
	return a.recordNPMState(ctx, serverID, npmServerState{})
}

func (a *App) cleanupAllNPMHostsLocked(ctx context.Context, cfg npmConfig) error {
	rows, err := a.db.QueryContext(ctx, `SELECT server_id FROM server_npm_state WHERE host_id<>'' OR cleanup_pending=1 ORDER BY server_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	var failures []error
	for _, id := range ids {
		if err = a.removeServerNPMHostLocked(ctx, id, cfg); err != nil {
			failures = append(failures, fmt.Errorf("server %s: %w", id, err))
		}
	}
	if err = a.cleanupAllExtraNPMRoutesLocked(ctx, cfg); err != nil {
		failures = append(failures, fmt.Errorf("additional server routes: %w", err))
	}
	return errors.Join(failures...)
}

func (a *App) syncRunningNPMHostsLocked(ctx context.Context) error {
	cfg, err := a.readNPMConfig()
	if err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM servers WHERE installed=1 AND status IN ('running','starting') ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	running := make(map[string]bool, len(ids))
	for _, id := range ids {
		running[id] = true
	}
	stateRows, err := a.db.QueryContext(ctx, `SELECT server_id FROM server_npm_state WHERE host_id<>'' OR cleanup_pending=1 ORDER BY server_id`)
	if err != nil {
		return err
	}
	var stale []string
	for stateRows.Next() {
		var id string
		if err = stateRows.Scan(&id); err != nil {
			stateRows.Close()
			return err
		}
		if !running[id] {
			stale = append(stale, id)
		}
	}
	if err = stateRows.Err(); err != nil {
		stateRows.Close()
		return err
	}
	stateRows.Close()
	var failures []error
	for _, id := range stale {
		if err = a.removeServerNPMHostLocked(ctx, id, cfg); err != nil {
			failures = append(failures, fmt.Errorf("stopped server %s: %w", id, err))
		}
	}
	for _, id := range ids {
		s, getErr := a.getServer(id)
		if getErr == nil {
			if getErr = a.openServerNPMHostLocked(ctx, s, cfg); getErr != nil {
				failures = append(failures, fmt.Errorf("server %s: %w", id, getErr))
			}
		}
	}
	if err = a.reconcileAllExtraNPMRoutesLocked(ctx, cfg, running); err != nil {
		failures = append(failures, fmt.Errorf("additional server routes: %w", err))
	}
	return errors.Join(failures...)
}

// StartNPMReconciler repairs managed proxy hosts after restarts and every ten minutes.
func (a *App) StartNPMReconciler(ctx context.Context) {
	go func() {
		if err := a.reconcileNPMHosts(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("Nginx Proxy Manager reconciliation: %v", err)
		}
		ticker := time.NewTicker(npmReconcileEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.reconcileNPMHosts(ctx); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("Nginx Proxy Manager reconciliation: %v", err)
				}
			}
		}
	}()
}

func (a *App) reconcileNPMHosts(ctx context.Context) error {
	a.npmMu.Lock()
	defer a.npmMu.Unlock()
	cfg, err := a.readNPMConfig()
	if err != nil || !cfg.configured() {
		return err
	}
	workCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if !cfg.Enabled {
		return a.cleanupAllNPMHostsLocked(workCtx, cfg)
	}
	return a.syncRunningNPMHostsLocked(workCtx)
}

func (a *App) openServerNPMHost(ctx context.Context, s Server) error {
	a.npmMu.Lock()
	defer a.npmMu.Unlock()
	cfg, err := a.readNPMConfig()
	if err != nil {
		return err
	}
	primaryErr := a.openServerNPMHostLocked(ctx, s, cfg)
	extraErr := a.openServerExtraNPMRoutesLocked(ctx, s, cfg)
	return errors.Join(primaryErr, extraErr)
}

func (a *App) openServerNPMHostLocked(ctx context.Context, s Server, cfg npmConfig) error {
	var subdomain string
	if err := a.db.QueryRowContext(ctx, `SELECT npm_subdomain FROM servers WHERE id=?`, s.ID).Scan(&subdomain); err != nil {
		return err
	}
	hostname, err := npmHostname(subdomain, cfg.BaseDomain)
	if err != nil {
		_ = a.setNPMError(ctx, s.ID, err.Error())
		return err
	}
	if hostname != "" && cfg.Enabled {
		if other, inUse, useErr := a.serverRouteProviderHostnameInUse(ctx, hostname, "npm", "", s.ID, cfg, cloudflareConfig{}); useErr != nil {
			_ = a.setNPMError(ctx, s.ID, useErr.Error())
			return useErr
		} else if inUse {
			err = fmt.Errorf("Nginx Proxy Manager hostname %s is also assigned to server %s", hostname, other)
			_ = a.setNPMError(ctx, s.ID, err.Error())
			return err
		}
	}
	if hostname == "" || !cfg.Enabled {
		return a.removeServerNPMHostLocked(ctx, s.ID, cfg)
	}
	if !cfg.configured() {
		err = errors.New("Nginx Proxy Manager is enabled but not configured")
		_ = a.setNPMError(ctx, s.ID, err.Error())
		return err
	}
	if err = a.removeServerNPMHostLocked(ctx, s.ID, cfg); err != nil {
		return fmt.Errorf("remove previous proxy host: %w", err)
	}
	serverRune, err := a.loadRune(s.GameskillID)
	if err != nil {
		_ = a.setNPMError(ctx, s.ID, err.Error())
		return err
	}
	portName, hostPort := npmProxyPort(s, serverRune)
	if hostPort == 0 {
		return a.recordNPMState(ctx, s.ID, npmServerState{LastError: "No published TCP web port is available; Nginx Proxy Manager skipped this server."})
	}
	forwardHost := cfg.InternalHost
	if forwardHost == "" {
		localIP, ipErr := a.hostIPv4ForURL(ctx, cfg.URL)
		if ipErr != nil {
			_ = a.setNPMError(ctx, s.ID, ipErr.Error())
			return ipErr
		}
		forwardHost = localIP.String()
	}
	forwardHost, err = normalizeNPMInternalHost(forwardHost)
	if err != nil {
		_ = a.setNPMError(ctx, s.ID, err.Error())
		return err
	}
	client, err := a.npmClient(cfg)
	if err != nil {
		_ = a.setNPMError(ctx, s.ID, err.Error())
		return err
	}
	meta := map[string]any{"docklight_managed": true, "docklight_server_id": s.ID}
	base := npm.ProxyHostCreate{DomainNames: []string{hostname}, ForwardScheme: "http", ForwardHost: forwardHost, ForwardPort: hostPort, CertificateID: 0, SSLForced: false, HTTP2Support: false, BlockExploits: true, AllowWebsocketUpgrade: true, AccessListID: 0, Enabled: true, Meta: meta}
	warning := ""
	hostID, err := client.CreateProxyHost(ctx, base)
	if err != nil {
		warning = "create Nginx Proxy Manager host: " + err.Error()
		if stateErr := a.recordNPMState(ctx, s.ID, npmServerState{Hostname: hostname, LastError: warning, CleanupPending: true}); stateErr != nil {
			return errors.Join(errors.New(warning), stateErr)
		}
		if cleanupErr := a.removePartialNPMHosts(ctx, client, hostname, s.ID); cleanupErr != nil {
			return errors.Join(errors.New(warning), cleanupErr)
		}
		_ = a.recordNPMState(ctx, s.ID, npmServerState{})
		_ = a.setNPMError(ctx, s.ID, warning)
		return fmt.Errorf("create Nginx Proxy Manager host for %s on %s/%d: %w", hostname, portName, hostPort, err)
	}
	state := npmServerState{HostID: hostID, Hostname: hostname}
	if err = a.recordNPMState(ctx, s.ID, state); err != nil {
		cleanupErr := client.DeleteProxyHost(ctx, hostID)
		return errors.Join(fmt.Errorf("save Nginx Proxy Manager host ownership: %w", err), cleanupErr)
	}

	if cfg.LEEmail != "" || cfg.Email != "" {
		// NPM reuses proxy-host metadata as certificate metadata when it creates
		// a certificate. Clear Docklight's ownership marker during that request;
		// the certificate's schema accepts only ACME options.
		emptyMeta := map[string]any{}
		if clearErr := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{Meta: &emptyMeta}); clearErr != nil {
			warning = "Let's Encrypt setup could not start; proxy host remains available without SSL: " + clearErr.Error()
		} else {
			sslForced := true
			sslMeta := map[string]any{"dns_challenge": false}
			updateErr := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{CertificateID: "new", SSLForced: &sslForced, Meta: &sslMeta})
			if updateErr != nil {
				// NPM can save the certificate and host before a later nginx reload
				// error reaches this client. Confirm the saved state before saying
				// that the plain HTTP host is the no-SSL fallback.
				if confirmed, checkErr := a.npmHostHasSSL(ctx, client, hostID); confirmed {
					warning = "Nginx Proxy Manager reported an error after applying the Let's Encrypt update; verify the host there: " + updateErr.Error()
				} else {
					warning = "Let's Encrypt certificate could not be issued; proxy host remains available without SSL: " + updateErr.Error()
					if checkErr != nil {
						warning += " (could not confirm NPM host state: " + checkErr.Error() + ")"
					}
				}
			}
		}
	}
	if markerErr := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{Meta: &meta}); markerErr != nil {
		if warning != "" {
			warning += " | "
		}
		warning += "could not update Docklight ownership metadata in NPM: " + markerErr.Error()
	}
	state.LastError = warning
	if err = a.recordNPMState(ctx, s.ID, state); err != nil {
		return fmt.Errorf("save Nginx Proxy Manager status: %w", err)
	}
	if warning != "" {
		a.audit(User{Username: "system"}, "server.npm_warning", "server", s.ID, warning)
	}
	return nil
}

func (a *App) npmHostHasSSL(ctx context.Context, client *npm.Client, hostID string) (bool, error) {
	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		return false, err
	}
	for _, host := range hosts {
		id, idErr := parseNPMHostID(host.ID)
		if idErr != nil || id != hostID {
			continue
		}
		certificateID, certErr := parseNPMHostID(host.CertificateID)
		if certErr != nil {
			return false, certErr
		}
		return host.SSLForced && certificateID != "0", nil
	}
	return false, errors.New("saved proxy host was not returned by NPM")
}

func (a *App) removePartialNPMHosts(ctx context.Context, client *npm.Client, hostname, serverID string) error {
	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		return err
	}
	var failures []error
	pendingID := ""
	for _, host := range hosts {
		owned := fmt.Sprint(host.Meta["docklight_managed"]) == "true" && fmt.Sprint(host.Meta["docklight_server_id"]) == serverID
		if !owned || !containsString(host.DomainNames, hostname) {
			continue
		}
		id, idErr := parseNPMHostID(host.ID)
		if idErr != nil {
			failures = append(failures, idErr)
			continue
		}
		if deleteErr := client.DeleteProxyHost(ctx, id); deleteErr != nil {
			if pendingID == "" {
				pendingID = id
			}
			failures = append(failures, deleteErr)
		}
	}
	if len(failures) != 0 {
		message := errors.Join(failures...).Error()
		if stateErr := a.recordNPMState(ctx, serverID, npmServerState{HostID: pendingID, Hostname: hostname, LastError: message, CleanupPending: true}); stateErr != nil {
			failures = append(failures, stateErr)
		}
		return errors.Join(failures...)
	}
	return nil
}

func parseNPMHostID(raw json.RawMessage) (string, error) {
	var id string
	if len(raw) > 0 && raw[0] == '"' {
		err := json.Unmarshal(raw, &id)
		return id, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return "", errors.New("Nginx Proxy Manager returned a host without an ID")
	}
	return strings.TrimSpace(string(raw)), nil
}

func npmProxyPort(s Server, gs rune.Rune) (string, int) {
	for _, p := range gs.Ports {
		if p.Name == "web" && portHasTCP(p.Protocol) {
			if port := s.Ports[p.Name]; port > 0 && port <= 65535 {
				return p.Name, port
			}
		}
	}
	for _, p := range gs.Ports {
		if portHasTCP(p.Protocol) {
			if port := s.Ports[p.Name]; port > 0 && port <= 65535 {
				return p.Name, port
			}
		}
	}
	return "", 0
}

func portHasTCP(protocol string) bool {
	for _, item := range strings.Split(strings.ToLower(protocol), "+") {
		if strings.TrimSpace(item) == "tcp" {
			return true
		}
	}
	return false
}

func (a *App) removeServerNPMHostLifecycle(serverID string) {
	ctx, cancel := context.WithTimeout(context.Background(), npmRequestTimeout)
	defer cancel()
	if err := a.removeServerNPMHost(ctx, serverID); err != nil {
		a.audit(User{Username: "system"}, "server.npm_cleanup_error", "server", serverID, err.Error())
	}
}
