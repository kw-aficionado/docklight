package panel

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	cfapi "example.com/yggdrasil-panel/internal/cloudflare"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const (
	cloudflareRequestTimeout   = 25 * time.Second
	cloudflareReconcileEvery   = 10 * time.Minute
	cloudflareTunnelServiceEnd = ".cfargotunnel.com"
)

var cloudflareIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var cloudflareLabelPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type cloudflareConfig struct {
	Enabled      bool
	APIToken     string
	AccountID    string
	TunnelID     string
	BaseDomain   string
	ZoneID       string
	InternalHost string
}

type cloudflareSettingsResponse struct {
	Enabled            bool   `json:"enabled"`
	Configured         bool   `json:"configured"`
	APITokenConfigured bool   `json:"api_token_configured"`
	AccountID          string `json:"account_id"`
	TunnelID           string `json:"tunnel_id"`
	BaseDomain         string `json:"base_domain"`
	ZoneID             string `json:"zone_id"`
	InternalHost       string `json:"internal_host"`
	TunnelTokenWarning string `json:"tunnel_token_warning,omitempty"`
}

type cloudflareServerState struct {
	Hostname       string
	Service        string
	DNSRecordID    string
	LastError      string
	CleanupPending bool
}

type cloudflareIngressRule struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
	Path     string `json:"path,omitempty"`
}

type cloudflareDomain struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
	Path     string `json:"path,omitempty"`
}

func (a *App) readCloudflareConfig() (cloudflareConfig, error) {
	var enabled int
	var tokenEnc string
	var cfg cloudflareConfig
	err := a.db.QueryRow(`SELECT enabled,api_token_enc,account_id,tunnel_id,base_domain,zone_id,internal_host FROM cloudflare_settings WHERE id=1`).Scan(&enabled, &tokenEnc, &cfg.AccountID, &cfg.TunnelID, &cfg.BaseDomain, &cfg.ZoneID, &cfg.InternalHost)
	if errors.Is(err, sql.ErrNoRows) {
		return cloudflareConfig{}, nil
	}
	if err != nil {
		return cloudflareConfig{}, err
	}
	cfg.Enabled = enabled != 0
	if tokenEnc != "" {
		plain, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), tokenEnc)
		if decryptErr != nil {
			return cloudflareConfig{}, errors.New("stored Cloudflare API token cannot be decrypted; check auth.secret_key")
		}
		cfg.APIToken = string(plain)
	}
	cfg.AccountID = strings.TrimSpace(cfg.AccountID)
	cfg.TunnelID = strings.TrimSpace(cfg.TunnelID)
	cfg.BaseDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.BaseDomain), "."))
	cfg.ZoneID = strings.TrimSpace(cfg.ZoneID)
	cfg.InternalHost = strings.TrimSpace(cfg.InternalHost)
	return cfg, nil
}

func (cfg cloudflareConfig) configured() bool {
	return strings.TrimSpace(cfg.APIToken) != "" && cloudflareIDPattern.MatchString(cfg.AccountID) && cloudflareIDPattern.MatchString(cfg.TunnelID) && cfg.BaseDomain != ""
}

func summarizeCloudflareConfig(cfg cloudflareConfig, warning string) cloudflareSettingsResponse {
	return cloudflareSettingsResponse{Enabled: cfg.Enabled, Configured: cfg.configured(), APITokenConfigured: cfg.APIToken != "", AccountID: cfg.AccountID, TunnelID: cfg.TunnelID, BaseDomain: cfg.BaseDomain, ZoneID: cfg.ZoneID, InternalHost: cfg.InternalHost, TunnelTokenWarning: warning}
}

func (a *App) cloudflareClient(cfg cloudflareConfig) *cfapi.Client {
	client := cfapi.NewClient(cfg.APIToken, a.cfHTTPClient)
	if a.cfAPIBaseURL != "" {
		client.BaseURL = a.cfAPIBaseURL
	}
	return client
}

func normalizeCloudflareDomain(raw string, allowEmpty bool) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if domain == "" && allowEmpty {
		return "", nil
	}
	if domain == "" || len(domain) > 253 || strings.Contains(domain, "://") || !npmDomainPattern.MatchString(domain) {
		return "", errors.New("enter a valid DNS name using letters, numbers, hyphens, and dots; use punycode for internationalized domains")
	}
	return domain, nil
}

func normalizeCloudflareID(raw, label string, allowEmpty bool) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" && allowEmpty {
		return "", nil
	}
	if !cloudflareIDPattern.MatchString(value) {
		return "", fmt.Errorf("%s must contain only letters, numbers, hyphens, or underscores", label)
	}
	return value, nil
}

func normalizeCloudflareInternalHost(raw string) (string, error) {
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

func cloudflareHostname(value, baseDomain string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return "", nil
	}
	if !strings.Contains(value, ".") {
		if len(value) > 63 || !cloudflareLabelPattern.MatchString(value) {
			return "", errors.New("enter a subdomain label or a full hostname")
		}
		if baseDomain == "" {
			return "", errors.New("set a Cloudflare base domain before using a subdomain label")
		}
		value += "." + baseDomain
	}
	name, err := normalizeCloudflareDomain(value, false)
	if err != nil {
		return "", err
	}
	if name != baseDomain && !strings.HasSuffix(name, "."+baseDomain) {
		return "", errors.New("hostname must be inside the configured Cloudflare base domain")
	}
	return name, nil
}

func (a *App) getCloudflareSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare settings")
		return
	}
	writeJSON(w, http.StatusOK, summarizeCloudflareConfig(cfg, a.cloudflaredTokenWarning(cfg)))
}

func (a *App) updateCloudflareSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled      *bool  `json:"enabled"`
		APIToken     string `json:"api_token"`
		AccountID    string `json:"account_id"`
		TunnelID     string `json:"tunnel_id"`
		BaseDomain   string `json:"base_domain"`
		ZoneID       string `json:"zone_id"`
		InternalHost string `json:"internal_host"`
		ClearToken   bool   `json:"clear_token"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	next := cloudflareConfig{Enabled: *in.Enabled, APIToken: strings.TrimSpace(in.APIToken)}
	var err error
	if next.AccountID, err = normalizeCloudflareID(in.AccountID, "account ID", false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if next.TunnelID, err = normalizeCloudflareID(in.TunnelID, "tunnel ID", false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if next.BaseDomain, err = normalizeCloudflareDomain(in.BaseDomain, false); err != nil {
		writeError(w, http.StatusBadRequest, "base domain: "+err.Error())
		return
	}
	if next.ZoneID, err = normalizeCloudflareID(in.ZoneID, "zone ID", true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if next.InternalHost, err = normalizeCloudflareInternalHost(in.InternalHost); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	current, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current Cloudflare settings")
		return
	}
	if !in.ClearToken && next.APIToken == "" {
		next.APIToken = current.APIToken
	}
	if next.Enabled && !next.configured() {
		writeError(w, http.StatusBadRequest, "Cloudflare API token, account ID, tunnel ID, and base domain are required before enabling Tunnel routes")
		return
	}
	changed := current.APIToken != next.APIToken || current.AccountID != next.AccountID || current.TunnelID != next.TunnelID || current.BaseDomain != next.BaseDomain || current.ZoneID != next.ZoneID || current.InternalHost != next.InternalHost
	if current.configured() && (changed || current.Enabled && !next.Enabled) {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		cleanupErr := a.cleanupAllCloudflareRoutesLocked(ctx, current)
		cancel()
		if cleanupErr != nil {
			writeError(w, http.StatusConflict, "saved Cloudflare routes could not be safely cleared; settings were not changed: "+cleanupErr.Error())
			return
		}
	}
	tokenEnc := ""
	if next.APIToken != "" {
		tokenEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.APIToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt the Cloudflare API token")
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE cloudflare_settings SET enabled=?,api_token_enc=?,account_id=?,tunnel_id=?,base_domain=?,zone_id=?,internal_host=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(next.Enabled), tokenEnc, next.AccountID, next.TunnelID, next.BaseDomain, next.ZoneID, next.InternalHost); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save Cloudflare settings")
		return
	}
	a.audit(principal(r), "cloudflare.settings", "network", "cloudflare", fmt.Sprintf("enabled=%t account_id=%s tunnel_id=%s base_domain=%s", next.Enabled, next.AccountID, next.TunnelID, next.BaseDomain))
	var syncErr error
	if next.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		syncErr = a.syncRunningCloudflareRoutesLocked(ctx, next)
		cancel()
		if saved, readErr := a.readCloudflareConfig(); readErr == nil {
			next = saved
		}
	}
	response := summarizeCloudflareConfig(next, a.cloudflaredTokenWarning(next))
	if syncErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"settings": response, "message": syncErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) testCloudflareConnection(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readCloudflareConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save a Cloudflare API token, account ID, tunnel ID, and base domain first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
	defer cancel()
	client := a.cloudflareClient(cfg)
	config, err := client.GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if cfg.ZoneID == "" {
		cfg.ZoneID, err = a.resolveCloudflareZone(ctx, client, cfg)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	var rules []json.RawMessage
	if raw := config.Config["ingress"]; len(raw) != 0 {
		if err = json.Unmarshal(raw, &rules); err != nil {
			writeError(w, http.StatusBadGateway, "Cloudflare returned an invalid Tunnel ingress configuration")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "ingress_rules": len(rules), "zone_id": cfg.ZoneID})
}

func (a *App) listCloudflareDomains(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readCloudflareConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "Cloudflare Tunnel is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
	defer cancel()
	config, err := a.cloudflareClient(cfg).GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	var rules []json.RawMessage
	if raw := config.Config["ingress"]; len(raw) != 0 {
		if err = json.Unmarshal(raw, &rules); err != nil {
			writeError(w, http.StatusBadGateway, "Cloudflare returned an invalid Tunnel ingress configuration")
			return
		}
	}
	var domains []cloudflareDomain
	for _, raw := range rules {
		var rule cloudflareIngressRule
		if json.Unmarshal(raw, &rule) != nil || rule.Hostname == "" {
			continue
		}
		domains = append(domains, cloudflareDomain{Hostname: rule.Hostname, Service: rule.Service, Path: rule.Path})
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Hostname == domains[j].Hostname {
			return domains[i].Path < domains[j].Path
		}
		return domains[i].Hostname < domains[j].Hostname
	})
	writeJSON(w, http.StatusOK, domains)
}

func (a *App) getServerCloudflareSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.view", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare settings")
		return
	}
	var hostname string
	if err = a.db.QueryRowContext(r.Context(), `SELECT cf_hostname FROM servers WHERE id=?`, s.ID).Scan(&hostname); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server hostname settings")
		return
	}
	state, err := a.readServerCloudflareState(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare route state")
		return
	}
	resolved, _ := cloudflareHostname(hostname, cfg.BaseDomain)
	if state.Hostname != "" {
		resolved = state.Hostname
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": cfg.Enabled, "configured": cfg.configured(), "subdomain": hostname, "hostname": resolved, "active": state.Hostname != "" && !state.CleanupPending, "cleanup_pending": state.CleanupPending, "last_error": state.LastError})
}

func (a *App) updateServerCloudflareSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.control", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.control permission is required")
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare settings")
		return
	}
	hostnameInput := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Hostname), "."))
	hostname, err := cloudflareHostname(hostnameInput, cfg.BaseDomain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if hostname != "" {
		if other, inUse, useErr := a.cloudflareHostnameInUse(r.Context(), hostname, s.ID, cfg.BaseDomain); useErr != nil {
			writeError(w, http.StatusInternalServerError, "could not check for duplicate Cloudflare hostnames")
			return
		} else if inUse {
			writeError(w, http.StatusConflict, fmt.Sprintf("hostname %s is already assigned to server %s", hostname, other))
			return
		}
	}
	var previous string
	if err = a.db.QueryRowContext(r.Context(), `SELECT cf_hostname FROM servers WHERE id=?`, s.ID).Scan(&previous); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current Cloudflare hostname")
		return
	}
	previousName, _ := cloudflareHostname(previous, cfg.BaseDomain)
	state, err := a.readServerCloudflareState(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current Cloudflare route state")
		return
	}
	if previousName != hostname || state.CleanupPending || (s.Status != "running" && s.Status != "starting" && state.Hostname != "") {
		ctx, cancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
		cleanupErr := a.removeServerCloudflareRouteLocked(ctx, s.ID, cfg)
		cancel()
		if cleanupErr != nil {
			writeError(w, http.StatusConflict, "the existing Cloudflare route could not be safely removed; hostname was not changed: "+cleanupErr.Error())
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE servers SET cf_hostname=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, hostnameInput, s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save server Cloudflare hostname")
		return
	}
	a.audit(principal(r), "server.cloudflare_hostname", "server", s.ID, "hostname="+hostname)
	if (s.Status == "running" || s.Status == "starting") && hostname != "" && cfg.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
		openErr := a.openServerCloudflareRouteLocked(ctx, s, cfg)
		cancel()
		if openErr != nil {
			state, _ = a.readServerCloudflareState(r.Context(), s.ID)
			writeJSON(w, http.StatusOK, map[string]any{"subdomain": hostnameInput, "hostname": hostname, "active": state.Hostname != "" && !state.CleanupPending, "cleanup_pending": state.CleanupPending, "last_error": openErr.Error(), "message": openErr.Error()})
			return
		}
	}
	state, err = a.readServerCloudflareState(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hostname was saved but Cloudflare route status could not be read")
		return
	}
	if state.Hostname == "" {
		state.Hostname = hostname
	}
	writeJSON(w, http.StatusOK, map[string]any{"subdomain": hostnameInput, "hostname": state.Hostname, "active": state.Hostname != "" && !state.CleanupPending, "cleanup_pending": state.CleanupPending, "last_error": state.LastError})
}

func (a *App) readServerCloudflareState(ctx context.Context, serverID string) (cloudflareServerState, error) {
	var state cloudflareServerState
	var pending int
	err := a.db.QueryRowContext(ctx, `SELECT hostname,service,dns_record_id,last_error,cleanup_pending FROM server_cf_state WHERE server_id=?`, serverID).Scan(&state.Hostname, &state.Service, &state.DNSRecordID, &state.LastError, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return cloudflareServerState{}, nil
	}
	state.CleanupPending = pending != 0
	return state, err
}

func (a *App) recordServerCloudflareState(ctx context.Context, serverID string, state cloudflareServerState) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO server_cf_state(server_id,hostname,service,dns_record_id,last_error,cleanup_pending,updated_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(server_id) DO UPDATE SET hostname=excluded.hostname,service=excluded.service,dns_record_id=excluded.dns_record_id,last_error=excluded.last_error,cleanup_pending=excluded.cleanup_pending,updated_at=CURRENT_TIMESTAMP`, serverID, state.Hostname, state.Service, state.DNSRecordID, state.LastError, boolInt(state.CleanupPending))
	return err
}

func (a *App) setCloudflareError(ctx context.Context, serverID, message string) error {
	state, err := a.readServerCloudflareState(ctx, serverID)
	if err != nil {
		return err
	}
	state.LastError = message
	return a.recordServerCloudflareState(ctx, serverID, state)
}

func (a *App) cloudflareHostnameInUse(ctx context.Context, hostname, exceptServerID, baseDomain string) (string, bool, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,cf_hostname FROM servers WHERE id<>? AND cf_hostname<>'' ORDER BY id`, exceptServerID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var serverID, saved string
		if err = rows.Scan(&serverID, &saved); err != nil {
			return "", false, err
		}
		resolved, resolveErr := cloudflareHostname(saved, baseDomain)
		if resolveErr == nil && strings.EqualFold(resolved, hostname) {
			return serverID, true, nil
		}
	}
	return "", false, rows.Err()
}

func (a *App) openServerCloudflareRoute(ctx context.Context, s Server) error {
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		return err
	}
	return a.openServerCloudflareRouteLocked(ctx, s, cfg)
}

func (a *App) openServerCloudflareRouteLocked(ctx context.Context, s Server, cfg cloudflareConfig) error {
	var configuredName string
	if err := a.db.QueryRowContext(ctx, `SELECT cf_hostname FROM servers WHERE id=?`, s.ID).Scan(&configuredName); err != nil {
		return err
	}
	hostname, err := cloudflareHostname(configuredName, cfg.BaseDomain)
	if err != nil {
		_ = a.setCloudflareError(ctx, s.ID, err.Error())
		return err
	}
	state, err := a.readServerCloudflareState(ctx, s.ID)
	if err != nil {
		return err
	}
	if hostname == "" || !cfg.Enabled {
		return a.removeServerCloudflareRouteLocked(ctx, s.ID, cfg)
	}
	if !cfg.configured() {
		err = errors.New("Cloudflare Tunnel routes are enabled but the API token, account, tunnel, or base domain is missing")
		_ = a.setCloudflareError(ctx, s.ID, err.Error())
		return err
	}
	if other, inUse, useErr := a.cloudflareHostnameInUse(ctx, hostname, s.ID, cfg.BaseDomain); useErr != nil {
		_ = a.setCloudflareError(ctx, s.ID, useErr.Error())
		return useErr
	} else if inUse {
		err = fmt.Errorf("Cloudflare hostname %s is also assigned to server %s", hostname, other)
		_ = a.setCloudflareError(ctx, s.ID, err.Error())
		return err
	}
	serverRune, err := a.loadRune(s.GameskillID)
	if err != nil {
		_ = a.setCloudflareError(ctx, s.ID, err.Error())
		return err
	}
	_, hostPort := npmProxyPort(s, serverRune)
	if hostPort == 0 {
		warning := "No published TCP web port is available; Cloudflare Tunnel skipped this server."
		if state.Hostname != "" || state.CleanupPending {
			if cleanupErr := a.removeServerCloudflareRouteLocked(ctx, s.ID, cfg); cleanupErr != nil {
				return cleanupErr
			}
		}
		return a.recordServerCloudflareState(ctx, s.ID, cloudflareServerState{LastError: warning})
	}
	forwardHost, warning := a.cloudflareForwardHost(ctx, cfg)
	if forwardHost == "" {
		_ = a.setCloudflareError(ctx, s.ID, warning)
		return errors.New(warning)
	}
	service := "http://" + net.JoinHostPort(forwardHost, fmt.Sprint(hostPort))
	if state.Hostname != "" && (state.Hostname != hostname || state.Service != service) {
		if err = a.removeServerCloudflareRouteLocked(ctx, s.ID, cfg); err != nil {
			return fmt.Errorf("remove previous Cloudflare Tunnel route: %w", err)
		}
		state = cloudflareServerState{}
	}
	client := a.cloudflareClient(cfg)
	zoneID, zoneErr := a.resolveCloudflareZone(ctx, client, cfg)
	if zoneErr != nil {
		_ = a.setCloudflareError(ctx, s.ID, zoneErr.Error())
		return zoneErr
	}
	state = cloudflareServerState{Hostname: hostname, Service: service, DNSRecordID: state.DNSRecordID, CleanupPending: true}
	if err = a.recordServerCloudflareState(ctx, s.ID, state); err != nil {
		return err
	}
	tunnelConfig, err := client.GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
	if err != nil {
		state.LastError = "read Cloudflare Tunnel configuration: " + err.Error()
		_ = a.recordServerCloudflareState(ctx, s.ID, state)
		return errors.New(state.LastError)
	}
	updated, changed, err := upsertCloudflareIngress(tunnelConfig.Config, hostname, service, state)
	if err != nil {
		state.LastError = err.Error()
		_ = a.recordServerCloudflareState(ctx, s.ID, state)
		return err
	}
	if changed {
		if err = client.UpdateTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID, updated); err != nil {
			state.LastError = "update Cloudflare Tunnel ingress: " + err.Error()
			_ = a.recordServerCloudflareState(ctx, s.ID, state)
			return errors.New(state.LastError)
		}
	}
	record, dnsErr := a.upsertCloudflareDNS(ctx, client, zoneID, hostname, cfg.TunnelID)
	if dnsErr != nil {
		state.LastError = "Tunnel route is active but DNS could not be reconciled: " + dnsErr.Error()
		state.CleanupPending = false
		_ = a.recordServerCloudflareState(ctx, s.ID, state)
		a.audit(User{Username: "system"}, "server.cloudflare_warning", "server", s.ID, state.LastError)
		return errors.New(state.LastError)
	}
	state.DNSRecordID = record.ID
	state.LastError = warning
	state.CleanupPending = false
	if err = a.recordServerCloudflareState(ctx, s.ID, state); err != nil {
		return fmt.Errorf("route and DNS were created but Docklight could not save ownership: %w", err)
	}
	if warning != "" {
		a.audit(User{Username: "system"}, "server.cloudflare_warning", "server", s.ID, warning)
	}
	return nil
}

func (a *App) cloudflareForwardHost(ctx context.Context, cfg cloudflareConfig) (string, string) {
	host := cfg.InternalHost
	if host == "" {
		ip, err := a.hostIPv4ForURL(ctx, "https://api.cloudflare.com")
		if err != nil {
			return "", err.Error()
		}
		return ip.String(), ""
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || hostIPIsLocal(ip) {
		return host, ""
	}
	ip, err := a.hostIPv4ForURL(ctx, "https://api.cloudflare.com")
	if err != nil {
		return "", "configured Cloudflare internal IP is no longer assigned to this host and a current LAN address could not be detected: " + err.Error()
	}
	message := fmt.Sprintf("Configured Cloudflare internal IP %s is no longer assigned to this host; using current LAN address %s.", host, ip.String())
	log.Printf("cloudflare: %s", message)
	return ip.String(), message
}

func hostIPIsLocal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, address := range addresses {
			var local net.IP
			switch value := address.(type) {
			case *net.IPNet:
				local = value.IP
			case *net.IPAddr:
				local = value.IP
			}
			if local != nil && local.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func (a *App) removeServerCloudflareRoute(ctx context.Context, serverID string) error {
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		return err
	}
	return a.removeServerCloudflareRouteLocked(ctx, serverID, cfg)
}

func (a *App) removeServerCloudflareRouteLocked(ctx context.Context, serverID string, cfg cloudflareConfig) error {
	state, err := a.readServerCloudflareState(ctx, serverID)
	if err != nil || state.Hostname == "" && !state.CleanupPending {
		return err
	}
	if !cfg.configured() {
		missing := errors.New("a Cloudflare route is recorded but its API credentials are not configured")
		state.CleanupPending = true
		state.LastError = missing.Error()
		return errors.Join(missing, a.recordServerCloudflareState(ctx, serverID, state))
	}
	client := a.cloudflareClient(cfg)
	if state.Hostname != "" && state.Service != "" {
		config, getErr := client.GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
		if getErr != nil {
			state.CleanupPending = true
			state.LastError = getErr.Error()
			_ = a.recordServerCloudflareState(ctx, serverID, state)
			return getErr
		}
		updated, changed, removeErr := removeCloudflareIngress(config.Config, state.Hostname, state.Service)
		if removeErr != nil {
			state.CleanupPending = true
			state.LastError = removeErr.Error()
			_ = a.recordServerCloudflareState(ctx, serverID, state)
			return removeErr
		}
		if changed {
			if err = client.UpdateTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID, updated); err != nil {
				state.CleanupPending = true
				state.LastError = "remove Cloudflare Tunnel ingress: " + err.Error()
				_ = a.recordServerCloudflareState(ctx, serverID, state)
				return errors.New(state.LastError)
			}
		}
	}
	if state.Hostname != "" {
		zoneID, zoneErr := a.resolveCloudflareZone(ctx, client, cfg)
		if zoneErr != nil {
			state.CleanupPending = true
			state.LastError = zoneErr.Error()
			_ = a.recordServerCloudflareState(ctx, serverID, state)
			return zoneErr
		}
		if err = a.deleteOwnedCloudflareDNS(ctx, client, zoneID, state.Hostname, cfg.TunnelID); err != nil {
			state.CleanupPending = true
			state.LastError = err.Error()
			_ = a.recordServerCloudflareState(ctx, serverID, state)
			return err
		}
	}
	return a.recordServerCloudflareState(ctx, serverID, cloudflareServerState{})
}

func (a *App) cleanupAllCloudflareRoutesLocked(ctx context.Context, cfg cloudflareConfig) error {
	rows, err := a.db.QueryContext(ctx, `SELECT server_id FROM server_cf_state WHERE hostname<>'' OR cleanup_pending=1 ORDER BY server_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	var failures []error
	for _, id := range ids {
		if err = a.removeServerCloudflareRouteLocked(ctx, id, cfg); err != nil {
			failures = append(failures, fmt.Errorf("server %s: %w", id, err))
		}
	}
	return errors.Join(failures...)
}

func (a *App) syncRunningCloudflareRoutesLocked(ctx context.Context, cfg cloudflareConfig) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM servers WHERE status IN ('running','starting') ORDER BY id`)
	if err != nil {
		return err
	}
	var running []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		running = append(running, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	runningSet := make(map[string]bool, len(running))
	for _, id := range running {
		runningSet[id] = true
	}
	stateRows, err := a.db.QueryContext(ctx, `SELECT server_id FROM server_cf_state WHERE hostname<>'' OR cleanup_pending=1 ORDER BY server_id`)
	if err != nil {
		return err
	}
	var stale []string
	for stateRows.Next() {
		var id string
		if err = stateRows.Scan(&id); err != nil {
			_ = stateRows.Close()
			return err
		}
		if !runningSet[id] {
			stale = append(stale, id)
		}
	}
	if err = stateRows.Err(); err != nil {
		_ = stateRows.Close()
		return err
	}
	_ = stateRows.Close()
	var failures []error
	for _, id := range stale {
		if err = a.removeServerCloudflareRouteLocked(ctx, id, cfg); err != nil {
			failures = append(failures, fmt.Errorf("clean up stopped server %s: %w", id, err))
		}
	}
	for _, id := range running {
		if err = ctx.Err(); err != nil {
			return errors.Join(errors.Join(failures...), err)
		}
		s, getErr := a.getServer(id)
		if getErr != nil {
			failures = append(failures, fmt.Errorf("load server %s: %w", id, getErr))
			continue
		}
		if err = a.openServerCloudflareRouteLocked(ctx, s, cfg); err != nil {
			failures = append(failures, fmt.Errorf("server %s: %w", id, err))
		}
	}
	return errors.Join(failures...)
}

// StartCloudflareReconciler repairs managed tunnel routes after restarts and every ten minutes.
func (a *App) StartCloudflareReconciler(ctx context.Context) {
	go func() {
		if err := a.reconcileCloudflareRoutes(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("Cloudflare route reconciliation: %v", err)
		}
		ticker := time.NewTicker(cloudflareReconcileEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.reconcileCloudflareRoutes(ctx); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("Cloudflare route reconciliation: %v", err)
				}
			}
		}
	}()
}

func (a *App) reconcileCloudflareRoutes(ctx context.Context) error {
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	cfg, err := a.readCloudflareConfig()
	if err != nil || !cfg.Enabled || !cfg.configured() {
		return err
	}
	workCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return a.syncRunningCloudflareRoutesLocked(workCtx, cfg)
}

func (a *App) resolveCloudflareZone(ctx context.Context, client *cfapi.Client, cfg cloudflareConfig) (string, error) {
	if cfg.ZoneID != "" {
		return cfg.ZoneID, nil
	}
	zones, err := client.ListZones(ctx, cfg.AccountID, cfg.BaseDomain)
	if err != nil {
		return "", fmt.Errorf("resolve Cloudflare zone: %w", err)
	}
	var matches []string
	for _, zone := range zones {
		if strings.EqualFold(zone.Name, cfg.BaseDomain) && zone.ID != "" {
			matches = append(matches, zone.ID)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected one Cloudflare zone named %s in account %s, found %d", cfg.BaseDomain, cfg.AccountID, len(matches))
	}
	_, err = a.db.ExecContext(ctx, `UPDATE cloudflare_settings SET zone_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND account_id=? AND base_domain=?`, matches[0], cfg.AccountID, cfg.BaseDomain)
	if err != nil {
		return "", fmt.Errorf("cache resolved Cloudflare zone ID: %w", err)
	}
	return matches[0], nil
}

func tunnelTarget(tunnelID string) string {
	return strings.ToLower(strings.TrimSuffix(tunnelID, ".") + cloudflareTunnelServiceEnd)
}

func (a *App) upsertCloudflareDNS(ctx context.Context, client *cfapi.Client, zoneID, hostname, tunnelID string) (cfapi.DNSRecord, error) {
	records, err := client.ListDNSRecords(ctx, zoneID, hostname)
	if err != nil {
		return cfapi.DNSRecord{}, fmt.Errorf("list Cloudflare DNS records for %s: %w", hostname, err)
	}
	var owned *cfapi.DNSRecord
	target := tunnelTarget(tunnelID)
	for i := range records {
		record := records[i]
		if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), hostname) {
			continue
		}
		if !strings.EqualFold(record.Type, "CNAME") {
			return cfapi.DNSRecord{}, fmt.Errorf("Cloudflare DNS conflict for %s: an existing %s record is not managed by Docklight", hostname, record.Type)
		}
		if !strings.EqualFold(strings.TrimSuffix(record.Content, "."), target) {
			return cfapi.DNSRecord{}, cfapi.ErrForeignTunnel
		}
		if owned != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("Cloudflare has multiple CNAME records for %s; resolve the duplicate before provisioning", hostname)
		}
		owned = &records[i]
	}
	if owned == nil {
		created, createErr := client.CreateDNSRecord(ctx, zoneID, cfapi.DNSRecord{Type: "CNAME", Name: hostname, Content: target, Proxied: true})
		if createErr != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("create proxied Cloudflare CNAME for %s: %w", hostname, createErr)
		}
		return created, nil
	}
	if !owned.Proxied || !strings.EqualFold(strings.TrimSuffix(owned.Content, "."), target) {
		owned.Content = target
		owned.Proxied = true
		updated, updateErr := client.UpdateDNSRecord(ctx, zoneID, *owned)
		if updateErr != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("update proxied Cloudflare CNAME for %s: %w", hostname, updateErr)
		}
		return updated, nil
	}
	return *owned, nil
}

func (a *App) deleteOwnedCloudflareDNS(ctx context.Context, client *cfapi.Client, zoneID, hostname, tunnelID string) error {
	records, err := client.ListDNSRecords(ctx, zoneID, hostname)
	if err != nil {
		return fmt.Errorf("inspect Cloudflare DNS before cleanup: %w", err)
	}
	target := tunnelTarget(tunnelID)
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), hostname) || !strings.EqualFold(record.Type, "CNAME") || !strings.EqualFold(strings.TrimSuffix(record.Content, "."), target) {
			continue
		}
		if err = client.DeleteDNSRecord(ctx, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete Docklight-owned Cloudflare CNAME for %s: %w", hostname, err)
		}
	}
	return nil
}

func cloudflareIngressRules(config map[string]json.RawMessage) ([]json.RawMessage, error) {
	raw := config["ingress"]
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, errors.New("Cloudflare returned an invalid Tunnel ingress configuration")
	}
	return rules, nil
}

func ingressRule(raw json.RawMessage) (cloudflareIngressRule, error) {
	var rule cloudflareIngressRule
	err := json.Unmarshal(raw, &rule)
	return rule, err
}

func upsertCloudflareIngress(config map[string]json.RawMessage, hostname, service string, owned cloudflareServerState) (map[string]json.RawMessage, bool, error) {
	rules, err := cloudflareIngressRules(config)
	if err != nil {
		return nil, false, err
	}
	terminalIndex := -1
	for i, raw := range rules {
		rule, parseErr := ingressRule(raw)
		if parseErr != nil {
			return nil, false, errors.New("Cloudflare returned an invalid Tunnel ingress rule")
		}
		if rule.Hostname == "" && rule.Service == "http_status:404" {
			terminalIndex = i
		}
	}
	var terminal json.RawMessage
	if terminalIndex >= 0 {
		terminal = rules[terminalIndex]
	}
	filtered := make([]json.RawMessage, 0, len(rules)+1)
	changed := false
	if terminalIndex >= 0 && terminalIndex != len(rules)-1 {
		changed = true
	}
	keptDesired := false
	for i, raw := range rules {
		rule, parseErr := ingressRule(raw)
		if parseErr != nil {
			return nil, false, errors.New("Cloudflare returned an invalid Tunnel ingress rule")
		}
		if i == terminalIndex {
			continue
		}
		isPlainTarget := strings.EqualFold(rule.Hostname, hostname) && rule.Path == ""
		if isPlainTarget && rule.Service == service && !keptDesired {
			filtered = append(filtered, raw)
			keptDesired = true
			continue
		}
		removeOld := owned.Hostname != "" && strings.EqualFold(rule.Hostname, owned.Hostname) && rule.Path == "" && rule.Service == owned.Service
		if removeOld {
			changed = true
			continue
		}
		if isPlainTarget {
			changed = true
			continue
		}
		filtered = append(filtered, raw)
	}
	if !keptDesired {
		managed, marshalErr := json.Marshal(cloudflareIngressRule{Hostname: hostname, Service: service})
		if marshalErr != nil {
			return nil, false, marshalErr
		}
		insertAt := len(filtered)
		if insertAt > 0 {
			last, parseErr := ingressRule(filtered[insertAt-1])
			if parseErr == nil && last.Hostname == "" && last.Service == "http_status:404" {
				insertAt--
			}
		}
		filtered = append(filtered, nil)
		copy(filtered[insertAt+1:], filtered[insertAt:])
		filtered[insertAt] = managed
		changed = true
	}
	if terminalIndex == -1 {
		terminal, err = json.Marshal(cloudflareIngressRule{Service: "http_status:404"})
		if err != nil {
			return nil, false, err
		}
		changed = true
	}
	filtered = append(filtered, terminal)
	if !changed {
		return config, false, nil
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, false, err
	}
	updated := make(map[string]json.RawMessage, len(config)+1)
	for key, value := range config {
		updated[key] = value
	}
	updated["ingress"] = encoded
	return updated, true, nil
}

func removeCloudflareIngress(config map[string]json.RawMessage, hostname, service string) (map[string]json.RawMessage, bool, error) {
	rules, err := cloudflareIngressRules(config)
	if err != nil {
		return nil, false, err
	}
	filtered := make([]json.RawMessage, 0, len(rules))
	changed := false
	for _, raw := range rules {
		rule, parseErr := ingressRule(raw)
		if parseErr != nil {
			return nil, false, errors.New("Cloudflare returned an invalid Tunnel ingress rule")
		}
		if strings.EqualFold(rule.Hostname, hostname) && rule.Service == service && rule.Path == "" {
			changed = true
			continue
		}
		filtered = append(filtered, raw)
	}
	if !changed {
		return config, false, nil
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, false, err
	}
	updated := make(map[string]json.RawMessage, len(config)+1)
	for key, value := range config {
		updated[key] = value
	}
	updated["ingress"] = encoded
	return updated, true, nil
}

func (a *App) cloudflaredTokenWarning(cfg cloudflareConfig) string {
	if cfg.TunnelID == "" {
		return ""
	}
	rows, err := a.db.Query(`SELECT name,env_json FROM servers WHERE gameskill_id='cloudflared' ORDER BY name`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var name, raw string
		if rows.Scan(&name, &raw) != nil {
			continue
		}
		var env map[string]string
		if json.Unmarshal([]byte(raw), &env) != nil {
			continue
		}
		token := strings.TrimSpace(env["TUNNEL_TOKEN"])
		if token == "" {
			continue
		}
		if strings.EqualFold(token, cfg.TunnelID) {
			return fmt.Sprintf("The managed cloudflared server %q has the tunnel ID saved as TUNNEL_TOKEN. It needs the tunnel connector token instead.", name)
		}
		tokenID := tokenTunnelID(token)
		if tokenID != "" && !strings.EqualFold(tokenID, cfg.TunnelID) {
			return fmt.Sprintf("The managed cloudflared server %q uses a connector token for a different tunnel.", name)
		}
	}
	return ""
}

func tokenTunnelID(token string) string {
	for _, decode := range []func(string) ([]byte, error){base64.RawURLEncoding.DecodeString, base64.URLEncoding.DecodeString, base64.RawStdEncoding.DecodeString, base64.StdEncoding.DecodeString} {
		decoded, err := decode(token)
		if err != nil {
			continue
		}
		var payload map[string]any
		if json.Unmarshal(decoded, &payload) == nil {
			for _, key := range []string{"tunnel_id", "tunnelId", "t"} {
				if value, ok := payload[key].(string); ok {
					return value
				}
			}
		}
		parts := strings.Split(string(decoded), ".")
		if len(parts) == 3 {
			if jwtPayload, decodeErr := base64.RawURLEncoding.DecodeString(parts[1]); decodeErr == nil {
				var payload map[string]any
				if json.Unmarshal(jwtPayload, &payload) == nil {
					for _, key := range []string{"tunnel_id", "tunnelId", "t"} {
						if value, ok := payload[key].(string); ok {
							return value
						}
					}
				}
			}
		}
	}
	return ""
}
