package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"example.com/yggdrasil-panel/internal/unifi"
)

const uniFiRequestTimeout = 20 * time.Second

var uniFiServerTagPattern = regexp.MustCompile(`(?i)^Docklight:\s*\[docklight:([a-z0-9_-]+)\]`)

type uniFiConfig struct {
	Enabled       bool
	ControllerURL string
	Username      string
	Password      string
	Site          string
}

type uniFiSettingsResponse struct {
	Enabled       bool   `json:"enabled"`
	Configured    bool   `json:"configured"`
	ControllerURL string `json:"controller_url"`
	UsernameSet   bool   `json:"username_configured"`
	PasswordSet   bool   `json:"password_configured"`
	Site          string `json:"site"`
}

type uniFiRuleResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol,omitempty"`
	ExternalPort   string `json:"external_port,omitempty"`
	InternalClient string `json:"internal_client,omitempty"`
	InternalPort   string `json:"internal_port,omitempty"`
	Enabled        bool   `json:"enabled"`
	ServerID       string `json:"server_id,omitempty"`
	Managed        bool   `json:"managed"`
	DocklightNamed bool   `json:"docklight_named"`
	Stray          bool   `json:"stray"`
}

type uniFiControllerRule = unifi.PortForward
type uniFiRuleCreate = unifi.PortForwardCreate

func (a *App) readUniFiConfig() (uniFiConfig, error) {
	var enabled int
	var usernameEnc, passwordEnc string
	var cfg uniFiConfig
	err := a.db.QueryRow(`SELECT enabled,controller_url,username_enc,password_enc,site FROM unifi_settings WHERE id=1`).Scan(&enabled, &cfg.ControllerURL, &usernameEnc, &passwordEnc, &cfg.Site)
	if errors.Is(err, sql.ErrNoRows) {
		return uniFiConfig{Site: "default"}, nil
	}
	if err != nil {
		return uniFiConfig{}, err
	}
	cfg.Enabled = enabled != 0
	for _, field := range []struct {
		name string
		enc  string
		out  *string
	}{{"username", usernameEnc, &cfg.Username}, {"password", passwordEnc, &cfg.Password}} {
		if field.enc == "" {
			continue
		}
		plain, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), field.enc)
		if decryptErr != nil {
			return uniFiConfig{}, fmt.Errorf("stored UniFi %s cannot be decrypted; check auth.secret_key", field.name)
		}
		*field.out = plain
	}
	if strings.TrimSpace(cfg.Site) == "" {
		cfg.Site = "default"
	}
	return cfg, nil
}

func (c uniFiConfig) configured() bool {
	return strings.TrimSpace(c.ControllerURL) != "" && strings.TrimSpace(c.Username) != "" && c.Password != ""
}

func summarizeUniFiConfig(c uniFiConfig) uniFiSettingsResponse {
	return uniFiSettingsResponse{
		Enabled: c.Enabled, Configured: c.configured(), ControllerURL: c.ControllerURL,
		UsernameSet: c.Username != "", PasswordSet: c.Password != "", Site: c.Site,
	}
}

func (a *App) getUniFiSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, err := a.readUniFiConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read UniFi settings")
		return
	}
	writeJSON(w, http.StatusOK, summarizeUniFiConfig(cfg))
}

func (a *App) updateUniFiSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled       *bool  `json:"enabled"`
		ControllerURL string `json:"controller_url"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		Site          string `json:"site"`
		ClearLogin    bool   `json:"clear_login"`
	}
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	a.unifiMu.Lock()
	defer a.unifiMu.Unlock()
	current, err := a.readUniFiConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current UniFi settings")
		return
	}
	next := uniFiConfig{Enabled: *in.Enabled, Site: strings.TrimSpace(in.Site)}
	if next.Site == "" {
		next.Site = "default"
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(next.Site) {
		writeError(w, http.StatusBadRequest, "site must contain only letters, numbers, underscores, or hyphens")
		return
	}
	next.ControllerURL, err = normalizeUniFiURL(in.ControllerURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.ClearLogin {
		if strings.TrimSpace(in.Username) == "" {
			next.Username = current.Username
		} else {
			next.Username = strings.TrimSpace(in.Username)
		}
		if in.Password == "" {
			next.Password = current.Password
		} else {
			next.Password = in.Password
		}
	}
	if next.Enabled && !next.configured() {
		writeError(w, http.StatusBadRequest, "controller URL, local username, and password are required before enabling UniFi forwarding")
		return
	}
	if !next.Enabled && (next.Username == "" || next.Password == "") {
		next.ControllerURL = current.ControllerURL
		next.Site = current.Site
	}

	credentialsChanged := current.ControllerURL != next.ControllerURL || current.Username != next.Username || current.Password != next.Password || current.Site != next.Site
	if current.configured() && (credentialsChanged || current.Enabled && !next.Enabled) {
		ctx, cancel := context.WithTimeout(r.Context(), uniFiRequestTimeout)
		cleanupErr := a.cleanupAllUniFiMappingsLocked(ctx, current)
		cancel()
		if cleanupErr != nil {
			writeError(w, http.StatusConflict, "saved UniFi rules could not be cleared; settings were not changed: "+cleanupErr.Error())
			return
		}
	}
	usernameEnc, passwordEnc := "", ""
	if next.Username != "" {
		usernameEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.Username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt UniFi username")
			return
		}
	}
	if next.Password != "" {
		passwordEnc, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), next.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt UniFi password")
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE unifi_settings SET enabled=?,controller_url=?,username_enc=?,password_enc=?,site=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(next.Enabled), next.ControllerURL, usernameEnc, passwordEnc, next.Site); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save UniFi settings")
		return
	}
	a.audit(principal(r), "unifi.settings", "network", "unifi", fmt.Sprintf("enabled=%t controller=%s", next.Enabled, next.ControllerURL))
	var syncErr error
	if next.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		syncErr = a.syncRunningUniFiMappingsLocked(ctx, next)
		cancel()
	}
	response := summarizeUniFiConfig(next)
	if syncErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"settings": response, "message": syncErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func normalizeUniFiURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter a valid UniFi controller URL using http or https, without credentials or query parameters")
	}
	if u.Port() != "" {
		if _, err = strconv.Atoi(u.Port()); err != nil {
			return "", errors.New("controller URL has an invalid port")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.TrimRight(u.String(), "/"), nil
}

func (a *App) testUniFiConnection(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readUniFiConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save a controller URL and local UniFi credentials first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), uniFiRequestTimeout)
	defer cancel()
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "site": cfg.Site, "port_forward_rules": len(rules)})
}

func (a *App) listUniFiRules(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readUniFiConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save a controller URL and local UniFi credentials first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), uniFiRequestTimeout)
	defer cancel()
	localIP, err := a.hostIPv4ForURL(ctx, cfg.ControllerURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a.presentUniFiRules(rules, localIP))
}

func (a *App) listUniFiStrayRules(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readUniFiConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save a controller URL and local UniFi credentials first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), uniFiRequestTimeout)
	defer cancel()
	localIP, err := a.hostIPv4ForURL(ctx, cfg.ControllerURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	all := a.presentUniFiRules(rules, localIP)
	strays := make([]uniFiRuleResponse, 0)
	for _, rule := range all {
		if rule.ID != "" && rule.Stray {
			strays = append(strays, rule)
		}
	}
	writeJSON(w, http.StatusOK, strays)
}

func (a *App) deleteUniFiStrayRules(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 100 {
		writeError(w, http.StatusBadRequest, "select between 1 and 100 stray rule IDs")
		return
	}
	cfg, err := a.readUniFiConfig()
	if err != nil || !cfg.configured() {
		writeError(w, http.StatusConflict, "save a controller URL and local UniFi credentials first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), uniFiRequestTimeout)
	defer cancel()
	localIP, err := a.hostIPv4ForURL(ctx, cfg.ControllerURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	byID := make(map[string]uniFiControllerRule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	deleted := 0
	seen := make(map[string]bool, len(in.IDs))
	for _, id := range in.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		rule, exists := byID[id]
		if !exists || !isDocklightRuleName(rule.Name) || !uniFiRuleTargetsIP(rule, localIP) {
			continue
		}
		var found int
		if parseUniFiServerTag(rule.Name) != "" && a.db.QueryRowContext(ctx, `SELECT 1 FROM servers WHERE id=?`, parseUniFiServerTag(rule.Name)).Scan(&found) == nil {
			continue
		}
		if err = controller.DeletePortForward(ctx, cfg.Site, id); err != nil {
			writeError(w, http.StatusBadGateway, "one or more selected Docklight stray rules could not be removed: "+err.Error())
			return
		}
		deleted++
	}
	a.audit(principal(r), "unifi.strays_delete", "network", "unifi", fmt.Sprintf("deleted=%d", deleted))
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

func uniFiRuleTargetsIP(rule uniFiControllerRule, ip net.IP) bool {
	return uniFiRuleTargetMatches(firstText(rule.Fwd, rule.Internal), ip)
}

func uniFiRuleTargetMatches(value string, ip net.IP) bool {
	target := net.ParseIP(value)
	return target != nil && ip != nil && target.Equal(ip)
}

func (a *App) presentUniFiRules(rules []uniFiControllerRule, localIP net.IP) []uniFiRuleResponse {
	out := make([]uniFiRuleResponse, 0, len(rules))
	for _, rule := range rules {
		serverID := parseUniFiServerTag(rule.Name)
		managed := false
		if serverID != "" {
			var found int
			managed = a.db.QueryRow(`SELECT 1 FROM servers WHERE id=?`, serverID).Scan(&found) == nil
		}
		stray := isDocklightRuleName(rule.Name) && !managed && uniFiRuleTargetsIP(rule, localIP)
		protocol := strings.ToLower(firstText(rule.Proto, rule.Protocol))
		if protocol == "tcp_udp" {
			protocol = "tcp+udp"
		}
		out = append(out, uniFiRuleResponse{
			ID: rule.ID, Name: rule.Name, Protocol: protocol,
			ExternalPort: rawText(rule.DstPort), InternalClient: firstText(rule.Fwd, rule.Internal),
			InternalPort: firstText(rawText(rule.FwdPort), rawText(rule.IntPort)),
			Enabled:      rule.Enabled, ServerID: serverID, Managed: managed, DocklightNamed: isDocklightRuleName(rule.Name), Stray: stray,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *App) newUniFiController(ctx context.Context, cfg uniFiConfig) (*unifi.Client, error) {
	return unifi.New(ctx, cfg.ControllerURL, cfg.Username, cfg.Password, a.unifiHTTPClient)
}

func rawText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil {
		return number.String()
	}
	return ""
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniFiServerTag(serverID string) string { return "Docklight: [docklight:" + serverID + "]" }

func parseUniFiServerTag(name string) string {
	match := uniFiServerTagPattern.FindStringSubmatch(strings.TrimSpace(name))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func isDocklightRuleName(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "docklight")
}

func (a *App) removeServerUniFiMappings(ctx context.Context, serverID string) error {
	a.unifiMu.Lock()
	defer a.unifiMu.Unlock()
	return a.removeServerUniFiMappingsLocked(ctx, serverID)
}

func (a *App) removeServerUniFiMappingsLocked(ctx context.Context, serverID string) error {
	cfg, err := a.readUniFiConfig()
	if err != nil {
		return err
	}
	return a.removeServerUniFiMappingsWithConfigLocked(ctx, serverID, cfg)
}

func (a *App) removeServerUniFiMappingsWithConfigLocked(ctx context.Context, serverID string, cfg uniFiConfig) error {
	var saved int
	if err := a.db.QueryRowContext(ctx, `SELECT count(*) FROM server_unifi_mappings WHERE server_id=?`, serverID).Scan(&saved); err != nil {
		return err
	}
	if !cfg.configured() {
		if saved > 0 {
			return a.recordUniFiError(serverID, errors.New("UniFi forwards are still recorded, but controller credentials are not configured"))
		}
		return nil
	}
	if !cfg.Enabled && saved == 0 {
		return nil
	}
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		return a.recordUniFiError(serverID, err)
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		return a.recordUniFiError(serverID, err)
	}
	for _, rule := range rules {
		if rule.ID == "" || parseUniFiServerTag(rule.Name) != serverID {
			continue
		}
		if err = controller.DeletePortForward(ctx, cfg.Site, rule.ID); err != nil {
			return a.recordUniFiError(serverID, err)
		}
		_, _ = a.db.ExecContext(ctx, `DELETE FROM server_unifi_mappings WHERE server_id=? AND rule_id=?`, serverID, rule.ID)
	}
	if _, err = a.db.ExecContext(ctx, `DELETE FROM server_unifi_mappings WHERE server_id=?`, serverID); err != nil {
		return a.recordUniFiError(serverID, err)
	}
	return a.recordUniFiError(serverID, nil)
}

func (a *App) openServerUniFiMappings(ctx context.Context, s Server) error {
	a.unifiMu.Lock()
	defer a.unifiMu.Unlock()
	cfg, err := a.readUniFiConfig()
	if err != nil {
		return err
	}
	return a.openServerUniFiMappingsLocked(ctx, s, cfg)
}

func (a *App) openServerUniFiMappingsLocked(ctx context.Context, s Server, cfg uniFiConfig) error {
	if !cfg.Enabled || !cfg.configured() || !s.AutoForward {
		return nil
	}
	if err := a.removeServerUniFiMappingsWithConfigLocked(ctx, s.ID, cfg); err != nil {
		return err
	}
	ip, err := a.hostIPv4ForURL(ctx, cfg.ControllerURL)
	if err != nil {
		return a.recordUniFiError(s.ID, err)
	}
	game, err := a.loadRune(s.GameskillID)
	if err != nil {
		return a.recordUniFiError(s.ID, fmt.Errorf("could not load the server template: %w", err))
	}
	desired := desiredUniFiMappings(s, game, ip.String())
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		return a.recordUniFiError(s.ID, err)
	}
	expected := make(map[string]bool, len(desired))
	createErrors := make(map[string]error)
	for _, mapping := range desired {
		if err = ctx.Err(); err != nil {
			return a.recordUniFiError(s.ID, err)
		}
		proto := uniFiControllerProtocol(mapping.Protocol)
		name := uniFiServerTag(s.ID) + " " + mapping.PortName + " " + proto + "/" + strconv.Itoa(int(mapping.ExternalPort))
		expected[name] = true
		rule := uniFiRuleCreate{Name: name, Enabled: true, Proto: proto, Source: "any", Destination: "any", DstPort: strconv.Itoa(int(mapping.ExternalPort)), ForwardTo: ip.String(), ForwardPort: strconv.Itoa(int(mapping.InternalPort))}
		if err = controller.CreatePortForward(ctx, cfg.Site, rule); err != nil {
			createErrors[name] = fmt.Errorf("%s/%d: %w", mapping.Protocol, mapping.ExternalPort, err)
		}
	}
	rules, listErr := controller.ListPortForwards(ctx, cfg.Site)
	var failures []error
	if listErr != nil {
		failures = append(failures, listErr)
		for _, createErr := range createErrors {
			failures = append(failures, createErr)
		}
	} else {
		confirmed := make(map[string]bool, len(expected))
		for _, rule := range rules {
			if rule.ID == "" || parseUniFiServerTag(rule.Name) != s.ID || !expected[rule.Name] {
				continue
			}
			confirmed[rule.Name] = true
			proto := strings.ToUpper(firstText(rule.Proto, rule.Protocol))
			if proto == "TCP_UDP" || proto == "TCP+UDP" {
				proto = "TCP+UDP"
			}
			_, saveErr := a.db.ExecContext(ctx, `INSERT INTO server_unifi_mappings(server_id,rule_id,controller_url,rule_name,protocol,external_port,internal_port,internal_client)
				VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(server_id,rule_id) DO UPDATE SET controller_url=excluded.controller_url,rule_name=excluded.rule_name,protocol=excluded.protocol,external_port=excluded.external_port,internal_port=excluded.internal_port,internal_client=excluded.internal_client`,
				s.ID, rule.ID, cfg.ControllerURL, rule.Name, proto, numericPort(rawText(rule.DstPort)), numericPort(firstText(rawText(rule.FwdPort), rawText(rule.IntPort))), firstText(rule.Fwd, rule.Internal))
			if saveErr != nil {
				failures = append(failures, saveErr)
			}
		}
		for name := range expected {
			if confirmed[name] {
				continue
			}
			if createErr := createErrors[name]; createErr != nil {
				failures = append(failures, createErr)
			} else {
				failures = append(failures, fmt.Errorf("UniFi did not confirm rule %q after creation", name))
			}
		}
	}
	return a.recordUniFiError(s.ID, errors.Join(failures...))
}

func numericPort(value string) int {
	port, _ := strconv.Atoi(value)
	return port
}

func desiredUniFiMappings(s Server, game rune.Rune, hostIP string) []serverUPnPMapping {
	base := desiredServerMappings(s, game, hostIP)
	var desired []serverUPnPMapping
	for i := 0; i < len(base); i++ {
		mapping := base[i]
		if mapping.Protocol == "TCP" && i+1 < len(base) && base[i+1].Protocol == "UDP" && sameUniFiPortTarget(mapping, base[i+1]) {
			mapping.Protocol = "TCP+UDP"
			i++
		}
		desired = append(desired, mapping)
	}
	return desired
}

func sameUniFiPortTarget(left, right serverUPnPMapping) bool {
	return left.ServerID == right.ServerID && left.PortName == right.PortName && left.ExternalPort == right.ExternalPort && left.InternalPort == right.InternalPort && left.InternalClient == right.InternalClient
}

func uniFiControllerProtocol(protocol string) string {
	switch strings.ToUpper(protocol) {
	case "TCP+UDP", "TCP_UDP":
		return "tcp_udp"
	case "UDP":
		return "udp"
	default:
		return "tcp"
	}
}

func (a *App) hostIPv4ForURL(ctx context.Context, targetURL string) (net.IP, error) {
	if a.hostLocalIP != nil {
		return a.hostLocalIP(ctx, targetURL)
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("could not determine a LAN address for the server host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, errors.New("could not resolve the configured service address")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", address.String())
	if err != nil {
		return nil, errors.New("could not determine the host LAN address from its route to the configured service")
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil || local.IP.IsLoopback() || local.IP.IsUnspecified() || local.IP.IsLinkLocalUnicast() {
		return nil, errors.New("network forwarding requires a usable host LAN IPv4 address")
	}
	return append(net.IP(nil), local.IP.To4()...), nil
}

func (a *App) recordUniFiError(serverID string, err error) error {
	message := ""
	if err != nil {
		message = err.Error()
	}
	if _, dbErr := a.db.Exec(`INSERT INTO server_unifi_state(server_id,last_error,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(server_id) DO UPDATE SET last_error=excluded.last_error,updated_at=CURRENT_TIMESTAMP`, serverID, message); dbErr != nil {
		if err != nil {
			return errors.Join(err, dbErr)
		}
		return dbErr
	}
	return err
}

func (a *App) cleanupAllUniFiMappingsLocked(ctx context.Context, cfg uniFiConfig) error {
	if !cfg.configured() {
		return nil
	}
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT server_id FROM server_unifi_mappings ORDER BY server_id`)
	if err != nil {
		return err
	}
	ids := make([]string, 0)
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
	// Also scan every local server so rules survive a lost local ownership row.
	rows, err = a.db.QueryContext(ctx, `SELECT id FROM servers ORDER BY id`)
	if err != nil {
		return err
	}
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
	sort.Strings(ids)
	controller, err := a.newUniFiController(ctx, cfg)
	if err != nil {
		return err
	}
	rules, err := controller.ListPortForwards(ctx, cfg.Site)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	for _, rule := range rules {
		serverID := parseUniFiServerTag(rule.Name)
		if serverID == "" || !wanted[serverID] || rule.ID == "" {
			continue
		}
		if err = controller.DeletePortForward(ctx, cfg.Site, rule.ID); err != nil {
			return fmt.Errorf("%s: %w", serverID, err)
		}
	}
	if _, err = a.db.ExecContext(ctx, `DELETE FROM server_unifi_mappings`); err != nil {
		return err
	}
	for _, id := range ids {
		_ = a.recordUniFiError(id, nil)
	}
	return nil
}

func (a *App) syncRunningUniFiMappingsLocked(ctx context.Context, cfg uniFiConfig) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM servers WHERE auto_forward=1 AND installed=1 AND status IN ('running','starting') ORDER BY id`)
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
	var servers []Server
	for _, id := range ids {
		s, loadErr := a.getServer(id)
		if loadErr != nil {
			return loadErr
		}
		servers = append(servers, s)
	}
	var failures []error
	for _, s := range servers {
		if err = a.openServerUniFiMappingsLocked(ctx, s, cfg); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", s.ID, err))
		}
	}
	return errors.Join(failures...)
}
