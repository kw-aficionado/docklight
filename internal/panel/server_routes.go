package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	cfapi "example.com/yggdrasil-panel/internal/cloudflare"
	"example.com/yggdrasil-panel/internal/npm"
	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

type serverRoute struct {
	ID                string `json:"id,omitempty"`
	ServerID          string `json:"server_id,omitempty"`
	Hostname          string `json:"hostname"`
	PortName          string `json:"port_name"`
	Primary           bool   `json:"primary,omitempty"`
	PrimaryProvider   string `json:"primary_provider,omitempty"`
	CFService         string `json:"-"`
	CFDNSRecordID     string `json:"-"`
	CFLastError       string `json:"cf_last_error,omitempty"`
	CFCleanupPending  bool   `json:"cf_cleanup_pending,omitempty"`
	NPMHostID         string `json:"-"`
	NPMLastError      string `json:"npm_last_error,omitempty"`
	NPMCleanupPending bool   `json:"npm_cleanup_pending,omitempty"`
	DeletePending     bool   `json:"delete_pending"`
	CFActive          bool   `json:"cf_active"`
	NPMActive         bool   `json:"npm_active"`
	CFEnabled         bool   `json:"cf_enabled"`
	NPMEnabled        bool   `json:"npm_enabled"`
}

func scanServerRoute(row interface{ Scan(...any) error }) (serverRoute, error) {
	var route serverRoute
	var cfPending, npmPending, deleting int
	err := row.Scan(&route.ID, &route.ServerID, &route.Hostname, &route.PortName, &route.CFService, &route.CFDNSRecordID, &route.CFLastError, &cfPending, &route.NPMHostID, &route.NPMLastError, &npmPending, &deleting)
	route.CFCleanupPending = cfPending != 0
	route.NPMCleanupPending = npmPending != 0
	route.DeletePending = deleting != 0
	route.CFActive = route.CFService != "" && !route.CFCleanupPending
	route.NPMActive = route.NPMHostID != "" && !route.NPMCleanupPending
	return route, err
}

const serverRouteColumns = `id,server_id,hostname,port_name,cf_service,cf_dns_record_id,cf_last_error,cf_cleanup_pending,npm_host_id,npm_last_error,npm_cleanup_pending,delete_pending`

func (a *App) serverRoutes(ctx context.Context, serverID string) ([]serverRoute, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT `+serverRouteColumns+` FROM server_routes WHERE server_id=? ORDER BY created_at,id`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []serverRoute
	for rows.Next() {
		route, scanErr := scanServerRoute(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

func (a *App) serverRoute(ctx context.Context, routeID string) (serverRoute, error) {
	return scanServerRoute(a.db.QueryRowContext(ctx, `SELECT `+serverRouteColumns+` FROM server_routes WHERE id=?`, routeID))
}

func (a *App) saveServerRouteCloudflare(ctx context.Context, route serverRoute) error {
	_, err := a.db.ExecContext(ctx, `UPDATE server_routes SET cf_service=?,cf_dns_record_id=?,cf_last_error=?,cf_cleanup_pending=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, route.CFService, route.CFDNSRecordID, route.CFLastError, boolInt(route.CFCleanupPending), route.ID)
	return err
}

func (a *App) saveServerRouteNPM(ctx context.Context, route serverRoute) error {
	_, err := a.db.ExecContext(ctx, `UPDATE server_routes SET npm_host_id=?,npm_last_error=?,npm_cleanup_pending=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, route.NPMHostID, route.NPMLastError, boolInt(route.NPMCleanupPending), route.ID)
	return err
}

func (a *App) listServerRoutes(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.view", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	extraRoutes, err := a.serverRoutes(r.Context(), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list server hostnames")
		return
	}
	cfCfg, cfErr := a.readCloudflareConfig()
	npmCfg, npmErr := a.readNPMConfig()
	if cfErr != nil || npmErr != nil {
		writeError(w, http.StatusInternalServerError, "could not read hostname provider settings")
		return
	}
	var cfValue, npmValue string
	if err = a.db.QueryRowContext(r.Context(), `SELECT cf_hostname,npm_subdomain FROM servers WHERE id=?`, s.ID).Scan(&cfValue, &npmValue); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read primary hostname settings")
		return
	}
	routes := make([]serverRoute, 0, len(extraRoutes)+2)
	if hostname, hostErr := cloudflareHostname(cfValue, cfCfg.BaseDomain); hostErr == nil && hostname != "" {
		state, stateErr := a.readServerCloudflareState(r.Context(), s.ID)
		if stateErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read primary Cloudflare route state")
			return
		}
		routes = append(routes, serverRoute{ServerID: s.ID, Hostname: hostname, Primary: true, PrimaryProvider: "cloudflare", CFLastError: state.LastError, CFCleanupPending: state.CleanupPending, CFActive: state.Hostname == hostname && !state.CleanupPending, CFEnabled: cfCfg.Enabled && cfCfg.configured()})
	}
	if hostname, hostErr := npmHostname(npmValue, npmCfg.BaseDomain); hostErr == nil && hostname != "" {
		state, stateErr := a.readServerNPMState(r.Context(), s.ID)
		if stateErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read primary NPM route state")
			return
		}
		routes = append(routes, serverRoute{ServerID: s.ID, Hostname: hostname, Primary: true, PrimaryProvider: "npm", NPMLastError: state.LastError, NPMCleanupPending: state.CleanupPending, NPMActive: state.HostID != "" && !state.CleanupPending, NPMEnabled: npmCfg.Enabled && npmCfg.configured()})
	}
	for i := range extraRoutes {
		extraRoutes[i].CFEnabled = cfCfg.Enabled && cfCfg.configured()
		extraRoutes[i].NPMEnabled = npmCfg.Enabled && npmCfg.configured()
		routes = append(routes, extraRoutes[i])
	}
	writeJSON(w, http.StatusOK, routes)
}

func (a *App) createServerRoute(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
		PortName string `json:"port_name"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	hostname, err := normalizeNPMDomain(in.Hostname, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "hostname: "+err.Error())
		return
	}
	in.PortName = strings.TrimSpace(in.PortName)
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		writeError(w, http.StatusConflict, "could not load the server template: "+err.Error())
		return
	}
	if _, _, err = serverRouteTarget(s, gs, in.PortName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	npmCfg, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager settings")
		return
	}
	cfCfg, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare settings")
		return
	}
	if cfCfg.Enabled && cfCfg.BaseDomain != "" {
		if _, err = cloudflareHostname(hostname, cfCfg.BaseDomain); err != nil {
			writeError(w, http.StatusBadRequest, "Cloudflare Tunnel: "+err.Error())
			return
		}
	}
	if otherServer, provider, inUse, checkErr := a.serverRouteHostnameInUse(r.Context(), hostname, npmCfg, cfCfg); checkErr != nil {
		writeError(w, http.StatusInternalServerError, "could not check hostname ownership")
		return
	} else if inUse {
		writeError(w, http.StatusConflict, fmt.Sprintf("hostname %s is already assigned through %s to server %s", hostname, provider, otherServer))
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a hostname route ID")
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO server_routes(id,server_id,hostname,port_name) VALUES(?,?,?,?)`, id, s.ID, hostname, in.PortName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save server hostname")
		return
	}
	a.audit(principal(r), "server.route_add", "server", s.ID, "hostname="+hostname+" port_name="+in.PortName)
	if s.Status == "running" || s.Status == "starting" {
		if npmCfg.Enabled {
			ctx, cancel := context.WithTimeout(r.Context(), npmRequestTimeout)
			a.npmMu.Lock()
			route, loadErr := a.serverRoute(ctx, id)
			var routeErr error
			if loadErr == nil {
				activeConfig, configErr := a.readNPMConfig()
				if configErr != nil {
					routeErr = configErr
				} else if activeConfig.Enabled {
					routeErr = a.openServerExtraNPMRouteLocked(ctx, s, route, activeConfig)
				}
			}
			a.npmMu.Unlock()
			cancel()
			if routeErr != nil {
				a.audit(User{Username: "system"}, "server.route_npm_error", "server", s.ID, routeErr.Error())
			}
			if loadErr != nil {
				a.audit(User{Username: "system"}, "server.route_npm_error", "server", s.ID, loadErr.Error())
			}
		}
		if cfCfg.Enabled {
			ctx, cancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
			a.cfMu.Lock()
			route, loadErr := a.serverRoute(ctx, id)
			var routeErr error
			if loadErr == nil {
				activeConfig, configErr := a.readCloudflareConfig()
				if configErr != nil {
					routeErr = configErr
				} else if activeConfig.Enabled {
					routeErr = a.openServerExtraCloudflareRouteLocked(ctx, s, route, activeConfig)
				}
			}
			a.cfMu.Unlock()
			cancel()
			if routeErr != nil {
				a.audit(User{Username: "system"}, "server.route_cloudflare_error", "server", s.ID, routeErr.Error())
			}
			if loadErr != nil {
				a.audit(User{Username: "system"}, "server.route_cloudflare_error", "server", s.ID, loadErr.Error())
			}
		}
	}
	route, err := a.serverRoute(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hostname was saved but its status could not be read")
		return
	}
	if currentCF, readErr := a.readCloudflareConfig(); readErr == nil {
		route.CFEnabled = currentCF.Enabled && currentCF.configured()
	}
	if currentNPM, readErr := a.readNPMConfig(); readErr == nil {
		route.NPMEnabled = currentNPM.Enabled && currentNPM.configured()
	}
	writeJSON(w, http.StatusCreated, route)
}

func (a *App) deleteServerRoute(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	routeID := chi.URLParam(r, "routeID")
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	route, err := a.serverRoute(r.Context(), routeID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && route.ServerID != s.ID {
		writeError(w, http.StatusNotFound, "hostname route not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read hostname route")
		return
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE server_routes SET delete_pending=1,updated_at=CURRENT_TIMESTAMP WHERE id=?`, route.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not mark hostname for removal")
		return
	}
	var failures []error
	cfCtx, cfCancel := context.WithTimeout(r.Context(), cloudflareRequestTimeout)
	a.cfMu.Lock()
	if route, err = a.serverRoute(cfCtx, route.ID); err == nil {
		if route.CFService != "" || route.CFDNSRecordID != "" || route.CFCleanupPending {
			err = a.removeServerExtraCloudflareRouteLocked(cfCtx, route)
		} else {
			err = nil
		}
	}
	a.cfMu.Unlock()
	cfCancel()
	if err != nil {
		failures = append(failures, fmt.Errorf("Cloudflare: %w", err))
	}
	npmCtx, npmCancel := context.WithTimeout(r.Context(), npmRequestTimeout)
	a.npmMu.Lock()
	if route, err = a.serverRoute(npmCtx, route.ID); err == nil {
		if route.NPMHostID != "" || route.NPMCleanupPending {
			npmCfg, cfgErr := a.readNPMConfig()
			if cfgErr != nil {
				err = cfgErr
			} else {
				err = a.removeServerExtraNPMRouteLocked(npmCtx, route, npmCfg)
			}
		} else {
			err = nil
		}
	}
	a.npmMu.Unlock()
	npmCancel()
	if err != nil {
		failures = append(failures, fmt.Errorf("Nginx Proxy Manager: %w", err))
	}
	if len(failures) > 0 {
		writeError(w, http.StatusServiceUnavailable, "route is marked for removal; retry after correcting the provider connection: "+errors.Join(failures...).Error())
		return
	}
	if err = a.finalizeDeletedServerRoute(r.Context(), route.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "provider routes were removed but the saved hostname could not be forgotten")
		return
	}
	a.audit(principal(r), "server.route_remove", "server", s.ID, "hostname="+route.Hostname)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) finalizeDeletedServerRoute(ctx context.Context, routeID string) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM server_routes WHERE id=? AND delete_pending=1 AND cf_service='' AND cf_dns_record_id='' AND cf_cleanup_pending=0 AND npm_host_id='' AND npm_cleanup_pending=0`, routeID)
	return err
}

func (a *App) serverRouteHostnameInUse(ctx context.Context, hostname string, npmCfg npmConfig, cfCfg cloudflareConfig) (string, string, bool, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,cf_hostname,npm_subdomain FROM servers ORDER BY id`)
	if err != nil {
		return "", "", false, err
	}
	for rows.Next() {
		var serverID, cfName, npmName string
		if err = rows.Scan(&serverID, &cfName, &npmName); err != nil {
			rows.Close()
			return "", "", false, err
		}
		if resolved, resolveErr := cloudflareHostname(cfName, cfCfg.BaseDomain); resolveErr == nil && strings.EqualFold(resolved, hostname) {
			rows.Close()
			return serverID, "Cloudflare", true, nil
		}
		if resolved, resolveErr := npmHostname(npmName, npmCfg.BaseDomain); resolveErr == nil && strings.EqualFold(resolved, hostname) {
			rows.Close()
			return serverID, "Nginx Proxy Manager", true, nil
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", "", false, err
	}
	rows.Close()
	var serverID string
	err = a.db.QueryRowContext(ctx, `SELECT server_id FROM server_routes WHERE lower(hostname)=lower(?) LIMIT 1`, hostname).Scan(&serverID)
	if err == nil {
		return serverID, "server route", true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", false, err
	}
	return "", "", false, nil
}

func (a *App) serverRouteProviderHostnameInUse(ctx context.Context, hostname, provider, exceptRouteID, exceptServerID string, npmCfg npmConfig, cfCfg cloudflareConfig) (string, bool, error) {
	column := "npm_subdomain"
	baseDomain := npmCfg.BaseDomain
	if provider == "cloudflare" {
		column = "cf_hostname"
		baseDomain = cfCfg.BaseDomain
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,`+column+` FROM servers ORDER BY id`)
	if err != nil {
		return "", false, err
	}
	for rows.Next() {
		var serverID, configured string
		if err = rows.Scan(&serverID, &configured); err != nil {
			rows.Close()
			return "", false, err
		}
		if serverID == exceptServerID {
			continue
		}
		var resolved string
		if provider == "cloudflare" {
			resolved, err = cloudflareHostname(configured, baseDomain)
		} else {
			resolved, err = npmHostname(configured, baseDomain)
		}
		if err == nil && strings.EqualFold(resolved, hostname) {
			rows.Close()
			return serverID, true, nil
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", false, err
	}
	rows.Close()
	rows, err = a.db.QueryContext(ctx, `SELECT id,server_id,hostname FROM server_routes WHERE id<>? ORDER BY server_id,created_at,id`, exceptRouteID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var routeID, serverID, saved string
		if err = rows.Scan(&routeID, &serverID, &saved); err != nil {
			return "", false, err
		}
		if strings.EqualFold(saved, hostname) {
			return serverID, true, nil
		}
	}
	return "", false, rows.Err()
}

func serverRouteTarget(s Server, gs rune.Rune, portName string) (string, int, error) {
	if portName == "" {
		name, port := npmProxyPort(s, gs)
		if port == 0 {
			return "", 0, errors.New("this server has no published TCP port to route")
		}
		return name, port, nil
	}
	for _, declared := range gs.Ports {
		if declared.Name != portName {
			continue
		}
		if !portHasTCP(declared.Protocol) {
			return "", 0, fmt.Errorf("port %s does not support TCP", portName)
		}
		port := s.Ports[portName]
		if port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("port %s is not allocated on this server", portName)
		}
		return portName, port, nil
	}
	return "", 0, fmt.Errorf("port %s is not declared by this server template", portName)
}

func (a *App) openServerExtraCloudflareRoutesLocked(ctx context.Context, s Server, cfg cloudflareConfig) error {
	return a.reconcileServerExtraCloudflareRoutesLocked(ctx, s.ID, &s, cfg)
}

func (a *App) reconcileServerExtraCloudflareRoutesLocked(ctx context.Context, serverID string, running *Server, cfg cloudflareConfig) error {
	routes, err := a.serverRoutes(ctx, serverID)
	if err != nil {
		return err
	}
	var failures []error
	for _, route := range routes {
		if route.DeletePending || running == nil || running.Status != "running" && running.Status != "starting" {
			if err = a.removeServerExtraCloudflareRouteLocked(ctx, route); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", route.Hostname, err))
			} else if route.DeletePending {
				if err = a.finalizeDeletedServerRoute(ctx, route.ID); err != nil {
					failures = append(failures, fmt.Errorf("%s: could not forget removed route: %w", route.Hostname, err))
				}
			}
			continue
		}
		if err = a.openServerExtraCloudflareRouteLocked(ctx, *running, route, cfg); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", route.Hostname, err))
		}
	}
	return errors.Join(failures...)
}

func (a *App) openServerExtraCloudflareRouteLocked(ctx context.Context, s Server, route serverRoute, cfg cloudflareConfig) error {
	if route.DeletePending {
		return a.removeServerExtraCloudflareRouteLocked(ctx, route)
	}
	if !cfg.Enabled {
		return nil
	}
	if !cfg.configured() {
		err := errors.New("Cloudflare Tunnel routes are enabled but not configured")
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	hostname, err := cloudflareHostname(route.Hostname, cfg.BaseDomain)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	if serverID, inUse, checkErr := a.serverRouteProviderHostnameInUse(ctx, hostname, "cloudflare", route.ID, "", npmConfig{}, cfg); checkErr != nil {
		route.CFLastError = checkErr.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return checkErr
	} else if inUse {
		route.CFLastError = fmt.Sprintf("hostname is already assigned through Cloudflare to server %s", serverID)
		_ = a.saveServerRouteCloudflare(ctx, route)
		return errors.New(route.CFLastError)
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	_, hostPort, err := serverRouteTarget(s, gs, route.PortName)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	forwardHost, warning := a.cloudflareForwardHost(ctx, cfg)
	if forwardHost == "" {
		route.CFLastError = warning
		_ = a.saveServerRouteCloudflare(ctx, route)
		return errors.New(warning)
	}
	service := "http://" + net.JoinHostPort(forwardHost, fmt.Sprint(hostPort))
	client := a.cloudflareClient(cfg)
	zoneID, err := a.resolveCloudflareZone(ctx, client, cfg)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	tunnelConfig, err := client.GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
	if err != nil {
		route.CFLastError = "read Cloudflare Tunnel configuration: " + err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return errors.New(route.CFLastError)
	}
	rules, err := cloudflareIngressRules(tunnelConfig.Config)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	matched := 0
	for _, raw := range rules {
		rule, parseErr := ingressRule(raw)
		if parseErr != nil {
			route.CFLastError = "Cloudflare returned an invalid Tunnel ingress rule"
			_ = a.saveServerRouteCloudflare(ctx, route)
			return errors.New(route.CFLastError)
		}
		if strings.EqualFold(rule.Hostname, hostname) && rule.Path == "" {
			matched++
			if route.CFService == "" || rule.Service != route.CFService {
				route.CFLastError = "Cloudflare already has an ingress rule for this hostname that Docklight does not own"
				_ = a.saveServerRouteCloudflare(ctx, route)
				return errors.New(route.CFLastError)
			}
		}
	}
	if matched > 1 {
		route.CFLastError = "Cloudflare has duplicate ingress rules for this hostname; resolve them before provisioning"
		_ = a.saveServerRouteCloudflare(ctx, route)
		return errors.New(route.CFLastError)
	}
	owned := cloudflareServerState{Hostname: hostname, Service: route.CFService, DNSRecordID: route.CFDNSRecordID}
	route.CFService = service
	route.CFCleanupPending = true
	route.CFLastError = ""
	if err = a.saveServerRouteCloudflare(ctx, route); err != nil {
		return err
	}
	updated, changed, err := upsertCloudflareIngress(tunnelConfig.Config, hostname, service, owned)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	if changed {
		if err = client.UpdateTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID, updated); err != nil {
			route.CFLastError = "update Cloudflare Tunnel ingress: " + err.Error()
			_ = a.saveServerRouteCloudflare(ctx, route)
			return errors.New(route.CFLastError)
		}
	}
	record, err := a.upsertExtraCloudflareDNS(ctx, client, zoneID, route, cfg.TunnelID)
	if err != nil {
		route.CFCleanupPending = false
		route.CFLastError = "Tunnel route is active but DNS could not be reconciled: " + err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		a.audit(User{Username: "system"}, "server.route_cloudflare_warning", "server", s.ID, route.CFLastError)
		return errors.New(route.CFLastError)
	}
	route.CFDNSRecordID = record.ID
	route.CFCleanupPending = false
	route.CFLastError = warning
	if err = a.saveServerRouteCloudflare(ctx, route); err != nil {
		return fmt.Errorf("route and DNS were created but Docklight could not save ownership: %w", err)
	}
	if warning != "" {
		a.audit(User{Username: "system"}, "server.route_cloudflare_warning", "server", s.ID, warning)
	}
	return nil
}

func (a *App) removeServerExtraCloudflareRouteLocked(ctx context.Context, route serverRoute) error {
	if route.CFService == "" && route.CFDNSRecordID == "" && !route.CFCleanupPending {
		return nil
	}
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		return err
	}
	if !cfg.configured() {
		err = errors.New("Cloudflare ownership is recorded but API credentials are unavailable")
		route.CFCleanupPending = true
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	route.CFCleanupPending = true
	if err = a.saveServerRouteCloudflare(ctx, route); err != nil {
		return err
	}
	client := a.cloudflareClient(cfg)
	zoneID, err := a.resolveCloudflareZone(ctx, client, cfg)
	if err != nil {
		route.CFLastError = err.Error()
		_ = a.saveServerRouteCloudflare(ctx, route)
		return err
	}
	if route.CFService != "" {
		config, getErr := client.GetTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID)
		if getErr != nil {
			route.CFLastError = "read Cloudflare Tunnel configuration for cleanup: " + getErr.Error()
			_ = a.saveServerRouteCloudflare(ctx, route)
			return errors.New(route.CFLastError)
		}
		updated, changed, removeErr := removeCloudflareIngress(config.Config, route.Hostname, route.CFService)
		if removeErr != nil {
			route.CFLastError = removeErr.Error()
			_ = a.saveServerRouteCloudflare(ctx, route)
			return removeErr
		}
		if changed {
			if err = client.UpdateTunnelConfiguration(ctx, cfg.AccountID, cfg.TunnelID, updated); err != nil {
				route.CFLastError = "remove Cloudflare Tunnel ingress: " + err.Error()
				_ = a.saveServerRouteCloudflare(ctx, route)
				return errors.New(route.CFLastError)
			}
		}
	}
	if route.CFDNSRecordID != "" {
		if err = a.deleteExtraCloudflareDNS(ctx, client, zoneID, route, cfg.TunnelID); err != nil {
			route.CFLastError = err.Error()
			_ = a.saveServerRouteCloudflare(ctx, route)
			return err
		}
	}
	route.CFService = ""
	route.CFDNSRecordID = ""
	route.CFLastError = ""
	route.CFCleanupPending = false
	if err = a.saveServerRouteCloudflare(ctx, route); err != nil {
		return err
	}
	return nil
}

func (a *App) deleteExtraCloudflareDNS(ctx context.Context, client *cfapi.Client, zoneID string, route serverRoute, tunnelID string) error {
	records, err := client.ListDNSRecords(ctx, zoneID, route.Hostname)
	if err != nil {
		return fmt.Errorf("inspect Cloudflare DNS before cleanup: %w", err)
	}
	for _, record := range records {
		if record.ID != route.CFDNSRecordID {
			continue
		}
		if !strings.EqualFold(record.Type, "CNAME") || !strings.EqualFold(strings.TrimSuffix(record.Name, "."), route.Hostname) || !strings.EqualFold(strings.TrimSuffix(record.Content, "."), tunnelTarget(tunnelID)) {
			return errors.New("saved Cloudflare DNS record no longer matches Docklight's tunnel ownership; left it untouched")
		}
		if err = client.DeleteDNSRecord(ctx, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete Docklight-owned Cloudflare DNS record for %s: %w", route.Hostname, err)
		}
		break
	}
	return nil
}

func (a *App) upsertExtraCloudflareDNS(ctx context.Context, client *cfapi.Client, zoneID string, route serverRoute, tunnelID string) (cfapi.DNSRecord, error) {
	records, err := client.ListDNSRecords(ctx, zoneID, route.Hostname)
	if err != nil {
		return cfapi.DNSRecord{}, fmt.Errorf("list Cloudflare DNS records for %s: %w", route.Hostname, err)
	}
	var owned *cfapi.DNSRecord
	for i := range records {
		record := &records[i]
		if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), route.Hostname) {
			continue
		}
		if route.CFDNSRecordID == "" || record.ID != route.CFDNSRecordID {
			return cfapi.DNSRecord{}, fmt.Errorf("Cloudflare DNS conflict for %s: an existing record is not recorded as Docklight-owned", route.Hostname)
		}
		if !strings.EqualFold(record.Type, "CNAME") || !strings.EqualFold(strings.TrimSuffix(record.Content, "."), tunnelTarget(tunnelID)) {
			return cfapi.DNSRecord{}, fmt.Errorf("saved Cloudflare DNS record for %s no longer points to this Tunnel; left it untouched", route.Hostname)
		}
		if owned != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("Cloudflare has multiple DNS records for %s; resolve the duplicate before provisioning", route.Hostname)
		}
		owned = record
	}
	if owned == nil {
		created, createErr := client.CreateDNSRecord(ctx, zoneID, cfapi.DNSRecord{Type: "CNAME", Name: route.Hostname, Content: tunnelTarget(tunnelID), Proxied: true})
		if createErr != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("create proxied Cloudflare CNAME for %s: %w", route.Hostname, createErr)
		}
		return created, nil
	}
	if !owned.Proxied {
		owned.Proxied = true
		updated, updateErr := client.UpdateDNSRecord(ctx, zoneID, *owned)
		if updateErr != nil {
			return cfapi.DNSRecord{}, fmt.Errorf("enable proxying for Docklight-owned CNAME %s: %w", route.Hostname, updateErr)
		}
		return updated, nil
	}
	return *owned, nil
}

func (a *App) cleanupAllExtraCloudflareRoutesLocked(ctx context.Context) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM server_routes WHERE cf_service<>'' OR cf_dns_record_id<>'' OR cf_cleanup_pending=1 OR delete_pending=1 ORDER BY server_id,created_at,id`)
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
		route, loadErr := a.serverRoute(ctx, id)
		if loadErr == nil {
			loadErr = a.removeServerExtraCloudflareRouteLocked(ctx, route)
			if loadErr == nil && route.DeletePending {
				loadErr = a.finalizeDeletedServerRoute(ctx, route.ID)
			}
		}
		if loadErr != nil {
			failures = append(failures, fmt.Errorf("route %s: %w", id, loadErr))
		}
	}
	return errors.Join(failures...)
}

func (a *App) reconcileAllExtraCloudflareRoutesLocked(ctx context.Context, cfg cloudflareConfig, running map[string]bool) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM server_routes ORDER BY server_id,created_at,id`)
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
		route, loadErr := a.serverRoute(ctx, id)
		if loadErr != nil {
			failures = append(failures, loadErr)
			continue
		}
		if route.DeletePending || !running[route.ServerID] {
			loadErr = a.removeServerExtraCloudflareRouteLocked(ctx, route)
			if loadErr == nil && route.DeletePending {
				loadErr = a.finalizeDeletedServerRoute(ctx, route.ID)
			}
		} else {
			server, getErr := a.getServer(route.ServerID)
			if getErr != nil {
				loadErr = getErr
			} else {
				loadErr = a.openServerExtraCloudflareRouteLocked(ctx, server, route, cfg)
			}
		}
		if loadErr != nil {
			failures = append(failures, fmt.Errorf("route %s: %w", id, loadErr))
		}
	}
	return errors.Join(failures...)
}

func (a *App) openServerExtraNPMRoutesLocked(ctx context.Context, s Server, cfg npmConfig) error {
	return a.reconcileServerExtraNPMRoutesLocked(ctx, s.ID, &s, cfg)
}

func (a *App) reconcileServerExtraNPMRoutesLocked(ctx context.Context, serverID string, running *Server, cfg npmConfig) error {
	routes, err := a.serverRoutes(ctx, serverID)
	if err != nil {
		return err
	}
	var failures []error
	for _, route := range routes {
		if route.DeletePending || running == nil || running.Status != "running" && running.Status != "starting" {
			if err = a.removeServerExtraNPMRouteLocked(ctx, route, cfg); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", route.Hostname, err))
			} else if route.DeletePending {
				if err = a.finalizeDeletedServerRoute(ctx, route.ID); err != nil {
					failures = append(failures, fmt.Errorf("%s: could not forget removed route: %w", route.Hostname, err))
				}
			}
			continue
		}
		if err = a.openServerExtraNPMRouteLocked(ctx, *running, route, cfg); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", route.Hostname, err))
		}
	}
	return errors.Join(failures...)
}

func (a *App) openServerExtraNPMRouteLocked(ctx context.Context, s Server, route serverRoute, cfg npmConfig) error {
	if route.DeletePending {
		return a.removeServerExtraNPMRouteLocked(ctx, route, cfg)
	}
	if !cfg.Enabled {
		return nil
	}
	if !cfg.configured() {
		err := errors.New("Nginx Proxy Manager is enabled but not configured")
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	if route.NPMCleanupPending {
		if err := a.removeServerExtraNPMRouteLocked(ctx, route, cfg); err != nil {
			return fmt.Errorf("finish removing previous proxy host: %w", err)
		}
		refreshed, loadErr := a.serverRoute(ctx, route.ID)
		if loadErr != nil {
			return fmt.Errorf("reload route after cleanup: %w", loadErr)
		}
		route = refreshed
	}
	client, err := a.npmClient(cfg)
	if err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	for _, host := range hosts {
		id, idErr := parseNPMHostID(host.ID)
		if idErr != nil {
			continue
		}
		markedRouteID := fmt.Sprint(host.Meta["docklight_route_id"])
		if route.NPMHostID != "" && id == route.NPMHostID {
			if markedRouteID != "<nil>" && markedRouteID != "" && markedRouteID != route.ID {
				route.NPMLastError = "saved NPM host ID is marked as belonging to a different Docklight route"
				_ = a.saveServerRouteNPM(ctx, route)
				return errors.New(route.NPMLastError)
			}
			markedServerID := fmt.Sprint(host.Meta["docklight_server_id"])
			if markedServerID != "<nil>" && markedServerID != "" && markedServerID != s.ID {
				route.NPMLastError = "saved NPM host ID is marked as belonging to a different Docklight server"
				_ = a.saveServerRouteNPM(ctx, route)
				return errors.New(route.NPMLastError)
			}
			managed := fmt.Sprint(host.Meta["docklight_managed"])
			if managed != "<nil>" && managed != "" && managed != "true" {
				route.NPMLastError = "saved NPM host has a different ownership marker; left it untouched"
				_ = a.saveServerRouteNPM(ctx, route)
				return errors.New(route.NPMLastError)
			}
			if !containsString(host.DomainNames, route.Hostname) {
				route.NPMLastError = "saved NPM host no longer contains this route hostname; left it untouched"
				_ = a.saveServerRouteNPM(ctx, route)
				return errors.New(route.NPMLastError)
			}
			meta := routeNPMMetadata(host.Meta, s.ID, route.ID)
			if markedRouteID == "<nil>" || markedRouteID == "" || fmt.Sprint(host.Meta["docklight_server_id"]) != s.ID {
				if err = client.UpdateProxyHost(ctx, id, npm.ProxyHostUpdate{Meta: &meta}); err != nil {
					route.NPMLastError = "could not restore Docklight ownership metadata: " + err.Error()
					_ = a.saveServerRouteNPM(ctx, route)
					return errors.New(route.NPMLastError)
				}
			}
			route.NPMLastError = ""
			route.NPMCleanupPending = false
			return a.saveServerRouteNPM(ctx, route)
		}
		if containsString(host.DomainNames, route.Hostname) {
			if markedRouteID == route.ID && fmt.Sprint(host.Meta["docklight_server_id"]) == s.ID && fmt.Sprint(host.Meta["docklight_managed"]) == "true" {
				route.NPMHostID = id
				route.NPMCleanupPending = false
				route.NPMLastError = ""
				return a.saveServerRouteNPM(ctx, route)
			}
			route.NPMLastError = "Nginx Proxy Manager already has a host for this hostname that Docklight does not own"
			_ = a.saveServerRouteNPM(ctx, route)
			return errors.New(route.NPMLastError)
		}
	}
	if serverID, inUse, checkErr := a.serverRouteProviderHostnameInUse(ctx, route.Hostname, "npm", route.ID, "", cfg, cloudflareConfig{}); checkErr != nil {
		route.NPMLastError = checkErr.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return checkErr
	} else if inUse {
		route.NPMLastError = fmt.Sprintf("hostname is already assigned through Nginx Proxy Manager to server %s", serverID)
		_ = a.saveServerRouteNPM(ctx, route)
		return errors.New(route.NPMLastError)
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	portName, hostPort, err := serverRouteTarget(s, gs, route.PortName)
	if err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	forwardHost := cfg.InternalHost
	if forwardHost == "" {
		localIP, ipErr := a.hostIPv4ForURL(ctx, cfg.URL)
		if ipErr != nil {
			route.NPMLastError = ipErr.Error()
			_ = a.saveServerRouteNPM(ctx, route)
			return ipErr
		}
		forwardHost = localIP.String()
	}
	forwardHost, err = normalizeNPMInternalHost(forwardHost)
	if err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	meta := routeNPMMetadata(nil, s.ID, route.ID)
	route.NPMCleanupPending = true
	route.NPMLastError = ""
	if err = a.saveServerRouteNPM(ctx, route); err != nil {
		return err
	}
	create := npm.ProxyHostCreate{DomainNames: []string{route.Hostname}, ForwardScheme: "http", ForwardHost: forwardHost, ForwardPort: hostPort, CertificateID: 0, SSLForced: false, HTTP2Support: false, BlockExploits: true, AllowWebsocketUpgrade: true, AccessListID: 0, Enabled: true, Meta: meta}
	hostID, err := client.CreateProxyHost(ctx, create)
	if err != nil {
		warning := "create Nginx Proxy Manager host: " + err.Error()
		route.NPMLastError = warning
		_ = a.saveServerRouteNPM(ctx, route)
		cleanupErr := a.removePartialExtraNPMHosts(ctx, client, route)
		if cleanupErr == nil {
			route.NPMCleanupPending = false
			_ = a.saveServerRouteNPM(ctx, route)
		}
		return errors.Join(fmt.Errorf("create Nginx Proxy Manager host for %s on %s/%d: %w", route.Hostname, portName, hostPort, err), cleanupErr)
	}
	route.NPMHostID = hostID
	if err = a.saveServerRouteNPM(ctx, route); err != nil {
		return fmt.Errorf("proxy host was created but Docklight could not save its ID: %w", err)
	}
	warning := a.configureExtraNPMHostSSL(ctx, client, hostID, meta, cfg)
	route.NPMLastError = warning
	route.NPMCleanupPending = false
	if err = a.saveServerRouteNPM(ctx, route); err != nil {
		return fmt.Errorf("proxy host was created but Docklight could not save its status: %w", err)
	}
	if warning != "" {
		a.audit(User{Username: "system"}, "server.route_npm_warning", "server", s.ID, warning)
	}
	return nil
}

func routeNPMMetadata(existing map[string]any, serverID, routeID string) map[string]any {
	meta := make(map[string]any, len(existing)+3)
	for key, value := range existing {
		meta[key] = value
	}
	meta["docklight_managed"] = true
	meta["docklight_server_id"] = serverID
	meta["docklight_route_id"] = routeID
	return meta
}

func (a *App) configureExtraNPMHostSSL(ctx context.Context, client *npm.Client, hostID string, meta map[string]any, cfg npmConfig) string {
	if cfg.LEEmail == "" && cfg.Email == "" {
		return ""
	}
	emptyMeta := map[string]any{}
	if err := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{Meta: &emptyMeta}); err != nil {
		return "Let's Encrypt setup could not start; proxy host remains available without SSL: " + err.Error()
	}
	sslForced := true
	sslMeta := map[string]any{"dns_challenge": false}
	updateErr := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{CertificateID: "new", SSLForced: &sslForced, Meta: &sslMeta})
	warning := ""
	if updateErr != nil {
		if confirmed, checkErr := a.npmHostHasSSL(ctx, client, hostID); confirmed {
			warning = "Nginx Proxy Manager reported an error after applying the Let's Encrypt update; verify the host there: " + updateErr.Error()
		} else {
			warning = "Let's Encrypt certificate could not be issued; proxy host remains available without SSL: " + updateErr.Error()
			if checkErr != nil {
				warning += " (could not confirm NPM host state: " + checkErr.Error() + ")"
			}
		}
	}
	if err := client.UpdateProxyHost(ctx, hostID, npm.ProxyHostUpdate{Meta: &meta}); err != nil {
		if warning != "" {
			warning += " | "
		}
		warning += "could not restore Docklight ownership metadata in NPM: " + err.Error()
	}
	return warning
}

func (a *App) removeServerExtraNPMRouteLocked(ctx context.Context, route serverRoute, cfg npmConfig) error {
	if route.NPMHostID == "" && !route.NPMCleanupPending {
		return nil
	}
	if !cfg.configured() {
		err := errors.New("Nginx Proxy Manager ownership is recorded but credentials are unavailable")
		route.NPMCleanupPending = true
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	client, err := a.npmClient(cfg)
	if err != nil {
		return err
	}
	route.NPMCleanupPending = true
	if err = a.saveServerRouteNPM(ctx, route); err != nil {
		return err
	}
	if err = a.removeOwnedExtraNPMHosts(ctx, client, route); err != nil {
		route.NPMLastError = err.Error()
		_ = a.saveServerRouteNPM(ctx, route)
		return err
	}
	route.NPMHostID = ""
	route.NPMLastError = ""
	route.NPMCleanupPending = false
	if err = a.saveServerRouteNPM(ctx, route); err != nil {
		return err
	}
	return nil
}

func (a *App) removeOwnedExtraNPMHosts(ctx context.Context, client *npm.Client, route serverRoute) error {
	hosts, err := client.ListProxyHosts(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, host := range hosts {
		id, idErr := parseNPMHostID(host.ID)
		if idErr != nil {
			continue
		}
		marked := fmt.Sprint(host.Meta["docklight_managed"]) == "true" && fmt.Sprint(host.Meta["docklight_server_id"]) == route.ServerID && fmt.Sprint(host.Meta["docklight_route_id"]) == route.ID
		knownID := route.NPMHostID != "" && id == route.NPMHostID
		if !marked && !knownID {
			continue
		}
		markedServerID := fmt.Sprint(host.Meta["docklight_server_id"])
		if markedServerID != "<nil>" && markedServerID != "" && markedServerID != route.ServerID {
			failures = append(failures, fmt.Errorf("NPM host %s has a different Docklight server marker; left it untouched", id))
			continue
		}
		if !containsString(host.DomainNames, route.Hostname) {
			failures = append(failures, fmt.Errorf("NPM host %s no longer contains %s; left it untouched", id, route.Hostname))
			continue
		}
		if markedRouteID := fmt.Sprint(host.Meta["docklight_route_id"]); markedRouteID != "<nil>" && markedRouteID != "" && markedRouteID != route.ID {
			failures = append(failures, fmt.Errorf("NPM host %s has a different Docklight route marker; left it untouched", id))
			continue
		}
		if deleteErr := client.DeleteProxyHost(ctx, id); deleteErr != nil {
			failures = append(failures, deleteErr)
		}
	}
	return errors.Join(failures...)
}

func (a *App) removePartialExtraNPMHosts(ctx context.Context, client *npm.Client, route serverRoute) error {
	return a.removeOwnedExtraNPMHosts(ctx, client, route)
}

func (a *App) cleanupAllExtraNPMRoutesLocked(ctx context.Context, cfg npmConfig) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM server_routes WHERE npm_host_id<>'' OR npm_cleanup_pending=1 OR delete_pending=1 ORDER BY server_id,created_at,id`)
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
		route, loadErr := a.serverRoute(ctx, id)
		if loadErr == nil {
			loadErr = a.removeServerExtraNPMRouteLocked(ctx, route, cfg)
			if loadErr == nil && route.DeletePending {
				loadErr = a.finalizeDeletedServerRoute(ctx, route.ID)
			}
		}
		if loadErr != nil {
			failures = append(failures, fmt.Errorf("route %s: %w", id, loadErr))
		}
	}
	return errors.Join(failures...)
}

func (a *App) reconcileAllExtraNPMRoutesLocked(ctx context.Context, cfg npmConfig, running map[string]bool) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM server_routes ORDER BY server_id,created_at,id`)
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
		route, loadErr := a.serverRoute(ctx, id)
		if loadErr != nil {
			failures = append(failures, loadErr)
			continue
		}
		if route.DeletePending || !running[route.ServerID] {
			loadErr = a.removeServerExtraNPMRouteLocked(ctx, route, cfg)
			if loadErr == nil && route.DeletePending {
				loadErr = a.finalizeDeletedServerRoute(ctx, route.ID)
			}
		} else {
			server, getErr := a.getServer(route.ServerID)
			if getErr != nil {
				loadErr = getErr
			} else {
				loadErr = a.openServerExtraNPMRouteLocked(ctx, server, route, cfg)
			}
		}
		if loadErr != nil {
			failures = append(failures, fmt.Errorf("route %s: %w", id, loadErr))
		}
	}
	return errors.Join(failures...)
}
